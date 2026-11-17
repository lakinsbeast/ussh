//! Client: bootstraps over SSH, then talks to the session over UDP and the
//! SSH channel (the server-side relay) at once, so a lossy UDP path costs
//! nothing. Reconnects SSH by itself when everything goes quiet.

use crate::crypto::{self, Keys, DIR_TO_CLIENT};
use crate::proto::{self, ClientMsg, FileAck, FileChunk, ServerMsg, ESC_BYTE, FLAG_ENDED, FLAG_SUPERSEDED, MAX_INPUT_CHUNK};
use crate::proto::{FILE_DONE, FILE_FAILED, MAX_FILE_CHUNK};
use crate::server::valid_name;
use crate::term;
use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, OnceLock};
use std::time::{Duration, Instant};

const PASTE_START: &[u8] = b"\x1b[200~";
const PASTE_END: &[u8] = b"\x1b[201~";
const PASTE_MAX: usize = 64 * 1024;

/// A kitty keyboard protocol key report at the start of `b`: (length, key
/// code, modifier bits, event type).
fn csi_u(b: &[u8]) -> Option<(usize, u32, u32, u32)> {
    let body = b.strip_prefix(b"\x1b[")?;
    let end = body.iter().position(|&c| !(c.is_ascii_digit() || c == b';' || c == b':'))?;
    if body[end] != b'u' || end == 0 {
        return None;
    }
    let params = std::str::from_utf8(&body[..end]).ok()?;
    let mut fields = params.split(';');
    let code = fields.next()?.split(':').next()?.parse().ok()?;
    let mut m = fields.next().unwrap_or("1").split(':');
    let mods: u32 = m.next().and_then(|v| v.parse().ok()).unwrap_or(1);
    let event = m.next().and_then(|v| v.parse().ok()).unwrap_or(1);
    Some((end + 3, code, mods.saturating_sub(1), event))
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

const USAGE: &str = "\
usage: ussh [options] [user@]host

options:
  -s, --session NAME   attach this session (taking it over from another
                       window) or create it
  -n, --new            start a new session (the default)
  --ssh CMD            ssh command to use, e.g. --ssh=\"ssh -p 2222\"
  -l, --list           list sessions on host
  --kill               end the session on host
  --clean[=DAYS]       end sessions idle longer than DAYS (default 7); this
                       also runs by itself once a day
  -V, --version

keys (Ctrl-^ is Ctrl-6 / Ctrl-Shift-6 on most keyboards):
  Ctrl-^ .             detach (the session keeps running)
  Ctrl-^ h             history viewer: scroll and / search
  Ctrl-^ ?             this help over the screen
  Ctrl-^ Ctrl-^        send a literal Ctrl-^
";

#[derive(Clone)]
struct Opts {
    host: String,
    session: String,
    /// No -s: let the server pick the existing session.
    auto: bool,
    /// -n: let the server start a new session.
    new: bool,
    ssh: Vec<String>,
}

pub fn main(args: &[String]) -> i32 {
    let mut host = None;
    let mut session = "main".to_string();
    let mut auto = true;
    let mut new = false;
    let mut ssh = std::env::var("USSH_SSH").unwrap_or_else(|_| "ssh".into());
    let (mut list, mut kill) = (false, false);
    let mut clean: Option<u64> = None;
    // -n and -s are only contradictory when both were typed: a plain
    // "ussh host" now means a new session, which sets neither.
    let (mut explicit_new, mut explicit_session) = (false, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return 0;
            }
            "-s" | "--session" => {
                session = it.next().cloned().unwrap_or_default();
                auto = false;
                explicit_session = true;
            }
            "-n" | "--new" => {
                new = true;
                explicit_new = true;
            }
            "--ssh" => ssh = it.next().cloned().unwrap_or_default(),
            "-l" | "--list" => list = true,
            "--kill" => kill = true,
            "--clean" => clean = Some(7),
            s if s.starts_with("--clean=") => clean = Some(s["--clean=".len()..].parse().unwrap_or(7)),
            s if s.starts_with("--ssh=") => ssh = s["--ssh=".len()..].to_string(),
            s if s.starts_with('-') => {
                eprintln!("ussh: unknown option {s}\n\n{USAGE}");
                return 2;
            }
            s => host = Some(s.to_string()),
        }
    }
    let Some(host) = host else {
        eprint!("{USAGE}");
        return 2;
    };
    if !valid_name(&session) {
        eprintln!("ussh: session name may only contain letters, digits, - and _");
        return 2;
    }
    let ssh: Vec<String> = ssh.split_whitespace().map(str::to_string).collect();
    if ssh.is_empty() {
        eprintln!("ussh: empty --ssh");
        return 2;
    }
    if new && !auto {
        eprintln!("ussh: -n and -s don't go together");
        return 2;
    }
    // Plain "ussh host" opens a fresh session (main, main-2, ...): sharing one
    // screen by accident is worse than one extra session. -s NAME is how you
    // come back to one that already runs.
    if !explicit_session && !explicit_new {
        new = true;
    }
    let mut o = Opts { host, session, auto, new, ssh };
    if let Some(home) = std::env::var_os("HOME") {
        let _ = std::fs::create_dir_all(std::path::Path::new(&home).join(".ussh"));
    }

    if list || kill || clean.is_some() {
        let cmd = if list {
            "server list".to_string()
        } else if kill {
            format!("server kill {}", o.session)
        } else {
            format!("server clean {}", clean.unwrap_or(7))
        };
        return match run_remote(&o, &cmd) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("ussh: {e}");
                1
            }
        };
    }

    let (cols, rows) = term::size();
    crate::log_to(std::env::var_os("USSH_LOG").map(Into::into));
    let boot = match bootstrap(&o, cols, rows, false) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ussh: {e}");
            return 1;
        }
    };
    // Reconnects must come back to this very session.
    let picked = o.new;
    o.session = boot.session.clone();
    o.auto = false;
    o.new = false;
    let msg = match run(o, boot, picked) {
        Ok(m) => m,
        Err(e) => format!("error: {e}"),
    };
    eprintln!("[ussh: {msg}]");
    0
}

// ---------------------------------------------------------------- bootstrap

struct Boot {
    port: u16,
    generation: u32,
    key: [u8; 32],
    mask: [u8; 12],
    server_ip: Option<IpAddr>,
    /// The session we got (the server picks one for a plain `ussh host`).
    session: String,
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

/// This binary's platform, spelled like `uname -sm`.
fn local_platform() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "Linux x86_64",
        ("linux", "aarch64") => "Linux aarch64",
        ("macos", "x86_64") => "Darwin x86_64",
        ("macos", "aarch64") => "Darwin arm64",
        _ => "unknown",
    }
}

/// The ussh binary to install on a host of `platform`: ourselves if the
/// platform matches, else one embedded at build time.
fn payload_for(platform: &str) -> Option<Cow<'static, [u8]>> {
    if platform == local_platform() {
        return std::env::current_exe().and_then(std::fs::read).ok().map(Cow::Owned);
    }
    crate::embedded::EMBEDDED.iter().find(|(p, _)| *p == platform).map(|(_, b)| Cow::Borrowed(*b))
}

/// (platform, build id) of every binary we can install.
fn known_builds() -> &'static [(String, String)] {
    static IDS: OnceLock<Vec<(String, String)>> = OnceLock::new();
    IDS.get_or_init(|| {
        let mut v = vec![(local_platform().to_string(), crate::build_id())];
        for (p, bytes) in crate::embedded::EMBEDDED {
            v.push((p.to_string(), crate::fnv_id(bytes)));
        }
        v
    })
}

/// Runs `ussh ARGS` on the host if the installed binary is the build we'd
/// install there; otherwise prints `USSH_NEED_INSTALL <uname -sm>`.
fn remote_cmd(args: &str) -> String {
    let cases: String = known_builds().iter().map(|(p, id)| format!("\"{p}\") E={id};; ")).collect();
    format!(
        "sh -c 'B=\"$HOME/.local/bin/ussh\"; case \"$(uname -sm)\" in {cases}*) E=none;; esac; \
         if [ -x \"$B\" ] && [ \"$(\"$B\" build-id 2>/dev/null)\" = \"$E\" ]; \
         then exec \"$B\" {args}; fi; echo \"USSH_NEED_INSTALL $(uname -sm)\"'"
    )
}

fn ssh_command(o: &Opts, batch: bool) -> Command {
    let mut c = Command::new(&o.ssh[0]);
    c.args(&o.ssh[1..]).arg("-T");
    c.args(["-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3"]);
    // One authenticated connection for install, connect and reconnects:
    // a password is asked once, and later ssh runs start instantly.
    c.args(["-o", "ControlMaster=auto", "-o", "ControlPath=%d/.ussh/cm-%C", "-o", "ControlPersist=600"]);
    if batch {
        c.args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=8"]);
    }
    c
}

fn install(o: &Opts, remote_platform: &str) -> Result<(), String> {
    let Some(bin) = payload_for(remote_platform) else {
        let have: Vec<&str> = known_builds().iter().map(|(p, _)| p.as_str()).collect();
        return Err(format!(
            "{} is {remote_platform}; this ussh can install: {}. Put a matching ussh at ~/.local/bin/ussh there",
            o.host,
            have.join(", ")
        ));
    };
    eprintln!("ussh: installing ussh on {} (~/.local/bin/ussh, {remote_platform})…", o.host);
    let script = "sh -c 'mkdir -p \"$HOME/.local/bin\" && cat > \"$HOME/.local/bin/.ussh.tmp\" && \
                  chmod 755 \"$HOME/.local/bin/.ussh.tmp\" && mv -f \"$HOME/.local/bin/.ussh.tmp\" \"$HOME/.local/bin/ussh\"'";
    let status = ssh_command(o, false)
        .arg(&o.host)
        .arg(script)
        .stdin(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            let mut stdin = child.stdin.take().unwrap();
            let written = stdin.write_all(&bin);
            drop(stdin);
            let status = child.wait()?;
            written.map(|_| status)
        })
        .map_err(|e| format!("ssh: {e}"))?;
    if !status.success() {
        return Err("installing ussh on the server failed".into());
    }
    Ok(())
}

fn run_remote(o: &Opts, args: &str) -> Result<i32, String> {
    for _ in 0..2 {
        let out = ssh_command(o, false)
            .arg(&o.host)
            .arg(remote_cmd(args))
            .stderr(Stdio::inherit())
            .output()
            .map_err(|e| format!("ssh: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout);
        if let Some(p) = text.lines().find_map(|l| l.strip_prefix("USSH_NEED_INSTALL ")) {
            install(o, p.trim())?;
            continue;
        }
        print!("{text}");
        return Ok(out.status.code().unwrap_or(1));
    }
    Err("install did not take effect".into())
}

/// The server's answer to a reconnect when the session no longer exists.
const GONE: &str = "USSH_GONE";

fn bootstrap(o: &Opts, cols: u16, rows: u16, batch: bool) -> Result<Boot, String> {
    // Terminal identity for the remote shell: programs such as Claude Code
    // pick their notification style by TERM_PROGRAM.
    let env: Vec<String> = ["COLORTERM", "TERM_PROGRAM", "TERM_PROGRAM_VERSION"]
        .iter()
        .filter_map(|k| {
            let v = std::env::var(k).ok()?;
            let ok = !v.is_empty() && v.len() <= 64 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b));
            ok.then(|| format!("{k}={v}"))
        })
        .collect();
    let env = if env.is_empty() { "-".to_string() } else { env.join(",") };
    // A reconnect only reattaches: if the session is gone, a fresh one in
    // its place would not match the screen we have.
    let name = if o.new {
        "@new".to_string()
    } else if o.auto {
        "@auto".to_string()
    } else if batch {
        format!("={}", o.session)
    } else {
        o.session.clone()
    };
    let args = format!("server connect {name} {cols} {rows} {env}");
    for _ in 0..2 {
        let mut child = ssh_command(o, batch)
            .arg(&o.host)
            .arg(remote_cmd(&args))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(if batch { Stdio::null() } else { Stdio::inherit() })
            .spawn()
            .map_err(|e| format!("ssh: {e}"))?;
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        let _ = stdout.read_line(&mut line);
        let line = line.trim();
        if line == GONE {
            let _ = child.wait();
            return Err(GONE.into());
        }
        if let Some(p) = line.strip_prefix("USSH_NEED_INSTALL ") {
            let _ = child.wait();
            if batch {
                return Err("ussh on the server changed; reconnect manually".into());
            }
            install(o, p.trim())?;
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if !(6..=7).contains(&f.len()) || f[0] != "USSH1" {
            let _ = child.kill();
            let status = child.wait().ok().and_then(|s| s.code());
            return Err(if line.is_empty() {
                format!("ssh to {} failed (exit {})", o.host, status.map_or("?".into(), |c| c.to_string()))
            } else {
                format!("unexpected reply from server: {line}")
            });
        }
        let bad = || format!("bad connect line: {line}");
        return Ok(Boot {
            port: f[1].parse().map_err(|_| bad())?,
            generation: f[2].parse().map_err(|_| bad())?,
            key: crypto::unhex(f[3]).ok_or_else(bad)?,
            mask: crypto::unhex(f[4]).ok_or_else(bad)?,
            server_ip: f[5].parse().ok(),
            session: f.get(6).map_or(o.session.clone(), |s| s.to_string()),
            stdin: child.stdin.take().unwrap(),
            child,
            stdout,
        });
    }
    Err("install did not take effect".into())
}

/// Copies a local file into the session's paste directory on the server
/// over SSH and returns its remote path. Only for sessions started by an
/// older ussh: newer ones take pastes in-band (`Outgoing`), which needs no
/// login (a password can't be asked mid-session).
fn upload(
    o: &Opts,
    local: &std::path::Path,
    name: &str,
    pid: &std::sync::atomic::AtomicU32,
    progress: &mut dyn FnMut(u64),
) -> Result<String, String> {
    let mut file = std::fs::File::open(local).map_err(|e| format!("{}: {e}", local.display()))?;
    let size = file.metadata().map_err(|e| e.to_string())?.len();
    // Only a complete file gets its final name (a cancelled upload ends the
    // stream early, which `cat` can't tell from a normal end).
    let script = format!(
        "sh -c 'd=\"$HOME/.ussh/run/{}.files\"; mkdir -p \"$d\" && chmod 700 \"$d\" && n=\"{name}\"; t=\"$d/$n\"; i=1; \
         while [ -e \"$t\" ]; do t=\"$d/$i-$n\"; i=$((i+1)); done; cat > \"$t.part\"; \
         if [ $(($(wc -c < \"$t.part\"))) -eq {size} ]; then mv \"$t.part\" \"$t\" && printf \"%s\\n\" \"$t\"; \
         else rm -f \"$t.part\"; echo incomplete upload >&2; exit 1; fi'",
        o.session
    );
    let out = ssh_command(o, true)
        .arg(&o.host)
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            pid.store(child.id(), Ordering::SeqCst);
            // We feed the file ourselves to report progress.
            let mut stdin = child.stdin.take().unwrap();
            let mut buf = vec![0u8; 256 * 1024];
            let mut sent = 0u64;
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 || stdin.write_all(&buf[..n]).is_err() {
                    break;
                }
                sent += n as u64;
                progress(sent);
            }
            drop(stdin);
            child.wait_with_output()
        })
        .map_err(|e| format!("ssh: {e}"))?;
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.status.success() || path.is_empty() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(err.lines().last().unwrap_or("ssh failed").to_string());
    }
    Ok(path)
}

fn human_size(n: u64) -> String {
    match n {
        n if n >= 1 << 30 => format!("{:.1} GB", n as f64 / (1u64 << 30) as f64),
        n if n >= 1 << 20 => format!("{:.1} MB", n as f64 / (1u64 << 20) as f64),
        n if n >= 1 << 10 => format!("{:.0} KB", n as f64 / 1024.0),
        n => format!("{n} B"),
    }
}

/// The address ssh actually dials (resolves ~/.ssh/config aliases).
fn resolve_host(o: &Opts) -> Option<IpAddr> {
    let out = Command::new(&o.ssh[0]).args(&o.ssh[1..]).arg("-G").arg(&o.host).stderr(Stdio::null()).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let hostname = text.lines().find_map(|l| l.strip_prefix("hostname "))?.trim().to_string();
    (hostname.as_str(), 0).to_socket_addrs().ok()?.map(|a| a.ip()).next()
}

// ---------------------------------------------------------------- session

enum Ev {
    Stdin(Vec<u8>),
    StdinEof,
    Winch,
    Net(Vec<u8>, bool),
    RelayDead(u64),
    Reconnected(Result<Box<Boot>, String>),
    ClipChecked(Option<crate::clipboard::Clip>),
    UploadProgress { done: u64, total: u64, file: usize, files: usize, name: String },
    Uploaded(Result<Vec<String>, String>),
}

struct Relay {
    id: u64,
    child: Child,
    tx: mpsc::SyncSender<Vec<u8>>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Upload window (bytes in flight): starts small, grows with acks, shrinks
/// on loss.
const UPLOAD_WINDOW: (u64, u64) = (32 << 10, 1 << 20);

/// A paste going up inside the session: one file after another, each in
/// chunks. The server acks what it has (everything below `acked`, plus
/// ranges past a gap), and we resend just the gaps.
struct Outgoing {
    /// Local path, name on the server, name in the progress bar.
    files: Vec<(std::path::PathBuf, String, String)>,
    /// A clipboard image's temp file, deleted when done.
    temp: Option<std::path::PathBuf>,
    total: u64,
    /// Bytes of the files already done, and their server paths.
    before: u64,
    paths: Vec<String>,
    drawn: Instant,
    window: u64,
    /// Last time the window shrank (once per round trip at most).
    cut_at: Instant,
    srtt: Option<Duration>,
    // The current file.
    i: usize,
    file: std::fs::File,
    size: u64,
    id: u32,
    acked: u64,
    /// Ranges past `acked` the server has, from its latest ack.
    sacked: Vec<(u64, u64)>,
    /// Everything below `sent` went out at least once.
    sent: u64,
    /// When each gap (by start) was last resent.
    resent: std::collections::BTreeMap<u64, Instant>,
    /// An empty file's only chunk is out.
    empty_sent: bool,
    /// Last progress reported by the server: the timeout runs from here.
    progress_at: Instant,
    /// A chunk end being timed for the round-trip estimate.
    probe: Option<(u64, Instant)>,
}

impl Outgoing {
    fn new(files: Vec<(std::path::PathBuf, String, String)>, temp: Option<std::path::PathBuf>, total: u64, now: Instant) -> Result<Self, String> {
        let (file, size) = Self::open(&files[0].0)?;
        Ok(Outgoing {
            files,
            temp,
            total,
            before: 0,
            paths: Vec::new(),
            drawn: now,
            window: UPLOAD_WINDOW.0,
            cut_at: now,
            srtt: None,
            i: 0,
            file,
            size,
            id: crypto::random_u64() as u32,
            acked: 0,
            sacked: Vec::new(),
            sent: 0,
            resent: Default::default(),
            empty_sent: false,
            progress_at: now,
            probe: None,
        })
    }

    fn open(path: &std::path::Path) -> Result<(std::fs::File, u64), String> {
        let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let size = file.metadata().map_err(|e| e.to_string())?.len();
        Ok((file, size))
    }

    fn next(&mut self, now: Instant) -> Result<(), String> {
        (self.file, self.size) = Self::open(&self.files[self.i + 1].0)?;
        self.i += 1;
        self.id = crypto::random_u64() as u32;
        (self.acked, self.sent, self.empty_sent) = (0, 0, false);
        self.sacked.clear();
        self.resent.clear();
        self.progress_at = now;
        self.probe = None;
        Ok(())
    }

    fn rto(&self) -> Duration {
        self.srtt.map_or(Duration::from_secs(1), |s| (s * 2 + Duration::from_millis(100)).clamp(Duration::from_millis(200), Duration::from_secs(3)))
    }

    /// The chunk at `off`, up to `end`; the name rides along at offset 0.
    fn chunk(&self, off: u64, end: u64) -> Result<FileChunk, String> {
        use std::os::unix::fs::FileExt;
        let name = if off == 0 { self.files[self.i].1.clone() } else { String::new() };
        let n = (MAX_FILE_CHUNK - name.len()).min((end - off) as usize);
        let mut data = vec![0u8; n];
        self.file.read_exact_at(&mut data, off).map_err(|e| format!("{}: {e}", self.files[self.i].0.display()))?;
        Ok(FileChunk { id: self.id, total: self.size, off, name, data })
    }

    /// Chunks to send now: gaps the server reported (or, after a timeout,
    /// everything it hasn't confirmed), then new data as the window allows.
    fn due(&mut self, now: Instant) -> Result<Vec<FileChunk>, String> {
        let mut out = Vec::new();
        if self.size == 0 {
            if !self.empty_sent || now.duration_since(self.progress_at) > self.rto() {
                self.empty_sent = true;
                self.progress_at = now;
                out.push(FileChunk { id: self.id, total: 0, off: 0, name: self.files[self.i].1.clone(), data: Vec::new() });
            }
            return Ok(out);
        }
        let timeout = self.sent > self.acked && now.duration_since(self.progress_at) > self.rto();
        if timeout {
            self.window = (self.window / 2).max(UPLOAD_WINDOW.0);
            self.progress_at = now;
            self.resent.clear();
        }
        // Gaps below the last range the server has are lost (or late); on a
        // timeout, so is the tail after it.
        let limit = if timeout { self.sent } else { self.sacked.last().map_or(self.acked, |r| r.1) };
        let mut gaps = Vec::new();
        let mut cur = self.acked;
        for &(s, e) in &self.sacked {
            if s > cur {
                gaps.push((cur, s.min(limit)));
            }
            cur = cur.max(e);
        }
        if cur < limit {
            gaps.push((cur, limit));
        }
        let again = self.srtt.map_or(self.rto(), |s| s + s / 4 + Duration::from_millis(20));
        let mut budget = self.window;
        for (s, e) in gaps {
            if s >= e || budget == 0 || self.resent.get(&s).is_some_and(|t| now.duration_since(*t) < again) {
                continue;
            }
            self.resent.insert(s, now);
            self.probe = None;
            if !timeout && self.srtt.is_some_and(|rtt| now.duration_since(self.cut_at) > rtt) {
                self.window = (self.window * 3 / 4).max(UPLOAD_WINDOW.0);
                self.cut_at = now;
            }
            let mut off = s;
            while off < e && budget > 0 {
                let c = self.chunk(off, e)?;
                off += c.data.len() as u64;
                budget = budget.saturating_sub(c.data.len() as u64);
                out.push(c);
            }
        }
        let have: u64 = self.sacked.iter().map(|(s, e)| e - s).sum();
        while self.sent < self.size && self.sent - self.acked - have.min(self.sent - self.acked) < self.window {
            if self.sent == self.acked {
                self.progress_at = now;
            }
            let c = self.chunk(self.sent, self.size)?;
            self.sent += c.data.len() as u64;
            if self.probe.is_none() {
                self.probe = Some((self.sent, now));
            }
            out.push(c);
        }
        Ok(out)
    }

    fn ack(&mut self, have: u64, ranges: Vec<(u64, u64)>, now: Instant) {
        let before: u64 = self.sacked.iter().map(|(s, e)| e - s).sum();
        let after: u64 = ranges.iter().filter(|r| r.0 > have).map(|(s, e)| e - s).sum();
        if have > self.acked || after > before {
            self.progress_at = now;
        }
        self.sacked = ranges.into_iter().filter(|r| r.0 > have).collect();
        if have <= self.acked {
            return;
        }
        let gained = have - self.acked;
        self.acked = have.min(self.size);
        self.sent = self.sent.max(self.acked);
        self.resent.retain(|s, _| *s >= have);
        if let Some((_, t)) = self.probe.filter(|(end, _)| have >= *end) {
            let sample = now.duration_since(t);
            self.srtt = Some(self.srtt.map_or(sample, |s| s * 7 / 8 + sample / 8));
            self.probe = None;
        }
        self.window = (self.window + gained).min(UPLOAD_WINDOW.1);
    }
}

struct Assembly {
    base: u64,
    parts: Vec<Option<Vec<u8>>>,
    got: usize,
}

/// Test knobs: USSH_DROP=0.3 (drop 30% of packets each way), USSH_NO_UDP=1,
/// USSH_ROAM_SECS=5 (rebind the UDP socket periodically), USSH_BLACKHOLE=path
/// (drop everything while that file exists).
struct Knobs {
    drop: f64,
    /// Share of UDP packets from the server to drop (a lossy UDP path).
    udp_drop: f64,
    no_udp: bool,
    roam: Option<Duration>,
    blackhole: Option<std::path::PathBuf>,
    rng: u64,
}

impl Knobs {
    fn from_env() -> Self {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Knobs {
            drop: var("USSH_DROP").and_then(|v| v.parse().ok()).unwrap_or(0.0),
            udp_drop: var("USSH_UDP_DROP").and_then(|v| v.parse().ok()).unwrap_or(0.0),
            no_udp: var("USSH_NO_UDP").is_some(),
            roam: var("USSH_ROAM_SECS").and_then(|v| v.parse().ok()).map(Duration::from_secs_f64),
            blackhole: var("USSH_BLACKHOLE").map(Into::into),
            rng: crypto::random_u64() | 1,
        }
    }

    fn lose(&mut self) -> bool {
        if self.blackhole.as_ref().is_some_and(|p| p.exists()) {
            return true;
        }
        let p = self.drop;
        self.chance(p)
    }

    fn lose_udp(&mut self) -> bool {
        let p = self.udp_drop;
        self.chance(p)
    }

    fn chance(&mut self, p: f64) -> bool {
        if p <= 0.0 {
            return false;
        }
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        ((self.rng >> 11) as f64 / (1u64 << 53) as f64) < p
    }
}

struct Client {
    o: Opts,
    tx: mpsc::Sender<Ev>,
    out: io::Stdout,
    knobs: Knobs,

    keys: Keys,
    mask: [u8; 12],
    generation: u32,
    seq: u64,
    server: Option<SocketAddr>,
    udp: Option<UdpSocket>,
    udp_id: Arc<AtomicU64>,
    last_roam: Instant,
    relay: Option<Relay>,
    relay_ids: u64,

    instance: u64,
    epoch: u32,
    version: u64,
    input: Vec<u8>,
    input_base: u64,
    frags: HashMap<u64, Assembly>,
    cols: u16,
    rows: u16,
    prefix: bool,

    last_recv: Instant,
    last_send: Instant,
    last_input_send: Instant,
    reconnecting: bool,
    next_reconnect: Instant,
    backoff: Duration,
    last_error: String,
    overlay_drawn: Option<Instant>,
    /// What the terminal shows, so we can repaint without asking the server.
    mirror: vt100::Parser,
    hist_have: u64,
    hist_pending: Vec<String>,
    /// Kitty graphics: whether the terminal can, and the stream from the server.
    graphics: bool,
    /// Our terminal's name, answered to XTVERSION by the server.
    term_name: String,
    px: (u16, u16),
    gfx_have: u64,
    /// Chunks that arrived ahead of a gap, by offset.
    gfx_ahead: std::collections::BTreeMap<u64, Vec<u8>>,
    sink: crate::graphics::Sink,
    /// Ctrl+V pressed: keys typed until the clipboard is checked wait here.
    paste_pending: bool,
    held: Vec<u8>,
    /// pid of the ssh doing an upload (0 = none), for Ctrl+C to cancel.
    upload_pid: Arc<std::sync::atomic::AtomicU32>,
    /// A paste going up in-band, and whether the server takes those.
    upload: Option<Outgoing>,
    server_files: bool,
    status_until: Option<Instant>,
    /// Top-row notice, repainted over incoming frames while shown.
    status_text: Option<String>,
    /// Inside a bracketed paste: what has arrived so far.
    paste_buf: Option<Vec<u8>>,
    upload_started: Instant,
    /// The key map is being shown over the screen.
    help: bool,
}

enum Exit {
    Detach,
    Ended,
    Superseded,
}

fn run(o: Opts, boot: Boot, picked: bool) -> Result<String, String> {
    let resolved = resolve_host(&o);
    let (tx, rx) = mpsc::channel::<Ev>();

    let raw = term::RawMode::enter().map_err(|e| format!("raw mode: {e}"))?;
    let mut out = io::stdout();
    // No alternate screen: scrolled-off rows go into the terminal's own
    // scrollback. Push whatever is on screen now up into it first.
    let (cols0, rows0) = term::size();
    let _ = write!(out, "\x1b[999;1H{}\x1b[H", "\r\n".repeat(rows0 as usize));
    let _ = out.flush();

    // Keyboard.
    {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut stdin = io::stdin().lock();
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) | Err(_) => {
                        let _ = tx.send(Ev::StdinEof);
                        break;
                    }
                    Ok(n) => {
                        if tx.send(Ev::Stdin(buf[..n].to_vec())).is_err() {
                            break;
                        }
                    }
                }
            }
        });
    }
    // Window size changes.
    {
        let tx = tx.clone();
        let mut signals = signal_hook::iterator::Signals::new([libc::SIGWINCH]).map_err(|e| e.to_string())?;
        std::thread::spawn(move || {
            for _ in signals.forever() {
                if tx.send(Ev::Winch).is_err() {
                    break;
                }
            }
        });
    }

    let (cols, rows) = term::size();
    let now = Instant::now();
    let mut c = Client {
        o,
        tx,
        out,
        knobs: Knobs::from_env(),
        keys: Keys::new(&boot.key),
        mask: boot.mask,
        generation: boot.generation,
        seq: 0,
        server: None,
        udp: None,
        udp_id: Arc::new(AtomicU64::new(0)),
        last_roam: now,
        relay: None,
        relay_ids: 0,
        instance: crypto::random_u64(),
        epoch: 0,
        version: 0,
        input: Vec::new(),
        input_base: 0,
        frags: HashMap::new(),
        cols,
        rows,
        prefix: false,
        last_recv: now,
        last_send: now,
        last_input_send: now,
        reconnecting: false,
        next_reconnect: now,
        backoff: Duration::from_secs(1),
        last_error: String::new(),
        overlay_drawn: None,
        mirror: vt100::Parser::new(crate::history::nz(rows0), crate::history::nz(cols0), 0),
        hist_have: 0,
        hist_pending: Vec::new(),
        graphics: crate::graphics::local_support(),
        term_name: if crate::graphics::local_support() { crate::graphics::local_name() } else { String::new() },
        px: term::size_px(),
        gfx_have: 0,
        gfx_ahead: Default::default(),
        sink: Default::default(),
        paste_pending: false,
        held: Vec::new(),
        upload_pid: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        upload: None,
        server_files: false,
        status_until: None,
        status_text: None,
        paste_buf: None,
        upload_started: now,
        help: false,
    };
    let ip = resolved.or(boot.server_ip);
    c.server = ip.map(|ip| SocketAddr::new(ip, boot.port));
    c.adopt(boot);
    c.rebind_udp();
    c.send(Instant::now());
    if picked {
        let text = format!("ussh: new session {} (ussh --list shows all)", c.o.session);
        c.status(&text, Duration::from_secs(4));
    }

    let result = loop {
        match rx.recv_timeout(Duration::from_millis(20)) {
            Ok(ev) => {
                if let Some(exit) = c.handle(ev) {
                    break exit;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break Exit::Detach,
        }
        let budget = Instant::now() + Duration::from_millis(10);
        while Instant::now() < budget {
            let Ok(ev) = rx.try_recv() else { break };
            if let Some(exit) = c.handle(ev) {
                return Ok(c.finish(raw, exit));
            }
        }
        if let Some(exit) = c.tick() {
            break exit;
        }
    };
    Ok(c.finish(raw, result))
}

impl Client {
    fn finish(mut self, raw: term::RawMode, exit: Exit) -> String {
        self.relay = None;
        if !self.term_name.is_empty() {
            // Back to plain keys (the server may have turned on kitty's).
            let _ = self.out.write_all(b"\x1b[=0;1u");
        }
        let _ = self.out.write_all(
            b"\x1b[0m\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l\x1b[?1l\x1b>\x1b[?25h\x1b[?2026l",
        );
        let _ = write!(self.out, "\x1b[{};1H\r\n", self.rows);
        let _ = self.out.flush();
        drop(raw);
        match exit {
            Exit::Detach => format!("detached; `ussh -s {s} {h}` reattaches session {s}, or `ussh {h}` the last free one", s = self.o.session, h = self.o.host),
            Exit::Ended => "session ended".into(),
            Exit::Superseded => "session was attached from another client".into(),
        }
    }

    /// Switch to fresh credentials (and the SSH relay) from a bootstrap.
    fn adopt(&mut self, boot: Boot) {
        self.keys = Keys::new(&boot.key);
        self.mask = boot.mask;
        self.generation = boot.generation;
        self.seq = 0;
        if let Some(s) = &mut self.server {
            s.set_port(boot.port);
        } else if let Some(ip) = boot.server_ip {
            self.server = Some(SocketAddr::new(ip, boot.port));
        }
        self.relay_ids += 1;
        let id = self.relay_ids;
        let (rtx, rrx) = mpsc::sync_channel::<Vec<u8>>(256);
        let mut stdin = boot.stdin;
        std::thread::spawn(move || {
            for pkt in rrx {
                let ok = stdin.write_all(&(pkt.len() as u16).to_be_bytes()).is_ok()
                    && stdin.write_all(&pkt).is_ok()
                    && stdin.flush().is_ok();
                if !ok {
                    break;
                }
            }
        });
        let tx = self.tx.clone();
        let mut stdout = boot.stdout;
        std::thread::spawn(move || {
            let mut len = [0u8; 2];
            let mut buf = vec![0u8; 65536];
            loop {
                if stdout.read_exact(&mut len).is_err() {
                    break;
                }
                let n = u16::from_be_bytes(len) as usize;
                if stdout.read_exact(&mut buf[..n]).is_err() {
                    break;
                }
                if tx.send(Ev::Net(buf[..n].to_vec(), false)).is_err() {
                    return;
                }
            }
            let _ = tx.send(Ev::RelayDead(id));
        });
        self.relay = Some(Relay { id, child: boot.child, tx: rtx });
    }

    fn rebind_udp(&mut self) {
        let Some(server) = self.server else { return };
        if self.knobs.no_udp {
            return;
        }
        let bind = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let Ok(sock) = UdpSocket::bind(bind) else { return };
        let id = self.udp_id.fetch_add(1, Ordering::SeqCst) + 1;
        let current = self.udp_id.clone();
        let rx = sock.try_clone().unwrap();
        let _ = rx.set_read_timeout(Some(Duration::from_millis(500)));
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            while current.load(Ordering::SeqCst) == id {
                if let Ok((n, from)) = rx.recv_from(&mut buf) {
                    if from.ip().to_canonical() == server.ip().to_canonical() && current.load(Ordering::SeqCst) == id {
                        if tx.send(Ev::Net(buf[..n].to_vec(), true)).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        self.udp = Some(sock);
        self.last_roam = Instant::now();
    }

    fn handle(&mut self, ev: Ev) -> Option<Exit> {
        let now = Instant::now();
        match ev {
            Ev::Stdin(data) => return self.on_keys(&data, now),
            Ev::StdinEof => return Some(Exit::Detach),
            Ev::Winch => {
                (self.cols, self.rows) = term::size();
                self.px = term::size_px();
                self.send(now);
            }
            Ev::Net(wire, via_udp) => return self.on_packet(&wire, via_udp, now),
            Ev::RelayDead(id) => {
                // The relay is the reliable path: get a new one at once (UDP
                // that seems to work may still be losing most packets).
                if self.relay.as_ref().is_some_and(|r| r.id == id) {
                    self.relay = None;
                    if !self.reconnecting {
                        self.next_reconnect = self.next_reconnect.min(now);
                    }
                }
            }
            Ev::ClipChecked(clip) => {
                let uploading = match clip {
                    None => {
                        self.input.push(0x16);
                        false
                    }
                    Some(clip) => self.start_upload(clip),
                };
                // Keys typed meanwhile wait until the paste lands, so they
                // can't overtake it.
                if !uploading {
                    return self.release_held(now);
                }
            }
            Ev::UploadProgress { done, total, file, files, name } => {
                if self.paste_pending {
                    let line = self.progress_line(done, total, file, files, &name);
                    self.status_text = Some(line);
                    self.draw_status();
                }
            }
            Ev::Uploaded(r) => return self.uploaded(r, now),
            Ev::Reconnected(r) => {
                self.reconnecting = false;
                match r {
                    Ok(boot) => {
                        self.relay = None;
                        self.adopt(*boot);
                        self.backoff = Duration::from_secs(1);
                        self.last_error.clear();
                        // Give the new credentials time for a first reply
                        // before deciding they don't work either.
                        self.next_reconnect = now + Duration::from_secs(3);
                        self.send(now);
                    }
                    Err(e) if e == GONE => return Some(Exit::Ended),
                    Err(e) => {
                        self.last_error = e;
                        self.next_reconnect = now + self.backoff;
                        self.backoff = (self.backoff * 2).min(Duration::from_secs(15));
                    }
                }
            }
        }
        None
    }

    /// A paste is up (or failed): type its paths in, then the keys held
    /// back meanwhile.
    fn uploaded(&mut self, r: Result<Vec<String>, String>, now: Instant) -> Option<Exit> {
        match r {
            Ok(paths) if !self.paste_pending => drop(paths),
            Ok(paths) => {
                // Typed in as if dropped onto the terminal.
                let text = paths.join(" ");
                if self.mirror.screen().bracketed_paste() {
                    self.input.extend_from_slice(b"\x1b[200~");
                    self.input.extend_from_slice(text.as_bytes());
                    self.input.extend_from_slice(b"\x1b[201~");
                } else {
                    self.input.extend_from_slice(text.as_bytes());
                }
                self.status_until = None;
                self.status_text = None;
                self.redraw_local();
                return self.release_held(now);
            }
            Err(_) if !self.paste_pending => {}
            Err(e) => {
                self.status(&format!("ussh: upload failed: {e}"), Duration::from_secs(4));
                return self.release_held(now);
            }
        }
        None
    }

    /// Ends the in-band upload (removing a clipboard image's temp file).
    fn end_upload(&mut self, r: Result<Vec<String>, String>, now: Instant) -> Option<Exit> {
        if let Some(t) = self.upload.take().and_then(|u| u.temp) {
            let _ = std::fs::remove_file(t);
        }
        self.uploaded(r, now)
    }

    fn on_file_ack(&mut self, a: FileAck, now: Instant) -> Option<Exit> {
        let u = self.upload.as_mut()?;
        if a.id != u.id {
            return None;
        }
        match a.state {
            FILE_FAILED => return self.end_upload(Err(a.text), now),
            FILE_DONE => {
                u.paths.push(a.text);
                u.before += u.size;
                if u.i + 1 == u.files.len() {
                    let paths = std::mem::take(&mut u.paths);
                    return self.end_upload(Ok(paths), now);
                }
                if let Err(e) = u.next(now) {
                    return self.end_upload(Err(e), now);
                }
            }
            _ => u.ack(a.have, a.ranges, now),
        }
        self.pump_upload(now)
    }

    /// Sends the upload chunks that are due and updates the progress bar.
    fn pump_upload(&mut self, now: Instant) -> Option<Exit> {
        let u = self.upload.as_mut()?;
        let chunks = match u.due(now) {
            Ok(c) => c,
            Err(e) => return self.end_upload(Err(e), now),
        };
        let shown = (now.duration_since(u.drawn) >= Duration::from_millis(100)).then(|| {
            u.drawn = now;
            (u.before + u.acked, u.total, u.i + 1, u.files.len(), u.files[u.i].2.clone())
        });
        for c in chunks {
            self.transmit(self.input_base, Vec::new(), Some(c));
        }
        if let Some((done, total, file, files, name)) = shown.filter(|_| self.paste_pending) {
            self.status_text = Some(self.progress_line(done, total, file, files, &name));
            self.draw_status();
        }
        None
    }

    /// Keyboard input, with bracketed pastes picked out: a paste that is only
    /// local file paths (Cmd+V or drag & drop of files) becomes an upload.
    fn on_keys(&mut self, data: &[u8], now: Instant) -> Option<Exit> {
        if let Some(p) = &mut self.paste_buf {
            let old = p.len();
            p.extend_from_slice(data);
            let from = old.saturating_sub(PASTE_END.len() - 1);
            let Some(k) = find(&p[from..], PASTE_END) else {
                if p.len() > PASTE_MAX {
                    // Too big to be a list of paths: pass it through as is.
                    let p = self.paste_buf.take().unwrap();
                    self.forward_paste(&[PASTE_START, &p].concat(), now);
                }
                return None;
            };
            let p = self.paste_buf.take().unwrap();
            let end = from + k;
            let rest = p[end + PASTE_END.len()..].to_vec();
            if let Some(exit) = self.finish_paste(&p[..end], now) {
                return Some(exit);
            }
            return self.on_keys(&rest, now);
        }
        match find(data, PASTE_START) {
            None => self.keys_raw(data, now),
            Some(k) => {
                if let Some(exit) = self.keys_raw(&data[..k], now) {
                    return Some(exit);
                }
                if self.paste_pending {
                    self.held.extend_from_slice(&data[k..]);
                    return None;
                }
                self.paste_buf = Some(Vec::new());
                self.on_keys(&data[k + PASTE_START.len()..], now)
            }
        }
    }

    fn finish_paste(&mut self, content: &[u8], now: Instant) -> Option<Exit> {
        let text = String::from_utf8_lossy(content);
        if let Some(files) = crate::clipboard::local_files(&text) {
            if self.start_upload(crate::clipboard::Clip::Files(files)) {
                self.paste_pending = true;
                return None;
            }
        }
        self.forward_paste(&[PASTE_START, content, PASTE_END].concat(), now);
        None
    }

    /// Pasted bytes go to the server verbatim (no Ctrl+V or Ctrl-^ handling).
    fn forward_paste(&mut self, bytes: &[u8], now: Instant) {
        for &b in bytes {
            if b == ESC_BYTE {
                self.input.extend_from_slice(&[ESC_BYTE, ESC_BYTE]);
            } else {
                self.input.push(b);
            }
        }
        self.send(now);
    }

    fn keys_raw(&mut self, data: &[u8], now: Instant) -> Option<Exit> {
        if self.help {
            // The key that closes the help is swallowed, not passed on.
            self.help = false;
            self.redraw_local();
            return None;
        }
        let mut i = 0;
        while i < data.len() {
            let (b, len) = match self.own_key(&data[i..]) {
                Some((_, n, true)) => {
                    // The release of one of our keys.
                    i += n;
                    continue;
                }
                Some((b, n, false)) => (b, n),
                None => (data[i], 1),
            };
            let next = i + len;
            i = next;
            if self.paste_pending {
                let pid = self.upload_pid.load(Ordering::SeqCst);
                if b == 0x03 && (pid != 0 || self.upload.is_some()) {
                    // Ctrl+C cancels the upload.
                    if pid != 0 {
                        unsafe {
                            libc::kill(pid as i32, libc::SIGTERM);
                        }
                    }
                    self.upload_pid.store(0, Ordering::SeqCst);
                    if let Some(t) = self.upload.take().and_then(|u| u.temp) {
                        let _ = std::fs::remove_file(t);
                    }
                    self.status("ussh: upload cancelled", Duration::from_secs(2));
                    self.paste_pending = false;
                    let mut rest = std::mem::take(&mut self.held);
                    rest.extend_from_slice(&data[next..]);
                    return self.on_keys(&rest, now);
                }
                self.held.push(b);
                continue;
            }
            if b == 0x16 && !self.prefix {
                // Ctrl+V: upload copied files/images; plain text passes through.
                self.paste_pending = true;
                let tx = self.tx.clone();
                std::thread::spawn(move || {
                    let _ = tx.send(Ev::ClipChecked(crate::clipboard::read()));
                });
                continue;
            }
            if self.prefix && b == 0x16 {
                // Ctrl-^ Ctrl-V: a literal Ctrl+V.
                self.prefix = false;
                self.input.push(0x16);
                continue;
            }
            if self.prefix {
                self.prefix = false;
                match b {
                    b'?' => {
                        self.help = true;
                        self.draw_help();
                    }
                    b'.' => return Some(Exit::Detach),
                    ESC_BYTE => self.input.extend_from_slice(&[ESC_BYTE, ESC_BYTE]),
                    b'h' | b'[' => self.input.extend_from_slice(&[ESC_BYTE, b'h']),
                    other => self.input.extend_from_slice(&[ESC_BYTE, ESC_BYTE, other]),
                }
            } else if b == ESC_BYTE {
                self.prefix = true;
            } else {
                self.input.push(b);
            }
        }
        self.send(now);
        None
    }

    /// Under the kitty keyboard protocol our own keys (Ctrl-^ and what
    /// follows it, Ctrl+V, Ctrl+C during an upload) arrive as `CSI … u`:
    /// returns the legacy byte, the sequence length, and whether it's a
    /// key release.
    fn own_key(&self, b: &[u8]) -> Option<(u8, usize, bool)> {
        let (n, code, mods, event) = csi_u(b)?;
        let mods = mods & !(64 | 128); // caps and num lock
        let ctrl = mods & !1 == 4;
        let uploading = self.paste_pending && (self.upload_pid.load(Ordering::SeqCst) != 0 || self.upload.is_some());
        let byte = match code {
            54 | 94 if ctrl => ESC_BYTE,
            118 if mods == 4 => 0x16,
            99 if mods == 4 && uploading => 0x03,
            0x20..=0x7e if mods & !1 == 0 && self.prefix => code as u8,
            _ => return None,
        };
        Some((byte, n, event == 3))
    }

    fn on_packet(&mut self, wire: &[u8], via_udp: bool, now: Instant) -> Option<Exit> {
        if self.knobs.lose() || (via_udp && self.knobs.lose_udp()) {
            return None;
        }
        let hdr = crypto::peek_header(&self.mask, wire)?;
        if hdr.generation != self.generation || hdr.seq_dir & DIR_TO_CLIENT == 0 {
            return None;
        }
        let plain = self.keys.open(&hdr, wire)?;
        let msg = ServerMsg::decode(&plain)?;
        if let Some(f) = &msg.frame {
            crate::dlog!("cli recv {}->{} {}/{} have {}", f.base, f.new, f.idx, f.count, self.version);
        } else {
            crate::dlog!("cli recv hb flags {}", msg.flags);
        }

        self.last_recv = now;
        self.server_files = msg.files;
        self.backoff = Duration::from_secs(1);
        let mut reply = false;
        if self.overlay_drawn.take().is_some() {
            // Back in contact: paint over the banner from our mirror.
            self.redraw_local();
        }
        if msg.flags & FLAG_ENDED != 0 {
            return Some(Exit::Ended);
        }
        // (Our own reconnect supersedes these credentials too.)
        if msg.flags & FLAG_SUPERSEDED != 0 && !self.reconnecting {
            return Some(Exit::Superseded);
        }
        if msg.input_ack > self.input_base {
            let n = ((msg.input_ack - self.input_base) as usize).min(self.input.len());
            self.input.drain(..n);
            self.input_base += n as u64;
        }
        if let Some(a) = msg.file {
            if let Some(exit) = self.on_file_ack(a, now) {
                return Some(exit);
            }
        }
        if let Some(f) = msg.frame {
            if f.new > self.version && f.count > 0 && f.idx < f.count {
                // A retransmission of the same version may be diffed from a
                // different base: start that assembly over.
                let fresh = || Assembly { base: f.base, parts: vec![None; f.count as usize], got: 0 };
                let a = self.frags.entry(f.new).or_insert_with(fresh);
                if a.base != f.base || a.parts.len() != f.count as usize {
                    *a = fresh();
                }
                if a.parts[f.idx as usize].is_none() {
                    a.parts[f.idx as usize] = Some(f.data);
                    a.got += 1;
                }
                if a.got == a.parts.len() && (a.base == self.version || a.base == 0) {
                    let a = self.frags.remove(&f.new).unwrap();
                    let data: Vec<u8> = a.parts.into_iter().flatten().flatten().collect();
                    if let Some(bytes) = proto::inflate(&data) {
                        let (mr, mc) = self.mirror.screen().size();
                        if (mr.get(), mc.get()) != (f.rows, f.cols) {
                            self.mirror.set_size(crate::history::nz(f.rows), crate::history::nz(f.cols));
                        }
                        self.mirror.process(&bytes);
                        // Synchronized output: the terminal shows the frame whole.
                        let _ = self.out.write_all(b"\x1b[?2026h");
                        let _ = self.out.write_all(&bytes);
                        let _ = self.out.write_all(b"\x1b[?2026l");
                        let _ = self.out.flush();
                        self.draw_status();
                        crate::dlog!("cli apply {}->{}", a.base, f.new);
                        self.version = f.new;
                        let v = self.version;
                        self.frags.retain(|k, _| *k > v);
                    }
                    reply = true;
                } else if a.got == a.parts.len() {
                    // Built on a state we don't have; the server will resend
                    // from our ack after its timeout.
                    self.frags.remove(&f.new);
                    reply = true;
                }
            }
        }
        if let Some(h) = msg.hist {
            if let Some(text) = proto::inflate(&h.data) {
                let text = String::from_utf8_lossy(&text);
                let lines: Vec<&str> = text.split('\n').collect();
                let end = h.start + lines.len() as u64;
                if h.start <= self.hist_have && end > self.hist_have {
                    let skip = (self.hist_have - h.start) as usize;
                    self.hist_pending.extend(lines[skip..].iter().map(|l| l.to_string()));
                    self.hist_have = end;
                } else if h.skip && h.start > self.hist_have {
                    if self.hist_have != 0 {
                        let n = h.start - self.hist_have;
                        self.hist_pending.push(format!("\x1b[2m··· {n} lines skipped · Ctrl-^ h to browse them ···"));
                    }
                    self.hist_pending.extend(lines.iter().map(|l| l.to_string()));
                    self.hist_have = end;
                }
            }
            reply = true;
        }
        if let Some(g) = msg.gfx {
            if g.reset && g.start > self.gfx_have {
                self.sink.reset();
                self.gfx_have = g.start;
                self.gfx_ahead.retain(|off, _| *off > g.start);
            }
            if g.start > self.gfx_have {
                if self.gfx_ahead.len() < 8192 {
                    self.gfx_ahead.insert(g.start, g.data);
                }
            } else {
                self.take_gfx(g.start, &g.data);
                while let Some(e) = self.gfx_ahead.first_entry() {
                    if *e.key() > self.gfx_have {
                        break;
                    }
                    let (off, data) = e.remove_entry();
                    self.take_gfx(off, &data);
                }
            }
            reply = true;
        }
        if reply {
            self.send(now);
        }
        None
    }

    /// Graphics stream bytes at `off` (which is at or before `gfx_have`).
    fn take_gfx(&mut self, off: u64, data: &[u8]) {
        let end = off + data.len() as u64;
        if end <= self.gfx_have {
            return;
        }
        let out = self.sink.feed(&data[(self.gfx_have - off) as usize..]);
        self.gfx_have = end;
        if !out.is_empty() && self.graphics {
            crate::dlog!("cli gfx {} bytes to terminal, have {}", out.len(), end);
            let _ = self.out.write_all(&out);
            let _ = self.out.flush();
        }
    }

    fn release_held(&mut self, now: Instant) -> Option<Exit> {
        self.paste_pending = false;
        let held = std::mem::take(&mut self.held);
        let exit = self.on_keys(&held, now);
        self.send(now);
        exit
    }

    /// Returns whether an upload was started.
    fn start_upload(&mut self, clip: crate::clipboard::Clip) -> bool {
        use crate::clipboard::{safe_name, Clip};
        let (files, temp) = match clip {
            Clip::Files(f) => (f, None),
            Clip::Image(p) => {
                let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                (vec![p.clone()], Some((p, format!("paste-{secs}.png"))))
            }
        };
        let files: Vec<std::path::PathBuf> = files.into_iter().filter(|f| f.is_file()).collect();
        if files.is_empty() {
            self.status("ussh: nothing to upload (folders aren't supported yet)", Duration::from_secs(3));
            return false;
        }
        let size: u64 = files.iter().filter_map(|f| f.metadata().ok()).map(|m| m.len()).sum();
        let what = if files.len() == 1 {
            temp.as_ref().map(|t| t.1.clone()).unwrap_or_else(|| files[0].file_name().unwrap_or_default().to_string_lossy().into_owned())
        } else {
            format!("{} files", files.len())
        };
        // (name on the server, name in the progress bar)
        let names: Vec<(String, String)> = files
            .iter()
            .map(|f| match &temp {
                Some((_, n)) => (n.clone(), n.clone()),
                None => {
                    let shown = f.file_name().unwrap_or_default().to_string_lossy().into_owned();
                    (safe_name(&shown), shown)
                }
            })
            .collect();
        self.upload_started = Instant::now();
        let first = self.progress_line(0, size, 1, files.len(), &what);
        self.status(&first, Duration::from_secs(24 * 3600));
        if self.server_files {
            let list = files.into_iter().zip(names).map(|(f, (name, shown))| (f, name, shown)).collect();
            match Outgoing::new(list, temp.map(|t| t.0), size, self.upload_started) {
                Ok(u) => self.upload = Some(u),
                Err(e) => {
                    self.status(&format!("ussh: upload failed: {e}"), Duration::from_secs(4));
                    return false;
                }
            }
            self.pump_upload(Instant::now());
            return true;
        }
        let (o, tx, pid) = (self.o.clone(), self.tx.clone(), self.upload_pid.clone());
        std::thread::spawn(move || {
            let mut paths = Vec::new();
            let mut result = Ok(());
            let mut before = 0u64;
            let mut last_report = Instant::now();
            let n = files.len();
            for (i, (f, (name, shown))) in files.iter().zip(&names).enumerate() {
                let mut report = |sent: u64| {
                    if last_report.elapsed() >= Duration::from_millis(100) {
                        last_report = Instant::now();
                        let ev = Ev::UploadProgress { done: before + sent, total: size, file: i + 1, files: n, name: shown.clone() };
                        let _ = tx.send(ev);
                    }
                };
                let r = upload(&o, f, name, &pid, &mut report);
                before += f.metadata().map(|m| m.len()).unwrap_or(0);
                match r {
                    Ok(p) => paths.push(p),
                    Err(e) => {
                        result = Err(e);
                        break;
                    }
                }
            }
            if let Some((p, _)) = &temp {
                let _ = std::fs::remove_file(p);
            }
            pid.store(0, Ordering::SeqCst);
            let _ = tx.send(Ev::Uploaded(result.map(|_| paths)));
        });
        true
    }

    /// `⬆ name 2/3 ▕██████░░░░▏ 63%  31.5 MB/50.0 MB  12.4 MB/s  Ctrl+C`
    fn progress_line(&self, done: u64, total: u64, file: usize, files: usize, name: &str) -> String {
        let cols = self.cols as usize;
        let pct = if total == 0 { 100 } else { (done.saturating_mul(100) / total).min(100) };
        let secs = self.upload_started.elapsed().as_secs_f64().max(0.001);
        let rate = human_size((done as f64 / secs) as u64);
        let count = if files > 1 { format!(" {file}/{files}") } else { String::new() };
        let right = format!(" {pct:>3}%  {}/{}  {rate}/s  Ctrl+C cancels ", human_size(done), human_size(total));
        let budget = cols.saturating_sub(right.chars().count() + 14);
        // Leave most of the width to the bar itself.
        let budget = budget.clamp(8, 28);
        let name: String = if name.chars().count() > budget {
            name.chars().take(budget - 1).chain(['…']).collect()
        } else {
            name.to_string()
        };
        let left = format!(" ⬆ {name}{count} ");
        let bar_w = cols.saturating_sub(left.chars().count() + right.chars().count() + 2).max(4);
        let filled = (bar_w as u64 * pct / 100) as usize;
        format!("{left}▕{}{}▏{right}", "█".repeat(filled), "░".repeat(bar_w - filled))
    }

    /// A one-line notice on the top row until `dur` elapses or it's replaced.
    fn status(&mut self, text: &str, dur: Duration) {
        self.status_text = Some(text.to_string());
        self.status_until = Some(Instant::now() + dur);
        self.draw_status();
    }

    /// The key map, drawn over the screen after every frame until a key comes.
    fn draw_help(&mut self) {
        const LINES: [&str; 7] = [
            "Ctrl-^ .  detach; the session keeps running",
            "Ctrl-^ h  history: arrows, PgUp/PgDn, g/G, / then n/N, q",
            "Ctrl-^ ?  this help",
            "Ctrl-^ Ctrl-^  a literal Ctrl-^",
            "Ctrl-V    paste files or an image from the clipboard",
            "Ctrl-C    cancel an upload in progress",
            "any key   close this help",
        ];
        let (cols, rows) = (self.cols as usize, self.rows as usize);
        if cols < 40 || rows < LINES.len() + 4 {
            return;
        }
        let w = LINES.iter().map(|l| l.chars().count()).max().unwrap_or(0).min(cols - 4);
        let border = format!("+{}+", "-".repeat(w + 2));
        let mut s = String::from("\x1b7\x1b[0;36m");
        s.push_str(&format!("\x1b[2;1H{border}"));
        for (i, l) in LINES.iter().enumerate() {
            let text: String = l.chars().take(w).collect();
            s.push_str(&format!("\x1b[{};1H| {:<w$} |", i + 3, text, w = w));
        }
        s.push_str(&format!("\x1b[{};1H{border}\x1b[0m\x1b8", LINES.len() + 3));
        let _ = self.out.write_all(s.as_bytes());
        let _ = self.out.flush();
    }

    fn draw_status(&mut self) {
        if self.help {
            self.draw_help();
            return;
        }
        let Some(text) = &self.status_text else { return };
        let text: String = if text.starts_with(' ') { text.clone() } else { format!(" {text}") };
        let text: String = text.chars().take(self.cols as usize).collect();
        let pad = (self.cols as usize).saturating_sub(text.chars().count());
        let _ = write!(self.out, "\x1b7\x1b[1;1H\x1b[0;30;46m{text}{}\x1b[0m\x1b8", " ".repeat(pad));
        let _ = self.out.flush();
    }

    /// Repaint the terminal from the mirror.
    fn redraw_local(&mut self) {
        let s = self.mirror.screen().contents_formatted();
        let _ = write!(self.out, "\x1b[?2026h{s}\x1b[?2026l");
        let _ = self.out.flush();
    }

    /// Push pending history rows into the terminal's native scrollback: draw
    /// them from the top and scroll them off, then repaint the screen.
    fn flush_history(&mut self) {
        if self.hist_pending.is_empty() {
            return;
        }
        let lines = std::mem::take(&mut self.hist_pending);
        let (rows, cols) = (self.rows.max(2) as usize, self.cols.max(1) as usize);
        let mut s = String::from("\x1b[?2026h\x1b[0m\x1b[r");
        for r in 1..=rows {
            s.push_str(&format!("\x1b[{r};1H\x1b[2K"));
        }
        s.push_str("\x1b[1;1H");
        let mut phys = 0;
        for l in &lines {
            s.push_str(l);
            s.push_str("\x1b[0m\r\n");
            let plain: String = vt100::capture::basic_formatted_to_plain(l).collect();
            let w = unicode_width::UnicodeWidthStr::width(plain.as_str());
            phys += w.div_ceil(cols).max(1);
        }
        s.push_str(&format!("\x1b[{rows};1H{}", "\n".repeat(phys.min(rows - 1))));
        s.push_str(&self.mirror.screen().contents_formatted());
        s.push_str("\x1b[?2026l");
        let _ = self.out.write_all(s.as_bytes());
        let _ = self.out.flush();
        self.draw_status();
    }

    fn send(&mut self, now: Instant) {
        let mut chunks: Vec<(u64, Vec<u8>)> = self
            .input
            .chunks(MAX_INPUT_CHUNK)
            .take(32)
            .enumerate()
            .map(|(i, c)| (self.input_base + (i * MAX_INPUT_CHUNK) as u64, c.to_vec()))
            .collect();
        if chunks.is_empty() {
            chunks.push((self.input_base, Vec::new()));
        }
        for (off, data) in chunks {
            self.transmit(off, data, None);
        }
        self.last_send = now;
        if !self.input.is_empty() {
            self.last_input_send = now;
        }
    }

    /// One packet to the server, over UDP and the SSH relay (if up).
    fn transmit(&mut self, input_off: u64, input: Vec<u8>, file: Option<FileChunk>) {
        let msg = ClientMsg {
            instance: self.instance,
            epoch: self.epoch,
            ack: self.version,
            input_off,
            input,
            cols: self.cols,
            rows: self.rows,
            hist_have: self.hist_have,
            graphics: self.graphics,
            px_w: self.px.0,
            px_h: self.px.1,
            gfx_have: self.gfx_have,
            term: self.term_name.clone(),
            file,
        }
        .encode();
        self.seq += 1;
        let w = self.keys.seal(&self.mask, self.generation, self.seq, &msg);
        if self.knobs.lose() {
            return;
        }
        if let (Some(sock), Some(server)) = (&self.udp, self.server) {
            let _ = sock.send_to(&w, server);
        }
        if let Some(r) = &self.relay {
            let _ = r.tx.try_send(w);
        }
    }

    fn tick(&mut self) -> Option<Exit> {
        let now = Instant::now();
        if self.overlay_drawn.is_none() {
            self.flush_history();
        }
        if self.status_until.is_some_and(|t| now >= t) {
            self.status_until = None;
            self.status_text = None;
            self.redraw_local();
        }
        if let Some(every) = self.knobs.roam {
            if now.duration_since(self.last_roam) >= every {
                self.rebind_udp();
            }
        }
        if !self.input.is_empty() && now.duration_since(self.last_input_send) > Duration::from_millis(250) {
            self.send(now);
        } else if now.duration_since(self.last_send) > Duration::from_millis(500) {
            self.send(now);
        }

        // The SSH relay stays up next to UDP: some networks pass the first
        // seconds of a UDP flow and then drop most of it, which looks like
        // working UDP. Every packet goes both ways; duplicates are harmless.
        let silent = now.duration_since(self.last_recv);
        let relay_lost = self.relay.is_none() && self.relay_ids > 0;
        if (silent > Duration::from_secs(5) || relay_lost) && !self.reconnecting && now >= self.next_reconnect {
            self.reconnecting = true;
            let (o, tx, cols, rows) = (self.o.clone(), self.tx.clone(), self.cols, self.rows);
            std::thread::spawn(move || {
                let r = bootstrap(&o, cols, rows, true).map(Box::new);
                let _ = tx.send(Ev::Reconnected(r));
            });
        }

        if silent > Duration::from_millis(2500) && self.overlay_drawn.is_none_or(|t| now.duration_since(t) >= Duration::from_secs(1)) {
            let mut text = format!(" ussh: no contact with {} for {}s", self.o.host, silent.as_secs());
            if self.reconnecting {
                text.push_str(", reconnecting…");
            } else if !self.last_error.is_empty() {
                text.push_str(&format!(" ({})", self.last_error));
            }
            text.push_str("   Ctrl-^ . to detach");
            let text: String = text.chars().take(self.cols as usize).collect();
            let pad = (self.cols as usize).saturating_sub(text.chars().count());
            let _ = write!(self.out, "\x1b7\x1b[1;1H\x1b[0;30;43m{text}{}\x1b[0m\x1b8", " ".repeat(pad));
            let _ = self.out.flush();
            self.overlay_drawn = Some(now);
        }
        self.pump_upload(now)
    }
}
