//! Client: bootstraps over SSH, then talks to the session over UDP, falling
//! back to the SSH channel (the server-side relay) when UDP doesn't get
//! through. Reconnects SSH by itself when everything goes quiet.

use crate::crypto::{self, Keys, DIR_TO_CLIENT};
use crate::proto::{self, ClientMsg, ServerMsg, ESC_BYTE, FLAG_ENDED, FLAG_SUPERSEDED, MAX_INPUT_CHUNK};
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

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

const USAGE: &str = "\
usage: ussh [options] [user@]host

options:
  -s, --session NAME   session to attach or create (default: main)
  --ssh CMD            ssh command to use, e.g. --ssh=\"ssh -p 2222\"
  -l, --list           list sessions on host
  --kill               end the session on host
  -V, --version

keys (Ctrl-^ is Ctrl-6 / Ctrl-Shift-6 on most keyboards):
  Ctrl-^ .             detach (the session keeps running)
  Ctrl-^ h             history viewer: scroll and / search
  Ctrl-^ Ctrl-^        send a literal Ctrl-^
";

#[derive(Clone)]
struct Opts {
    host: String,
    session: String,
    ssh: Vec<String>,
}

pub fn main(args: &[String]) -> i32 {
    let mut host = None;
    let mut session = "main".to_string();
    let mut ssh = std::env::var("USSH_SSH").unwrap_or_else(|_| "ssh".into());
    let (mut list, mut kill) = (false, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return 0;
            }
            "-s" | "--session" => session = it.next().cloned().unwrap_or_default(),
            "--ssh" => ssh = it.next().cloned().unwrap_or_default(),
            "-l" | "--list" => list = true,
            "--kill" => kill = true,
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
    let o = Opts { host, session, ssh };
    if let Some(home) = std::env::var_os("HOME") {
        let _ = std::fs::create_dir_all(std::path::Path::new(&home).join(".ussh"));
    }

    if list || kill {
        let cmd = if list { "server list".to_string() } else { format!("server kill {}", o.session) };
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
    let msg = match run(o, boot) {
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

fn bootstrap(o: &Opts, cols: u16, rows: u16, batch: bool) -> Result<Boot, String> {
    let colorterm = std::env::var("COLORTERM")
        .ok()
        .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric()))
        .unwrap_or_else(|| "-".into());
    let args = format!("server connect {} {cols} {rows} {colorterm}", o.session);
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
        if let Some(p) = line.strip_prefix("USSH_NEED_INSTALL ") {
            let _ = child.wait();
            if batch {
                return Err("ussh on the server changed; reconnect manually".into());
            }
            install(o, p.trim())?;
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() != 6 || f[0] != "USSH1" {
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
            stdin: child.stdin.take().unwrap(),
            child,
            stdout,
        });
    }
    Err("install did not take effect".into())
}

/// Copies a local file into the session's paste directory on the server
/// (over the shared SSH connection) and returns its remote path.
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
    started: Instant,
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
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
        if self.drop <= 0.0 {
            return false;
        }
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        ((self.rng >> 11) as f64 / (1u64 << 53) as f64) < self.drop
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
    last_udp: Option<Instant>,
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
    /// Ctrl+V pressed: keys typed until the clipboard is checked wait here.
    paste_pending: bool,
    held: Vec<u8>,
    /// pid of the ssh doing an upload (0 = none), for Ctrl+C to cancel.
    upload_pid: Arc<std::sync::atomic::AtomicU32>,
    status_until: Option<Instant>,
    /// Top-row notice, repainted over incoming frames while shown.
    status_text: Option<String>,
    /// Inside a bracketed paste: what has arrived so far.
    paste_buf: Option<Vec<u8>>,
    upload_started: Instant,
}

enum Exit {
    Detach,
    Ended,
    Superseded,
}

fn run(o: Opts, boot: Boot) -> Result<String, String> {
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
        last_udp: None,
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
        paste_pending: false,
        held: Vec::new(),
        upload_pid: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        status_until: None,
        status_text: None,
        paste_buf: None,
        upload_started: now,
    };
    let ip = resolved.or(boot.server_ip);
    c.server = ip.map(|ip| SocketAddr::new(ip, boot.port));
    c.adopt(boot);
    c.rebind_udp();
    c.send(Instant::now());

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
        c.tick();
    };
    Ok(c.finish(raw, result))
}

impl Client {
    fn finish(mut self, raw: term::RawMode, exit: Exit) -> String {
        self.relay = None;
        let _ = self.out.write_all(
            b"\x1b[0m\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l\x1b[?1l\x1b>\x1b[?25h\x1b[?2026l",
        );
        let _ = write!(self.out, "\x1b[{};1H\r\n", self.rows);
        let _ = self.out.flush();
        drop(raw);
        match exit {
            Exit::Detach => format!("detached; `ussh {}` reattaches session {}", self.o.host, self.o.session),
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
        self.relay = Some(Relay { id, child: boot.child, tx: rtx, started: Instant::now() });
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
                self.send(now);
            }
            Ev::Net(wire, via_udp) => return self.on_packet(&wire, via_udp, now),
            Ev::RelayDead(id) => {
                if self.relay.as_ref().is_some_and(|r| r.id == id) {
                    self.relay = None;
                    let udp_ok = self.last_udp.is_some_and(|t| now.duration_since(t) < Duration::from_secs(2));
                    if !udp_ok && !self.reconnecting {
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
            Ev::Uploaded(r) => match r {
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
            },
            Ev::Reconnected(r) => {
                self.reconnecting = false;
                match r {
                    Ok(boot) => {
                        self.relay = None;
                        self.adopt(*boot);
                        self.backoff = Duration::from_secs(1);
                        self.last_error.clear();
                        self.send(now);
                    }
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
        for (i, &b) in data.iter().enumerate() {
            if self.paste_pending {
                let pid = self.upload_pid.load(Ordering::SeqCst);
                if b == 0x03 && pid != 0 {
                    // Ctrl+C cancels the upload.
                    unsafe {
                        libc::kill(pid as i32, libc::SIGTERM);
                    }
                    self.upload_pid.store(0, Ordering::SeqCst);
                    self.status("ussh: upload cancelled", Duration::from_secs(2));
                    self.paste_pending = false;
                    let mut rest = std::mem::take(&mut self.held);
                    rest.extend_from_slice(&data[i + 1..]);
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

    fn on_packet(&mut self, wire: &[u8], via_udp: bool, now: Instant) -> Option<Exit> {
        if self.knobs.lose() {
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
        if via_udp {
            self.last_udp = Some(now);
        }
        self.backoff = Duration::from_secs(1);
        let mut reply = false;
        if self.overlay_drawn.take().is_some() {
            // Back in contact: paint over the banner from our mirror.
            self.redraw_local();
        }
        if msg.flags & FLAG_ENDED != 0 {
            return Some(Exit::Ended);
        }
        if msg.flags & FLAG_SUPERSEDED != 0 {
            return Some(Exit::Superseded);
        }
        if msg.input_ack > self.input_base {
            let n = ((msg.input_ack - self.input_base) as usize).min(self.input.len());
            self.input.drain(..n);
            self.input_base += n as u64;
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
        if reply {
            self.send(now);
        }
        None
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
        self.upload_started = Instant::now();
        let first = self.progress_line(0, size, 1, files.len(), &what);
        self.status(&first, Duration::from_secs(24 * 3600));
        let (o, tx, pid) = (self.o.clone(), self.tx.clone(), self.upload_pid.clone());
        std::thread::spawn(move || {
            let mut paths = Vec::new();
            let mut result = Ok(());
            let mut before = 0u64;
            let mut last_report = Instant::now();
            let n = files.len();
            for (i, f) in files.iter().enumerate() {
                let name = match &temp {
                    Some((_, n)) => n.clone(),
                    None => safe_name(&f.file_name().unwrap_or_default().to_string_lossy()),
                };
                let shown = f.file_name().unwrap_or_default().to_string_lossy().into_owned();
                let shown = if temp.is_some() { name.clone() } else { shown };
                let mut report = |sent: u64| {
                    if last_report.elapsed() >= Duration::from_millis(100) {
                        last_report = Instant::now();
                        let ev = Ev::UploadProgress { done: before + sent, total: size, file: i + 1, files: n, name: shown.clone() };
                        let _ = tx.send(ev);
                    }
                };
                let r = upload(&o, f, &name, &pid, &mut report);
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

    fn draw_status(&mut self) {
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
        let mut chunks: Vec<(u64, &[u8])> = self
            .input
            .chunks(MAX_INPUT_CHUNK)
            .take(32)
            .enumerate()
            .map(|(i, c)| (self.input_base + (i * MAX_INPUT_CHUNK) as u64, c))
            .collect();
        if chunks.is_empty() {
            chunks.push((self.input_base, &[]));
        }
        let wires: Vec<Vec<u8>> = chunks
            .into_iter()
            .map(|(off, data)| {
                let msg = ClientMsg {
                    instance: self.instance,
                    epoch: self.epoch,
                    ack: self.version,
                    input_off: off,
                    input: data.to_vec(),
                    cols: self.cols,
                    rows: self.rows,
                    hist_have: self.hist_have,
                }
                .encode();
                self.seq += 1;
                self.keys.seal(&self.mask, self.generation, self.seq, &msg)
            })
            .collect();
        for w in wires {
            if self.knobs.lose() {
                continue;
            }
            if let (Some(sock), Some(server)) = (&self.udp, self.server) {
                let _ = sock.send_to(&w, server);
            }
            if let Some(r) = &self.relay {
                let _ = r.tx.try_send(w);
            }
        }
        self.last_send = now;
        if !self.input.is_empty() {
            self.last_input_send = now;
        }
    }

    fn tick(&mut self) {
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

        // UDP works: drop the SSH relay (after a grace period, to avoid flapping).
        let udp_fresh = self.last_udp.is_some_and(|t| now.duration_since(t) < Duration::from_secs(1));
        if udp_fresh && self.relay.as_ref().is_some_and(|r| now.duration_since(r.started) > Duration::from_secs(2)) {
            self.relay = None;
        }

        let silent = now.duration_since(self.last_recv);
        if silent > Duration::from_secs(5) && !self.reconnecting && now >= self.next_reconnect {
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
    }
}
