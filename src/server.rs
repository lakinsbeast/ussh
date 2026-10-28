//! Server side. Three entry points, all run as the remote user:
//!
//! * `ussh server connect NAME COLS ROWS ENV` — run by the client over
//!   SSH. Finds (or spawns) the session process, obtains fresh credentials,
//!   prints them, then stays alive as a relay that forwards packets between
//!   its stdio and the session's UDP port. That relay is the TCP fallback.
//! * `ussh server session ...` — the detached session process: owns the PTY,
//!   the terminal emulator, history, and the UDP socket.
//! * `ussh server list` / `ussh server kill NAME`.

use crate::crypto::{self, Keys, DIR_TO_CLIENT};
use crate::graphics::{Gfx, Piece, Splitter};
use crate::history::{self, Hooks, KeyResult, Viewer};
use crate::proto::{self, ClientMsg, FileAck, FileChunk, Frame, GfxChunk, Hist, ServerMsg, ESC_BYTE, FLAG_ENDED, FLAG_SUPERSEDED, MAX_FRAG};
use crate::proto::{FILE_DONE, FILE_FAILED, FILE_RECEIVING};
use portable_pty::{CommandBuilder, MasterPty, PtySize};
use std::collections::{BTreeMap, HashMap};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const PORT_RANGE: std::ops::RangeInclusive<u16> = 60001..=61000;
/// Lines of history a newly attached client gets in its scrollback.
const HIST_SEED: u64 = 1000;
/// History lines in flight before waiting for acks.
const HIST_WINDOW: u64 = 600;
/// Backlog that counts as a flood, and how much of it to keep.
const HIST_SKIP_AT: u64 = 3000;
const HIST_SKIP_TO: u64 = 300;
/// How far past the first missing byte upload chunks are taken.
const UPLOAD_AHEAD: u64 = 16 << 20;
/// Ranges past a gap reported in one upload ack.
const UPLOAD_RANGES: usize = 32;

pub fn main(args: &[String]) -> i32 {
    let r = match args.first().map(String::as_str) {
        Some("connect") if args.len() >= 5 => connect(&args[1], &args[2], &args[3], &args[4]),
        Some("session") if args.len() >= 5 => run_session(&args[1], &args[2], &args[3], &args[4]),
        Some("list") => list(),
        Some("kill") if args.len() >= 2 => kill(&args[1]),
        Some("dump") if args.len() >= 2 => control(&args[1], "DUMP").map(|r| {
            let hex = r.strip_prefix("OK ").unwrap_or("");
            let bytes: Vec<u8> = (0..hex.len() / 2).filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()).collect();
            print!("{}", String::from_utf8_lossy(&bytes));
        }),
        _ => Err("usage: ussh server connect|session|list|kill ...".into()),
    };
    match r {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("ussh server: {e}");
            1
        }
    }
}

pub fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn run_dir() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME not set")?;
    let dir = PathBuf::from(home).join(".ussh/run");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir.parent().unwrap(), std::fs::Permissions::from_mode(0o700));
    Ok(dir)
}

fn sock_path(name: &str) -> Result<PathBuf, String> {
    Ok(run_dir()?.join(format!("{name}.sock")))
}

fn control(name: &str, cmd: &str) -> Result<String, String> {
    let mut s = UnixStream::connect(sock_path(name)?).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    writeln!(s, "{cmd}").map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).map_err(|e| e.to_string())?;
    Ok(line.trim().to_string())
}

// ---------------------------------------------------------------- connect

/// The session a plain `ussh host` gets: the most recently used `main` /
/// `main-N` that no live client holds, or else a new one. Runs under a lock
/// so that windows opened together don't pick the same session; the lock is
/// held until the CONNECT, which marks the session taken.
fn pick_session() -> Result<(String, std::fs::File), String> {
    let lock = std::fs::File::create(run_dir()?.join(".pick.lock")).map_err(|e| e.to_string())?;
    unsafe {
        libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX);
    }
    let names: Vec<String> = std::fs::read_dir(run_dir()?)
        .map_err(|e| e.to_string())?
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.strip_suffix(".sock").map(str::to_string))
        .filter(|n| n == "main" || n.strip_prefix("main-").is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit())))
        .collect();
    let states: Vec<(String, String)> = names.iter().map(|n| (n.clone(), control(n, "STATE").unwrap_or_default())).collect();
    let mut free: Vec<(u64, String)> = states
        .iter()
        .filter_map(|(n, r)| Some((r.strip_prefix("OK free ")?.parse().ok()?, n.clone())))
        .collect();
    free.sort();
    if let Some((_, n)) = free.into_iter().next() {
        return Ok((n, lock));
    }
    // A session on its way out frees its name (connect waits for it).
    let taken = |n: &str| states.iter().any(|(x, r)| x == n && !r.starts_with("ERR ending"));
    let name = if !taken("main") { "main".to_string() } else { (2..).map(|i| format!("main-{i}")).find(|n| !taken(n)).unwrap() };
    Ok((name, lock))
}

fn connect(name: &str, cols: &str, rows: &str, env: &str) -> Result<(), String> {
    let (name, lock) = if name == "@auto" {
        let (n, l) = pick_session()?;
        (n, Some(l))
    } else {
        (name.to_string(), None)
    };
    let name = name.as_str();
    if !valid_name(name) {
        return Err(format!("bad session name {name:?}"));
    }
    // A session that is shutting down refuses CONNECT; wait for it to go
    // away and start a fresh one.
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut spawned = false;
    let reply = loop {
        match control(name, "CONNECT") {
            Ok(r) if r.starts_with("ERR ending") => {}
            Ok(r) => break r,
            Err(e) if spawned && Instant::now() > deadline => return Err(format!("session did not start: {e}")),
            Err(_) if !spawned && UnixStream::connect(sock_path(name)?).is_err() => {
                spawn_session(name, cols, rows, env)?;
                spawned = true;
            }
            Err(_) => {}
        }
        if Instant::now() > deadline {
            return Err("timed out waiting for the session".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    drop(lock);
    let mut it = reply.split_whitespace();
    if it.next() != Some("OK") {
        return Err(format!("session refused: {reply}"));
    }
    let (port, generation, key, mask) = (it.next(), it.next(), it.next(), it.next());
    let (Some(port), Some(generation), Some(key), Some(mask)) = (port, generation, key, mask) else {
        return Err(format!("bad reply: {reply}"));
    };
    let port: u16 = port.parse().map_err(|_| "bad port")?;
    // The server address the client reached us on, as a fallback for UDP.
    let ip = std::env::var("SSH_CONNECTION")
        .ok()
        .and_then(|s| s.split_whitespace().nth(2).map(str::to_string))
        .unwrap_or_else(|| "-".into());
    let mut out = io::stdout().lock();
    writeln!(out, "USSH1 {port} {generation} {key} {mask} {ip} {name}").map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())?;
    drop(out);
    relay(port)
}

/// Forward length-prefixed packets between stdio (the SSH channel) and the
/// session's UDP port on localhost. Exits when the client closes the channel.
fn relay(port: u16) -> Result<(), String> {
    let sock = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    sock.connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    let rx = sock.try_clone().map_err(|e| e.to_string())?;
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        let mut out = io::stdout().lock();
        loop {
            let Ok(n) = rx.recv(&mut buf) else { continue };
            let ok = out.write_all(&(n as u16).to_be_bytes()).is_ok()
                && out.write_all(&buf[..n]).is_ok()
                && out.flush().is_ok();
            if !ok {
                std::process::exit(0);
            }
        }
    });
    let mut inp = io::stdin().lock();
    let mut len = [0u8; 2];
    let mut buf = vec![0u8; 65536];
    loop {
        if inp.read_exact(&mut len).is_err() {
            return Ok(());
        }
        let n = u16::from_be_bytes(len) as usize;
        if inp.read_exact(&mut buf[..n]).is_err() {
            return Ok(());
        }
        let _ = sock.send(&buf[..n]);
    }
}

fn spawn_session(name: &str, cols: &str, rows: &str, env: &str) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(run_dir()?.join(format!("{name}.log")))
        .map_err(|e| e.to_string())?;
    let mut cmd = Command::new(exe);
    cmd.args(["server", "session", name, cols, rows, env])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log);
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    cmd.spawn().map_err(|e| format!("spawn session: {e}"))?;
    Ok(())
}

fn list() -> Result<(), String> {
    let mut names: Vec<String> = std::fs::read_dir(run_dir()?)
        .map_err(|e| e.to_string())?
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.strip_suffix(".sock").map(str::to_string))
        .collect();
    names.sort_by_key(|n| (n != "main", n.len(), n.clone()));
    let ago = |ms: u64| match ms / 1000 {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86400 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86400),
    };
    for n in names {
        match control(&n, "INFO") {
            Ok(r) => {
                // INFO: OK COLSxROWS last-client AGE rtt RTT
                let f: Vec<&str> = r.split_whitespace().collect();
                let size = f.get(1).copied().unwrap_or("?");
                let rtt = f.iter().position(|x| *x == "rtt").and_then(|i| f.get(i + 1)).copied().unwrap_or("-");
                let state = match control(&n, "STATE").as_deref() {
                    Ok("OK busy") => "attached".to_string(),
                    Ok(s) if s.starts_with("ERR") => "ending".to_string(),
                    Ok(s) => match s.strip_prefix("OK free ").and_then(|v| v.parse::<u64>().ok()) {
                        Some(u64::MAX) | None => "free".to_string(),
                        Some(ms) => format!("free {}", ago(ms)),
                    },
                    Err(_) => "?".to_string(),
                };
                let rtt = if state == "attached" { format!("rtt {rtt}") } else { String::new() };
                println!("{n:<12} {state:<10} {size:<8} {rtt}");
            }
            Err(_) => {
                let _ = std::fs::remove_file(sock_path(&n)?);
                let _ = std::fs::remove_dir_all(run_dir()?.join(format!("{n}.files")));
            }
        }
    }
    Ok(())
}

fn kill(name: &str) -> Result<(), String> {
    control(name, "KILL").map(|r| println!("{r}"))
}

// ---------------------------------------------------------------- session

enum Ev {
    Pty(Vec<u8>),
    PtyEof,
    Udp(Vec<u8>, SocketAddr),
    Control(String, mpsc::Sender<String>),
}

struct GenKeys {
    keys: Keys,
    seq: u64,
    max_rx_seq: u64,
}

struct Snap {
    screen: vt100::Screen,
    title: String,
    clip_seq: u64,
    event_seq: u64,
    progress: String,
    /// Kitty keyboard flags for the client's terminal.
    kbd: u16,
}

struct Session {
    /// Session name, shown in the client's window title.
    name: String,
    parser: vt100::Parser<Hooks>,
    master: Box<dyn MasterPty + Send>,
    pty_in: mpsc::Sender<Vec<u8>>,
    child_pid: Option<u32>,
    cols: u16,
    rows: u16,
    udp: UdpSocket,
    port: u16,
    mask: [u8; 12],
    gens: HashMap<u32, GenKeys>,
    cur_gen: u32,
    peers: Vec<(SocketAddr, Instant)>,
    instance: Option<u64>,
    epoch: u32,
    last_client_msg: Option<Instant>,
    last_connect: Option<Instant>,

    version: u64,
    dirty: bool,
    dirty_since: Instant,
    last_output: Instant,
    snaps: BTreeMap<u64, Snap>,
    sent_at: HashMap<u64, Instant>,
    acked: u64,
    last_sent: u64,
    last_send: Instant,
    last_frame_at: Instant,
    /// Frames sent back-to-back; a long streak means bulk output.
    frame_streak: u32,
    rto_anchor: Instant,
    /// History streaming: client has everything below `hist_have`; we've
    /// sent up to `hist_sent`; nothing below `hist_floor` will be sent.
    hist_have: u64,
    hist_sent: u64,
    hist_floor: u64,
    hist_reported: u64,
    hist_anchor: Instant,
    last_input_at: Option<Instant>,
    clip_acked: u64,
    event_acked: u64,
    srtt_ms: Option<f64>,
    /// Kitty graphics: cut out of the output, stored, streamed to the client.
    split: Splitter,
    gfx: Gfx,
    /// Client terminal size in pixels.
    px: (u16, u16),

    input_expected: u64,
    esc_pending: bool,
    ack_pending: bool,
    viewer: Option<Viewer>,
    ended: Option<Instant>,
    /// The file being pasted, and whether its state is owed to the client.
    upload: Option<Incoming>,
    upload_reply: bool,
    /// Recent upload ids: a late duplicate of an earlier file's first chunk
    /// must not restart that file.
    upload_ids: Vec<u32>,
}

/// A pasted file arriving in chunks, written into the session's paste
/// directory under `<name>.part` until complete.
struct Incoming {
    id: u32,
    total: u64,
    /// Everything below `have` is written; `ahead` holds ranges past a gap.
    have: u64,
    ahead: BTreeMap<u64, u64>,
    file: Option<std::fs::File>,
    path: PathBuf,
    part: PathBuf,
    state: u8,
    text: String,
}

impl Incoming {
    fn start(session: &str, c: &FileChunk) -> Incoming {
        let mut u = Incoming {
            id: c.id,
            total: c.total,
            have: 0,
            ahead: BTreeMap::new(),
            file: None,
            path: PathBuf::new(),
            part: PathBuf::new(),
            state: FILE_RECEIVING,
            text: String::new(),
        };
        let open = || -> Result<(PathBuf, PathBuf, std::fs::File), String> {
            use std::os::unix::fs::PermissionsExt;
            let dir = run_dir()?.join(format!("{session}.files"));
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            let name = crate::clipboard::safe_name(&c.name);
            let free = |p: &PathBuf| !p.exists() && !part_of(p).exists();
            let path = std::iter::once(dir.join(&name))
                .chain((1..).map(|i| dir.join(format!("{i}-{name}"))))
                .find(free)
                .unwrap();
            let part = part_of(&path);
            let file = std::fs::File::create(&part).map_err(|e| e.to_string())?;
            Ok((path, part, file))
        };
        match open() {
            Ok((path, part, file)) => (u.path, u.part, u.file) = (path, part, Some(file)),
            Err(e) => u.fail(e),
        }
        u.take(c.off, &c.data);
        u
    }

    fn take(&mut self, off: u64, data: &[u8]) {
        use std::os::unix::fs::FileExt;
        if self.state != FILE_RECEIVING {
            return;
        }
        let end = off + data.len() as u64;
        if !data.is_empty() && end <= self.total && end > self.have && off <= self.have + UPLOAD_AHEAD {
            if let Err(e) = self.file.as_ref().unwrap().write_at(data, off) {
                return self.fail(e.to_string());
            }
            if off <= self.have {
                self.have = end;
            } else {
                self.add_ahead(off, end);
            }
            while let Some((&s, &e)) = self.ahead.first_key_value() {
                if s > self.have {
                    break;
                }
                self.have = self.have.max(e);
                self.ahead.pop_first();
            }
        }
        if self.have == self.total {
            self.file = None;
            match std::fs::rename(&self.part, &self.path) {
                Ok(()) => {
                    self.state = FILE_DONE;
                    self.text = self.path.to_string_lossy().into_owned();
                }
                Err(e) => self.fail(e.to_string()),
            }
        }
    }

    /// Records `off..end` past the gap, merged with ranges it touches.
    fn add_ahead(&mut self, mut off: u64, mut end: u64) {
        if let Some((&s, &e)) = self.ahead.range(..=off).next_back() {
            if e >= off {
                self.ahead.remove(&s);
                (off, end) = (s, e.max(end));
            }
        }
        while let Some((&s, &e)) = self.ahead.range(off..).next() {
            if s > end {
                break;
            }
            self.ahead.remove(&s);
            end = end.max(e);
        }
        self.ahead.insert(off, end);
    }

    fn fail(&mut self, e: String) {
        self.file = None;
        let _ = std::fs::remove_file(&self.part);
        self.state = FILE_FAILED;
        self.text = e;
    }

    fn ack(&self) -> FileAck {
        let ranges = self.ahead.iter().take(UPLOAD_RANGES).map(|(&s, &e)| (s, e)).collect();
        FileAck { id: self.id, have: self.have, ranges, state: self.state, text: self.text.clone() }
    }
}

impl Drop for Incoming {
    fn drop(&mut self) {
        if self.state == FILE_RECEIVING {
            let _ = std::fs::remove_file(&self.part);
        }
    }
}

fn part_of(path: &std::path::Path) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(".part");
    p.into()
}

fn run_session(name: &str, cols: &str, rows: &str, env: &str) -> Result<(), String> {
    let cols: u16 = cols.parse().unwrap_or(80).clamp(2, 1000);
    let rows: u16 = rows.parse().unwrap_or(24).clamp(2, 1000);
    let path = sock_path(name)?;
    crate::log_to(Some(run_dir()?.join("../debug")).filter(|p| p.exists()).map(|_| run_dir().unwrap().join(format!("{name}.debug"))));
    if UnixStream::connect(&path).is_ok() {
        return Err(format!("session {name} already running"));
    }
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).map_err(|e| format!("bind {}: {e}", path.display()))?;

    let (udp, port) = bind_udp()?;

    let pair = portable_pty::native_pty_system()
        .openpty(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })
        .map_err(|e| e.to_string())?;
    let mut cmd = CommandBuilder::new_default_prog();
    cmd.env("TERM", "xterm-256color");
    cmd.env("USSH_SESSION", name);
    // `K=V,K=V` from the client's environment (a bare value is COLORTERM,
    // as older clients sent it).
    for kv in env.split(',').filter(|s| *s != "-") {
        match kv.split_once('=') {
            Some((k @ ("COLORTERM" | "TERM_PROGRAM" | "TERM_PROGRAM_VERSION"), v)) => cmd.env(k, v),
            Some(_) => {}
            None => cmd.env("COLORTERM", kv),
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        cmd.cwd(home);
    }
    let mut child = pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;
    drop(pair.slave);
    let child_pid = child.process_id();
    let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
    let mut writer = pair.master.take_writer().map_err(|e| e.to_string())?;

    // Bounded: a program flooding output gets backpressure, like on a real
    // terminal, instead of growing our queue.
    let (tx, rx) = mpsc::sync_channel::<Ev>(256);

    // PTY output.
    {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send(Ev::Pty(buf[..n].to_vec())).is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = tx.send(Ev::PtyEof);
        });
    }
    // Shell exit (the PTY may stay open if background jobs hold it).
    {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let _ = child.wait();
            let _ = tx.send(Ev::PtyEof);
        });
    }
    // PTY input, on its own thread so a stalled program can't block us.
    let (pty_in, pty_rx) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        for data in pty_rx {
            if writer.write_all(&data).is_err() {
                break;
            }
            let _ = writer.flush();
        }
    });
    // UDP.
    {
        let tx = tx.clone();
        let sock = udp.try_clone().map_err(|e| e.to_string())?;
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            loop {
                if let Ok((n, from)) = sock.recv_from(&mut buf) {
                    if tx.send(Ev::Udp(buf[..n].to_vec(), from)).is_err() {
                        break;
                    }
                }
            }
        });
    }
    // Control socket.
    {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let tx = tx.clone();
                std::thread::spawn(move || {
                    let mut line = String::new();
                    let Ok(s2) = stream.try_clone() else { return };
                    if BufReader::new(s2).read_line(&mut line).is_err() {
                        return;
                    }
                    let (rtx, rrx) = mpsc::channel();
                    if tx.send(Ev::Control(line.trim().to_string(), rtx)).is_err() {
                        return;
                    }
                    if let Ok(reply) = rrx.recv_timeout(Duration::from_secs(5)) {
                        let mut stream = stream;
                        let _ = writeln!(stream, "{reply}");
                    }
                });
            }
        });
    }

    let now = Instant::now();
    let mut s = Session {
        name: name.to_string(),
        parser: vt100::Parser::new_with_callbacks(history::nz(rows), history::nz(cols), 0, Hooks::new()),
        master: pair.master,
        pty_in,
        child_pid,
        cols,
        rows,
        udp,
        port,
        mask: crypto::random_bytes(),
        gens: HashMap::new(),
        cur_gen: 0,
        peers: Vec::new(),
        instance: None,
        epoch: 0,
        last_client_msg: None,
        last_connect: None,
        version: 0,
        dirty: true,
        dirty_since: now,
        last_output: now,
        snaps: BTreeMap::new(),
        sent_at: HashMap::new(),
        acked: 0,
        last_sent: 0,
        last_send: now,
        last_frame_at: now,
        frame_streak: 0,
        rto_anchor: now,
        hist_have: 0,
        hist_sent: 0,
        hist_floor: 0,
        hist_reported: 0,
        hist_anchor: now,
        last_input_at: None,
        clip_acked: 0,
        event_acked: 0,
        srtt_ms: None,
        split: Splitter::default(),
        gfx: Gfx::new(now),
        px: (0, 0),
        input_expected: 0,
        esc_pending: false,
        ack_pending: false,
        viewer: None,
        ended: None,
        upload: None,
        upload_reply: false,
        upload_ids: Vec::new(),
    };
    eprintln!("ussh session {name}: udp port {port}, pid {}", std::process::id());

    loop {
        let loop_start = Instant::now();
        let busy = s.dirty || s.last_sent > s.acked || s.ack_pending || s.ended.is_some() || s.hist_pending() || s.gfx_pending() || s.upload_reply;
        let timeout = if busy { Duration::from_millis(1) } else { Duration::from_millis(100) };
        match rx.recv_timeout(timeout) {
            Ok(ev) => s.handle(ev),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        // Drain what is queued, but never so long that sending starves.
        let budget = Instant::now() + Duration::from_millis(10);
        while Instant::now() < budget {
            match rx.try_recv() {
                Ok(ev) => s.handle(ev),
                Err(_) => break,
            }
        }
        if s.tick() {
            break;
        }
        let took = loop_start.elapsed().saturating_sub(timeout);
        if took > Duration::from_millis(40) {
            crate::dlog!("srv slow loop {}ms", took.as_millis());
        }
    }
    let _ = std::fs::remove_file(&path);
    // Files pasted into this session live only as long as it does.
    let _ = std::fs::remove_dir_all(run_dir()?.join(format!("{name}.files")));
    Ok(())
}

fn bind_udp() -> Result<(UdpSocket, u16), String> {
    for port in PORT_RANGE {
        for addr in [format!("[::]:{port}"), format!("0.0.0.0:{port}")] {
            if let Ok(s) = UdpSocket::bind(&addr) {
                return Ok((s, port));
            }
        }
    }
    Err("no free UDP port in 60001-61000".into())
}

impl Session {
    fn handle(&mut self, ev: Ev) {
        let now = Instant::now();
        match ev {
            Ev::Pty(data) => {
                let h = self.parser.callbacks();
                let before = (h.clip_seq, h.event_seq, h.progress.clone());
                for piece in self.split.feed(&data) {
                    match piece {
                        Piece::Text(t) => self.parser.process(&t),
                        Piece::Graphics(cmd) => {
                            let hooks = self.parser.callbacks();
                            self.gfx.line = hooks.dropped + hooks.lines.len() as u64;
                            let fx = self.gfx.command(&cmd, self.parser.screen());
                            self.parser.process(fx.draw.as_bytes());
                            if !fx.reply.is_empty() {
                                let _ = self.pty_in.send(fx.reply);
                            }
                        }
                    }
                }
                // Answers to terminal queries (device attributes, sizes).
                let replies = std::mem::take(&mut self.parser.callbacks_mut().replies);
                if !replies.is_empty() {
                    let _ = self.pty_in.send(replies);
                }
                let h = self.parser.callbacks();
                if (h.clip_seq, h.event_seq, &h.progress) != (before.0, before.1, &before.2) {
                    self.mark_dirty(now);
                }
                if let Some(v) = &mut self.viewer {
                    v.note_changes(self.parser.callbacks());
                    if v.stale {
                        self.mark_dirty(now);
                    }
                } else {
                    self.mark_dirty(now);
                }
                self.last_output = now;
            }
            Ev::PtyEof => {
                if self.ended.is_none() {
                    self.ended = Some(now);
                }
            }
            Ev::Udp(wire, from) => self.on_packet(&wire, from, now),
            Ev::Control(cmd, reply) => {
                let r = match cmd.as_str() {
                    "CONNECT" if self.ended.is_some() => "ERR ending".to_string(),
                    "CONNECT" => {
                        self.cur_gen += 1;
                        let key: [u8; 32] = crypto::random_bytes();
                        self.gens.insert(self.cur_gen, GenKeys { keys: Keys::new(&key), seq: 0, max_rx_seq: 0 });
                        self.peers.clear();
                        self.last_connect = Some(now);
                        format!("OK {} {} {} {}", self.port, self.cur_gen, crypto::hex(&key), crypto::hex(&self.mask))
                    }
                    // Held by a live client (it sends twice a second), or
                    // free and since when.
                    "STATE" => {
                        let age = |t: Option<Instant>| t.map_or(u64::MAX, |t| now.duration_since(t).as_millis() as u64);
                        let (msg, conn) = (age(self.last_client_msg), age(self.last_connect));
                        if self.ended.is_some() {
                            "ERR ending".to_string()
                        } else if msg < 3000 || (conn < 10_000 && conn < msg) {
                            // (A client that has connected but not yet
                            // sent anything counts as there.)
                            "OK busy".to_string()
                        } else {
                            format!("OK free {}", msg.min(conn))
                        }
                    }
                    "INFO" => {
                        let idle = self.last_client_msg.map_or("never".to_string(), |t| format!("{}s", t.elapsed().as_secs()));
                        let rtt = self.srtt_ms.map_or("-".to_string(), |r| format!("{r:.0}ms"));
                        format!("OK {}x{} last-client {idle} rtt {rtt}", self.cols, self.rows)
                    }
                    // Plain-text screen contents, hex-encoded (for tests).
                    "DUMP" => {
                        let rows: Vec<String> = self.parser.screen().rows(0, self.cols).collect();
                        format!("OK {}", crypto::hex(rows.join("\n").as_bytes()))
                    }
                    "KILL" => {
                        if let Some(pid) = self.child_pid {
                            unsafe {
                                libc::kill(pid as i32, libc::SIGHUP);
                            }
                        }
                        self.ended = Some(now);
                        "OK killed".to_string()
                    }
                    _ => "ERR unknown command".to_string(),
                };
                let _ = reply.send(r);
            }
        }
    }

    fn mark_dirty(&mut self, now: Instant) {
        if !self.dirty {
            self.dirty = true;
            self.dirty_since = now;
        }
    }

    fn reset_sync(&mut self, now: Instant) {
        self.acked = 0;
        self.last_sent = 0;
        self.snaps.clear();
        self.sent_at.clear();
        self.dirty = false;
        self.mark_dirty(now);
    }

    fn on_packet(&mut self, wire: &[u8], from: SocketAddr, now: Instant) {
        let Some(hdr) = crypto::peek_header(&self.mask, wire) else { return };
        if hdr.seq_dir & DIR_TO_CLIENT != 0 {
            return;
        }
        let Some(g) = self.gens.get_mut(&hdr.generation) else { return };
        let Some(plain) = g.keys.open(&hdr, wire) else { return };
        if hdr.generation != self.cur_gen {
            // An older client: tell it someone else took over.
            g.seq += 1;
            let msg = ServerMsg { flags: FLAG_SUPERSEDED, input_ack: 0, frame: None, hist: None, gfx: None, file: None, files: true }.encode();
            let out = g.keys.seal(&self.mask, hdr.generation, DIR_TO_CLIENT | g.seq, &msg);
            let _ = self.udp.send_to(&out, from);
            return;
        }
        let newest = hdr.seq_dir > g.max_rx_seq;
        if newest {
            g.max_rx_seq = hdr.seq_dir;
        }
        let Some(msg) = ClientMsg::decode(&plain) else { return };
        self.last_client_msg = Some(now);

        match self.peers.iter_mut().find(|(a, _)| *a == from) {
            Some(p) => p.1 = now,
            None => {
                self.peers.push((from, now));
                if self.peers.len() > 4 {
                    self.peers.sort_by_key(|p| std::cmp::Reverse(p.1));
                    self.peers.truncate(4);
                }
            }
        }

        if self.instance != Some(msg.instance) {
            // A different client process: start its screen from scratch and
            // take its input stream as-is.
            self.instance = Some(msg.instance);
            self.epoch = msg.epoch;
            self.input_expected = msg.input_off;
            self.esc_pending = false;
            self.reset_sync(now);
            // Seed the new client's scrollback with recent history only.
            let hooks = self.parser.callbacks();
            let end = hooks.dropped + hooks.lines.len() as u64;
            self.hist_floor = end.saturating_sub(HIST_SEED).max(hooks.dropped);
            self.hist_have = self.hist_floor;
            self.hist_sent = self.hist_floor;
            self.hist_reported = 0;
            self.hist_anchor = now;
            // The new client's terminal has none of our images yet.
            self.gfx.rebase(now, self.hist_floor);
            self.gfx.stream.reported = 0;
        } else if msg.epoch > self.epoch {
            self.epoch = msg.epoch;
            self.reset_sync(now);
        }

        if newest {
            self.gfx.enabled = msg.graphics;
            if self.parser.callbacks().term != msg.term {
                self.parser.callbacks_mut().term = msg.term.clone();
            }
            if (msg.px_w, msg.px_h) != self.px {
                self.px = (msg.px_w, msg.px_h);
                self.parser.callbacks_mut().px = self.px;
                let _ = self.master.resize(PtySize { rows: self.rows, cols: self.cols, pixel_width: self.px.0, pixel_height: self.px.1 });
            }
        }
        if newest && msg.cols > 0 && msg.rows > 0 && (msg.cols, msg.rows) != (self.cols, self.rows) {
            self.resize(msg.cols.min(1000), msg.rows.min(1000), now);
        }
        if self.px.0 > 0 && self.px.1 > 0 {
            self.gfx.cell = (self.px.0 as u32 / self.cols.max(1) as u32, self.px.1 as u32 / self.rows.max(1) as u32);
        }
        self.gfx.stream.ack(msg.gfx_have, now);

        if msg.epoch == self.epoch && msg.ack > self.acked && self.snaps.contains_key(&msg.ack) {
            if let Some(t) = self.sent_at.get(&msg.ack) {
                let sample = now.duration_since(*t).as_secs_f64() * 1000.0;
                self.srtt_ms = Some(self.srtt_ms.map_or(sample, |s| s * 0.875 + sample * 0.125));
            }
            crate::dlog!("srv ack {} (sent {})", msg.ack, self.last_sent);
            self.acked = msg.ack;
            self.rto_anchor = now;
            self.clip_acked = self.clip_acked.max(self.snaps[&msg.ack].clip_seq);
            self.event_acked = self.event_acked.max(self.snaps[&msg.ack].event_seq);
            let acked = self.event_acked;
            self.parser.callbacks_mut().events.retain(|(seq, _)| *seq > acked);
            let keep = self.snaps.split_off(&self.acked);
            self.snaps = keep;
            self.sent_at.retain(|v, _| *v >= msg.ack);
        }

        self.hist_reported = self.hist_reported.max(msg.hist_have);
        let have = msg.hist_have.max(self.hist_floor);
        if have > self.hist_have {
            self.hist_have = have;
            self.hist_anchor = now;
        }
        self.hist_sent = self.hist_sent.max(self.hist_have);

        let off = msg.input_off;
        let end = off + msg.input.len() as u64;
        if !msg.input.is_empty() {
            if off <= self.input_expected && end > self.input_expected {
                let fresh = msg.input[(self.input_expected - off) as usize..].to_vec();
                self.input_expected = end;
                self.feed_input(&fresh, now);
                self.last_input_at = Some(now);
            }
            self.ack_pending = true;
        }

        if let Some(c) = msg.file {
            match &mut self.upload {
                Some(u) if u.id == c.id => u.take(c.off, &c.data),
                // A new upload starts with its first chunk (it has the name).
                _ if c.off == 0 && !self.upload_ids.contains(&c.id) => {
                    if self.upload_ids.len() >= 64 {
                        self.upload_ids.remove(0);
                    }
                    self.upload_ids.push(c.id);
                    // (An unfinished one goes first, freeing its name.)
                    self.upload = None;
                    self.upload = Some(Incoming::start(&self.name, &c));
                }
                _ => {}
            }
            self.upload_reply = true;
        }
    }

    fn resize(&mut self, cols: u16, rows: u16, now: Instant) {
        self.cols = cols;
        self.rows = rows;
        self.parser.set_size(history::nz(rows), history::nz(cols));
        let _ = self.master.resize(PtySize { rows, cols, pixel_width: self.px.0, pixel_height: self.px.1 });
        if let Some(v) = &mut self.viewer {
            v.stale = true;
        }
        self.reset_sync(now);
    }

    /// Decode the in-band escapes and route keys to the shell or the viewer.
    fn feed_input(&mut self, bytes: &[u8], now: Instant) {
        let mut out = Vec::with_capacity(bytes.len());
        for &b in bytes {
            if self.esc_pending {
                self.esc_pending = false;
                match b {
                    ESC_BYTE => out.push(ESC_BYTE),
                    b'h' => {
                        self.route(&mut out, now);
                        self.toggle_history(now);
                    }
                    _ => {}
                }
            } else if b == ESC_BYTE {
                self.esc_pending = true;
            } else {
                out.push(b);
            }
        }
        self.route(&mut out, now);
    }

    fn route(&mut self, out: &mut Vec<u8>, now: Instant) {
        if out.is_empty() {
            return;
        }
        let data = std::mem::take(out);
        match &mut self.viewer {
            None => {
                let _ = self.pty_in.send(data);
            }
            Some(v) => {
                let r = v.keys(&data, self.parser.callbacks(), self.parser.screen(), self.rows);
                if let KeyResult::Exit = r {
                    self.viewer = None;
                }
                self.mark_dirty(now);
            }
        }
    }

    fn toggle_history(&mut self, now: Instant) {
        self.viewer = match self.viewer {
            Some(_) => None,
            None => Some(Viewer::new(self.rows, self.cols)),
        };
        self.mark_dirty(now);
    }

    fn current_snap(&mut self) -> Snap {
        let (hooks, live) = (self.parser.callbacks(), self.parser.screen());
        let screen = match &mut self.viewer {
            Some(v) => {
                if v.stale || v.screen().size() != live.size() {
                    v.render(hooks, live);
                }
                v.screen().clone()
            }
            None => live.clone(),
        };
        let hooks = self.parser.callbacks();
        // The viewer reads plain keys.
        let kbd = if self.viewer.is_some() { 0 } else { hooks.kbd_flags(self.parser.screen().alternate_screen()) };
        // The session name leads, so tabs stay apart when titles are cut.
        let title = if hooks.title.is_empty() { self.name.clone() } else { format!("{} · {}", self.name, hooks.title) };
        Snap { screen, title, clip_seq: hooks.clip_seq, event_seq: hooks.event_seq, progress: hooks.progress.clone(), kbd }
    }

    fn payload(&self, base: Option<&Snap>, new: &Snap) -> Vec<u8> {
        let mut s = match base {
            // Full redraw: also switch off any input modes the client's
            // terminal may still have from an earlier state.
            None => "\x1b[0m\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l\x1b[?1l\x1b>".to_string()
                + &new.screen.state_formatted(),
            Some(b) => new.screen.state_diff(&b.screen),
        };
        if base.map_or(!new.title.is_empty(), |b| b.title != new.title) {
            s.push_str(&format!("\x1b]2;{}\x07", new.title));
        }
        // Re-sent with every diff until a frame carrying it is acked.
        if new.clip_seq > base.map_or(self.clip_acked, |b| b.clip_seq) {
            s.push_str(&self.parser.callbacks().clip);
        }
        if !self.parser.callbacks().term.is_empty() && base.is_none_or(|b| b.kbd != new.kbd) {
            s.push_str(&format!("\x1b[={};1u", new.kbd));
        }
        // Bells and notifications the client hasn't had, once each.
        let since = base.map_or(self.event_acked, |b| b.event_seq);
        for (_, e) in self.parser.callbacks().events.iter().filter(|(seq, _)| *seq > since && *seq <= new.event_seq) {
            s.push_str(e);
        }
        match base {
            Some(b) if b.progress == new.progress => {}
            Some(_) if new.progress.is_empty() => s.push_str("\x1b]9;4;0\x07"),
            None if new.progress.is_empty() => {}
            _ => s.push_str(&new.progress),
        }
        proto::deflate(s.as_bytes())
    }

    /// Send the current screen as a new version, diffed against `base`.
    fn send_new_frame(&mut self, base: u64, now: Instant) {
        let snap = self.current_snap();
        let payload = self.payload(self.snaps.get(&base), &snap);
        self.version += 1;
        let v = self.version;
        self.snaps.insert(v, snap);
        self.sent_at.insert(v, now);
        self.last_sent = v;
        self.dirty = false;
        self.frame_streak = if now.duration_since(self.last_frame_at) < Duration::from_millis(40) { self.frame_streak + 1 } else { 0 };
        self.last_frame_at = now;
        self.transmit(base, v, &payload, now);
    }

    fn transmit(&mut self, base: u64, new: u64, payload: &[u8], now: Instant) {
        crate::dlog!("srv frame {base}->{new} {}B streak {} inflight {}", payload.len(), self.frame_streak, self.snaps.range(self.acked + 1..).count());
        let count = payload.len().div_ceil(MAX_FRAG).max(1);
        for idx in 0..count {
            let chunk = &payload[(idx * MAX_FRAG).min(payload.len())..((idx + 1) * MAX_FRAG).min(payload.len())];
            let (rows, cols) = self.snaps.get(&new).map_or((self.rows, self.cols), |s| {
                let (r, c) = s.screen.size();
                (r.get(), c.get())
            });
            let frame = Frame { base, new, idx: idx as u16, count: count as u16, rows, cols, data: chunk.to_vec() };
            self.send_msg(0, Some(frame), None);
        }
        self.last_send = now;
        self.ack_pending = false;
    }

    fn send_msg(&mut self, flags: u8, frame: Option<Frame>, hist: Option<Hist>) {
        self.send_full(ServerMsg { flags, input_ack: self.input_expected, frame, hist, gfx: None, file: None, files: true });
    }

    fn send_full(&mut self, msg: ServerMsg) {
        let Some(g) = self.gens.get_mut(&self.cur_gen) else { return };
        let msg = msg.encode();
        g.seq += 1;
        let wire = g.keys.seal(&self.mask, self.cur_gen, DIR_TO_CLIENT | g.seq, &msg);
        for (addr, _) in &self.peers {
            let _ = self.udp.send_to(&wire, addr);
        }
    }

    /// Returns true when the session should exit.
    fn tick(&mut self) -> bool {
        let now = Instant::now();
        self.peers.retain(|(_, t)| now.duration_since(*t) < Duration::from_secs(15));

        if let Some(t) = self.ended {
            // Flush the final screen once, then tell the client we're done.
            if self.dirty && !self.peers.is_empty() {
                let base = self.acked;
                self.send_new_frame(base, now);
            }
            if now.duration_since(self.last_send) > Duration::from_millis(200) {
                self.send_msg(FLAG_ENDED, None, None);
                self.last_send = now;
            }
            return now.duration_since(t) > Duration::from_secs(3) || self.peers.is_empty();
        }
        if self.peers.is_empty() {
            return false;
        }

        let srtt = self.srtt_ms.unwrap_or(100.0);
        let rto = Duration::from_millis((srtt * 1.5 + 50.0).clamp(80.0, 1000.0) as u64);
        // Right after a keystroke, the echo goes out at once. Sustained output
        // with nobody typing is paced to ~2 frames per RTT so it can't flood a
        // slow link.
        let interactive = self.last_input_at.is_some_and(|t| now.duration_since(t) < Duration::from_millis(300));
        let (interval, quiet) = if interactive {
            (Duration::from_millis(1), Duration::from_millis(1))
        } else if self.frame_streak >= 4 {
            (Duration::from_millis((srtt / 2.0).clamp(20.0, 100.0) as u64), Duration::from_millis(3))
        } else {
            (Duration::from_millis((srtt / 4.0).clamp(3.0, 50.0) as u64), Duration::from_millis(3))
        };
        let since_frame = now.duration_since(self.last_frame_at);
        let since_send = now.duration_since(self.last_send);

        // The timeout runs from the last ack progress (or retransmit), not the
        // last send: during a stream of frames, a lost one must still be
        // noticed quickly.
        if self.last_sent > self.acked && now.duration_since(self.rto_anchor) > rto {
            self.rto_anchor = now;
            crate::dlog!("srv rto acked {} sent {}", self.acked, self.last_sent);
            // Assume what we sent since the last ack was lost: diff from the
            // acknowledged state again.
            if self.dirty {
                self.send_new_frame(self.acked, now);
            } else {
                let base = self.acked;
                let new = self.last_sent;
                let payload = self.payload(self.snaps.get(&base), &self.snaps[&new]);
                self.transmit(base, new, &payload, now);
            }
        } else if self.dirty
            && since_frame >= interval
            && (now.duration_since(self.last_output) >= quiet || now.duration_since(self.dirty_since) >= interval)
            && self.snaps.range(self.acked + 1..).count() < 32
        {
            // Diff from the newest state we've sent: in-order delivery is the
            // common case, and a loss is caught by the timeout above.
            let base = if self.last_sent > self.acked { self.last_sent } else { self.acked };
            if base == self.acked {
                self.rto_anchor = now;
            }
            self.send_new_frame(base, now);
        } else if self.ack_pending || since_send >= Duration::from_millis(500) {
            crate::dlog!("srv heartbeat");
            self.send_msg(0, None, None);
            self.last_send = now;
            self.ack_pending = false;
        }
        self.send_history(now, rto);
        self.send_graphics(now, rto);
        if std::mem::take(&mut self.upload_reply) {
            let file = self.upload.as_ref().map(Incoming::ack);
            self.send_full(ServerMsg { flags: 0, input_ack: self.input_expected, frame: None, hist: None, gfx: None, file, files: true });
        }
        false
    }

    fn hist_pending(&self) -> bool {
        let hooks = self.parser.callbacks();
        self.instance.is_some() && self.hist_sent < hooks.dropped + hooks.lines.len() as u64
    }

    /// Stream scrolled-off rows to the client (go-back-N on loss). If the
    /// client falls far behind (an output flood), skip ahead: the full
    /// history stays available in the viewer.
    fn send_history(&mut self, now: Instant, rto: Duration) {
        if self.instance.is_none() || self.peers.is_empty() {
            return;
        }
        let hooks = self.parser.callbacks();
        let (dropped, end) = (hooks.dropped, hooks.dropped + hooks.lines.len() as u64);
        if self.hist_sent > self.hist_have && now.duration_since(self.hist_anchor) > rto {
            self.hist_sent = self.hist_have;
            self.hist_anchor = now;
        }
        if end.saturating_sub(self.hist_have) > HIST_SKIP_AT || self.hist_have < dropped {
            self.hist_floor = end.saturating_sub(HIST_SKIP_TO).max(dropped);
            self.hist_have = self.hist_have.max(self.hist_floor);
            self.hist_sent = self.hist_sent.max(self.hist_have);
            self.hist_anchor = now;
        }
        let mut packets = 0;
        while self.hist_sent < end && self.hist_sent - self.hist_have < HIST_WINDOW && packets < 16 {
            let hooks = self.parser.callbacks();
            let first = (self.hist_sent - dropped) as usize;
            let mut n = 0;
            let mut raw = 0;
            while first + n < hooks.lines.len() && n < 200 && raw < 4000 {
                raw += hooks.lines[first + n].fmt.len() + 1;
                n += 1;
            }
            let data = loop {
                let text: Vec<&str> = hooks.lines.range(first..first + n).map(|l| l.fmt.as_str()).collect();
                let data = proto::deflate(text.join("\n").as_bytes());
                if data.len() <= MAX_FRAG || n == 1 {
                    break data;
                }
                n = n.div_ceil(2);
            };
            let start = self.hist_sent;
            // Only the chunk at a deliberate jump (the initial seed or a flood
            // skip) may be taken by a client that is behind it.
            let skip = start == self.hist_floor && start > self.hist_reported;
            let hist = Hist { start, skip, data };
            self.send_msg(0, None, Some(hist));
            self.hist_sent += n as u64;
            packets += 1;
        }
    }

    fn gfx_pending(&self) -> bool {
        self.instance.is_some() && self.gfx.enabled && self.gfx.stream.sent < self.gfx.stream.end
    }

    /// Stream images to the client: go-back-N within a window that halves
    /// on loss and grows with acks.
    fn send_graphics(&mut self, now: Instant, rto: Duration) {
        if self.instance.is_none() || self.peers.is_empty() || !self.gfx.enabled {
            return;
        }
        let hooks = self.parser.callbacks();
        let top = hooks.dropped + hooks.lines.len() as u64;
        if self.gfx.backlogged(top) {
            // Too far behind (e.g. a video): just send what's on screen.
            self.gfx.rebase(now, top);
        }
        let st = &mut self.gfx.stream;
        if st.sent > st.have && now.duration_since(st.anchor) > rto {
            st.on_timeout(now);
        } else if st.sent == st.have {
            st.anchor = now;
        }
        let mut packets = 0;
        while packets < 16 {
            let st = &self.gfx.stream;
            if st.sent >= st.end || st.sent - st.have >= st.window {
                break;
            }
            let data = st.slice(st.sent, MAX_FRAG);
            if data.is_empty() {
                break;
            }
            let start = st.sent;
            let reset = start == st.floor && start > st.reported;
            self.gfx.stream.sent += data.len() as u64;
            self.send_full(ServerMsg { flags: 0, input_ack: self.input_expected, frame: None, hist: None, gfx: Some(GfxChunk { start, reset, data }), file: None, files: true });
            packets += 1;
        }
    }
}
