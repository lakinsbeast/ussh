//! Server side. Three entry points, all run as the remote user:
//!
//! * `ussh server connect NAME COLS ROWS COLORTERM` — run by the client over
//!   SSH. Finds (or spawns) the session process, obtains fresh credentials,
//!   prints them, then stays alive as a relay that forwards packets between
//!   its stdio and the session's UDP port. That relay is the TCP fallback.
//! * `ussh server session ...` — the detached session process: owns the PTY,
//!   the terminal emulator, history, and the UDP socket.
//! * `ussh server list` / `ussh server kill NAME`.

use crate::crypto::{self, Keys, DIR_TO_CLIENT};
use crate::history::{self, Hooks, KeyResult, Viewer};
use crate::proto::{self, ClientMsg, Frame, ServerMsg, ESC_BYTE, FLAG_ENDED, FLAG_SUPERSEDED, MAX_FRAG};
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

fn connect(name: &str, cols: &str, rows: &str, colorterm: &str) -> Result<(), String> {
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
                spawn_session(name, cols, rows, colorterm)?;
                spawned = true;
            }
            Err(_) => {}
        }
        if Instant::now() > deadline {
            return Err("timed out waiting for the session".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
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
    writeln!(out, "USSH1 {port} {generation} {key} {mask} {ip}").map_err(|e| e.to_string())?;
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

fn spawn_session(name: &str, cols: &str, rows: &str, colorterm: &str) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(run_dir()?.join(format!("{name}.log")))
        .map_err(|e| e.to_string())?;
    let mut cmd = Command::new(exe);
    cmd.args(["server", "session", name, cols, rows, colorterm])
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
    names.sort();
    for n in names {
        match control(&n, "INFO") {
            Ok(r) => println!("{n}\t{}", r.strip_prefix("OK ").unwrap_or(&r)),
            Err(_) => {
                let _ = std::fs::remove_file(sock_path(&n)?);
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
}

struct Session {
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
    srtt_ms: Option<f64>,

    input_expected: u64,
    esc_pending: bool,
    ack_pending: bool,
    viewer: Option<Viewer>,
    ended: Option<Instant>,
}

fn run_session(name: &str, cols: &str, rows: &str, colorterm: &str) -> Result<(), String> {
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
    if colorterm != "-" {
        cmd.env("COLORTERM", colorterm);
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
        srtt_ms: None,
        input_expected: 0,
        esc_pending: false,
        ack_pending: false,
        viewer: None,
        ended: None,
    };
    eprintln!("ussh session {name}: udp port {port}, pid {}", std::process::id());

    loop {
        let loop_start = Instant::now();
        let busy = s.dirty || s.last_sent > s.acked || s.ack_pending || s.ended.is_some();
        let timeout = if busy { Duration::from_millis(2) } else { Duration::from_millis(100) };
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
                self.parser.process(&data);
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
                        format!("OK {} {} {} {}", self.port, self.cur_gen, crypto::hex(&key), crypto::hex(&self.mask))
                    }
                    "INFO" => {
                        let idle = self.last_client_msg.map_or("never".to_string(), |t| format!("{}s", t.elapsed().as_secs()));
                        format!("OK {}x{} last-client {idle}", self.cols, self.rows)
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
            let msg = ServerMsg { flags: FLAG_SUPERSEDED, input_ack: 0, frame: None }.encode();
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
        } else if msg.epoch > self.epoch {
            self.epoch = msg.epoch;
            self.reset_sync(now);
        }

        if newest && msg.cols > 0 && msg.rows > 0 && (msg.cols, msg.rows) != (self.cols, self.rows) {
            self.resize(msg.cols.min(1000), msg.rows.min(1000), now);
        }

        if msg.epoch == self.epoch && msg.ack > self.acked && self.snaps.contains_key(&msg.ack) {
            if let Some(t) = self.sent_at.get(&msg.ack) {
                let sample = now.duration_since(*t).as_secs_f64() * 1000.0;
                self.srtt_ms = Some(self.srtt_ms.map_or(sample, |s| s * 0.875 + sample * 0.125));
            }
            crate::dlog!("srv ack {} (sent {})", msg.ack, self.last_sent);
            self.acked = msg.ack;
            self.rto_anchor = now;
            let keep = self.snaps.split_off(&self.acked);
            self.snaps = keep;
            self.sent_at.retain(|v, _| *v >= msg.ack);
        }

        let off = msg.input_off;
        let end = off + msg.input.len() as u64;
        if !msg.input.is_empty() {
            if off <= self.input_expected && end > self.input_expected {
                let fresh = msg.input[(self.input_expected - off) as usize..].to_vec();
                self.input_expected = end;
                self.feed_input(&fresh, now);
            }
            self.ack_pending = true;
        }
    }

    fn resize(&mut self, cols: u16, rows: u16, now: Instant) {
        self.cols = cols;
        self.rows = rows;
        self.parser.set_size(history::nz(rows), history::nz(cols));
        let _ = self.master.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 });
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
        Snap { screen, title: self.parser.callbacks().title.clone() }
    }

    fn payload(base: Option<&Snap>, new: &Snap) -> Vec<u8> {
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
        proto::deflate(s.as_bytes())
    }

    /// Send the current screen as a new version, diffed against `base`.
    fn send_new_frame(&mut self, base: u64, now: Instant) {
        let snap = self.current_snap();
        let payload = Self::payload(self.snaps.get(&base), &snap);
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
            let frame = Frame { base, new, idx: idx as u16, count: count as u16, data: chunk.to_vec() };
            self.send_msg(0, Some(frame));
        }
        self.last_send = now;
        self.ack_pending = false;
    }

    fn send_msg(&mut self, flags: u8, frame: Option<Frame>) {
        let Some(g) = self.gens.get_mut(&self.cur_gen) else { return };
        let msg = ServerMsg { flags, input_ack: self.input_expected, frame }.encode();
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
                self.send_msg(FLAG_ENDED, None);
                self.last_send = now;
            }
            return now.duration_since(t) > Duration::from_secs(3) || self.peers.is_empty();
        }
        if self.peers.is_empty() {
            return false;
        }

        let srtt = self.srtt_ms.unwrap_or(100.0);
        let rto = Duration::from_millis((srtt * 1.5 + 50.0).clamp(80.0, 1000.0) as u64);
        // Interactive changes go out almost immediately; sustained output is
        // paced to ~2 frames per RTT so it can't flood a slow link.
        let interval = if self.frame_streak >= 4 {
            Duration::from_millis((srtt / 2.0).clamp(20.0, 100.0) as u64)
        } else {
            Duration::from_millis((srtt / 4.0).clamp(3.0, 50.0) as u64)
        };
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
                let payload = Self::payload(self.snaps.get(&base), &self.snaps[&new]);
                self.transmit(base, new, &payload, now);
            }
        } else if self.dirty
            && since_send >= interval
            && (now.duration_since(self.last_output) >= Duration::from_millis(3)
                || now.duration_since(self.dirty_since) >= interval)
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
            self.send_msg(0, None);
            self.last_send = now;
            self.ack_pending = false;
        }
        false
    }
}
