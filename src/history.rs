//! Session history: rows that scroll off the top of the main screen are kept
//! on the server, and the viewer renders them (plus the live screen) into its
//! own virtual screen, which is synced to the client like any other frame.

use std::collections::VecDeque;
use std::num::NonZeroU16;
use vt100::capture::{basic_formatted_to_plain, BasicFormattedCaptureState, RowContents};

pub const HISTORY_CAP: usize = 50_000;

pub struct Line {
    pub fmt: String,
    pub plain: String,
}

/// vt100 callbacks: collects scrolled-off rows and the window title.
pub struct Hooks {
    pub lines: VecDeque<Line>,
    /// Number of lines evicted from the front (keeps absolute indexes stable).
    pub dropped: u64,
    pub title: String,
    /// Bumped on every new history line, so the viewer knows to re-render.
    pub changes: u64,
    /// The latest OSC 52 clipboard write, ready to forward, and its number.
    pub clip: String,
    pub clip_seq: u64,
}

impl Hooks {
    pub fn new() -> Self {
        Hooks { lines: VecDeque::new(), dropped: 0, title: String::new(), changes: 0, clip: String::new(), clip_seq: 0 }
    }
}

impl vt100::Callbacks for Hooks {
    fn on_scroll(&mut self, row: RowContents<'_>, alternate_screen: bool) {
        if alternate_screen {
            return;
        }
        let mut fmt = String::new();
        let _ = row.write_formatted_basic(&mut fmt, &mut BasicFormattedCaptureState::new());
        let plain: String = basic_formatted_to_plain(&fmt).collect();
        if self.lines.len() >= HISTORY_CAP {
            self.lines.pop_front();
            self.dropped += 1;
        }
        self.lines.push_back(Line { fmt, plain });
        self.changes += 1;
    }

    fn copy_to_clipboard(&mut self, _: &mut vt100::Screen, ty: &[u8], data: &[u8]) {
        let b64 = |b: &u8| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=');
        if data.len() > 1 << 20 || !data.iter().all(b64) || !ty.iter().all(u8::is_ascii_alphanumeric) {
            return;
        }
        let ty = if ty.is_empty() { "c" } else { std::str::from_utf8(ty).unwrap() };
        self.clip = format!("\x1b]52;{ty};{}\x07", std::str::from_utf8(data).unwrap());
        self.clip_seq += 1;
    }

    fn set_window_title(&mut self, _: &mut vt100::Screen, title: &[u8]) {
        self.title = String::from_utf8_lossy(title).chars().filter(|c| !c.is_control()).collect();
    }
}

pub enum KeyResult {
    Stay,
    Exit,
}

pub struct Viewer {
    /// Absolute index of the top visible line; `None` follows the bottom.
    top: Option<u64>,
    query: Vec<u8>,
    typing: bool,
    matched: Option<u64>,
    msg: String,
    view: vt100::Parser,
    pub stale: bool,
    seen_changes: u64,
}

/// A line in the combined (history + live screen) space.
enum Src<'a> {
    Hist(&'a Line),
    Live(String),
}

impl Src<'_> {
    fn plain(&self) -> &str {
        match self {
            Src::Hist(l) => &l.plain,
            Src::Live(s) => s,
        }
    }
}

impl Viewer {
    pub fn new(rows: u16, cols: u16) -> Self {
        Viewer {
            top: None,
            query: Vec::new(),
            typing: false,
            matched: None,
            msg: String::new(),
            view: vt100::Parser::new(nz(rows), nz(cols), 0),
            stale: true,
            seen_changes: 0,
        }
    }

    pub fn screen(&self) -> &vt100::Screen {
        self.view.screen()
    }

    pub fn note_changes(&mut self, hooks: &Hooks) {
        if hooks.changes != self.seen_changes {
            self.seen_changes = hooks.changes;
            if self.top.is_none() {
                self.stale = true;
            }
        }
    }

    fn page(rows: u16) -> u64 {
        rows.saturating_sub(1).max(1) as u64
    }

    fn bounds(hooks: &Hooks, live: &vt100::Screen) -> (u64, u64) {
        let start = hooks.dropped;
        let end = start + hooks.lines.len() as u64 + live.size().0.get() as u64;
        (start, end)
    }

    fn line<'a>(hooks: &'a Hooks, live: &vt100::Screen, abs: u64) -> Option<Src<'a>> {
        let i = abs.checked_sub(hooks.dropped)? as usize;
        if i < hooks.lines.len() {
            return Some(Src::Hist(&hooks.lines[i]));
        }
        let r = i - hooks.lines.len();
        let cols = live.size().1.get();
        live.rows(0, cols).nth(r).map(Src::Live)
    }

    fn resolved_top(&self, hooks: &Hooks, live: &vt100::Screen, rows: u16) -> u64 {
        let (start, end) = Self::bounds(hooks, live);
        let bottom_top = end.saturating_sub(Self::page(rows)).max(start);
        self.top.map_or(bottom_top, |t| t.clamp(start, bottom_top))
    }

    fn scroll(&mut self, hooks: &Hooks, live: &vt100::Screen, rows: u16, delta: i64) {
        let (start, end) = Self::bounds(hooks, live);
        let bottom_top = end.saturating_sub(Self::page(rows)).max(start);
        let cur = self.resolved_top(hooks, live, rows) as i64;
        let next = (cur + delta).clamp(start as i64, bottom_top as i64) as u64;
        self.top = if next >= bottom_top { None } else { Some(next) };
        self.stale = true;
    }

    fn search(&mut self, hooks: &Hooks, live: &vt100::Screen, rows: u16, older: bool) {
        let q = String::from_utf8_lossy(&self.query).to_lowercase();
        if q.is_empty() {
            return;
        }
        let (start, end) = Self::bounds(hooks, live);
        let from = self.matched.unwrap_or_else(|| {
            if older {
                self.resolved_top(hooks, live, rows) + Self::page(rows)
            } else {
                self.resolved_top(hooks, live, rows).saturating_sub(1)
            }
        });
        let hit = |a: &u64| Self::matches(hooks, live, *a, &q);
        let split = if older { from.min(end) } else { (from + 1).clamp(start, end) };
        // Search in the requested direction, then wrap around the other end.
        let (found, wrapped) = if older {
            match (start..split).rev().find(hit) {
                Some(a) => (Some(a), false),
                None => ((split..end).rev().find(hit), true),
            }
        } else {
            match (split..end).find(hit) {
                Some(a) => (Some(a), false),
                None => ((start..split).find(hit), true),
            }
        };
        match found {
            Some(a) => {
                self.matched = Some(a);
                self.msg = if wrapped { "search wrapped".into() } else { String::new() };
                let half = Self::page(rows) / 2;
                self.top = Some(a.saturating_sub(half).max(start));
                // Re-clamp (and switch to follow mode if we hit the bottom).
                self.scroll(hooks, live, rows, 0);
            }
            None => self.msg = format!("not found: {q}"),
        }
        self.stale = true;
    }

    fn matches(hooks: &Hooks, live: &vt100::Screen, abs: u64, q: &str) -> bool {
        Self::line(hooks, live, abs).is_some_and(|l| l.plain().to_lowercase().contains(q))
    }

    pub fn keys(&mut self, data: &[u8], hooks: &Hooks, live: &vt100::Screen, rows: u16) -> KeyResult {
        let page = Self::page(rows) as i64;
        let mut i = 0;
        while i < data.len() {
            let rest = &data[i..];
            if self.typing {
                match rest[0] {
                    b'\r' | b'\n' => {
                        self.typing = false;
                        self.matched = None;
                        self.search(hooks, live, rows, true);
                    }
                    0x1b => {
                        self.typing = false;
                        // Swallow the rest of an escape sequence, if any.
                        i += esc_len(rest) - 1;
                    }
                    0x7f | 0x08 => {
                        // Drop one UTF-8 character.
                        while let Some(b) = self.query.pop() {
                            if b & 0xc0 != 0x80 {
                                break;
                            }
                        }
                    }
                    0x15 => self.query.clear(),
                    b if b >= 0x20 => self.query.push(b),
                    _ => {}
                }
                self.stale = true;
                i += 1;
                continue;
            }
            let n = esc_len(rest);
            let key = &rest[..n];
            i += n;
            match key {
                b"q" | b"\x1b" | b"\x03" => return KeyResult::Exit,
                b"k" | b"\x1b[A" | b"\x1bOA" | b"\x10" => self.scroll(hooks, live, rows, -1),
                b"j" | b"\x1b[B" | b"\x1bOB" | b"\x0e" | b"\r" => self.scroll(hooks, live, rows, 1),
                b"b" | b"\x02" | b"\x1b[5~" => self.scroll(hooks, live, rows, -page),
                b"f" | b" " | b"\x06" | b"\x1b[6~" => self.scroll(hooks, live, rows, page),
                b"u" | b"\x15" => self.scroll(hooks, live, rows, -page / 2),
                b"d" | b"\x04" => self.scroll(hooks, live, rows, page / 2),
                b"g" | b"\x1b[H" | b"\x1b[1~" | b"\x1bOH" => {
                    self.top = Some(0);
                    self.scroll(hooks, live, rows, 0);
                }
                b"G" | b"\x1b[F" | b"\x1b[4~" | b"\x1bOF" => {
                    self.top = None;
                    self.stale = true;
                }
                b"/" | b"?" => {
                    self.typing = true;
                    self.query.clear();
                    self.stale = true;
                }
                b"n" => self.search(hooks, live, rows, true),
                b"N" => self.search(hooks, live, rows, false),
                k if k.starts_with(b"\x1b[<") => {
                    // SGR mouse: wheel up = 64, wheel down = 65.
                    let body = &k[3..k.len() - 1];
                    let btn = body.split(|&c| c == b';').next().unwrap_or(b"");
                    match btn {
                        b"64" => self.scroll(hooks, live, rows, -3),
                        b"65" => self.scroll(hooks, live, rows, 3),
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        KeyResult::Stay
    }

    pub fn render(&mut self, hooks: &Hooks, live: &vt100::Screen) {
        let (rows, cols) = (live.size().0.get(), live.size().1.get());
        if self.view.screen().size() != live.size() {
            self.view = vt100::Parser::new(nz(rows), nz(cols), 0);
        }
        let (start, end) = Self::bounds(hooks, live);
        let top = self.resolved_top(hooks, live, rows);
        let q = String::from_utf8_lossy(&self.query).to_lowercase();
        let mut s = String::from("\x1b[0m\x1b[H\x1b[2J\x1b[?25l\x1b[?1000h\x1b[?1006h");
        for r in 0..rows.saturating_sub(1) {
            let abs = top + r as u64;
            if abs >= end {
                break;
            }
            let Some(line) = Self::line(hooks, live, abs) else { continue };
            s.push_str(&format!("\x1b[{};1H\x1b[0m", r + 1));
            let highlight = self.matched == Some(abs) && !q.is_empty();
            match &line {
                Src::Hist(l) if !highlight && l.plain.chars().count() <= cols as usize => s.push_str(&l.fmt),
                _ => s.push_str(&render_plain(line.plain(), cols, highlight.then_some(q.as_str()))),
            }
        }
        let pos = if self.top.is_none() { "bottom".to_string() } else { format!("{}/{}", top + Self::page(rows) - start, end - start) };
        let status = if self.typing {
            format!("/{}", String::from_utf8_lossy(&self.query))
        } else {
            let msg = if self.msg.is_empty() { String::new() } else { format!("  {}", self.msg) };
            format!(" HISTORY {pos}  ↑↓ PgUp/PgDn g/G  / search  n/N next/prev  q quit{msg}")
        };
        let status: String = status.chars().take(cols as usize).collect();
        let pad = (cols as usize).saturating_sub(status.chars().count());
        s.push_str(&format!("\x1b[{rows};1H\x1b[0;30;46m{status}{}\x1b[0m", " ".repeat(pad)));
        if self.typing {
            s.push_str(&format!("\x1b[{rows};{}H\x1b[?25h", (status.chars().count() + 1).min(cols as usize)));
        }
        self.view.process(s.as_bytes());
        self.stale = false;
    }
}

fn render_plain(text: &str, cols: u16, highlight: Option<&str>) -> String {
    let text: String = text.chars().take(cols as usize).collect();
    let Some(q) = highlight else { return text };
    let lower = text.to_lowercase();
    // Lowercasing can change byte lengths for some scripts; only highlight
    // when offsets line up.
    match lower.find(q) {
        Some(p) if lower.len() == text.len() && text.is_char_boundary(p) && text.is_char_boundary(p + q.len()) => {
            format!("{}\x1b[0;30;43m{}\x1b[0m{}", &text[..p], &text[p..p + q.len()], &text[p + q.len()..])
        }
        _ => format!("\x1b[7m{text}\x1b[0m"),
    }
}

/// Length of the key/escape sequence at the start of `b`.
fn esc_len(b: &[u8]) -> usize {
    if b[0] != 0x1b || b.len() == 1 {
        // A whole UTF-8 character counts as one key.
        let n = match b[0] {
            0xc0..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf7 => 4,
            _ => 1,
        };
        return n.min(b.len());
    }
    match b[1] {
        b'[' => {
            // CSI: parameters/intermediates then a final byte in 0x40..=0x7e.
            for (i, &c) in b.iter().enumerate().skip(2) {
                if (0x40..=0x7e).contains(&c) {
                    return i + 1;
                }
            }
            b.len()
        }
        b'O' => 3.min(b.len()),
        _ => 2,
    }
}

pub fn nz(v: u16) -> NonZeroU16 {
    NonZeroU16::new(v.max(1)).unwrap()
}
