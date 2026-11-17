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
    /// Answers to terminal queries, for the program's input.
    pub replies: Vec<u8>,
    /// Terminal size in pixels (0 = unknown), for size queries.
    pub px: (u16, u16),
    /// The client terminal's name, for XTVERSION (empty: no answer).
    pub term: String,
    /// Bells and desktop notifications for the client's terminal, numbered
    /// so each is delivered once.
    pub events: VecDeque<(u64, String)>,
    pub event_seq: u64,
    /// The current OSC 9;4 progress report (empty: none).
    pub progress: String,
    /// Kitty keyboard protocol flags, a stack per screen (main, alternate)
    /// over a base entry that is never popped.
    pub kbd: [Vec<u16>; 2],
}

const MAX_EVENTS: usize = 16;

impl Hooks {
    fn event(&mut self, s: String) {
        self.event_seq += 1;
        self.events.push_back((self.event_seq, s));
        if self.events.len() > MAX_EVENTS {
            self.events.pop_front();
        }
    }

    /// The keyboard flags the program asked for on this screen.
    pub fn kbd_flags(&self, alt: bool) -> u16 {
        *self.kbd[alt as usize].last().unwrap()
    }
}

impl Hooks {
    pub fn new() -> Self {
        Hooks { lines: VecDeque::new(), dropped: 0, title: String::new(), changes: 0, clip: String::new(), clip_seq: 0, replies: Vec::new(), px: (0, 0), term: String::new(), events: VecDeque::new(), event_seq: 0, progress: String::new(), kbd: [vec![0], vec![0]] }
    }
}

impl vt100::Callbacks for Hooks {
    fn on_scroll(&mut self, row: RowContents<'_>, alternate_screen: bool) {
        if alternate_screen {
            return;
        }
        let mut fmt = String::new();
        let _ = row.write_formatted_basic(&mut fmt, &mut BasicFormattedCaptureState::new());
        // Each line is printed on its own: don't let a hyperlink run past it.
        if fmt.contains("\x1b]8;") {
            fmt.push_str("\x1b]8;;\x07");
        }
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

    fn unhandled_csi(&mut self, screen: &mut vt100::Screen, i1: Option<u8>, _: Option<u8>, params: &[&[u16]], c: char) {
        let p0 = params.first().and_then(|p| p.first()).copied().unwrap_or(0);
        let (rows, cols) = screen.size();
        let (rows, cols) = (rows.get(), cols.get());
        let (w, h) = self.px;
        // The kitty keyboard protocol, if the client's terminal has it
        // (we only know the name of those that do).
        if c == 'u' && !self.term.is_empty() {
            let stack = &mut self.kbd[screen.alternate_screen() as usize];
            match i1 {
                Some(b'?') => {
                    let flags = stack.last().unwrap();
                    self.replies.extend_from_slice(format!("\x1b[?{flags}u").as_bytes());
                }
                Some(b'>') => {
                    if stack.len() > 16 {
                        stack.remove(1);
                    }
                    stack.push(p0 & 31);
                }
                Some(b'<') => {
                    for _ in 0..p0.max(1) {
                        if stack.len() > 1 {
                            stack.pop();
                        } else {
                            stack[0] = 0;
                        }
                    }
                }
                Some(b'=') => {
                    let top = stack.last_mut().unwrap();
                    match params.get(1).and_then(|p| p.first()).copied().unwrap_or(1) {
                        2 => *top |= p0 & 31,
                        3 => *top &= !p0,
                        _ => *top = p0 & 31,
                    }
                }
                _ => {}
            }
            return;
        }
        let r = match (i1, c, p0) {
            // Primary device attributes: a VT220 with colour, like mosh.
            (None, 'c', 0) => "\x1b[?62;22c".to_string(),
            (None, 't', 14) if w > 0 && h > 0 => format!("\x1b[4;{h};{w}t"),
            (None, 't', 16) if w > 0 && h > 0 => format!("\x1b[6;{};{}t", h / rows, w / cols),
            (None, 't', 18) => format!("\x1b[8;{rows};{cols}t"),
            (Some(b'>'), 'q', 0) if !self.term.is_empty() => format!("\x1bP>|{}\x1b\\", self.term),
            _ => return,
        };
        self.replies.extend_from_slice(r.as_bytes());
    }

    fn audible_bell(&mut self, _: &mut vt100::Screen) {
        // A burst of bells rings once.
        if self.events.back().is_none_or(|(_, e)| e != "\x07") {
            self.event("\x07".into());
        }
    }

    /// Desktop notifications (OSC 9 iTerm2, 777 rxvt/Ghostty, 99 kitty) and
    /// OSC 9;4 progress pass through to the client's terminal.
    fn unhandled_osc(&mut self, _: &mut vt100::Screen, params: &[&[u8]]) {
        let body = params.join(&b';');
        if body.len() > 4096 || body.iter().any(|&b| b < 0x20 || b == 0x7f) {
            return;
        }
        let Ok(body) = String::from_utf8(body) else { return };
        if body.starts_with("9;4;") || body == "9;4" {
            self.progress = if body.starts_with("9;4;0") || body == "9;4" { String::new() } else { format!("\x1b]{body}\x07") };
        } else if body.starts_with("9;") || body.starts_with("777;notify;") {
            self.event(format!("\x1b]{body}\x07"));
        } else if body.starts_with("99;") {
            self.event(format!("\x1b]{body}\x1b\\"));
        }
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
                    // SGR mouse: wheel up = 64, wheel down = 65. `esc_len` gives
                    // back the whole buffer for an unfinished CSI (input arrives
                    // in 1 KB chunks), so `k` can be exactly "\x1b[<": no body.
                    if let Some(body) = k.get(3..k.len().saturating_sub(1)) {
                        let btn = body.split(|&c| c == b';').next().unwrap_or(b"");
                        match btn {
                            b"64" => self.scroll(hooks, live, rows, -3),
                            b"65" => self.scroll(hooks, live, rows, 3),
                            _ => {}
                        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifications_and_progress() {
        let mut p = vt100::Parser::new_with_callbacks(nz(5), nz(20), 0, Hooks::new());
        p.process("\x07\x07\x1b]777;notify;Claude;Готово\x07\x1b]9;hi\x1b\\\x1b]99;i=1;x\x1b\\\x1b]9;4;1;42\x07".as_bytes());
        let h = p.callbacks();
        let ev: Vec<&str> = h.events.iter().map(|(_, e)| e.as_str()).collect();
        assert_eq!(ev, ["\x07", "\x1b]777;notify;Claude;Готово\x07", "\x1b]9;hi\x07", "\x1b]99;i=1;x\x1b\\"]);
        assert_eq!(h.progress, "\x1b]9;4;1;42\x07");
        p.process(b"\x1b]9;4;0\x07");
        assert_eq!(p.callbacks().progress, "");
    }

    #[test]
    fn unfinished_sgr_mouse_does_not_panic() {
        // Input arrives in 1000-byte chunks, so the escape can be cut anywhere,
        // including right after "\x1b[<"; the viewer must not slice past the end.
        let mut v = Viewer::new(5, 20);
        let hooks = Hooks::new();
        let p = vt100::Parser::new(nz(5), nz(20), 0);
        for k in [b"\x1b[<".as_slice(), b"\x1b[<64;1", b"\x1b[<64;1;2M"] {
            assert!(matches!(v.keys(k, &hooks, p.screen(), 5), KeyResult::Stay));
        }
    }

    #[test]
    fn hyperlinks() {
        let mut p = vt100::Parser::new_with_callbacks(nz(3), nz(20), 0, Hooks::new());
        p.process(b"a\x1b]8;id=1;http://x/?a=1;b=2\x1b\\li\x1b[mnk\x1b]8;;\x1b\\b\x1b[K");
        let s = p.screen().clone();
        let f = s.contents_formatted();
        assert!(f.ends_with("a\x1b]8;id=1;http://x/?a=1;b=2\x07link\x1b]8;;\x07b"), "{f:?}");
        // Erased cells don't get the link; the diff ends it again.
        p.process(b"\r\n\x1b]8;;http://y\x07z\x1b[K");
        let d = p.screen().contents_diff(&s);
        assert!(d.contains("\x1b]8;;http://y\x07z\x1b]8;;\x07"), "{d:?}");
        assert!(!d[d.find('z').unwrap()..].contains("http"), "{d:?}");
        p.process(b"\x1b]8;;\x07\r\n\n\n");
        let h = p.callbacks();
        assert_eq!(h.lines[0].plain, "alinkb");
        assert_eq!(h.lines[0].fmt, "a\x1b]8;id=1;http://x/?a=1;b=2\x07link\x1b]8;;\x07b\x1b]8;;\x07");
        assert_eq!(h.lines[1].plain, "z");
    }
}
