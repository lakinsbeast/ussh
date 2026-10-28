//! Kitty graphics protocol over ussh.
//!
//! The server's terminal emulator (`vt100`) can't hold images, so graphics
//! commands (APC `ESC _ G … ESC \`) are cut out of the program's output
//! before it gets there. Images are kept on the server and streamed to the
//! client reliably; on screen each one is a grid of Unicode placeholders
//! (U+10EEEE, image id in the foreground colour, row and column in
//! diacritics) that the client's terminal (kitty, Ghostty) draws as the
//! image. Placeholders are ordinary text: they diff, scroll into history and
//! survive reconnects like the rest of the screen.

use crate::diacritics::DIACRITICS;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Read;
use std::sync::Arc;
use std::time::Instant;

pub const PLACEHOLDER: char = '\u{10EEEE}';
/// Decoded size limit for one image.
const MAX_IMAGE: usize = 32 << 20;
/// Images kept for replay to a (re)connecting client.
const STORE_CAP: usize = 64 << 20;
const STORE_MAX_IMAGES: usize = 4096;
const MAX_APC: usize = 64 << 20;
/// Assumed cell size when the client's terminal doesn't report pixels.
const CELL_GUESS: (u32, u32) = (10, 20);
/// Ids the server picks itself (for images sent without `i=`).
const AUTO_IDS: std::ops::Range<u32> = 0xF0_0000..0xFF_FFFF;

pub const WINDOW_START: u64 = 128 << 10;
const WINDOW_MIN: u64 = 16 << 10;
const WINDOW_MAX: u64 = 4 << 20;
/// Replay the stored images instead of sending a backlog this much bigger.
const BACKLOG_SLACK: u64 = 8 << 20;

// ---------------------------------------------------------------- splitting

pub enum Piece {
    Text(Vec<u8>),
    /// A graphics command: the APC body after `G`.
    Graphics(Vec<u8>),
}

#[derive(Default, PartialEq)]
enum St {
    #[default]
    Text,
    Esc,
    Apc,
    ApcEsc,
}

/// Cuts APC strings out of PTY output (they may span reads).
#[derive(Default)]
pub struct Splitter {
    st: St,
    apc: Vec<u8>,
    overflow: bool,
    /// An ESC ended the previous chunk and hasn't been passed on yet.
    carry: bool,
}

fn push_text(out: &mut Vec<Piece>, b: &[u8]) {
    if !b.is_empty() {
        out.push(Piece::Text(b.to_vec()));
    }
}

impl Splitter {
    pub fn feed(&mut self, data: &[u8]) -> Vec<Piece> {
        let mut out = Vec::new();
        let (mut start, mut i) = (0, 0);
        while i < data.len() {
            match self.st {
                St::Text => match data[i..].iter().position(|&b| b == 0x1b) {
                    Some(j) => {
                        i += j + 1;
                        self.st = St::Esc;
                    }
                    None => i = data.len(),
                },
                St::Esc if data[i] == b'_' => {
                    if !self.carry {
                        push_text(&mut out, &data[start..i - 1]);
                    }
                    self.carry = false;
                    self.st = St::Apc;
                    self.apc.clear();
                    self.overflow = false;
                    i += 1;
                }
                St::Esc => {
                    if self.carry {
                        push_text(&mut out, b"\x1b");
                        self.carry = false;
                        start = i;
                    }
                    // data[i] goes to the text scan (it may be another ESC).
                    self.st = St::Text;
                }
                St::Apc => match data[i..].iter().position(|&b| b == 0x1b) {
                    Some(j) => {
                        self.grow(&data[i..i + j]);
                        i += j + 1;
                        self.st = St::ApcEsc;
                    }
                    None => {
                        self.grow(&data[i..]);
                        i = data.len();
                    }
                },
                St::ApcEsc if data[i] == b'\\' => {
                    let mut body = std::mem::take(&mut self.apc);
                    if !self.overflow && body.first() == Some(&b'G') {
                        out.push(Piece::Graphics(body.split_off(1)));
                    }
                    self.st = St::Text;
                    i += 1;
                    start = i;
                }
                St::ApcEsc => {
                    self.grow(b"\x1b");
                    self.st = St::Apc;
                }
            }
        }
        match self.st {
            St::Text => push_text(&mut out, &data[start..]),
            St::Esc if !self.carry => {
                push_text(&mut out, &data[start..data.len() - 1]);
                self.carry = true;
            }
            _ => {}
        }
        out
    }

    fn grow(&mut self, b: &[u8]) {
        if self.apc.len() + b.len() > MAX_APC {
            self.overflow = true;
            self.apc = Vec::new();
        }
        if !self.overflow {
            self.apc.extend_from_slice(b);
        }
    }
}

// ------------------------------------------------------------------ commands

/// Control data of a graphics command: `a=T,f=100,i=7`.
struct Keys(Vec<(u8, Vec<u8>)>);

impl Keys {
    fn parse(ctrl: &[u8]) -> Keys {
        Keys(
            ctrl.split(|&b| b == b',')
                .filter_map(|kv| match kv {
                    [k, b'=', v @ ..] => Some((*k, v.to_vec())),
                    _ => None,
                })
                .collect(),
        )
    }
    fn get(&self, k: u8) -> Option<&[u8]> {
        self.0.iter().rev().find(|(kk, _)| *kk == k).map(|(_, v)| v.as_slice())
    }
    fn num(&self, k: u8) -> u32 {
        self.get(k).and_then(|v| std::str::from_utf8(v).ok()?.parse().ok()).unwrap_or(0)
    }
    fn ch(&self, k: u8) -> Option<u8> {
        self.get(k).and_then(|v| v.first().copied())
    }
}

fn split_cmd(body: &[u8]) -> (&[u8], &[u8]) {
    match body.iter().position(|&b| b == b';') {
        Some(p) => (&body[..p], &body[p + 1..]),
        None => (body, &[]),
    }
}

/// What handling a command produced.
#[derive(Default)]
pub struct Effect {
    /// The terminal's answer, for the program's input.
    pub reply: Vec<u8>,
    /// Escapes for our own emulator: placeholders drawn or erased.
    pub draw: String,
}

struct Image {
    /// The transmit record, as sent to the client.
    rec: Arc<Vec<u8>>,
    px: (u32, u32),
    /// The current virtual placement record, once displayed.
    place: Option<Arc<Vec<u8>>>,
    /// Where it was last shown (absolute line, as history counts them):
    /// a new client only gets images it can still scroll to.
    line: u64,
    on_client: bool,
}

pub struct Gfx {
    /// The client's terminal draws kitty graphics with placeholders.
    pub enabled: bool,
    /// Cell size in pixels on the client's terminal (0 = unknown).
    pub cell: (u32, u32),
    /// Absolute line of the screen's top row, set before each command.
    pub line: u64,
    images: HashMap<u32, Image>,
    numbers: HashMap<u32, u32>,
    /// Image ids, oldest first.
    order: VecDeque<u32>,
    total: usize,
    next_auto: u32,
    /// A chunked transmission in progress: first chunk's control data, and
    /// the decoded payload so far (`None` after a bad chunk).
    chunked: Option<(Vec<u8>, Option<Vec<u8>>)>,
    pub stream: Stream,
}

impl Gfx {
    pub fn new(now: Instant) -> Self {
        Gfx {
            enabled: false,
            cell: (0, 0),
            line: 0,
            images: HashMap::new(),
            numbers: HashMap::new(),
            order: VecDeque::new(),
            total: 0,
            next_auto: AUTO_IDS.start,
            chunked: None,
            stream: Stream::new(now),
        }
    }

    pub fn command(&mut self, body: &[u8], screen: &vt100::Screen) -> Effect {
        let mut fx = Effect::default();
        if !self.enabled {
            // No answer: to the program this terminal has no graphics.
            self.chunked = None;
            return fx;
        }
        let (ctrl, payload) = split_cmd(body);
        let keys = Keys::parse(ctrl);
        // Each chunk is base64 on its own (some programs pad every chunk).
        let decoded = b64decode(payload);
        if let Some((_, data)) = &mut self.chunked {
            match (data.as_mut(), decoded) {
                (Some(d), Some(more)) if d.len() + more.len() <= MAX_APC => d.extend_from_slice(&more),
                _ => *data = None,
            }
            if keys.num(b'm') == 1 {
                return fx;
            }
            let (first, data) = self.chunked.take().unwrap();
            let mut first = Keys::parse(&first);
            // A later chunk may change how quiet to be.
            if let Some(q) = keys.get(b'q') {
                first.0.push((b'q', q.to_vec()));
            }
            match data {
                Some(data) => self.run(&first, &data, screen, &mut fx),
                None => respond(&first, 0, "EINVAL:bad payload", &mut fx),
            }
            return fx;
        }
        if keys.num(b'm') == 1 && matches!(keys.ch(b'a').unwrap_or(b't'), b't' | b'T' | b'q') {
            self.chunked = Some((ctrl.to_vec(), decoded));
            return fx;
        }
        match decoded {
            Some(data) => self.run(&keys, &data, screen, &mut fx),
            None => respond(&keys, 0, "EINVAL:bad base64", &mut fx),
        }
        fx
    }

    fn run(&mut self, k: &Keys, payload: &[u8], screen: &vt100::Screen, fx: &mut Effect) {
        match k.ch(b'a').unwrap_or(b't') {
            b't' | b'T' | b'q' => self.transmit(k, payload, screen, fx),
            b'p' => match self.find(k) {
                Some(id) => {
                    respond(k, id, "OK", fx);
                    self.display(id, k, screen, fx);
                }
                None => respond(k, 0, "ENOENT:image not found", fx),
            },
            b'd' => self.delete(k, screen, fx),
            _ => respond(k, 0, "ENOTSUP:animation is not supported over ussh", fx),
        }
    }

    fn find(&self, k: &Keys) -> Option<u32> {
        match (k.num(b'i'), k.num(b'I')) {
            (0, 0) => None,
            (0, n) => self.numbers.get(&n).copied(),
            (i, _) => Some(i),
        }
        .filter(|id| self.images.contains_key(id))
    }

    fn transmit(&mut self, k: &Keys, payload: &[u8], screen: &vt100::Screen, fx: &mut Effect) {
        let data = match load(k, payload) {
            Ok(d) => d,
            Err(e) => return respond(k, 0, &e, fx),
        };
        let f = match k.num(b'f') {
            0 => 32,
            f => f,
        };
        let (s, v) = (k.num(b's'), k.num(b'v'));
        let px = match f {
            100 => png_size(&data),
            24 | 32 => (s > 0 && v > 0 && s as u64 * v as u64 * (f / 8) as u64 == data.len() as u64).then_some((s, v)),
            _ => None,
        };
        let Some(px) = px else {
            return respond(k, 0, "EINVAL:bad image data", fx);
        };
        if k.ch(b'a') == Some(b'q') {
            return respond(k, k.num(b'i'), "OK", fx);
        }
        let id = match k.num(b'i') {
            0 => self.auto_id(),
            i => i,
        };
        let (ctrl, stored) = if f == 100 {
            (format!("a=t,q=2,i={id},f=100"), data)
        } else {
            // Raw pixels are big: the terminal inflates them itself.
            (format!("a=t,q=2,i={id},f={f},s={s},v={v},o=z"), zlib(&data))
        };
        let rec = Arc::new(record(&ctrl, &stored));
        // Re-sending an id replaces the image but keeps it on screen.
        let place = self.forget(id).and_then(|old| old.place);
        self.stream.push(rec.clone());
        if let Some(p) = &place {
            self.stream.push(p.clone());
        }
        self.total += rec.len();
        let line = self.line + screen.cursor_position().0 as u64;
        self.images.insert(id, Image { rec, px, place, line, on_client: true });
        self.order.push_back(id);
        if k.num(b'I') != 0 {
            self.numbers.insert(k.num(b'I'), id);
        }
        respond(k, id, "OK", fx);
        if k.ch(b'a') == Some(b'T') {
            self.display(id, k, screen, fx);
        }
        self.evict();
    }

    fn auto_id(&mut self) -> u32 {
        loop {
            self.next_auto = if AUTO_IDS.contains(&(self.next_auto + 1)) { self.next_auto + 1 } else { AUTO_IDS.start };
            if !self.images.contains_key(&self.next_auto) {
                return self.next_auto;
            }
        }
    }

    /// Show image `id` at the cursor, the way the terminal would: as a
    /// placement on the client and placeholders in our emulator.
    fn display(&mut self, id: u32, k: &Keys, screen: &vt100::Screen, fx: &mut Effect) {
        let Some(img) = self.images.get_mut(&id) else { return };
        let (c, r) = cells(k, img.px, if self.cell.0 > 0 && self.cell.1 > 0 { self.cell } else { CELL_GUESS });
        let mut ctrl = format!("a=p,q=2,U=1,i={id},c={c},r={r}");
        for key in [b'x', b'y', b'w', b'h'] {
            if k.num(key) > 0 {
                ctrl.push_str(&format!(",{}={}", key as char, k.num(key)));
            }
        }
        let place = Arc::new(record(&ctrl, &[]));
        img.place = Some(place.clone());
        img.line = self.line + screen.cursor_position().0 as u64 + r as u64 - 1;
        if !img.on_client {
            img.on_client = true;
            self.stream.push(img.rec.clone());
        }
        self.stream.push(place);
        // With U=1 the program writes the placeholders itself.
        if k.num(b'U') != 1 {
            fx.draw.push_str(&placeholders(id, c, r, k.num(b'C') == 1, screen));
        }
    }

    fn delete(&mut self, k: &Keys, screen: &vt100::Screen, fx: &mut Effect) {
        let d = k.ch(b'd').unwrap_or(b'a');
        let shown = scan(screen);
        let at = |row: u32, col: u32| shown.iter().filter(move |p| p.0 == row && p.1 == col).map(|p| p.2);
        let (row, col) = screen.cursor_position();
        // Low 24 bits of the ids to delete: what the placeholders carry.
        let low: HashSet<u32> = match d.to_ascii_lowercase() {
            b'a' => shown.iter().map(|p| p.2).collect(),
            b'i' => [k.num(b'i') & 0xFF_FFFF].into(),
            b'n' => self.numbers.get(&k.num(b'I')).map(|id| id & 0xFF_FFFF).into_iter().collect(),
            b'c' => at(row as u32, col as u32).collect(),
            b'p' => at(k.num(b'y').saturating_sub(1), k.num(b'x').saturating_sub(1)).collect(),
            b'x' => shown.iter().filter(|p| p.1 + 1 == k.num(b'x')).map(|p| p.2).collect(),
            b'y' => shown.iter().filter(|p| p.0 + 1 == k.num(b'y')).map(|p| p.2).collect(),
            b'r' => self.images.keys().filter(|id| (k.num(b'x')..=k.num(b'y')).contains(id)).map(|id| id & 0xFF_FFFF).collect(),
            _ => return,
        };
        if low.is_empty() {
            return;
        }
        let mut s = String::from("\x1b[0m");
        for (r, c, id) in &shown {
            if low.contains(id) {
                s.push_str(&format!("\x1b[{};{}H ", r + 1, c + 1));
            }
        }
        s.push_str(&format!("\x1b[{};{}H", row + 1, col + 1));
        s.push_str(&screen.attributes_formatted());
        fx.draw.push_str(&s);
        if d.is_ascii_uppercase() {
            let ids: Vec<u32> = self.images.keys().copied().filter(|id| low.contains(&(id & 0xFF_FFFF))).collect();
            for id in ids {
                self.forget(id);
                self.stream.push(Arc::new(record(&format!("a=d,q=2,d=I,i={id}"), &[])));
            }
        }
    }

    fn forget(&mut self, id: u32) -> Option<Image> {
        let img = self.images.remove(&id)?;
        self.total -= img.rec.len();
        self.order.retain(|x| *x != id);
        self.numbers.retain(|_, x| *x != id);
        Some(img)
    }

    fn evict(&mut self) {
        while (self.total > STORE_CAP || self.order.len() > STORE_MAX_IMAGES) && self.order.len() > 1 {
            let id = self.order[0];
            self.forget(id);
            self.stream.push(Arc::new(record(&format!("a=d,q=2,d=I,i={id}"), &[])));
        }
    }

    fn replay_size(&self, min_line: u64) -> u64 {
        let size = |i: &Image| (i.rec.len() + i.place.as_ref().map_or(0, |p| p.len())) as u64;
        self.images.values().filter(|i| i.line >= min_line).map(size).sum()
    }

    /// Restart the stream with the stored images shown at or below
    /// `min_line` (for a new client, or one too far behind to catch up on
    /// everything that happened). The rest follow if shown again.
    pub fn rebase(&mut self, now: Instant, min_line: u64) {
        let st = &mut self.stream;
        st.recs.clear();
        st.floor = st.end;
        st.have = st.end;
        st.sent = st.end;
        st.anchor = now;
        for id in &self.order {
            let img = self.images.get_mut(id).unwrap();
            img.on_client = img.line >= min_line;
            if img.on_client {
                st.push(img.rec.clone());
                if let Some(p) = &img.place {
                    st.push(p.clone());
                }
            }
        }
    }

    pub fn backlogged(&self, min_line: u64) -> bool {
        self.stream.end - self.stream.have > self.replay_size(min_line) + BACKLOG_SLACK
    }
}

fn respond(k: &Keys, id: u32, msg: &str, fx: &mut Effect) {
    let ok = msg == "OK";
    let q = k.num(b'q');
    if q >= 2 || (ok && q == 1) {
        return;
    }
    let (i, n, p) = (k.num(b'i'), k.num(b'I'), k.num(b'p'));
    if i == 0 && n == 0 {
        return;
    }
    let mut s = format!("\x1b_Gi={}", if i != 0 { i } else { id });
    if n != 0 {
        s.push_str(&format!(",I={n}"));
    }
    if p != 0 {
        s.push_str(&format!(",p={p}"));
    }
    s.push_str(&format!(";{msg}\x1b\\"));
    fx.reply.extend_from_slice(s.as_bytes());
}

/// The image bytes of a transmission (`payload` already decoded): inline, or from a file, temp file or
/// shared memory on this machine (where the program runs).
fn load(k: &Keys, payload: &[u8]) -> Result<Vec<u8>, String> {
    let raw = payload.to_vec();
    let medium = k.ch(b't').unwrap_or(b'd');
    let data = if medium == b'd' {
        raw
    } else {
        let name = String::from_utf8(raw).map_err(|_| "EINVAL:bad path")?;
        let path = match medium {
            b'f' | b't' => std::path::PathBuf::from(&name),
            b's' => std::path::Path::new("/dev/shm").join(name.trim_start_matches('/')),
            _ => return Err("EINVAL:bad transmission medium".into()),
        };
        let meta = std::fs::metadata(&path).map_err(|e| format!("ENOENT:{e}"))?;
        if !meta.is_file() {
            return Err("EINVAL:not a regular file".into());
        }
        let mut f = std::fs::File::open(&path).map_err(|e| format!("EBADF:{e}"))?;
        let (off, size) = (k.num(b'O') as u64, k.num(b'S') as u64);
        std::io::Seek::seek(&mut f, std::io::SeekFrom::Start(off)).map_err(|e| format!("EBADF:{e}"))?;
        let limit = if size > 0 { size } else { MAX_IMAGE as u64 + 1 };
        let mut data = Vec::new();
        f.take(limit).read_to_end(&mut data).map_err(|e| format!("EBADF:{e}"))?;
        // Temp files and shared memory are the terminal's to remove.
        if medium == b's' || (medium == b't' && name.contains("tty-graphics-protocol")) {
            let _ = std::fs::remove_file(&path);
        }
        data
    };
    let data = if k.ch(b'o') == Some(b'z') {
        let mut out = Vec::new();
        flate2::read::ZlibDecoder::new(data.as_slice())
            .take(MAX_IMAGE as u64 + 1)
            .read_to_end(&mut out)
            .map_err(|_| "EINVAL:bad zlib data")?;
        out
    } else {
        data
    };
    if data.len() > MAX_IMAGE {
        return Err("EFBIG:image too big".into());
    }
    Ok(data)
}

fn png_size(d: &[u8]) -> Option<(u32, u32)> {
    if d.len() < 24 || &d[..8] != b"\x89PNG\r\n\x1a\n" || &d[12..16] != b"IHDR" {
        return None;
    }
    let w = u32::from_be_bytes(d[16..20].try_into().ok()?);
    let h = u32::from_be_bytes(d[20..24].try_into().ok()?);
    (w > 0 && h > 0).then_some((w, h))
}

fn zlib(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// Columns and rows the image covers, as the terminal would compute them.
fn cells(k: &Keys, px: (u32, u32), cell: (u32, u32)) -> (u32, u32) {
    let w = if k.num(b'w') > 0 { k.num(b'w') } else { px.0.saturating_sub(k.num(b'x')) }.max(1) as u64;
    let h = if k.num(b'h') > 0 { k.num(b'h') } else { px.1.saturating_sub(k.num(b'y')) }.max(1) as u64;
    let (cw, ch) = (cell.0 as u64, cell.1 as u64);
    let (c, r) = match (k.num(b'c') as u64, k.num(b'r') as u64) {
        (0, 0) => (w.div_ceil(cw), h.div_ceil(ch)),
        (c, 0) => (c, (c * cw * h).div_ceil(w * ch)),
        (0, r) => ((r * ch * w).div_ceil(h * cw), r),
        (c, r) => (c, r),
    };
    let max = DIACRITICS.len() as u64;
    (c.clamp(1, max) as u32, r.clamp(1, max) as u32)
}

fn diacritic(n: u32) -> char {
    char::from_u32(DIACRITICS[(n as usize).min(DIACRITICS.len() - 1)]).unwrap()
}

/// Placeholder text for an image at the cursor. The cursor ends up where
/// kitty puts it: right of the image, on its last row (or stays, with C=1).
fn placeholders(id: u32, c: u32, r: u32, keep_cursor: bool, screen: &vt100::Screen) -> String {
    let (row0, col0) = screen.cursor_position();
    let cols = screen.size().1.get() as u32;
    let visible = c.min(cols.saturating_sub(col0 as u32)).max(1);
    let color = format!("\x1b[0;38;2;{};{};{}m", (id >> 16) & 255, (id >> 8) & 255, id & 255);
    let mut s = String::new();
    for row in 0..r {
        if row > 0 {
            s.push_str(&format!("\n\x1b[{}G", col0 + 1));
        }
        s.push_str(&color);
        s.push(PLACEHOLDER);
        s.push(diacritic(row));
        s.push(diacritic(0));
        if id >> 24 != 0 {
            s.push(diacritic(id >> 24));
        }
        for _ in 1..visible {
            s.push(PLACEHOLDER);
        }
    }
    s.push_str(&screen.attributes_formatted());
    if keep_cursor {
        s.push_str(&format!("\x1b[{};{}H", row0 + 1, col0 + 1));
    }
    s
}

/// Placeholder cells on screen: (row, col, low 24 bits of the image id).
fn scan(screen: &vt100::Screen) -> Vec<(u32, u32, u32)> {
    let (rows, cols) = screen.size();
    let mut out = Vec::new();
    for r in 0..rows.get() {
        for c in 0..cols.get() {
            let Some(cell) = screen.cell(r, c) else { continue };
            if !cell.contents().starts_with(PLACEHOLDER) {
                continue;
            }
            let id = match cell.fgcolor() {
                vt100::Color::Rgb(r, g, b) => (r as u32) << 16 | (g as u32) << 8 | b as u32,
                vt100::Color::Idx(i) => i as u32,
                vt100::Color::Default => continue,
            };
            out.push((r as u32, c as u32, id));
        }
    }
    out
}

// -------------------------------------------------------------------- stream

/// A record: `u16 len, control data, u32 len, image bytes`. The client turns
/// each into a graphics command (base64, chunked) for its terminal.
fn record(ctrl: &str, data: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(6 + ctrl.len() + data.len());
    r.extend_from_slice(&(ctrl.len() as u16).to_be_bytes());
    r.extend_from_slice(ctrl.as_bytes());
    r.extend_from_slice(&(data.len() as u32).to_be_bytes());
    r.extend_from_slice(data);
    r
}

/// The server→client graphics byte stream (go-back-N, like history).
pub struct Stream {
    recs: VecDeque<(u64, Arc<Vec<u8>>)>,
    pub end: u64,
    /// The client has everything below `have`; we've sent up to `sent`;
    /// nothing below `floor` will be sent.
    pub have: u64,
    pub sent: u64,
    pub floor: u64,
    pub reported: u64,
    pub anchor: Instant,
    pub window: u64,
}

impl Stream {
    fn new(now: Instant) -> Self {
        Stream { recs: VecDeque::new(), end: 0, have: 0, sent: 0, floor: 0, reported: 0, anchor: now, window: WINDOW_START }
    }

    fn push(&mut self, rec: Arc<Vec<u8>>) {
        let len = rec.len() as u64;
        self.recs.push_back((self.end, rec));
        self.end += len;
    }

    pub fn ack(&mut self, have: u64, now: Instant) {
        self.reported = self.reported.max(have);
        let have = have.max(self.floor).min(self.end);
        if have > self.have {
            self.window = (self.window + (have - self.have)).min(WINDOW_MAX);
            self.have = have;
            self.anchor = now;
            while self.recs.front().is_some_and(|(off, r)| off + r.len() as u64 <= have) {
                self.recs.pop_front();
            }
        }
        self.sent = self.sent.max(self.have);
    }

    pub fn on_timeout(&mut self, now: Instant) {
        self.sent = self.have;
        self.anchor = now;
        self.window = (self.window / 2).max(WINDOW_MIN);
    }

    /// Up to `max` bytes starting at offset `from`.
    pub fn slice(&self, from: u64, max: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(max);
        for (off, r) in &self.recs {
            let pos = from + out.len() as u64;
            if off + r.len() as u64 <= pos {
                continue;
            }
            let skip = pos.saturating_sub(*off) as usize;
            let take = (r.len() - skip).min(max - out.len());
            out.extend_from_slice(&r[skip..skip + take]);
            if out.len() == max {
                break;
            }
        }
        out
    }
}

// -------------------------------------------------------------------- client

/// Client side: reassembles records from the stream and writes them to the
/// terminal as graphics commands.
#[derive(Default)]
pub struct Sink {
    buf: Vec<u8>,
}

impl Sink {
    pub fn reset(&mut self) {
        self.buf.clear();
    }

    /// Append stream bytes; returns terminal output for complete records.
    pub fn feed(&mut self, data: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        let mut at = 0;
        loop {
            let b = &self.buf[at..];
            if b.len() < 2 {
                break;
            }
            let cl = u16::from_be_bytes([b[0], b[1]]) as usize;
            if b.len() < 2 + cl + 4 {
                break;
            }
            let dl = u32::from_be_bytes(b[2 + cl..6 + cl].try_into().unwrap()) as usize;
            if b.len() < 6 + cl + dl {
                break;
            }
            command_bytes(&b[2..2 + cl], &b[6 + cl..6 + cl + dl], &mut out);
            at += 6 + cl + dl;
        }
        self.buf.drain(..at);
        out
    }
}

fn command_bytes(ctrl: &[u8], data: &[u8], out: &mut Vec<u8>) {
    if data.is_empty() {
        out.extend_from_slice(b"\x1b_G");
        out.extend_from_slice(ctrl);
        out.extend_from_slice(b"\x1b\\");
        return;
    }
    let b64 = b64encode(data);
    let chunks: Vec<&[u8]> = b64.chunks(4096).collect();
    for (n, chunk) in chunks.iter().enumerate() {
        let more = (n + 1 < chunks.len()) as u8;
        out.extend_from_slice(b"\x1b_G");
        if n == 0 {
            out.extend_from_slice(ctrl);
            out.push(b',');
        }
        out.extend_from_slice(format!("m={more};").as_bytes());
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"\x1b\\");
    }
}

/// Whether the local terminal draws kitty graphics with Unicode placeholders.
pub fn local_support() -> bool {
    match std::env::var("USSH_GRAPHICS").as_deref() {
        Ok("0") => return false,
        Ok("1") => return true,
        _ => {}
    }
    let term = std::env::var("TERM").unwrap_or_default();
    let prog = std::env::var("TERM_PROGRAM").unwrap_or_default();
    term == "xterm-kitty" || term == "xterm-ghostty" || prog == "ghostty"
}

// -------------------------------------------------------------------- base64

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        out.push(B64[(n >> 18) as usize & 63]);
        out.push(B64[(n >> 12) as usize & 63]);
        out.push(if c.len() > 1 { B64[(n >> 6) as usize & 63] } else { b'=' });
        out.push(if c.len() > 2 { B64[n as usize & 63] } else { b'=' });
    }
    out
}

pub fn b64decode(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() / 4 * 3);
    let (mut acc, mut bits) = (0u32, 0);
    for &b in data {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => {
                // Padding ends a group: drop its leftover bits.
                (acc, bits) = (0, 0);
                continue;
            }
            b'\n' | b'\r' | b' ' => continue,
            _ => return None,
        };
        acc = acc << 6 | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        for n in 0..20 {
            let d: Vec<u8> = (0..n).map(|i| (i * 37 + 5) as u8).collect();
            assert_eq!(b64decode(&b64encode(&d)).unwrap(), d);
        }
        assert_eq!(b64encode(b"hello"), b"aGVsbG8=");
    }

    #[test]
    fn splitter_across_chunks() {
        let input = b"ab\x1b[1mc\x1b_Ga=T;QUJD\x1b\\de\x1b_Gm=0;\x1b\\f\x1b";
        for cut in 0..input.len() {
            let mut s = Splitter::default();
            let mut text = Vec::new();
            let mut cmds = Vec::new();
            for part in [&input[..cut], &input[cut..], b"x"] {
                for p in s.feed(part) {
                    match p {
                        Piece::Text(t) => text.extend(t),
                        Piece::Graphics(g) => cmds.push(g),
                    }
                }
            }
            assert_eq!(text, b"ab\x1b[1mcdef\x1bx", "cut {cut}");
            assert_eq!(cmds, vec![b"a=T;QUJD".to_vec(), b"m=0;".to_vec()], "cut {cut}");
        }
    }

    #[test]
    fn chunks_padded_separately() {
        // As chafa sends it: keys alone first, then each chunk padded.
        let px: Vec<u8> = (1..=8).collect();
        let mut g = Gfx::new(Instant::now());
        g.enabled = true;
        let p = vt100::Parser::new(crate::history::nz(5), crate::history::nz(20), 0);
        let mut chunks = vec![b"a=T,f=32,s=2,v=1,c=2,r=1,m=1".to_vec()];
        chunks.push([b"m=1;".as_slice(), &b64encode(&px[..5])].concat());
        chunks.push([b"m=0;".as_slice(), &b64encode(&px[5..])].concat());
        let mut draw = String::new();
        for c in chunks {
            draw.push_str(&g.command(&c, p.screen()).draw);
        }
        assert_eq!(g.images.len(), 1);
        assert_eq!(draw.matches(PLACEHOLDER).count(), 2);
        let img = g.images.values().next().unwrap();
        let mut sink = Sink::default();
        let out = sink.feed(&img.rec);
        let b64 = out.split(|&b| b == b';').nth(1).unwrap().split(|&b| b == 0x1b).next().unwrap();
        let mut raw = Vec::new();
        flate2::read::ZlibDecoder::new(b64decode(b64).unwrap().as_slice()).read_to_end(&mut raw).unwrap();
        assert_eq!(raw, px);
    }

    #[test]
    fn placeholder_is_one_cell() {
        let mut p = vt100::Parser::new(crate::history::nz(5), crate::history::nz(20), 0);
        let s = placeholders(0x123456, 3, 2, false, p.screen());
        p.process(s.as_bytes());
        p.process(b"X");
        let scr = p.screen();
        assert!(scr.cell(0, 0).unwrap().contents().starts_with(PLACEHOLDER));
        assert_eq!(scr.cell(0, 0).unwrap().contents().chars().count(), 3);
        assert_eq!(scr.cell(1, 2).unwrap().contents(), PLACEHOLDER.to_string());
        assert_eq!(scr.cell(1, 3).unwrap().contents(), "X");
        assert_eq!(scr.cell(1, 0).unwrap().fgcolor(), vt100::Color::Rgb(0x12, 0x34, 0x56));
        assert_eq!(scan(scr).len(), 6);
    }

    #[test]
    fn stream_slices() {
        let mut st = Stream::new(Instant::now());
        st.push(Arc::new(vec![1, 2, 3]));
        st.push(Arc::new(vec![4, 5]));
        st.push(Arc::new(vec![6, 7, 8, 9]));
        assert_eq!(st.slice(0, 4), vec![1, 2, 3, 4]);
        assert_eq!(st.slice(2, 100), vec![3, 4, 5, 6, 7, 8, 9]);
        st.ack(5, Instant::now());
        assert_eq!(st.slice(5, 2), vec![6, 7]);
        assert_eq!(st.slice(9, 2), Vec::<u8>::new());
    }

    #[test]
    fn sink_records() {
        let mut sink = Sink::default();
        let mut r = record("a=t,i=1", b"hi");
        r.extend(record("a=p,i=1", b""));
        let out1 = sink.feed(&r[..5]);
        let out2 = sink.feed(&r[5..]);
        assert!(out1.is_empty());
        assert_eq!(out2, b"\x1b_Ga=t,i=1,m=0;aGk=\x1b\\\x1b_Ga=p,i=1\x1b\\".to_vec());
    }
}

