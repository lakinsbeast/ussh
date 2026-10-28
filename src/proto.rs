//! Plaintext message encoding (inside the AEAD envelope).
//!
//! Client → server carries keystrokes as an offset-addressed byte stream
//! (idempotent, so duplicates and replays are harmless) plus the screen
//! version the client currently shows. Server → client carries fragments of
//! "turn screen version `base` into version `new`" diffs.

pub const PROTO: u8 = 3;
/// Max diff bytes per server packet (keeps datagrams under typical MTU).
pub const MAX_FRAG: usize = 1100;
/// Max keystroke bytes per client packet.
pub const MAX_INPUT_CHUNK: usize = 1000;

pub const FLAG_ENDED: u8 = 1;
pub const FLAG_SUPERSEDED: u8 = 2;

/// In-band escape inside the input stream: `ESC_BYTE ESC_BYTE` is a literal
/// Ctrl-^, `ESC_BYTE b'h'` toggles the history viewer.
pub const ESC_BYTE: u8 = 0x1e;

pub struct ClientMsg {
    pub instance: u64,
    pub epoch: u32,
    pub ack: u64,
    pub input_off: u64,
    pub input: Vec<u8>,
    pub cols: u16,
    pub rows: u16,
    /// History lines received so far (absolute index, exclusive).
    pub hist_have: u64,
    /// The terminal draws kitty graphics (Unicode placeholders).
    pub graphics: bool,
    /// Terminal size in pixels (0 = unknown).
    pub px_w: u16,
    pub px_h: u16,
    /// Graphics stream bytes received so far.
    pub gfx_have: u64,
    /// The terminal's name for XTVERSION, e.g. `ghostty 1.1.3` (may be
    /// empty; absent from older clients).
    pub term: String,
}

pub struct Frame {
    pub base: u64,
    pub new: u64,
    pub idx: u16,
    pub count: u16,
    /// Screen size of version `new`.
    pub rows: u16,
    pub cols: u16,
    pub data: Vec<u8>,
}

/// Rows that scrolled off the top of the server's screen, for the client's
/// native scrollback: deflated, `\n`-separated, starting at line `start`.
pub struct Hist {
    pub start: u64,
    /// Lines before `start` were skipped (output flood).
    pub skip: bool,
    pub data: Vec<u8>,
}

/// A piece of the graphics stream (see `graphics::Stream`).
pub struct GfxChunk {
    pub start: u64,
    /// The stream restarts here: drop anything partial before it.
    pub reset: bool,
    pub data: Vec<u8>,
}

pub struct ServerMsg {
    pub flags: u8,
    pub input_ack: u64,
    pub frame: Option<Frame>,
    pub hist: Option<Hist>,
    pub gfx: Option<GfxChunk>,
}

impl ClientMsg {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = W(Vec::with_capacity(48 + self.input.len()));
        w.u8(PROTO);
        w.u64(self.instance);
        w.u32(self.epoch);
        w.u64(self.ack);
        w.u64(self.input_off);
        w.bytes(&self.input);
        w.u16(self.cols);
        w.u16(self.rows);
        w.u64(self.hist_have);
        w.u8(self.graphics as u8);
        w.u16(self.px_w);
        w.u16(self.px_h);
        w.u64(self.gfx_have);
        w.bytes(self.term.as_bytes());
        w.0
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = R(b);
        if r.u8()? != PROTO {
            return None;
        }
        Some(ClientMsg {
            instance: r.u64()?,
            epoch: r.u32()?,
            ack: r.u64()?,
            input_off: r.u64()?,
            input: r.bytes()?.to_vec(),
            cols: r.u16()?,
            rows: r.u16()?,
            hist_have: r.u64()?,
            graphics: r.u8()? != 0,
            px_w: r.u16()?,
            px_h: r.u16()?,
            gfx_have: r.u64()?,
            term: r.bytes().map(|b| String::from_utf8_lossy(b).into_owned()).unwrap_or_default(),
        })
    }
}

impl ServerMsg {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = W(Vec::with_capacity(48 + self.frame.as_ref().map_or(0, |f| f.data.len())));
        w.u8(PROTO);
        w.u8(self.flags);
        w.u64(self.input_ack);
        match &self.frame {
            None => w.u8(0),
            Some(f) => {
                w.u8(1);
                w.u64(f.base);
                w.u64(f.new);
                w.u16(f.idx);
                w.u16(f.count);
                w.u16(f.rows);
                w.u16(f.cols);
                w.bytes(&f.data);
            }
        }
        match &self.hist {
            None => w.u8(0),
            Some(h) => {
                w.u8(1);
                w.u64(h.start);
                w.u8(h.skip as u8);
                w.bytes(&h.data);
            }
        }
        match &self.gfx {
            None => w.u8(0),
            Some(g) => {
                w.u8(1);
                w.u64(g.start);
                w.u8(g.reset as u8);
                w.bytes(&g.data);
            }
        }
        w.0
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = R(b);
        if r.u8()? != PROTO {
            return None;
        }
        let flags = r.u8()?;
        let input_ack = r.u64()?;
        let frame = match r.u8()? {
            0 => None,
            _ => Some(Frame {
                base: r.u64()?,
                new: r.u64()?,
                idx: r.u16()?,
                count: r.u16()?,
                rows: r.u16()?,
                cols: r.u16()?,
                data: r.bytes()?.to_vec(),
            }),
        };
        let hist = match r.u8()? {
            0 => None,
            _ => Some(Hist { start: r.u64()?, skip: r.u8()? != 0, data: r.bytes()?.to_vec() }),
        };
        let gfx = match r.u8()? {
            0 => None,
            _ => Some(GfxChunk { start: r.u64()?, reset: r.u8()? != 0, data: r.bytes()?.to_vec() }),
        };
        Some(ServerMsg { flags, input_ack, frame, hist, gfx })
    }
}

struct W(Vec<u8>);

impl W {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn bytes(&mut self, v: &[u8]) {
        self.u16(v.len() as u16);
        self.0.extend_from_slice(v);
    }
}

struct R<'a>(&'a [u8]);

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

pub fn deflate(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

pub fn inflate(data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    flate2::read::DeflateDecoder::new(data).read_to_end(&mut out).ok()?;
    Some(out)
}
