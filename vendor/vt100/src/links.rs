//! OSC 8 hyperlinks (patched in for ussh).
//!
//! Cells carry a `u16` id; the `params;uri` text lives in a process-wide
//! table so `Attrs` stays `Copy`. Ids are never reused: once the table is
//! full, new links are dropped (the text still shows, just not clickable).

extern crate std;

use alloc::string::String;
use std::collections::HashMap;
use std::sync::Mutex;

/// Longest `params;uri` kept (kitty uses 2083 for the URI alone).
const MAX_LEN: usize = 4096;

struct Table {
    texts: alloc::vec::Vec<String>,
    ids: HashMap<String, u16>,
}

static TABLE: Mutex<Option<Table>> = Mutex::new(None);

/// The id for `params;uri`, or 0 for "no link".
pub fn intern(params: &[u8], uri: &[u8]) -> u16 {
    if uri.is_empty()
        || params.len() + uri.len() + 1 > MAX_LEN
        || params.iter().chain(uri).any(|&b| b < 0x20 || b == 0x7f)
    {
        return 0;
    }
    let (Ok(params), Ok(uri)) =
        (core::str::from_utf8(params), core::str::from_utf8(uri))
    else {
        return 0;
    };
    let text = format!("{params};{uri}");
    let mut guard = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    let t = guard.get_or_insert_with(|| Table {
        texts: vec![String::new()],
        ids: HashMap::new(),
    });
    if let Some(&id) = t.ids.get(&text) {
        return id;
    }
    let Ok(id) = u16::try_from(t.texts.len()) else {
        return 0;
    };
    t.texts.push(text.clone());
    t.ids.insert(text, id);
    id
}

/// Writes the OSC 8 that switches to link `id` (0 ends the current link).
pub fn write_osc(
    writer: &mut impl alloc::fmt::Write,
    id: u16,
) -> alloc::fmt::Result {
    let guard = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    let text = guard
        .as_ref()
        .and_then(|t| t.texts.get(usize::from(id)))
        .filter(|_| id != 0)
        .map_or(";", String::as_str);
    // BEL-terminated: the capture helpers skip `ESC ] ... BEL`.
    write!(writer, "\x1b]8;{text}\x07")
}
