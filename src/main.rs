mod client;
mod crypto;
mod history;
mod proto;
mod server;
mod term;

/// Server binaries for other platforms, embedded at build time from
/// `$USSH_EMBED_DIR` (see build.rs).
mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded.rs"));
}

use std::sync::{Mutex, OnceLock};

/// Debug log (client: USSH_LOG=path; server: if ~/.ussh/debug exists).
pub static LOG: OnceLock<Option<Mutex<std::fs::File>>> = OnceLock::new();

pub fn log_to(path: Option<std::path::PathBuf>) {
    let f = path.and_then(|p| std::fs::OpenOptions::new().create(true).append(true).open(p).ok());
    let _ = LOG.set(f.map(Mutex::new));
}

#[macro_export]
macro_rules! dlog {
    ($($t:tt)*) => {
        if let Some(Some(f)) = $crate::LOG.get() {
            use std::io::Write as _;
            let ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() % 100_000_000;
            let _ = writeln!(f.lock().unwrap(), "{ms} {}", format!($($t)*));
        }
    };
}

/// Identifies this exact binary, so the client can tell whether the copy
/// installed on a server matches it.
pub fn build_id() -> String {
    fnv_id(&std::env::current_exe().and_then(std::fs::read).unwrap_or_default())
}

/// FNV-1a: identical on every platform and toolchain, unlike std's hasher.
pub fn fnv_id(bytes: &[u8]) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h = (h ^ b as u64).wrapping_mul(0x100000001b3);
    }
    format!("{}-{h:016x}", env!("CARGO_PKG_VERSION"))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("server") => server::main(&args[1..]),
        Some("build-id") => {
            println!("{}", build_id());
            0
        }
        Some("-V" | "--version") => {
            println!("ussh {}", env!("CARGO_PKG_VERSION"));
            0
        }
        _ => client::main(&args),
    };
    std::process::exit(code);
}
