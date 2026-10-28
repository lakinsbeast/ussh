mod client;
mod crypto;
mod history;
mod proto;
mod server;
mod term;

/// Identifies this exact binary, so the client can tell whether the copy
/// installed on a server matches it.
pub fn build_id() -> String {
    use std::hash::Hasher;
    let exe = std::env::current_exe().and_then(std::fs::read).unwrap_or_default();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    h.write(&exe);
    format!("{}-{:016x}", env!("CARGO_PKG_VERSION"), h.finish())
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
