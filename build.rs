//! Embeds server binaries for other platforms so one client can install
//! ussh anywhere: set USSH_EMBED_DIR to a directory with any of
//! `ussh-linux-x86_64`, `ussh-linux-aarch64`.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=USSH_EMBED_DIR");
    let mut code = String::from("pub static EMBEDDED: &[(&str, &[u8])] = &[\n");
    if let Ok(dir) = std::env::var("USSH_EMBED_DIR") {
        for (platform, file) in [("Linux x86_64", "ussh-linux-x86_64"), ("Linux aarch64", "ussh-linux-aarch64")] {
            let path = PathBuf::from(&dir).join(file);
            if let Ok(path) = path.canonicalize() {
                println!("cargo:rerun-if-changed={}", path.display());
                code.push_str(&format!("    ({platform:?}, include_bytes!({:?})),\n", path));
            }
        }
    }
    code.push_str("];\n");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("embedded.rs");
    std::fs::write(out, code).unwrap();
}
