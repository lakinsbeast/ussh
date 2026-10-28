//! Reads non-text clipboard contents (copied files, images) for Ctrl+V
//! uploads. Text is left alone: the terminal pastes it itself.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub enum Clip {
    Files(Vec<PathBuf>),
    /// An image saved to a local temp file (deleted after upload).
    Image(PathBuf),
}

/// What's on the clipboard, if it's something we should upload.
pub fn read() -> Option<Clip> {
    if let Ok(v) = std::env::var("USSH_TEST_CLIPBOARD") {
        // Test knob: "file:/a,/b", "image:/x.png" (copied, as a real paste
        // would produce a temp file), or anything else for "text".
        if let Some(list) = v.strip_prefix("file:") {
            return Some(Clip::Files(list.split(',').map(PathBuf::from).collect()));
        }
        if let Some(p) = v.strip_prefix("image:") {
            let tmp = temp_path("png");
            std::fs::copy(p, &tmp).ok()?;
            return Some(Clip::Image(tmp));
        }
        return None;
    }
    if cfg!(target_os = "macos") {
        macos()
    } else {
        linux()
    }
}

fn temp_path(ext: &str) -> PathBuf {
    let ns = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    std::env::temp_dir().join(format!("ussh-paste-{}-{ns}.{ext}", std::process::id()))
}

const MACOS_SCRIPT: &str = r#"
on run argv
	set out to item 1 of argv
	set kinds to {}
	repeat with e in (clipboard info)
		set end of kinds to item 1 of e
	end repeat
	if kinds contains «class furl» then
		set f to the clipboard as «class furl»
		return "FILE" & tab & (POSIX path of f)
	end if
	if kinds contains «class PNGf» then
		my save(the clipboard as «class PNGf», out & ".png")
		return "IMAGE" & tab & out & ".png"
	end if
	if kinds contains «class TIFF» then
		my save(the clipboard as «class TIFF», out & ".tiff")
		do shell script "sips -s format png " & quoted form of (out & ".tiff") & " --out " & quoted form of (out & ".png") & " >/dev/null && rm -f " & quoted form of (out & ".tiff")
		return "IMAGE" & tab & out & ".png"
	end if
	return "NONE"
end run

on save(d, p)
	set fh to open for access (POSIX file p) with write permission
	set eof fh to 0
	write d to fh
	close access fh
end save
"#;

fn macos() -> Option<Clip> {
    let base = temp_path("x");
    let base = base.with_extension("");
    let mut child = Command::new("osascript")
        .arg("-")
        .arg(&base)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(MACOS_SCRIPT.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let (kind, path) = text.trim_end().split_once('\t')?;
    let path = PathBuf::from(path);
    match kind {
        "FILE" if path.exists() => Some(Clip::Files(vec![path])),
        "IMAGE" if path.exists() => Some(Clip::Image(path)),
        _ => None,
    }
}

fn linux() -> Option<Clip> {
    let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
    let get = |ty: &str| -> Option<Vec<u8>> {
        let out = if wayland {
            Command::new("wl-paste").args(["--no-newline", "--type", ty]).stderr(Stdio::null()).output()
        } else {
            Command::new("xclip").args(["-selection", "clipboard", "-o", "-t", ty]).stderr(Stdio::null()).output()
        }
        .ok()?;
        out.status.success().then_some(out.stdout)
    };
    let types = if wayland { get_types_wayland()? } else { String::from_utf8(get("TARGETS")?).ok()? };
    if types.lines().any(|t| t.trim() == "text/uri-list") {
        let list = String::from_utf8(get("text/uri-list")?).ok()?;
        let files: Vec<PathBuf> = list
            .lines()
            .filter_map(|l| l.trim().strip_prefix("file://"))
            .map(|p| PathBuf::from(percent_decode(p)))
            .filter(|p| p.is_file())
            .collect();
        return (!files.is_empty()).then_some(Clip::Files(files));
    }
    if types.lines().any(|t| t.trim() == "image/png") {
        let data = get("image/png")?;
        let tmp = temp_path("png");
        std::fs::write(&tmp, data).ok()?;
        return Some(Clip::Image(tmp));
    }
    None
}

fn get_types_wayland() -> Option<String> {
    let out = Command::new("wl-paste").arg("--list-types").stderr(Stdio::null()).output().ok()?;
    String::from_utf8(out.stdout).ok()
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A remote-safe file name: letters, digits, `.`, `-`, `_` only.
pub fn safe_name(name: &str) -> String {
    let s: String = name.chars().map(|c| if c.is_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' }).collect();
    let s = s.trim_start_matches('.').to_string();
    if s.is_empty() { "file".into() } else { s.chars().take(120).collect() }
}
