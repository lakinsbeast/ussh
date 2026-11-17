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

/// AppleScriptObjC straight on NSPasteboard: every copied file, and PNG or
/// TIFF images (TIFF converted to PNG).
const MACOS_OBJC_SCRIPT: &str = r#"
use framework "AppKit"
use scripting additions

on run argv
	set out to (item 1 of argv) & ".png"
	set pb to current application's NSPasteboard's generalPasteboard()
	set urls to pb's readObjectsForClasses:{current application's NSURL} options:(missing value)
	set paths to {}
	if urls is not missing value then
		repeat with u in (urls as list)
			if (u's isFileURL()) as boolean then set end of paths to ((u's |path|()) as text)
		end repeat
	end if
	if (count of paths) > 0 then
		set AppleScript's text item delimiters to linefeed
		return "FILES" & linefeed & (paths as text)
	end if
	set png to pb's dataForType:(current application's NSPasteboardTypePNG)
	if png is missing value then
		set tiff to pb's dataForType:(current application's NSPasteboardTypeTIFF)
		if tiff is missing value then return "NONE"
		set rep to current application's NSBitmapImageRep's imageRepWithData:tiff
		set png to rep's representationUsingType:(current application's NSBitmapImageFileTypePNG) |properties|:(current application's NSDictionary's dictionary())
	end if
	png's writeToFile:out atomically:true
	return "IMAGE" & linefeed & out
end run
"#;

fn macos() -> Option<Clip> {
    let base = temp_path("x").with_extension("");
    // The ObjC script sees every file; the classic one is the fallback.
    let text = osascript(MACOS_OBJC_SCRIPT, &base).filter(|t| t.starts_with("FILES") || t.starts_with("IMAGE") || t.starts_with("NONE"));
    let text = match text {
        Some(t) => t,
        None => osascript(MACOS_SCRIPT, &base)?.replacen('\t', "\n", 1),
    };
    let mut lines = text.lines();
    match lines.next()? {
        "FILES" | "FILE" => {
            let files: Vec<PathBuf> = lines.map(PathBuf::from).filter(|p| p.exists()).collect();
            (!files.is_empty()).then_some(Clip::Files(files))
        }
        "IMAGE" => Some(PathBuf::from(lines.next()?)).filter(|p| p.exists()).map(Clip::Image),
        _ => None,
    }
}

fn osascript(script: &str, base: &std::path::Path) -> Option<String> {
    let mut child = Command::new("osascript")
        .arg("-")
        .arg(base)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(script.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim_end().to_string())
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
        // Byte-wise: `&s[i + 1..i + 3]` panics when a multi-byte character
        // follows `%` (a file named "100%€.png" is enough).
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(hi), Some(lo)) = (hex_digit(b[i + 1]), hex_digit(b[i + 2]))
        {
            out.push(hi << 4 | lo);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_digit(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

/// A remote-safe file name: letters, digits, `.`, `-`, `_` only.
pub fn safe_name(name: &str) -> String {
    let s: String = name.chars().map(|c| if c.is_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' }).collect();
    let s = s.trim_start_matches('.').to_string();
    if s.is_empty() { "file".into() } else { s.chars().take(120).collect() }
}

/// If pasted text is nothing but paths of existing local files (as terminals
/// produce for Cmd+V or drag & drop from Finder: `\ `-escaped, quoted or
/// `file://`), returns them.
pub fn local_files(text: &str) -> Option<Vec<PathBuf>> {
    let text = text.trim();
    if text.is_empty() || text.len() > 16 * 1024 {
        return None;
    }
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let mut files = Vec::new();
    for word in shell_words(text)? {
        let word = match word.strip_prefix("file://") {
            Some(u) => percent_decode(u.strip_prefix("localhost").unwrap_or(u)),
            None => word,
        };
        let path = match (word.strip_prefix("~/"), &home) {
            (Some(rest), Some(h)) => h.join(rest),
            _ => PathBuf::from(&word),
        };
        if !path.is_absolute() || !path.is_file() {
            return None;
        }
        files.push(path);
    }
    (!files.is_empty()).then_some(files)
}

/// Splits like a shell: whitespace separates words; quotes and backslashes
/// escape. None on an unterminated quote.
fn shell_words(s: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut it = s.chars();
    while let Some(c) = it.next() {
        match c {
            '\\' => {
                cur.push(it.next()?);
                in_word = true;
            }
            '\'' => {
                loop {
                    match it.next()? {
                        '\'' => break,
                        c => cur.push(c),
                    }
                }
                in_word = true;
            }
            '"' => {
                loop {
                    match it.next()? {
                        '"' => break,
                        '\\' => cur.push(it.next()?),
                        c => cur.push(c),
                    }
                }
                in_word = true;
            }
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            c => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    Some(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_cuts_bytes_not_chars() {
        // Used to panic: the slice ended inside the multi-byte character.
        assert_eq!(percent_decode("100%€"), "100%€");
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("%2F%2ftmp"), "//tmp");
        // An incomplete escape stays as it is.
        assert_eq!(percent_decode("100%2"), "100%2");
        assert_eq!(percent_decode("100%zz"), "100%zz");
    }

    #[test]
    fn safe_name_keeps_plain_names() {
        assert_eq!(safe_name("../etc/passwd"), "_etc_passwd");
        assert_eq!(safe_name(".hidden"), "hidden");
        assert_eq!(safe_name(""), "file");
    }
}
