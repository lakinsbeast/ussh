//! Local terminal: raw mode and window size.

use std::io;

pub struct RawMode {
    orig: libc::termios,
}

impl RawMode {
    pub fn enter() -> io::Result<Self> {
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut t) != 0 {
                return Err(io::Error::last_os_error());
            }
            let orig = t;
            libc::cfmakeraw(&mut t);
            if libc::tcsetattr(0, libc::TCSANOW, &t) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(RawMode { orig })
        }
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &self.orig);
        }
    }
}

/// (cols, rows) of the controlling terminal.
pub fn size() -> (u16, u16) {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        for fd in [1, 0, 2] {
            if libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
                return (ws.ws_col, ws.ws_row);
            }
        }
    }
    (80, 24)
}
