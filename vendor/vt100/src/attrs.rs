use crate::term::BufWrite as _;
use alloc::string::String;

/// Represents a foreground or background color for cells.
#[derive(Eq, PartialEq, Debug, Copy, Clone, Default)]
pub enum Color {
    /// The default terminal color.
    #[default]
    Default,

    /// An indexed terminal color.
    Idx(u8),

    /// An RGB terminal color. The parameters are (red, green, blue).
    Rgb(u8, u8, u8),
}

const TEXT_MODE_INTENSITY: u8 = 0b0000_0011;
const TEXT_MODE_BOLD: u8 = 0b0000_0001;
const TEXT_MODE_DIM: u8 = 0b0000_0010;
const TEXT_MODE_ITALIC: u8 = 0b0000_0100;
const TEXT_MODE_UNDERLINE: u8 = 0b0000_1000;
const TEXT_MODE_INVERSE: u8 = 0b0001_0000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Attrs {
    pub fgcolor: Color,
    pub bgcolor: Color,
    pub mode: u8,
    /// OSC 8 hyperlink (see `crate::links`); 0 = none.
    pub link: u16,
}

impl Default for Attrs {
    fn default() -> Self {
        Self::new()
    }
}

impl Attrs {
    pub const fn new() -> Self {
        Self {
            fgcolor: Color::Default,
            bgcolor: Color::Default,
            mode: 0,
            link: 0,
        }
    }

    pub fn bold(&self) -> bool {
        self.mode & TEXT_MODE_BOLD != 0
    }

    pub fn dim(&self) -> bool {
        self.mode & TEXT_MODE_DIM != 0
    }

    fn intensity(&self) -> u8 {
        self.mode & TEXT_MODE_INTENSITY
    }

    pub fn set_bold(&mut self) {
        self.mode &= !TEXT_MODE_INTENSITY;
        self.mode |= TEXT_MODE_BOLD;
    }

    pub fn set_dim(&mut self) {
        self.mode &= !TEXT_MODE_INTENSITY;
        self.mode |= TEXT_MODE_DIM;
    }

    pub fn set_normal_intensity(&mut self) {
        self.mode &= !TEXT_MODE_INTENSITY;
    }

    pub fn italic(&self) -> bool {
        self.mode & TEXT_MODE_ITALIC != 0
    }

    pub fn set_italic(&mut self, italic: bool) {
        if italic {
            self.mode |= TEXT_MODE_ITALIC;
        } else {
            self.mode &= !TEXT_MODE_ITALIC;
        }
    }

    pub fn underline(&self) -> bool {
        self.mode & TEXT_MODE_UNDERLINE != 0
    }

    pub fn set_underline(&mut self, underline: bool) {
        if underline {
            self.mode |= TEXT_MODE_UNDERLINE;
        } else {
            self.mode &= !TEXT_MODE_UNDERLINE;
        }
    }

    pub fn inverse(&self) -> bool {
        self.mode & TEXT_MODE_INVERSE != 0
    }

    pub fn set_inverse(&mut self, inverse: bool) {
        if inverse {
            self.mode |= TEXT_MODE_INVERSE;
        } else {
            self.mode &= !TEXT_MODE_INVERSE;
        }
    }

    pub fn write_escape_code_diff(
        &self,
        contents: &mut String,
        other: &Self,
    ) {
        self.write_escape_code_diff_fmt(contents, other)
            .expect("writing to a String cannot fail");
    }

    pub fn write_escape_code_diff_fmt(
        &self,
        writer: &mut impl alloc::fmt::Write,
        other: &Self,
    ) -> alloc::fmt::Result {
        // SGR 0 doesn't end a hyperlink on real terminals, so links are
        // diffed on their own.
        if self.link != other.link {
            crate::links::write_osc(writer, self.link)?;
        }
        let (this, other) =
            (Self { link: 0, ..*self }, Self { link: 0, ..*other });
        if this == other {
            return Ok(());
        }
        if this == Self::default() {
            return crate::term::ClearAttrs.write_fmt(writer);
        }

        let attrs = crate::term::Attrs::default();

        let attrs = if this.fgcolor == other.fgcolor {
            attrs
        } else {
            attrs.fgcolor(this.fgcolor)
        };
        let attrs = if this.bgcolor == other.bgcolor {
            attrs
        } else {
            attrs.bgcolor(this.bgcolor)
        };
        let attrs = if this.intensity() == other.intensity() {
            attrs
        } else {
            attrs.intensity(match this.intensity() {
                0 => crate::term::Intensity::Normal,
                TEXT_MODE_BOLD => crate::term::Intensity::Bold,
                TEXT_MODE_DIM => crate::term::Intensity::Dim,
                _ => unreachable!(),
            })
        };
        let attrs = if this.italic() == other.italic() {
            attrs
        } else {
            attrs.italic(this.italic())
        };
        let attrs = if this.underline() == other.underline() {
            attrs
        } else {
            attrs.underline(this.underline())
        };
        let attrs = if this.inverse() == other.inverse() {
            attrs
        } else {
            attrs.inverse(this.inverse())
        };

        attrs.write_fmt(writer)
    }
}
