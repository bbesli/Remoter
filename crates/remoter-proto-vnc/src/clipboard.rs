//! The RFB clipboard, and the two places it loses characters.
//!
//! RFC 6143 §7.5.6 (`ClientCutText`) and §7.6.4 (`ServerCutText`) carry one
//! thing: "text in ISO 8859-1 (Latin-1) format", with lines separated by a
//! single LF and CR not used at all. There is no format negotiation, no
//! encoding declaration and no way to carry a file — which is why
//! [`crate::capabilities`] reports `ClipboardSupport::Text` and nothing more.
//!
//! # Outbound: Latin-1 is only half the problem
//!
//! Latin-1 already cannot carry a euro sign, a Turkish dotless i, or any CJK
//! character, so some loss going out is inherent to RFB. But `vnc-rs` makes it
//! worse in a way this module has to work around: its `ClientCutText` writes
//! `String::as_bytes()`, which is **UTF-8**, and declares that byte count as
//! the length. So `é` — one byte, `0xE9`, in Latin-1 — would go out as the two
//! UTF-8 bytes `0xC3 0xA9`, and the server would paste `Ã©`.
//!
//! The set of characters where UTF-8 and Latin-1 agree is exactly ASCII. So
//! [`to_wire_text`] restricts to ASCII, substitutes anything else, and reports
//! that it did — because pasting a password that silently lost two characters
//! is worse than being told the paste was incomplete. When the library learns
//! to write Latin-1 bytes, the substitution set widens to `0x20..=0xff` and
//! this comment is how the next person knows that is the only change needed.
//!
//! # Inbound: already lost before it reaches us
//!
//! `vnc-rs` decodes `ServerCutText` with `String::from_utf8_lossy`, so a Latin-1
//! byte above `0x7f` has already become `U+FFFD` by the time this crate sees
//! it. Nothing here can undo that; [`inbound_was_mangled`] can only notice it
//! happened so the user is told their paste is not what the remote copied.

/// What replaces a character RFB cannot carry.
///
/// A question mark rather than a dropped character or `U+FFFD`: the length is
/// preserved, so a paste into a password field fails cleanly instead of
/// producing a shorter string that might match something, and it is visible in
/// a terminal that cannot render a replacement glyph.
pub const SUBSTITUTE: char = '?';

/// The replacement character `String::from_utf8_lossy` leaves behind.
pub const REPLACEMENT: char = '\u{fffd}';

/// The most text one paste may carry, in bytes.
///
/// RFC 6143 §7.5.6 puts a `U32` length on the message and no ceiling under it,
/// so a paste of a whole file is legal and would sit in the session's write
/// path for as long as it took to drain. A megabyte is far more than any
/// clipboard a person fills by hand and small enough that sending it is not
/// felt.
pub const MAX_CUT_TEXT_BYTES: usize = 1024 * 1024;

/// What happened while preparing text for the wire.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Transcoded {
    /// The text to send.
    ///
    /// Deliberately **not** `Debug`-printed by the containing struct's derive —
    /// see the manual implementation below. The most common thing on a system
    /// administrator's clipboard is a password they just copied out of a
    /// password manager.
    text: String,
    /// Whether any character was replaced by [`SUBSTITUTE`].
    pub substituted: bool,
    /// Whether the text was cut short at [`MAX_CUT_TEXT_BYTES`].
    pub truncated: bool,
}

impl Transcoded {
    /// The text to put on the wire.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Takes the text, leaving the flags behind.
    #[must_use]
    pub fn into_text(self) -> String {
        self.text
    }

    /// Whether the user should be told something was lost.
    #[must_use]
    pub const fn is_lossy(&self) -> bool {
        self.substituted || self.truncated
    }
}

impl std::fmt::Debug for Transcoded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transcoded")
            .field(
                "text",
                &format_args!("<redacted, {} chars>", self.text.chars().count()),
            )
            .field("substituted", &self.substituted)
            .field("truncated", &self.truncated)
            .finish()
    }
}

/// Prepares local clipboard text for `ClientCutText` (RFC 6143 §7.5.6).
///
/// Three transformations, in this order:
///
/// 1. **CRLF and bare CR become LF.** §7.5.6 says lines are separated by LF and
///    that CR is not used; leaving a CR in produces a stray `^M` at the end of
///    every line pasted into a Unix editor.
/// 2. **Anything outside ASCII becomes [`SUBSTITUTE`].** See the module
///    documentation for why the limit is ASCII and not Latin-1.
/// 3. **The result is cut at [`MAX_CUT_TEXT_BYTES`]**, on a character boundary.
#[must_use]
pub fn to_wire_text(text: &str) -> Transcoded {
    let mut out = String::with_capacity(text.len().min(MAX_CUT_TEXT_BYTES));
    let mut substituted = false;
    let mut truncated = false;
    let mut previous_was_cr = false;

    for character in text.chars() {
        let mapped = match character {
            '\r' => {
                previous_was_cr = true;
                '\n'
            }
            '\n' if previous_was_cr => {
                // The LF half of a CRLF pair; the CR already became the
                // newline, so emitting this one too would double every line
                // break in a paste from a Windows application.
                previous_was_cr = false;
                continue;
            }
            other => {
                previous_was_cr = false;
                // Tab and LF are the two control characters that are text; every
                // other one is how a paste becomes a terminal injection, and
                // anything outside ASCII is the encoding problem above.
                if matches!(other, '\n' | '\t') || (other.is_ascii() && !other.is_control()) {
                    other
                } else {
                    substituted = true;
                    SUBSTITUTE
                }
            }
        };
        if out.len() + mapped.len_utf8() > MAX_CUT_TEXT_BYTES {
            truncated = true;
            break;
        }
        out.push(mapped);
    }

    Transcoded {
        text: out,
        substituted,
        truncated,
    }
}

/// Whether inbound text lost characters before this crate could see it.
///
/// A `U+FFFD` in `ServerCutText` cannot have come from the wire: RFC 6143
/// §7.6.4 is Latin-1, and no Latin-1 byte decodes to the replacement
/// character. Its presence means the library's UTF-8 decode threw a byte away,
/// so the text on screen is not the text the remote copied.
#[must_use]
pub fn inbound_was_mangled(text: &str) -> bool {
    text.contains(REPLACEMENT)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]
mod tests {
    use super::*;

    #[test]
    fn ascii_text_passes_through_untouched() {
        let transcoded = to_wire_text("sudo systemctl restart nginx");
        assert_eq!(transcoded.text(), "sudo systemctl restart nginx");
        assert!(!transcoded.is_lossy());
    }

    #[test]
    fn crlf_becomes_one_lf_and_not_two() {
        // Doubling every line break is what happens when the CR is mapped to a
        // newline and the LF beside it is then also emitted.
        let transcoded = to_wire_text("one\r\ntwo\r\nthree");
        assert_eq!(transcoded.text(), "one\ntwo\nthree");
        assert!(
            !transcoded.is_lossy(),
            "a line ending is not a lost character"
        );

        // A bare CR, as classic Mac OS and some appliances still emit.
        assert_eq!(to_wire_text("one\rtwo").text(), "one\ntwo");
        // And a bare LF is left alone.
        assert_eq!(to_wire_text("one\ntwo").text(), "one\ntwo");
    }

    #[test]
    fn a_character_rfb_cannot_carry_is_substituted_and_reported() {
        // Silently dropping it would paste a password two characters short of
        // the one the user copied.
        let transcoded = to_wire_text("café");
        assert_eq!(transcoded.text(), "caf?");
        assert!(transcoded.substituted);
        assert!(transcoded.is_lossy());

        let transcoded = to_wire_text("Grüße aus Köln");
        assert!(transcoded.substituted);
        assert_eq!(
            transcoded.text().chars().count(),
            "Grüße aus Köln".chars().count(),
            "the length is preserved so a paste fails cleanly rather than nearly working"
        );
    }

    #[test]
    fn every_non_latin_script_is_substituted_rather_than_mangled() {
        for text in ["日本語", "Привет", "😀", "€100"] {
            let transcoded = to_wire_text(text);
            assert!(transcoded.substituted, "{text}");
            assert!(transcoded.text().is_ascii(), "{text}");
        }
    }

    #[test]
    fn control_characters_do_not_reach_the_far_ends_clipboard() {
        // A NUL or an escape sequence in a paste is how a clipboard becomes a
        // terminal injection. Tab and newline are the two that are text.
        let transcoded = to_wire_text("a\u{0}b\u{1b}[31mc\td\n");
        assert_eq!(transcoded.text(), "a?b?[31mc\td\n");
        assert!(transcoded.substituted);
    }

    #[test]
    fn an_enormous_paste_is_cut_and_says_so() {
        let huge = "x".repeat(MAX_CUT_TEXT_BYTES + 1000);
        let transcoded = to_wire_text(&huge);
        assert_eq!(transcoded.text().len(), MAX_CUT_TEXT_BYTES);
        assert!(transcoded.truncated);
        assert!(!transcoded.substituted);
    }

    #[test]
    fn truncation_lands_on_a_character_boundary() {
        // Substitution makes every character one byte, so the boundary is
        // trivially safe today. The assertion is here because the day the
        // library can write Latin-1 and multi-byte characters survive, a
        // byte-wise cut would produce an invalid `String`.
        let mut text = "a".repeat(MAX_CUT_TEXT_BYTES - 1);
        text.push('€');
        let transcoded = to_wire_text(&text);
        assert!(transcoded.text().is_char_boundary(transcoded.text().len()));
    }

    #[test]
    fn clipboard_text_is_never_debug_printed() {
        let transcoded = to_wire_text("s3cr3t-from-the-password-manager");
        let rendered = format!("{transcoded:?}");
        assert!(!rendered.contains("s3cr3t"), "{rendered}");
        assert!(rendered.contains("<redacted, 32 chars>"), "{rendered}");
    }

    #[test]
    fn a_replacement_character_inbound_means_the_library_lost_a_byte() {
        // No Latin-1 byte decodes to U+FFFD, so its presence can only be the
        // library's lossy UTF-8 decode of RFC 6143 §7.6.4 text.
        assert!(inbound_was_mangled("caf\u{fffd}"));
        assert!(!inbound_was_mangled("cafe"));
        assert!(!inbound_was_mangled(""));
    }

    #[test]
    fn empty_text_is_not_an_error() {
        let transcoded = to_wire_text("");
        assert!(transcoded.text().is_empty());
        assert!(!transcoded.is_lossy());
        assert!(transcoded.into_text().is_empty());
    }
}
