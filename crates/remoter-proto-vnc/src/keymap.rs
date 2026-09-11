//! Turning a key press into an RFB `KeyEvent`.
//!
//! # A keysym is not a scancode, and this is where that matters
//!
//! RFC 6143 §7.5.4 carries a **keysym**: the X Window System's name for a
//! *character or function*, already resolved through the user's keyboard
//! layout. MS-RDPBCGR §2.2.8.1.1.3.1.1.1 carries a **scancode**: the physical
//! position of the key, with the layout applied by the server at the far end.
//!
//! The two protocols therefore want opposite things from one keypress, and
//! neither can be derived from the other without knowing the layout — which
//! lives in the browser, not in Rust. [`remoter_proto::InputEvent::Key`] is
//! shaped around that: it carries a scancode *and* an optional keysym, and each
//! adapter takes the one it needs. This module takes the keysym.
//!
//! The consequence is worth stating plainly, because it inverts the intuition
//! that "the same key press should produce the same thing everywhere": on a
//! Turkish keyboard, pressing the key where `i` sits on a US layout must send
//! keysym `0x131` (`ı`, dotless i) to a VNC server and scancode `0x17` to an
//! RDP server, and both are correct.
//!
//! # What the scancode is still for
//!
//! A key that produces no character carries no keysym — a bare modifier, a
//! function key, an arrow, a dead key mid-composition. Those still have to
//! reach the server, and the physical key is the only thing left to name them
//! by. [`function_keysym`] is that table: PS/2 Set 1 make codes to the X11
//! keysyms in `keysymdef.h`, with the `E0` prefix carried as bit 8 (`0x100`),
//! which is the convention `InputEvent::Key` documents.
//!
//! **There is deliberately no fallback for a character key with no keysym.**
//! Guessing one from the scancode means assuming a US layout, and a session
//! that types correctly on a US keyboard and wrongly on a German one is worse
//! than a session that drops the key: the first is a bug the user cannot see
//! the shape of, the second is one they report in a sentence.
//!
//! # RFB has no lock-state synchronisation
//!
//! [`remoter_proto::Modifiers`] carries Caps Lock, Num Lock and Scroll Lock
//! because RDP needs them: MS-RDPBCGR §2.2.8.1.1.3.1.1.5 is a message whose
//! whole purpose is telling the server which locks are latched. RFB has no such
//! message. A lock in RFB is a key like any other — press and release
//! `XK_Caps_Lock` — so the lock bits are ignored here rather than translated
//! into something invented. The frontend sends the physical Caps Lock key, and
//! that is the entire mechanism RFC 6143 provides.

/// X11 keysyms, from `keysymdef.h`. Named rather than written inline because a
/// bare `0xffe1` in a match arm is unreviewable.
mod keysym {
    pub(super) const BACKSPACE: u32 = 0xff08;
    pub(super) const TAB: u32 = 0xff09;
    pub(super) const RETURN: u32 = 0xff0d;
    pub(super) const PAUSE: u32 = 0xff13;
    pub(super) const SCROLL_LOCK: u32 = 0xff14;
    pub(super) const ESCAPE: u32 = 0xff1b;
    pub(super) const HOME: u32 = 0xff50;
    pub(super) const LEFT: u32 = 0xff51;
    pub(super) const UP: u32 = 0xff52;
    pub(super) const RIGHT: u32 = 0xff53;
    pub(super) const DOWN: u32 = 0xff54;
    pub(super) const PAGE_UP: u32 = 0xff55;
    pub(super) const PAGE_DOWN: u32 = 0xff56;
    pub(super) const END: u32 = 0xff57;
    pub(super) const PRINT: u32 = 0xff61;
    pub(super) const INSERT: u32 = 0xff63;
    pub(super) const MENU: u32 = 0xff67;
    pub(super) const NUM_LOCK: u32 = 0xff7f;
    pub(super) const KP_ENTER: u32 = 0xff8d;
    pub(super) const KP_MULTIPLY: u32 = 0xffaa;
    pub(super) const KP_ADD: u32 = 0xffab;
    pub(super) const KP_SUBTRACT: u32 = 0xffad;
    pub(super) const KP_DECIMAL: u32 = 0xffae;
    pub(super) const KP_DIVIDE: u32 = 0xffaf;
    pub(super) const KP_0: u32 = 0xffb0;
    pub(super) const F1: u32 = 0xffbe;
    pub(super) const F11: u32 = 0xffc8;
    pub(super) const F12: u32 = 0xffc9;
    pub(super) const SHIFT_L: u32 = 0xffe1;
    pub(super) const SHIFT_R: u32 = 0xffe2;
    pub(super) const CONTROL_L: u32 = 0xffe3;
    pub(super) const CONTROL_R: u32 = 0xffe4;
    pub(super) const CAPS_LOCK: u32 = 0xffe5;
    pub(super) const ALT_L: u32 = 0xffe9;
    pub(super) const SUPER_L: u32 = 0xffeb;
    pub(super) const SUPER_R: u32 = 0xffec;
    pub(super) const DELETE: u32 = 0xffff;
    /// AltGr. `XK_ISO_Level3_Shift`, and **not** `XK_Alt_R`: on every
    /// non-US-layout keyboard the right-hand Alt selects a third level of the
    /// layout rather than acting as a modifier, and sending `Alt_R` makes
    /// `AltGr` + `q` arrive as `Alt` + `q` — which is a window-manager
    /// shortcut, not an `@`.
    pub(super) const ISO_LEVEL3_SHIFT: u32 = 0xfe03;
}

/// Bit 8 of a scancode: the key was reported with an `E0` prefix.
///
/// The convention [`remoter_proto::InputEvent::Key`] documents, and the same
/// one MS-RDPBCGR §2.2.8.1.1.3.1.1.1 encodes as `KBDFLAGS_EXTENDED` beside an
/// 8-bit code. Right Control is `0x11d`, left Control is `0x1d`.
pub const EXTENDED: u32 = 0x100;

/// The largest keysym in the Unicode range X11 defines.
///
/// The X keysym encoding maps a Unicode code point `U+NNNN` above Latin-1 onto
/// `0x0100_0000 + NNNN`. Unicode ends at `U+10FFFF`, so anything above this is
/// not a keysym any layout can have produced.
const MAX_UNICODE_KEYSYM: u32 = 0x0100_0000 + 0x0010_FFFF;

/// The keysym for a key that produced no character.
///
/// `None` for a key this table does not name — an unlabelled multimedia key, a
/// vendor key, or a scancode from a keyboard nobody here has seen. Dropping it
/// is right: RFB has no way to say "some key", and inventing a keysym would
/// type a character the user did not press.
#[must_use]
pub const fn function_keysym(scancode: u32) -> Option<u32> {
    match scancode {
        // --- unextended, PS/2 Set 1 ---
        0x01 => Some(keysym::ESCAPE),
        0x0e => Some(keysym::BACKSPACE),
        0x0f => Some(keysym::TAB),
        0x1c => Some(keysym::RETURN),
        0x1d => Some(keysym::CONTROL_L),
        0x2a => Some(keysym::SHIFT_L),
        0x36 => Some(keysym::SHIFT_R),
        0x37 => Some(keysym::KP_MULTIPLY),
        0x38 => Some(keysym::ALT_L),
        0x3a => Some(keysym::CAPS_LOCK),
        // F1 through F10 are contiguous in both tables, which is why the
        // arithmetic is safe to write rather than ten arms.
        0x3b..=0x44 => Some(keysym::F1 + (scancode - 0x3b)),
        0x45 => Some(keysym::NUM_LOCK),
        0x46 => Some(keysym::SCROLL_LOCK),
        // The keypad, in the order Set 1 lays it out: 7 8 9 - 4 5 6 + 1 2 3 0 .
        0x47 => Some(keysym::KP_0 + 7),
        0x48 => Some(keysym::KP_0 + 8),
        0x49 => Some(keysym::KP_0 + 9),
        0x4a => Some(keysym::KP_SUBTRACT),
        0x4b => Some(keysym::KP_0 + 4),
        0x4c => Some(keysym::KP_0 + 5),
        0x4d => Some(keysym::KP_0 + 6),
        0x4e => Some(keysym::KP_ADD),
        0x4f => Some(keysym::KP_0 + 1),
        0x50 => Some(keysym::KP_0 + 2),
        0x51 => Some(keysym::KP_0 + 3),
        0x52 => Some(keysym::KP_0),
        0x53 => Some(keysym::KP_DECIMAL),
        // F11 and F12 sit apart from F1..F10 in Set 1, as they were added
        // later; they are contiguous in the keysym table but not here.
        0x57 => Some(keysym::F11),
        0x58 => Some(keysym::F12),

        // --- extended, reported with an E0 prefix ---
        0x11c => Some(keysym::KP_ENTER),
        0x11d => Some(keysym::CONTROL_R),
        0x135 => Some(keysym::KP_DIVIDE),
        0x137 => Some(keysym::PRINT),
        0x138 => Some(keysym::ISO_LEVEL3_SHIFT),
        0x146 => Some(keysym::PAUSE),
        0x147 => Some(keysym::HOME),
        0x148 => Some(keysym::UP),
        0x149 => Some(keysym::PAGE_UP),
        0x14b => Some(keysym::LEFT),
        0x14d => Some(keysym::RIGHT),
        0x14f => Some(keysym::END),
        0x150 => Some(keysym::DOWN),
        0x151 => Some(keysym::PAGE_DOWN),
        0x152 => Some(keysym::INSERT),
        0x153 => Some(keysym::DELETE),
        0x15b => Some(keysym::SUPER_L),
        0x15c => Some(keysym::SUPER_R),
        0x15d => Some(keysym::MENU),
        _ => None,
    }
}

/// Whether a keysym is one RFB can carry.
///
/// RFC 6143 §7.5.4 says the key is "the keysym" and refers to the X Window
/// System's encoding. That encoding has three usable regions: the Latin-1 code
/// points `0x20..=0xff`, which are their own keysyms; the function-key space
/// `0xff00..=0xffff` together with the `0xfe00` block the ISO extensions use;
/// and the Unicode form `0x0100_0000 + code point`.
///
/// Zero is excluded because it names nothing, and a `0` keysym in a `KeyEvent`
/// is how a client tells a server to press a key that does not exist.
#[must_use]
pub const fn is_valid_keysym(keysym: u32) -> bool {
    // Three regions: Latin-1, the ISO and function-key blocks, and the Unicode
    // form. Zero is excluded because it names nothing, and a `0` keysym in a
    // `KeyEvent` tells a server to press a key that does not exist.
    matches!(
        keysym,
        0x20..=0xff | 0xfe00..=0xffff | 0x0100_0020..=MAX_UNICODE_KEYSYM
    )
}

/// The keysym to put in a `KeyEvent` for one key transition.
///
/// `keysym` is what the layout produced, where it produced anything;
/// `scancode` names the physical key. The layout wins whenever it has an
/// answer, because it is the only party that knows what the user's keyboard
/// prints.
///
/// `None` means the key cannot be expressed in RFB and the event should be
/// dropped. That is a real outcome, not a failure: a dead key mid-composition
/// produces no character *and* no function, and the composed character arrives
/// as its own event a keystroke later.
#[must_use]
pub const fn rfb_keysym(scancode: u32, keysym: Option<u32>) -> Option<u32> {
    match keysym {
        // A keysym the frontend could not encode properly is not passed
        // through: `0` is "no key" and an out-of-range value is not a keysym at
        // all, and RFB has no way to reject either — the server would simply
        // act on it.
        Some(from_layout) if is_valid_keysym(from_layout) => Some(from_layout),
        Some(_) => None,
        None => function_keysym(scancode),
    }
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
    fn the_layouts_keysym_wins_over_the_physical_key() {
        // The key where `i` sits on a US keyboard, pressed on a Turkish
        // layout, produces `ı` (U+0131, dotless i). RFB must carry that and
        // not the US letter, and the scancode is identical in both cases.
        let turkish_dotless_i = 0x0100_0131;
        assert_eq!(
            rfb_keysym(0x17, Some(turkish_dotless_i)),
            Some(turkish_dotless_i)
        );
        // The same physical key on a US layout.
        assert_eq!(rfb_keysym(0x17, Some(u32::from(b'i'))), Some(0x69));
    }

    #[test]
    fn a_bare_modifier_has_no_character_and_is_named_by_its_position() {
        assert_eq!(rfb_keysym(0x2a, None), Some(keysym::SHIFT_L));
        assert_eq!(rfb_keysym(0x36, None), Some(keysym::SHIFT_R));
        assert_eq!(rfb_keysym(0x1d, None), Some(keysym::CONTROL_L));
        // The extended bit is what tells the two Controls apart.
        assert_eq!(rfb_keysym(0x1d | EXTENDED, None), Some(keysym::CONTROL_R));
        assert_eq!(rfb_keysym(0x38, None), Some(keysym::ALT_L));
    }

    #[test]
    fn altgr_is_level3_shift_and_not_the_right_alt_key() {
        // Sending `Alt_R` would make AltGr + q arrive as Alt + q, which is a
        // window-manager shortcut rather than an `@`. Every non-US layout
        // depends on this one being right.
        assert_eq!(
            rfb_keysym(0x38 | EXTENDED, None),
            Some(keysym::ISO_LEVEL3_SHIFT)
        );
        assert_ne!(rfb_keysym(0x38 | EXTENDED, None), Some(0xffea));
    }

    #[test]
    fn the_arrows_and_the_keypad_are_told_apart_by_the_extended_bit() {
        // Unextended 0x48 is keypad 8; extended 0x48 is the arrow above the
        // cursor block. A client that ignores the prefix types an `8` every
        // time the user presses Up with Num Lock off.
        assert_eq!(rfb_keysym(0x48, None), Some(keysym::KP_0 + 8));
        assert_eq!(rfb_keysym(0x48 | EXTENDED, None), Some(keysym::UP));
        assert_eq!(rfb_keysym(0x4b, None), Some(keysym::KP_0 + 4));
        assert_eq!(rfb_keysym(0x4b | EXTENDED, None), Some(keysym::LEFT));
        assert_eq!(rfb_keysym(0x1c, None), Some(keysym::RETURN));
        assert_eq!(rfb_keysym(0x1c | EXTENDED, None), Some(keysym::KP_ENTER));
    }

    #[test]
    fn the_function_keys_land_on_the_right_keysyms() {
        assert_eq!(rfb_keysym(0x3b, None), Some(0xffbe)); // F1
        assert_eq!(rfb_keysym(0x44, None), Some(0xffc7)); // F10
        // F11 and F12 sit apart from F1..F10 in Set 1 because they were added
        // later; reading them as 0x45 and 0x46 would send Num Lock and Scroll
        // Lock instead.
        assert_eq!(rfb_keysym(0x57, None), Some(0xffc8));
        assert_eq!(rfb_keysym(0x58, None), Some(0xffc9));
        assert_eq!(rfb_keysym(0x45, None), Some(keysym::NUM_LOCK));
        assert_eq!(rfb_keysym(0x46, None), Some(keysym::SCROLL_LOCK));
    }

    #[test]
    fn the_full_keypad_is_covered_in_set_one_order() {
        // Set 1 lays the keypad out 7 8 9 - / 4 5 6 + / 1 2 3 / 0 . — not in
        // numeric order, which is exactly the mistake this test exists to
        // catch.
        let expected = [
            (0x47, 7),
            (0x48, 8),
            (0x49, 9),
            (0x4b, 4),
            (0x4c, 5),
            (0x4d, 6),
            (0x4f, 1),
            (0x50, 2),
            (0x51, 3),
            (0x52, 0),
        ];
        for (scancode, digit) in expected {
            assert_eq!(
                rfb_keysym(scancode, None),
                Some(keysym::KP_0 + digit),
                "scancode {scancode:#x}"
            );
        }
        assert_eq!(rfb_keysym(0x4a, None), Some(keysym::KP_SUBTRACT));
        assert_eq!(rfb_keysym(0x4e, None), Some(keysym::KP_ADD));
        assert_eq!(rfb_keysym(0x37, None), Some(keysym::KP_MULTIPLY));
        assert_eq!(rfb_keysym(0x35 | EXTENDED, None), Some(keysym::KP_DIVIDE));
        assert_eq!(rfb_keysym(0x53, None), Some(keysym::KP_DECIMAL));
    }

    #[test]
    fn a_character_key_with_no_keysym_is_dropped_rather_than_guessed() {
        // Guessing means assuming a US layout, and a session that types
        // correctly on one keyboard and wrongly on another is a bug the user
        // cannot describe.
        assert_eq!(rfb_keysym(0x10, None), None, "the Q position");
        assert_eq!(rfb_keysym(0x1e, None), None, "the A position");
        assert_eq!(rfb_keysym(0x02, None), None, "the 1 position");
    }

    #[test]
    fn a_keysym_that_is_not_a_keysym_is_not_forwarded() {
        // RFB gives the server no way to reject one, so the client is the only
        // place it can be stopped. Zero is "no key" and would be acted on.
        assert_eq!(rfb_keysym(0x10, Some(0)), None);
        assert_eq!(rfb_keysym(0x10, Some(0x1f)), None, "a C0 control code");
        assert_eq!(rfb_keysym(0x10, Some(0x0100)), None, "the dead zone");
        assert_eq!(rfb_keysym(0x10, Some(0xfdff)), None, "below the ISO block");
        assert_eq!(
            rfb_keysym(0x10, Some(0x0100_0000 + 0x0011_0000)),
            None,
            "past the end of Unicode"
        );
    }

    #[test]
    fn the_three_keysym_regions_are_all_accepted() {
        assert!(is_valid_keysym(0x20), "space, the first Latin-1 keysym");
        assert!(is_valid_keysym(0xe9), "e-acute, its own Latin-1 code point");
        assert!(is_valid_keysym(0xfe03), "ISO_Level3_Shift");
        assert!(is_valid_keysym(0xffff), "Delete, the last function keysym");
        assert!(is_valid_keysym(0x0100_20ac), "the euro sign, U+20AC");
        assert!(!is_valid_keysym(0));
        assert!(!is_valid_keysym(0x0100_0000), "no code point");
    }

    #[test]
    fn an_unknown_physical_key_is_dropped_and_not_mapped_to_something_nearby() {
        assert_eq!(function_keysym(0x7f), None);
        assert_eq!(function_keysym(0x1ff), None);
        assert_eq!(function_keysym(u32::MAX), None);
    }
}
