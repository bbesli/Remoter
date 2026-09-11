//! Which RFB encodings to ask for, and which ones this build must not ask for.
//!
//! # The encodings RFB defines
//!
//! RFC 6143 §7.7 defines six: Raw (§7.7.1), CopyRect (§7.7.2), RRE (§7.7.3),
//! Hextile (§7.7.4), TRLE (§7.7.5) and ZRLE (§7.7.6). **Tight is not among
//! them.** It is encoding number 7 in the IANA RFB registry, defined in the
//! community RFB protocol document rather than in the RFC.
//!
//! Pseudo-encodings are entries in the same list that request a *behaviour*
//! rather than describe a rectangle. Two come from RFC 6143 §7.8: Cursor
//! (§7.8.1, number `-239`) and DesktopSize (§7.8.2, number `-223`).
//! LastRect (`-224`) is a registry entry, not an RFC one; it lets a server
//! start an update before it knows how many rectangles it will send.
//!
//! # Offering an encoding this build cannot decode is worse than not offering
//!
//! RFC 6143 §7.5.2 is a promise: the client tells the server which encodings it
//! understands, and the server may then use any of them. A client that lists an
//! encoding it cannot decode has lied, and the consequence is not a missing
//! rectangle — it is a desynchronised stream, because RFB rectangles are
//! self-delimiting only to a decoder that knows the encoding's length rules.
//!
//! `vnc-rs`'s `From<u32> for VncEncoding` folds **every** number it does not
//! recognise onto `Raw`, so a rectangle in an unpromised encoding is read as
//! `width * height * 4` bytes of raw pixels and takes the rest of the stream
//! with it. [`crate::gate`] now refuses such a rectangle before the library can
//! see it, which turns a desynchronised session into a named failure — but the
//! list below is still the first line, because a conforming server should never
//! be put in that position at all.
//!
//! # The compressed encodings were withdrawn, and that is the point
//!
//! ADR-0013. This build negotiates **Raw, CopyRect and the three
//! pseudo-encodings, and nothing else**. Tight, ZRLE and TRLE are gone, and the
//! reason is not that `vnc-rs` cannot decode them — it can — but that nothing
//! outside `vnc-rs` can bound what its decoders will allocate while doing so:
//!
//! - **Tight** has no RFC. Its rectangles are delimited by a compression
//!   control byte, optional filters, palettes and a 7-bit continuation length,
//!   so a parser sitting in front of the library cannot tell where one ends
//!   without reimplementing the encoding. [`crate::gate`] therefore cannot
//!   frame a stream that contains one, and a stream it cannot frame is a stream
//!   in which none of its other bounds hold either.
//! - **ZRLE and TRLE** (§7.7.6, §7.7.5) *are* framable — a `U32` length and
//!   then that many bytes — and the gate does bound that length. What it cannot
//!   bound is what is written *inside* the compressed stream: a ZRLE run length
//!   is a sequence of `0xff` bytes, `vnc-rs` accumulates it without a ceiling,
//!   and a few kilobytes of zlib input can therefore ask the decoder to grow a
//!   buffer to terabytes. That allocation fails, and an allocation failure
//!   **aborts** the process — every other tab and the unlocked vault with it.
//!
//! The cost is real and is stated rather than hidden: a desktop over a slow
//! link now sends raw pixels, and CopyRect is the only saving left. ADR-0013
//! records it, and records that the way to get compression back is to replace
//! `vnc-rs` rather than to re-promise an encoding whose decoder the far end can
//! aim at this process.
//!
//! [`WITHDRAWN`] keeps the list as data so that a test can assert none of them
//! reaches the wire.

use vnc::VncEncoding;

/// An RFB encoding number, as it appears in `SetEncodings` (RFC 6143 §7.5.2).
///
/// Signed, because pseudo-encodings are negative. A newtype over `i32` rather
/// than an enum for the same reason [`crate::security::SecurityType`] is one:
/// the registry is open and the wire carries a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RfbEncoding(i32);

impl RfbEncoding {
    /// Raw pixels, RFC 6143 §7.7.1. Every client must implement it.
    pub const RAW: Self = Self(0);
    /// CopyRect, RFC 6143 §7.7.2.
    pub const COPY_RECT: Self = Self(1);
    /// RRE, RFC 6143 §7.7.3. Not offered; see the module documentation.
    pub const RRE: Self = Self(2);
    /// Hextile, RFC 6143 §7.7.4. Not offered; see the module documentation.
    pub const HEXTILE: Self = Self(5);
    /// Tight. Registry number 7, defined outside RFC 6143. Not offered.
    pub const TIGHT: Self = Self(7);
    /// TRLE, RFC 6143 §7.7.5. Not offered.
    pub const TRLE: Self = Self(15);
    /// ZRLE, RFC 6143 §7.7.6. Not offered.
    pub const ZRLE: Self = Self(16);
    /// Cursor pseudo-encoding, RFC 6143 §7.8.1.
    pub const CURSOR: Self = Self(-239);
    /// DesktopSize pseudo-encoding, RFC 6143 §7.8.2.
    pub const DESKTOP_SIZE: Self = Self(-223);
    /// LastRect pseudo-encoding. A registry entry, not an RFC one.
    pub const LAST_RECT: Self = Self(-224);

    /// Wraps a number read from a rectangle header (RFC 6143 §7.6.1).
    ///
    /// Total, like [`crate::security::SecurityType::from_wire`]: the number
    /// survives, and whether this build will accept it is a separate question
    /// asked by [`crate::gate`].
    #[must_use]
    pub const fn from_wire(value: i32) -> Self {
        Self(value)
    }

    /// The number as it appears on the wire.
    #[must_use]
    pub const fn to_wire(self) -> i32 {
        self.0
    }

    /// A stable ASCII name, for logs and for a message-catalogue argument.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self.0 {
            0 => "Raw",
            1 => "CopyRect",
            2 => "RRE",
            5 => "Hextile",
            7 => "Tight",
            15 => "TRLE",
            16 => "ZRLE",
            -239 => "Cursor",
            -223 => "DesktopSize",
            -224 => "LastRect",
            _ => "an unregistered encoding",
        }
    }
}

/// Encodings this build will not promise, and a reader needs to know why.
///
/// RRE and Hextile because `vnc-rs` has no decoder for either — the variants
/// exist in its source as commented-out lines. Tight, ZRLE and TRLE because
/// their decoders allocate on lengths [`crate::gate`] cannot bound; see the
/// module documentation and ADR-0013.
///
/// Kept as data rather than as a comment so that a test can assert they never
/// reach the wire, and so that the day one of them becomes safe to offer the
/// list is the only thing that has to change.
pub const WITHDRAWN: &[RfbEncoding] = &[
    RfbEncoding::RRE,
    RfbEncoding::HEXTILE,
    RfbEncoding::TIGHT,
    RfbEncoding::TRLE,
    RfbEncoding::ZRLE,
];

/// Which rectangle encodings to ask for.
///
/// RFC 6143 §7.5.2: "the order of the encodings is a hint … the server should
/// use the first encoding it supports". With the compressed encodings
/// withdrawn there are two left, and the choice between them is a real one
/// rather than a preference: CopyRect carries no pixels at all, which is what
/// makes a window drag cheap — and is also a *read* from the surface the
/// presenter holds rather than a write into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum EncodingPreference {
    /// Raw and CopyRect. What a session wants.
    #[default]
    Auto,
    /// Raw only. Every rectangle carries its own pixels, so nothing depends on
    /// what the presenter already has — which is what a framebuffer recording
    /// (`remoter-record`) and a server whose CopyRect output is suspect both
    /// want.
    Raw,
}

impl EncodingPreference {
    /// Parses the stored setting value.
    ///
    /// `"tight"`, `"zrle"` and `"trle"` were options before ADR-0013 and are
    /// deliberately **not** accepted now: silently mapping a withdrawn choice
    /// onto `Auto` would leave a user believing a compressed session was
    /// negotiated. An unparsed value falls back to the default and is logged by
    /// the connect path as the unknown setting it is.
    #[must_use]
    pub fn from_setting(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "raw" => Some(Self::Raw),
            _ => None,
        }
    }

    /// The value this is stored as.
    #[must_use]
    pub const fn as_setting(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Raw => "raw",
        }
    }
}

/// Where the pointer is drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CursorMode {
    /// Ask for the Cursor pseudo-encoding (RFC 6143 §7.8.1) and draw the
    /// pointer locally. The pointer then moves at the local display's refresh
    /// rate instead of the network's, which is the difference between a
    /// desktop that feels remote and one that feels broken.
    #[default]
    Local,
    /// Do not ask. The server draws the pointer into the framebuffer, so it
    /// lags by a round trip — but it is always the pointer the *server* thinks
    /// it has, which is what a screen recording or a support session wants.
    Remote,
}

impl CursorMode {
    /// Parses the stored setting value.
    #[must_use]
    pub fn from_setting(value: &str) -> Option<Self> {
        match value {
            "local" => Some(Self::Local),
            "remote" => Some(Self::Remote),
            _ => None,
        }
    }

    /// The value this is stored as.
    #[must_use]
    pub const fn as_setting(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Remote => "remote",
        }
    }
}

/// The encoding list to send, in preference order.
///
/// Three rules hold whatever the preference:
///
/// - **Raw is always last and always present.** RFC 6143 §7.7.1 requires every
///   client to implement it, and a list without it gives a server that speaks
///   nothing else nowhere to go.
/// - **DesktopSize is always asked for.** It costs nothing, and without it a
///   server that changes resolution simply stops matching the surface the
///   presenter holds.
/// - **Everything in this list has a length rule in [`crate::gate`].** That is
///   what lets the gate bound the stream, and a new entry here without a rule
///   there ends sessions rather than desynchronising them — see
///   `rect_header`'s final arm.
#[must_use]
pub fn encoding_list(preference: EncodingPreference, cursor: CursorMode) -> Vec<RfbEncoding> {
    let mut list = match preference {
        // CopyRect is not a compression scheme, it is "these pixels are already
        // on your screen", and it is what makes a window drag cost four bytes.
        EncodingPreference::Auto => vec![RfbEncoding::COPY_RECT],
        EncodingPreference::Raw => Vec::new(),
    };

    if cursor == CursorMode::Local {
        list.push(RfbEncoding::CURSOR);
    }
    list.push(RfbEncoding::DESKTOP_SIZE);
    list.push(RfbEncoding::LAST_RECT);
    list.push(RfbEncoding::RAW);
    list
}

/// The same list, as the library's own type.
///
/// The mapping is total by construction — [`encoding_list`] only produces
/// encodings `vnc-rs` implements — but it is written as a `match` returning
/// `Option` rather than an infallible conversion, so that adding an encoding to
/// the list above without adding a decoder for it drops the entry instead of
/// putting a promise on the wire the decoder cannot keep.
#[must_use]
pub fn library_encodings(list: &[RfbEncoding]) -> Vec<VncEncoding> {
    list.iter().filter_map(|entry| to_library(*entry)).collect()
}

const fn to_library(encoding: RfbEncoding) -> Option<VncEncoding> {
    match encoding.to_wire() {
        0 => Some(VncEncoding::Raw),
        1 => Some(VncEncoding::CopyRect),
        -239 => Some(VncEncoding::CursorPseudo),
        -223 => Some(VncEncoding::DesktopSizePseudo),
        -224 => Some(VncEncoding::LastRectPseudo),
        _ => None,
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

    const PREFERENCES: [EncodingPreference; 2] =
        [EncodingPreference::Auto, EncodingPreference::Raw];

    #[test]
    fn raw_is_always_offered_and_always_last() {
        for preference in PREFERENCES {
            for cursor in [CursorMode::Local, CursorMode::Remote] {
                let list = encoding_list(preference, cursor);
                assert_eq!(
                    list.last(),
                    Some(&RfbEncoding::RAW),
                    "{preference:?}/{cursor:?}"
                );
                assert_eq!(
                    list.iter().filter(|e| **e == RfbEncoding::RAW).count(),
                    1,
                    "offered once, not twice"
                );
            }
        }
    }

    #[test]
    fn no_withdrawn_encoding_ever_reaches_the_wire() {
        // The list `crate::gate` can frame is exactly the list that goes out.
        // A compressed encoding here would be a promise whose decoder the far
        // end can aim at this process's allocator; see ADR-0013.
        for preference in PREFERENCES {
            for cursor in [CursorMode::Local, CursorMode::Remote] {
                let list = encoding_list(preference, cursor);
                for forbidden in WITHDRAWN {
                    assert!(
                        !list.contains(forbidden),
                        "{} must not be offered: {preference:?}",
                        forbidden.name()
                    );
                }
                // And every entry that *is* offered must map to a decoder.
                assert_eq!(
                    library_encodings(&list).len(),
                    list.len(),
                    "every offered encoding has a decoder: {preference:?}"
                );
            }
        }
    }

    #[test]
    fn raw_only_drops_copy_rect_and_nothing_else() {
        let auto = encoding_list(EncodingPreference::Auto, CursorMode::Local);
        let raw = encoding_list(EncodingPreference::Raw, CursorMode::Local);
        assert!(auto.contains(&RfbEncoding::COPY_RECT));
        assert!(!raw.contains(&RfbEncoding::COPY_RECT));
        assert!(raw.contains(&RfbEncoding::CURSOR));
        assert!(raw.contains(&RfbEncoding::DESKTOP_SIZE));
    }

    #[test]
    fn the_cursor_pseudo_encoding_is_asked_for_only_in_local_mode() {
        assert!(
            encoding_list(EncodingPreference::Auto, CursorMode::Local)
                .contains(&RfbEncoding::CURSOR)
        );
        assert!(
            !encoding_list(EncodingPreference::Auto, CursorMode::Remote)
                .contains(&RfbEncoding::CURSOR)
        );
    }

    #[test]
    fn desktop_size_is_always_asked_for() {
        // Without it a server that changes resolution just stops matching the
        // surface the presenter holds, with no event to say why.
        for cursor in [CursorMode::Local, CursorMode::Remote] {
            assert!(
                encoding_list(EncodingPreference::Auto, cursor)
                    .contains(&RfbEncoding::DESKTOP_SIZE)
            );
        }
    }

    #[test]
    fn the_wire_numbers_are_the_ones_the_rfc_and_the_registry_assign() {
        assert_eq!(RfbEncoding::RAW.to_wire(), 0);
        assert_eq!(RfbEncoding::COPY_RECT.to_wire(), 1);
        assert_eq!(RfbEncoding::RRE.to_wire(), 2);
        assert_eq!(RfbEncoding::HEXTILE.to_wire(), 5);
        assert_eq!(RfbEncoding::TIGHT.to_wire(), 7);
        assert_eq!(RfbEncoding::TRLE.to_wire(), 15);
        assert_eq!(RfbEncoding::ZRLE.to_wire(), 16);
        assert_eq!(RfbEncoding::CURSOR.to_wire(), -239);
        assert_eq!(RfbEncoding::DESKTOP_SIZE.to_wire(), -223);
        assert_eq!(RfbEncoding::LAST_RECT.to_wire(), -224);
        // And a number off the wire survives rather than becoming an error.
        assert_eq!(
            RfbEncoding::from_wire(-312).name(),
            "an unregistered encoding"
        );
    }

    #[test]
    fn settings_round_trip_and_a_withdrawn_choice_is_not_quietly_accepted() {
        for preference in PREFERENCES {
            assert_eq!(
                EncodingPreference::from_setting(preference.as_setting()),
                Some(preference)
            );
        }
        // Accepting these would let a stored connection claim a compressed
        // session that is not being negotiated.
        for withdrawn in ["tight", "zrle", "trle", "hextile"] {
            assert_eq!(
                EncodingPreference::from_setting(withdrawn),
                None,
                "{withdrawn}"
            );
        }
        for mode in [CursorMode::Local, CursorMode::Remote] {
            assert_eq!(CursorMode::from_setting(mode.as_setting()), Some(mode));
        }
        assert_eq!(CursorMode::from_setting("none"), None);
    }
}
