//! Which RFB encodings to ask for, and which ones this build must not ask for.
//!
//! # The encodings RFB defines
//!
//! RFC 6143 §7.7 defines six: Raw (§7.7.1), CopyRect (§7.7.2), RRE (§7.7.3),
//! Hextile (§7.7.4), TRLE (§7.7.5) and ZRLE (§7.7.6). **Tight is not among
//! them.** It is encoding number 7 in the IANA RFB registry, defined in the
//! community RFB protocol document rather than in the RFC, and it is the one
//! every modern server prefers — so it is offered, and it is cited as what it
//! is rather than pretending to an RFC section it does not have.
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
//! `vnc-rs` 0.5.3 implements Raw, CopyRect, Tight, TRLE and ZRLE. **RRE and
//! Hextile are absent**: the variants exist in the library's source as
//! commented-out lines. So they are not offered here, and
//! [`UNIMPLEMENTED`] records that fact where a reader will find it rather than
//! leaving the omission to look like an oversight.
//!
//! There is a second, sharper reason. `vnc-rs`'s `From<u32> for VncEncoding`
//! folds **every** number it does not recognise onto `Raw`. A server that sent
//! an RRE rectangle would have its rectangle read as raw pixels, and the read
//! loop would consume `width * height * 4` bytes of a much shorter rectangle —
//! taking the rest of the stream with it. Not offering RRE is what keeps a
//! conforming server from ever putting the library in that position.
//!
//! Both encodings are legacy: RRE is a 1998 rectangle-of-subrectangles scheme
//! and Hextile is its tiled successor, and both were superseded by ZRLE, which
//! RFC 6143 §7.7.6 describes and every server that speaks Hextile also speaks.
//! Nothing is lost that Raw does not cover.

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
    /// Tight. Registry number 7, defined outside RFC 6143.
    pub const TIGHT: Self = Self(7);
    /// TRLE, RFC 6143 §7.7.5.
    pub const TRLE: Self = Self(15);
    /// ZRLE, RFC 6143 §7.7.6.
    pub const ZRLE: Self = Self(16);
    /// Cursor pseudo-encoding, RFC 6143 §7.8.1.
    pub const CURSOR: Self = Self(-239);
    /// DesktopSize pseudo-encoding, RFC 6143 §7.8.2.
    pub const DESKTOP_SIZE: Self = Self(-223);
    /// LastRect pseudo-encoding. A registry entry, not an RFC one.
    pub const LAST_RECT: Self = Self(-224);

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

/// The encodings RFC 6143 §7.7 defines that this build cannot decode.
///
/// Kept as data rather than as a comment so that a test can assert they are
/// never offered, and so that the day `vnc-rs` grows a decoder for one the list
/// is the only thing that has to change.
pub const UNIMPLEMENTED: &[RfbEncoding] = &[RfbEncoding::RRE, RfbEncoding::HEXTILE];

/// Which encoding to put at the head of the list.
///
/// RFC 6143 §7.5.2: "the order of the encodings is a hint … the server should
/// use the first encoding it supports". So this is a preference and not a
/// demand, and a server that only speaks Raw still works.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum EncodingPreference {
    /// Tight first, then ZRLE. What a desktop over any real network wants:
    /// Tight is the best of these on photographic content and ZRLE the best on
    /// flat interface chrome.
    #[default]
    Auto,
    /// Tight first. Lossy on photographic regions, and the smallest.
    Tight,
    /// ZRLE first. Lossless, and cheaper to decode than Tight.
    Zrle,
    /// TRLE first. ZRLE without the zlib stream — for a link fast enough that
    /// compression costs more than it saves.
    Trle,
    /// Raw only. For a loopback connection, where copying pixels beats
    /// compressing them, and for diagnosing a server whose compressed output
    /// is suspect.
    Raw,
}

impl EncodingPreference {
    /// Parses the stored setting value.
    #[must_use]
    pub fn from_setting(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "tight" => Some(Self::Tight),
            "zrle" => Some(Self::Zrle),
            "trle" => Some(Self::Trle),
            "raw" => Some(Self::Raw),
            _ => None,
        }
    }

    /// The value this is stored as.
    #[must_use]
    pub const fn as_setting(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Tight => "tight",
            Self::Zrle => "zrle",
            Self::Trle => "trle",
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
/// Two rules hold whatever the preference:
///
/// - **Raw is always last and always present.** RFC 6143 §7.7.1 requires every
///   client to implement it, and a list without it gives a server that speaks
///   nothing else nowhere to go.
/// - **DesktopSize is always asked for.** It costs nothing, and without it a
///   server that changes resolution simply stops matching the surface the
///   presenter holds.
#[must_use]
pub fn encoding_list(preference: EncodingPreference, cursor: CursorMode) -> Vec<RfbEncoding> {
    let mut list = match preference {
        EncodingPreference::Auto => vec![
            RfbEncoding::TIGHT,
            RfbEncoding::ZRLE,
            RfbEncoding::TRLE,
            RfbEncoding::COPY_RECT,
        ],
        EncodingPreference::Tight => vec![
            RfbEncoding::TIGHT,
            RfbEncoding::ZRLE,
            RfbEncoding::TRLE,
            RfbEncoding::COPY_RECT,
        ],
        EncodingPreference::Zrle => vec![
            RfbEncoding::ZRLE,
            RfbEncoding::TRLE,
            RfbEncoding::TIGHT,
            RfbEncoding::COPY_RECT,
        ],
        EncodingPreference::Trle => vec![
            RfbEncoding::TRLE,
            RfbEncoding::ZRLE,
            RfbEncoding::TIGHT,
            RfbEncoding::COPY_RECT,
        ],
        // CopyRect survives even here: it is not a compression scheme, it is
        // "these pixels are already on your screen", and it is what makes a
        // window drag over loopback cost four bytes.
        EncodingPreference::Raw => vec![RfbEncoding::COPY_RECT],
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
        7 => Some(VncEncoding::Tight),
        15 => Some(VncEncoding::Trle),
        16 => Some(VncEncoding::Zrle),
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

    #[test]
    fn raw_is_always_offered_and_always_last() {
        for preference in [
            EncodingPreference::Auto,
            EncodingPreference::Tight,
            EncodingPreference::Zrle,
            EncodingPreference::Trle,
            EncodingPreference::Raw,
        ] {
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
    fn an_encoding_this_build_cannot_decode_is_never_offered() {
        // Offering one would not lose a rectangle, it would desynchronise the
        // stream: `vnc-rs` folds an unrecognised encoding number onto Raw and
        // then reads width * height * 4 bytes of a much shorter rectangle.
        for preference in [
            EncodingPreference::Auto,
            EncodingPreference::Tight,
            EncodingPreference::Zrle,
            EncodingPreference::Trle,
            EncodingPreference::Raw,
        ] {
            let list = encoding_list(preference, CursorMode::Local);
            for forbidden in UNIMPLEMENTED {
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

    #[test]
    fn the_preference_decides_the_head_of_the_list() {
        assert_eq!(
            encoding_list(EncodingPreference::Zrle, CursorMode::Local)[0],
            RfbEncoding::ZRLE
        );
        assert_eq!(
            encoding_list(EncodingPreference::Trle, CursorMode::Local)[0],
            RfbEncoding::TRLE
        );
        assert_eq!(
            encoding_list(EncodingPreference::Tight, CursorMode::Local)[0],
            RfbEncoding::TIGHT
        );
        // "Raw only" still keeps CopyRect: it is not compression, it is "you
        // already have these pixels".
        let raw_only = encoding_list(EncodingPreference::Raw, CursorMode::Remote);
        assert_eq!(raw_only[0], RfbEncoding::COPY_RECT);
        assert!(!raw_only.contains(&RfbEncoding::TIGHT));
        assert!(!raw_only.contains(&RfbEncoding::ZRLE));
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
    }

    #[test]
    fn settings_round_trip_through_their_stored_form() {
        for preference in [
            EncodingPreference::Auto,
            EncodingPreference::Tight,
            EncodingPreference::Zrle,
            EncodingPreference::Trle,
            EncodingPreference::Raw,
        ] {
            assert_eq!(
                EncodingPreference::from_setting(preference.as_setting()),
                Some(preference)
            );
        }
        assert_eq!(EncodingPreference::from_setting("hextile"), None);
        for mode in [CursorMode::Local, CursorMode::Remote] {
            assert_eq!(CursorMode::from_setting(mode.as_setting()), Some(mode));
        }
        assert_eq!(CursorMode::from_setting("none"), None);
    }
}
