//! Which keyboard layout this client asks the server to apply.
//!
//! # Why this file exists
//!
//! RDP sends **scancodes**: the Client Keyboard Event carries a PS/2 Set 1
//! make code (MS-RDPBCGR §2.2.8.1.1.3.1.1.1), which is a physical key position
//! and not a character. The *server* turns that position into a character,
//! using the layout the client named once in the Client Core Data
//! (MS-RDPBCGR §2.2.1.3.2, `keyboardLayout`).
//!
//! So the layout identifier is not a preference and not a cosmetic detail: it
//! is the only thing that decides which character appears. A Turkish user
//! presses the key that prints `ı` on their keyboard, and a session that said
//! `0x00000409` gets `i` — every time, with nothing anywhere reporting a
//! fault, because no fault occurred. The scancode arrived correctly and was
//! decoded by the layout the client asked for.
//!
//! Hard-coding US English therefore breaks every non-US keyboard in the world
//! and looks like a working connection while it does it. The default has to
//! come from the machine the user is sitting at.
//!
//! # What an identifier is
//!
//! A **KLID**: the 32-bit keyboard layout identifier Microsoft publishes in
//! "Keyboard identifiers and input method editors for Windows". The low word
//! is the language identifier and the high word distinguishes the layouts that
//! share one language — which is exactly the distinction that matters here,
//! because Turkish Q (`0x0000041F`) and Turkish F (`0x0001041F`) are one
//! language and two entirely different key positions.
//!
//! Every identifier in [`KEYBOARD_LAYOUTS`] was copied from that table rather
//! than recalled.
//!
//! # Detection, and what it is not
//!
//! Detection produces a **default**. An explicit choice on the connection, or
//! one inherited from a folder, always wins: the settings map is consulted
//! first and this is only consulted when the map is silent
//! (`SettingsSchema::string` falls back to the schema's default, and the
//! schema's default is what this module supplies).
//!
//! Where the layout cannot be determined the fallback is US English **and the
//! session says so** — see `WARNING_KEYBOARD_LAYOUT_GUESSED` in
//! [`crate::protocol`]. A wrong guess that announces itself costs a user one
//! glance; a silent one costs them an afternoon.

use std::sync::OnceLock;

use remoter_proto::SettingOption;

/// US English, `0x00000409`.
///
/// **Not the default.** It is what a connection gets when this build could not
/// work out what the machine is using, and reaching for it is reported rather
/// than assumed. The default is [`default_layout`].
pub const FALLBACK_KEYBOARD_LAYOUT: u32 = 0x0000_0409;

/// One layout offered by name.
pub struct KeyboardLayout {
    /// The Microsoft keyboard identifier.
    pub id: u32,
    /// The message catalogue key for its name, in `locales/*/connections.json`.
    /// Not English: these are read by a user choosing their own keyboard.
    pub label: &'static str,
}

impl KeyboardLayout {
    const fn new(id: u32, label: &'static str) -> Self {
        Self { id, label }
    }
}

/// The layouts worth putting in a list.
///
/// A selection, not the whole table: Microsoft publishes several hundred
/// identifiers and a list nobody can scroll is not a list. Anything absent
/// from here is still reachable — `keyboard_layout` is an integer field, so a
/// user with an identifier of their own types it in
/// (`SettingField::options_are_closed` is false for it).
///
/// Ordered as Microsoft's own table orders it, by English name. A form is free
/// to sort by the translated name instead; that is a rendering decision and
/// this is the data.
pub static KEYBOARD_LAYOUTS: &[KeyboardLayout] = &[
    KeyboardLayout::new(0x0000_041C, "settings.keyboardLayout.albanian"),
    KeyboardLayout::new(0x0000_0401, "settings.keyboardLayout.arabic101"),
    KeyboardLayout::new(0x0000_042C, "settings.keyboardLayout.azerbaijaniLatin"),
    KeyboardLayout::new(0x0000_0423, "settings.keyboardLayout.belarusian"),
    KeyboardLayout::new(0x0000_080C, "settings.keyboardLayout.belgianFrench"),
    // Microsoft's "Bulgarian" (`kbdbulg`). Its "Bulgarian (Typewriter)" is
    // `0x00000402`, and the two are different key positions.
    KeyboardLayout::new(0x0003_0402, "settings.keyboardLayout.bulgarian"),
    KeyboardLayout::new(0x0000_1009, "settings.keyboardLayout.canadianFrench"),
    KeyboardLayout::new(0x0001_1009, "settings.keyboardLayout.canadianMultilingual"),
    KeyboardLayout::new(0x0000_0804, "settings.keyboardLayout.chineseSimplified"),
    KeyboardLayout::new(0x0000_0404, "settings.keyboardLayout.chineseTraditional"),
    // Microsoft lists this one as plain "Standard" (`kbdcr`), which is a name
    // only its own row explains; it is the Croatian standard layout.
    KeyboardLayout::new(0x0000_041A, "settings.keyboardLayout.croatian"),
    KeyboardLayout::new(0x0000_0405, "settings.keyboardLayout.czech"),
    KeyboardLayout::new(0x0001_0405, "settings.keyboardLayout.czechQwerty"),
    KeyboardLayout::new(0x0000_0406, "settings.keyboardLayout.danish"),
    KeyboardLayout::new(0x0000_0439, "settings.keyboardLayout.devanagariInscript"),
    KeyboardLayout::new(0x0000_0413, "settings.keyboardLayout.dutch"),
    KeyboardLayout::new(0x0000_4009, "settings.keyboardLayout.englishIndia"),
    KeyboardLayout::new(0x0000_0425, "settings.keyboardLayout.estonian"),
    KeyboardLayout::new(0x0000_040B, "settings.keyboardLayout.finnish"),
    KeyboardLayout::new(0x0000_040C, "settings.keyboardLayout.french"),
    KeyboardLayout::new(0x0001_0437, "settings.keyboardLayout.georgianQwerty"),
    KeyboardLayout::new(0x0000_0407, "settings.keyboardLayout.german"),
    KeyboardLayout::new(0x0000_0408, "settings.keyboardLayout.greek"),
    KeyboardLayout::new(0x0000_040D, "settings.keyboardLayout.hebrew"),
    KeyboardLayout::new(0x0001_0439, "settings.keyboardLayout.hindiTraditional"),
    KeyboardLayout::new(0x0000_040E, "settings.keyboardLayout.hungarian"),
    KeyboardLayout::new(0x0001_040E, "settings.keyboardLayout.hungarian101"),
    KeyboardLayout::new(0x0000_040F, "settings.keyboardLayout.icelandic"),
    KeyboardLayout::new(0x0000_1809, "settings.keyboardLayout.irish"),
    KeyboardLayout::new(0x0000_0410, "settings.keyboardLayout.italian"),
    KeyboardLayout::new(0x0000_0411, "settings.keyboardLayout.japanese"),
    KeyboardLayout::new(0x0000_043F, "settings.keyboardLayout.kazakh"),
    KeyboardLayout::new(0x0000_0412, "settings.keyboardLayout.korean"),
    KeyboardLayout::new(0x0000_080A, "settings.keyboardLayout.latinAmerican"),
    KeyboardLayout::new(0x0000_0426, "settings.keyboardLayout.latvian"),
    // Microsoft's "Lithuanian" (`kbdlt1`). `0x00000427` is "Lithuanian IBM".
    KeyboardLayout::new(0x0001_0427, "settings.keyboardLayout.lithuanian"),
    KeyboardLayout::new(0x0001_042F, "settings.keyboardLayout.macedonianStandard"),
    KeyboardLayout::new(0x0000_0414, "settings.keyboardLayout.norwegian"),
    KeyboardLayout::new(0x0000_0429, "settings.keyboardLayout.persian"),
    KeyboardLayout::new(0x0001_0415, "settings.keyboardLayout.polish214"),
    KeyboardLayout::new(0x0000_0415, "settings.keyboardLayout.polishProgrammers"),
    KeyboardLayout::new(0x0000_0816, "settings.keyboardLayout.portuguese"),
    KeyboardLayout::new(0x0000_0416, "settings.keyboardLayout.portugueseBrazil"),
    KeyboardLayout::new(0x0001_0418, "settings.keyboardLayout.romanianStandard"),
    KeyboardLayout::new(0x0000_0419, "settings.keyboardLayout.russian"),
    KeyboardLayout::new(0x0000_081A, "settings.keyboardLayout.serbianLatin"),
    KeyboardLayout::new(0x0000_041B, "settings.keyboardLayout.slovak"),
    KeyboardLayout::new(0x0000_0424, "settings.keyboardLayout.slovenian"),
    KeyboardLayout::new(0x0000_040A, "settings.keyboardLayout.spanish"),
    KeyboardLayout::new(0x0000_041D, "settings.keyboardLayout.swedish"),
    KeyboardLayout::new(0x0000_100C, "settings.keyboardLayout.swissFrench"),
    KeyboardLayout::new(0x0000_0807, "settings.keyboardLayout.swissGerman"),
    KeyboardLayout::new(0x0000_041E, "settings.keyboardLayout.thaiKedmanee"),
    // The two the owner of this repository actually types on, and the reason
    // the whole module exists: one language, two layouts, and the identifier
    // is the only thing that tells the server which.
    KeyboardLayout::new(0x0001_041F, "settings.keyboardLayout.turkishF"),
    KeyboardLayout::new(0x0000_041F, "settings.keyboardLayout.turkishQ"),
    KeyboardLayout::new(0x0000_0422, "settings.keyboardLayout.ukrainian"),
    KeyboardLayout::new(0x0000_0809, "settings.keyboardLayout.unitedKingdom"),
    KeyboardLayout::new(FALLBACK_KEYBOARD_LAYOUT, "settings.keyboardLayout.us"),
    KeyboardLayout::new(0x0001_0409, "settings.keyboardLayout.usDvorak"),
    KeyboardLayout::new(0x0002_0409, "settings.keyboardLayout.usInternational"),
    KeyboardLayout::new(0x0000_042A, "settings.keyboardLayout.vietnamese"),
];

/// The offered layouts, as a settings schema's option list.
#[must_use]
pub fn keyboard_layout_options() -> Vec<SettingOption> {
    KEYBOARD_LAYOUTS
        .iter()
        // Decimal, because that is how the value is stored: the field is an
        // integer and `SettingsSchema::integer` parses it with `str::parse`.
        .map(|layout| SettingOption::message(layout.id.to_string(), layout.label))
        .collect()
}

/// Where the default layout came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutSource {
    /// Read off this machine.
    Detected,
    /// This build could not tell, and [`FALLBACK_KEYBOARD_LAYOUT`] is standing
    /// in. The session says so rather than typing the wrong characters
    /// quietly.
    Guessed,
}

/// A layout identifier and the standing of the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefaultLayout {
    /// The identifier.
    pub id: u32,
    /// Whether it was found or assumed.
    pub source: LayoutSource,
}

/// Cached, because the schema is built per adapter and the answer cannot
/// usefully change mid-process: a form that offered one default and a
/// connection that used another would be worse than either.
static DETECTED: OnceLock<DefaultLayout> = OnceLock::new();

/// The layout a connection gets when nothing on the inheritance path chose one.
#[must_use]
pub fn default_layout() -> DefaultLayout {
    *DETECTED.get_or_init(|| match machine_layout() {
        Some(id) => DefaultLayout {
            id,
            source: LayoutSource::Detected,
        },
        None => DefaultLayout {
            id: FALLBACK_KEYBOARD_LAYOUT,
            source: LayoutSource::Guessed,
        },
    })
}

/// What this machine says its keyboard is, if it says anything.
///
/// Windows answers with an identifier of exactly the kind the protocol wants.
/// Everything else answers with a layout name, which has to be mapped — see
/// [`layout_for_xkb`] and [`layout_for_locale`].
#[cfg(windows)]
fn machine_layout() -> Option<u32> {
    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;

    // `HKCU\Keyboard Layout\Preload` holds the user's input layouts in order,
    // keyed "1", "2", … Value "1" is the one Windows activates at sign-in, and
    // it is a KLID written as eight hexadecimal digits: "0000041F" is Turkish
    // Q, "0001041F" is Turkish F.
    //
    // The active layout — the one Alt+Shift switched to a minute ago — needs
    // `GetKeyboardLayout`, which is FFI, and this workspace forbids `unsafe`.
    // Preload's first entry is the configured layout rather than the momentary
    // one, and it is the right thing to default a *stored connection* to
    // anyway: the setting outlives whichever layout happened to be active when
    // the dialog was opened.
    let user = RegKey::predef(HKEY_CURRENT_USER);
    let preload = user.open_subkey("Keyboard Layout\\Preload").ok()?;
    let first: String = preload.get_value("1").ok()?;

    // `Substitutes` remaps a preloaded identifier to the one actually loaded —
    // it is how Windows represents "US keyboard, Dvorak arrangement"
    // (00000409 -> 00010409). Missing for almost everybody, and decisive for
    // the people it is not missing for.
    let klid = user
        .open_subkey("Keyboard Layout\\Substitutes")
        .ok()
        .and_then(|substitutes| substitutes.get_value::<String, _>(&first).ok())
        .unwrap_or(first);

    parse_klid(&klid)
}

/// What this machine says its keyboard is, if it says anything.
///
/// There is no equivalent of the Windows registry entry here, and no single
/// source that is right on every desktop. Two are consulted, in the order of
/// how specific they are:
///
/// 1. `XKB_DEFAULT_LAYOUT` (with `XKB_DEFAULT_VARIANT`) — the actual keyboard
///    layout, set by Wayland compositors and by `libxkbcommon` users. This is
///    the only one that can tell Turkish Q from Turkish F.
/// 2. The locale environment. A layout is not a locale — `tr_TR.UTF-8` with a
///    US keyboard plugged in is a real configuration — but it is what is
///    available, and being approximately right beats being confidently wrong
///    in US English.
///
/// macOS keeps its input sources in a preferences plist that is not readable
/// without FFI, so it reaches this by way of the locale or not at all. A user
/// whose macOS gives no locale gets the fallback and is told about it, which
/// is the whole reason [`LayoutSource::Guessed`] exists.
#[cfg(not(windows))]
fn machine_layout() -> Option<u32> {
    if let Ok(layout) = std::env::var("XKB_DEFAULT_LAYOUT") {
        let variant = std::env::var("XKB_DEFAULT_VARIANT").ok();
        if let Some(id) = layout_for_xkb(&layout, variant.as_deref()) {
            return Some(id);
        }
    }
    // POSIX order: LC_ALL overrides LC_CTYPE, which overrides LANG.
    for name in ["LC_ALL", "LC_CTYPE", "LANG"] {
        if let Ok(value) = std::env::var(name) {
            if let Some(id) = layout_for_locale(&value) {
                return Some(id);
            }
        }
    }
    None
}

/// A KLID as Windows writes it — eight hexadecimal digits, no prefix.
///
/// Rejects anything else rather than salvaging it: a half-parsed identifier is
/// a layout, just not the user's, and this is the one place that can still
/// tell the difference between "not found" and "found something odd".
#[must_use]
pub fn parse_klid(value: &str) -> Option<u32> {
    let trimmed = value.trim();
    if trimmed.len() != 8 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(trimmed, 16).ok()
}

/// An X keyboard layout name, and its variant where one narrows the answer.
///
/// The variant is consulted first, because that is where the distinctions that
/// matter live: `tr` alone is Turkish Q, and `tr` with variant `f` is a
/// different set of key positions and a different identifier.
#[must_use]
pub fn layout_for_xkb(layout: &str, variant: Option<&str>) -> Option<u32> {
    // A comma-separated list is several configured layouts; the first is the
    // one the session starts in.
    let first = layout.split(',').next().unwrap_or(layout).trim();
    let variant = variant
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|v| !v.is_empty());

    if let Some(variant) = variant {
        for (name, variant_name, id) in XKB_VARIANTS {
            if *name == first && *variant_name == variant {
                return Some(*id);
            }
        }
    }
    XKB_LAYOUTS
        .iter()
        .find(|(name, _)| *name == first)
        .map(|(_, id)| *id)
}

/// A POSIX locale — `tr_TR.UTF-8`, `pt_BR`, `en_GB.UTF-8@euro`, `C`.
///
/// The region is tried before the language, because for several languages the
/// region *is* the layout: `pt_BR` and `pt_PT` are two different keyboards,
/// and so are `de_DE` and `de_CH`.
#[must_use]
pub fn layout_for_locale(locale: &str) -> Option<u32> {
    // Strip the codeset and the modifier: `tr_TR.UTF-8@euro` -> `tr_TR`.
    let base = locale
        .split(['.', '@'])
        .next()
        .unwrap_or(locale)
        .trim()
        .replace('-', "_");
    if base.is_empty() || base.eq_ignore_ascii_case("c") || base.eq_ignore_ascii_case("posix") {
        // Not a language. A build machine, a cron job, or a desktop session
        // that lost its environment — all of which are "cannot tell", not
        // "American".
        return None;
    }

    let mut parts = base.split('_');
    let language = parts.next().unwrap_or_default().to_ascii_lowercase();
    let region = parts.next().unwrap_or_default().to_ascii_uppercase();

    if !region.is_empty() {
        for (lang, reg, id) in REGION_LAYOUTS {
            if *lang == language && *reg == region {
                return Some(*id);
            }
        }
    }
    LANGUAGE_LAYOUTS
        .iter()
        .find(|(lang, _)| *lang == language)
        .map(|(_, id)| *id)
}

/// X keyboard layout name to Microsoft keyboard identifier.
///
/// Only the layouts that also appear in [`KEYBOARD_LAYOUTS`]: an identifier
/// detection can produce but the list cannot name would show up in the form as
/// a number with no label.
static XKB_LAYOUTS: &[(&str, u32)] = &[
    ("al", 0x0000_041C),
    ("ara", 0x0000_0401),
    ("az", 0x0000_042C),
    ("be", 0x0000_080C),
    ("bg", 0x0003_0402),
    ("br", 0x0000_0416),
    ("by", 0x0000_0423),
    ("ca", 0x0000_1009),
    ("ch", 0x0000_0807),
    ("cn", 0x0000_0804),
    ("cz", 0x0000_0405),
    ("de", 0x0000_0407),
    ("dk", 0x0000_0406),
    ("ee", 0x0000_0425),
    ("es", 0x0000_040A),
    ("fi", 0x0000_040B),
    ("fr", 0x0000_040C),
    ("gb", 0x0000_0809),
    ("ge", 0x0001_0437),
    ("gr", 0x0000_0408),
    ("hr", 0x0000_041A),
    ("hu", 0x0000_040E),
    ("ie", 0x0000_1809),
    ("il", 0x0000_040D),
    ("in", 0x0000_0439),
    ("ir", 0x0000_0429),
    ("is", 0x0000_040F),
    ("it", 0x0000_0410),
    ("jp", 0x0000_0411),
    ("kr", 0x0000_0412),
    ("kz", 0x0000_043F),
    ("latam", 0x0000_080A),
    ("lt", 0x0001_0427),
    ("lv", 0x0000_0426),
    ("mk", 0x0001_042F),
    ("nl", 0x0000_0413),
    ("no", 0x0000_0414),
    ("pl", 0x0000_0415),
    ("pt", 0x0000_0816),
    ("ro", 0x0001_0418),
    ("rs", 0x0000_081A),
    ("ru", 0x0000_0419),
    ("se", 0x0000_041D),
    ("si", 0x0000_0424),
    ("sk", 0x0000_041B),
    ("th", 0x0000_041E),
    ("tr", 0x0000_041F),
    ("tw", 0x0000_0404),
    ("ua", 0x0000_0422),
    ("us", FALLBACK_KEYBOARD_LAYOUT),
    ("vn", 0x0000_042A),
];

/// Variants that change the identifier rather than decorating it.
///
/// Deliberately short. A variant this table does not know falls through to the
/// layout's own entry, which is the right answer for the great majority of
/// them — `de` with variant `nodeadkeys` is still the German keyboard.
static XKB_VARIANTS: &[(&str, &str, u32)] = &[
    // The distinction this whole module was written for.
    ("tr", "f", 0x0001_041F),
    ("us", "dvorak", 0x0001_0409),
    ("us", "intl", 0x0002_0409),
    ("us", "alt-intl", 0x0002_0409),
    ("ca", "multix", 0x0001_1009),
    ("cz", "qwerty", 0x0001_0405),
    ("hu", "101_qwerty_comma_dead", 0x0001_040E),
    ("pl", "qwertz", 0x0001_0415),
];

/// Language and region to identifier, for the pairs where the region decides.
static REGION_LAYOUTS: &[(&str, &str, u32)] = &[
    ("de", "CH", 0x0000_0807),
    ("de", "LI", 0x0000_0807),
    ("en", "CA", 0x0000_1009),
    ("en", "GB", 0x0000_0809),
    ("en", "IE", 0x0000_1809),
    ("en", "IN", 0x0000_4009),
    ("fr", "BE", 0x0000_080C),
    ("fr", "CA", 0x0000_1009),
    ("fr", "CH", 0x0000_100C),
    ("it", "CH", 0x0000_0807),
    ("nl", "BE", 0x0000_080C),
    ("pt", "BR", 0x0000_0416),
    // Spanish outside Spain is the Latin American keyboard, which is a
    // different arrangement rather than a different spelling.
    ("es", "AR", 0x0000_080A),
    ("es", "BO", 0x0000_080A),
    ("es", "CL", 0x0000_080A),
    ("es", "CO", 0x0000_080A),
    ("es", "CR", 0x0000_080A),
    ("es", "DO", 0x0000_080A),
    ("es", "EC", 0x0000_080A),
    ("es", "GT", 0x0000_080A),
    ("es", "HN", 0x0000_080A),
    ("es", "MX", 0x0000_080A),
    ("es", "NI", 0x0000_080A),
    ("es", "PA", 0x0000_080A),
    ("es", "PE", 0x0000_080A),
    ("es", "PR", 0x0000_080A),
    ("es", "PY", 0x0000_080A),
    ("es", "SV", 0x0000_080A),
    ("es", "US", 0x0000_080A),
    ("es", "UY", 0x0000_080A),
    ("es", "VE", 0x0000_080A),
];

/// Language to identifier, for when the region says nothing new.
static LANGUAGE_LAYOUTS: &[(&str, u32)] = &[
    ("ar", 0x0000_0401),
    ("az", 0x0000_042C),
    ("be", 0x0000_0423),
    ("bg", 0x0003_0402),
    ("cs", 0x0000_0405),
    ("da", 0x0000_0406),
    ("de", 0x0000_0407),
    ("el", 0x0000_0408),
    ("en", FALLBACK_KEYBOARD_LAYOUT),
    ("es", 0x0000_040A),
    ("et", 0x0000_0425),
    ("fa", 0x0000_0429),
    ("fi", 0x0000_040B),
    ("fr", 0x0000_040C),
    ("he", 0x0000_040D),
    ("hi", 0x0000_0439),
    ("hr", 0x0000_041A),
    ("hu", 0x0000_040E),
    ("is", 0x0000_040F),
    ("it", 0x0000_0410),
    ("ja", 0x0000_0411),
    ("ka", 0x0001_0437),
    ("kk", 0x0000_043F),
    ("ko", 0x0000_0412),
    ("lt", 0x0001_0427),
    ("lv", 0x0000_0426),
    ("mk", 0x0001_042F),
    ("nb", 0x0000_0414),
    ("nl", 0x0000_0413),
    ("nn", 0x0000_0414),
    ("no", 0x0000_0414),
    ("pl", 0x0000_0415),
    ("pt", 0x0000_0816),
    ("ro", 0x0001_0418),
    ("ru", 0x0000_0419),
    ("sk", 0x0000_041B),
    ("sl", 0x0000_0424),
    ("sq", 0x0000_041C),
    ("sr", 0x0000_081A),
    ("sv", 0x0000_041D),
    ("th", 0x0000_041E),
    ("tr", 0x0000_041F),
    ("uk", 0x0000_0422),
    ("vi", 0x0000_042A),
    ("zh", 0x0000_0804),
];

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code, per the workspace convention"
)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn turkish_q_and_turkish_f_are_two_different_identifiers() {
        // The defect in one assertion. Both are Turkish; only the high word
        // tells the server which set of key positions to decode the scancodes
        // with, and a user on the wrong one types the wrong characters with
        // nothing reporting a fault.
        //
        // Both values are Microsoft's, from "Keyboard identifiers and input
        // method editors for Windows": Turkish Q 0000041F, Turkish F 0001041F.
        let by_label = |label: &str| {
            KEYBOARD_LAYOUTS
                .iter()
                .find(|layout| layout.label == label)
                .map(|layout| layout.id)
        };
        assert_eq!(
            by_label("settings.keyboardLayout.turkishQ"),
            Some(0x0000_041F)
        );
        assert_eq!(
            by_label("settings.keyboardLayout.turkishF"),
            Some(0x0001_041F)
        );
        assert_ne!(
            by_label("settings.keyboardLayout.turkishQ"),
            by_label("settings.keyboardLayout.turkishF")
        );
    }

    #[test]
    fn the_offered_layouts_are_distinct_and_named() {
        let mut ids = BTreeSet::new();
        let mut labels = BTreeSet::new();
        for layout in KEYBOARD_LAYOUTS {
            assert!(ids.insert(layout.id), "{:#010x} is listed twice", layout.id);
            assert!(
                labels.insert(layout.label),
                "{} is listed twice",
                layout.label
            );
            assert!(
                layout.label.starts_with("settings.keyboardLayout."),
                "{} is not a catalogue key",
                layout.label
            );
        }
        // US English is offered explicitly, so a user whose machine was
        // detected as something else can still choose it.
        assert!(ids.contains(&FALLBACK_KEYBOARD_LAYOUT));
    }

    #[test]
    fn the_options_carry_the_stored_form_of_the_value() {
        // Decimal, not hex: the field is an integer and the schema parses the
        // stored string with `str::parse`. An option offering `0x41f` would be
        // a value the adapter then refuses.
        let options = keyboard_layout_options();
        assert_eq!(options.len(), KEYBOARD_LAYOUTS.len());
        assert!(
            options
                .iter()
                .any(|option| option.value == 0x0001_041F_u32.to_string()),
            "Turkish F is offered as a decimal identifier"
        );
        for option in &options {
            assert!(option.value.parse::<u32>().is_ok(), "{}", option.value);
        }
    }

    #[test]
    fn every_detectable_identifier_is_one_the_list_can_name() {
        // Detection that produced an identifier the form cannot label would
        // show the user a bare number as their default, which is the same
        // silence this module exists to end.
        let named: BTreeSet<u32> = KEYBOARD_LAYOUTS.iter().map(|layout| layout.id).collect();
        for (name, id) in XKB_LAYOUTS {
            assert!(named.contains(id), "xkb {name} -> {id:#010x} has no name");
        }
        for (layout, variant, id) in XKB_VARIANTS {
            assert!(
                named.contains(id),
                "xkb {layout}({variant}) -> {id:#010x} has no name"
            );
        }
        for (language, id) in LANGUAGE_LAYOUTS {
            assert!(named.contains(id), "{language} -> {id:#010x} has no name");
        }
        for (language, region, id) in REGION_LAYOUTS {
            assert!(
                named.contains(id),
                "{language}_{region} -> {id:#010x} has no name"
            );
        }
    }

    #[test]
    fn a_windows_identifier_is_read_as_it_is_written() {
        assert_eq!(parse_klid("0000041F"), Some(0x0000_041F));
        assert_eq!(parse_klid("0001041f"), Some(0x0001_041F));
        assert_eq!(parse_klid(" 00000409 "), Some(FALLBACK_KEYBOARD_LAYOUT));
        // Anything that is not the eight-digit form is "cannot tell" rather
        // than a salvaged guess: half an identifier is still a layout, and
        // still not the user's.
        assert_eq!(parse_klid("41F"), None);
        assert_eq!(parse_klid("0x0000041F"), None);
        assert_eq!(parse_klid(""), None);
        assert_eq!(parse_klid("ZZZZZZZZ"), None);
    }

    #[test]
    fn an_xkb_variant_decides_where_it_changes_the_layout() {
        assert_eq!(layout_for_xkb("tr", None), Some(0x0000_041F));
        assert_eq!(layout_for_xkb("tr", Some("f")), Some(0x0001_041F));
        // A variant that does not change the key positions falls back to the
        // layout itself rather than to nothing.
        assert_eq!(layout_for_xkb("de", Some("nodeadkeys")), Some(0x0000_0407));
        // Several configured layouts: the first is the one the session starts
        // in, and the variant list is read the same way.
        assert_eq!(layout_for_xkb("tr,us", Some("f,")), Some(0x0001_041F));
        assert_eq!(layout_for_xkb("us", Some("dvorak")), Some(0x0001_0409));
        assert_eq!(layout_for_xkb("zz", None), None);
    }

    #[test]
    fn a_locale_names_the_region_before_the_language() {
        // `pt_BR` and `pt_PT` are two different keyboards, not two spellings.
        assert_eq!(layout_for_locale("pt_BR.UTF-8"), Some(0x0000_0416));
        assert_eq!(layout_for_locale("pt_PT.UTF-8"), Some(0x0000_0816));
        assert_eq!(layout_for_locale("tr_TR.UTF-8"), Some(0x0000_041F));
        assert_eq!(layout_for_locale("de_CH"), Some(0x0000_0807));
        assert_eq!(layout_for_locale("de_DE@euro"), Some(0x0000_0407));
        assert_eq!(layout_for_locale("en_GB"), Some(0x0000_0809));
        assert_eq!(layout_for_locale("en-US"), Some(FALLBACK_KEYBOARD_LAYOUT));
        assert_eq!(layout_for_locale("es_MX"), Some(0x0000_080A));
        assert_eq!(layout_for_locale("es_ES"), Some(0x0000_040A));
    }

    #[test]
    fn a_locale_that_names_no_language_is_not_treated_as_american() {
        // `C` is the absence of a locale, and answering "US English" to it is
        // exactly the confident wrong answer this module replaces.
        assert_eq!(layout_for_locale("C"), None);
        assert_eq!(layout_for_locale("POSIX"), None);
        assert_eq!(layout_for_locale(""), None);
        assert_eq!(layout_for_locale("kl_GL"), None);
    }

    #[test]
    fn a_default_that_was_guessed_is_marked_as_guessed() {
        // Whatever this machine reports, the answer carries its own standing:
        // detection never produces a bare number that the rest of the program
        // has to take on trust.
        let layout = default_layout();
        match layout.source {
            LayoutSource::Guessed => assert_eq!(layout.id, FALLBACK_KEYBOARD_LAYOUT),
            LayoutSource::Detected => assert!(
                KEYBOARD_LAYOUTS.iter().any(|known| known.id == layout.id),
                "{:#010x} was detected and has no name",
                layout.id
            ),
        }
        // Cached: the form and the connection must not see two answers.
        assert_eq!(default_layout(), layout);
    }
}
