//! The secret-bearing newtype used while an import is in flight.
//!
//! A deliberate duplicate of `remoter_vault::Secret` rather than a dependency
//! on it. `remoter-vault` sits beside this crate in the layering, not below it,
//! and pulling it in would put SQLite, the platform keyring and the whole
//! envelope construction behind a parser whose only job is to read a file. The
//! type is fifteen lines; the dependency would not be.
//!
//! Everything the type refuses is refused on purpose: no `Clone`, because each
//! copy is another place to zero from; no `Display`, no `Serialize`, and a
//! `Debug` that prints nothing but the type name.

use std::fmt;

use zeroize::Zeroizing;

/// A password or passphrase recovered from an imported file, or supplied to
/// open one.
///
/// Held in plaintext only between the cipher and the vault's sealing call. It
/// is zeroed when dropped, so an abandoned preview leaves nothing behind.
///
/// ```
/// # use remoter_import::ImportedSecret;
/// let s = ImportedSecret::new(String::from("hunter2"));
/// assert_eq!(format!("{s:?}"), "ImportedSecret(<redacted>)");
/// assert_eq!(s.expose(), "hunter2");
/// ```
pub struct ImportedSecret(Zeroizing<String>);

impl ImportedSecret {
    /// Wraps a recovered secret.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Borrows the plaintext.
    ///
    /// Named as a verb so that a security review can grep for every place a
    /// secret is read.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether the secret is the empty string.
    ///
    /// mRemoteNG writes `Password=""` for a connection with no password, so
    /// "present but empty" is a case the mapping has to distinguish from
    /// "absent".
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consumes the wrapper and yields the still-zeroing buffer, for handing to
    /// a sealing call that wants ownership.
    #[must_use]
    pub fn into_zeroizing(self) -> Zeroizing<String> {
        self.0
    }
}

impl fmt::Debug for ImportedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ImportedSecret(<redacted>)")
    }
}

impl From<String> for ImportedSecret {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for ImportedSecret {
    fn from(value: &str) -> Self {
        Self::new(value.to_owned())
    }
}

/// Equality is by content, in the ordinary way.
///
/// Not constant time, and not meant to be: these are values that came out of a
/// file the user already holds, compared to deduplicate credentials during an
/// import. Nothing here gates authentication.
impl PartialEq for ImportedSecret {
    fn eq(&self, other: &Self) -> bool {
        *self.0 == *other.0
    }
}

impl Eq for ImportedSecret {}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code, per docs/development/coding-standards.md"
)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = ImportedSecret::new(String::from("correct horse"));
        let rendered = format!("{s:?}");
        assert_eq!(rendered, "ImportedSecret(<redacted>)");
        assert!(!rendered.contains("horse"));
    }

    #[test]
    fn debug_is_redacted_when_nested() {
        #[derive(Debug)]
        #[allow(dead_code, reason = "the Debug output is the point of the test")]
        struct Holder {
            name: &'static str,
            password: ImportedSecret,
        }

        let rendered = format!(
            "{:?}",
            Holder {
                name: "web-01",
                password: ImportedSecret::from("battery staple"),
            }
        );
        assert!(rendered.contains("web-01"));
        assert!(!rendered.contains("battery"));
    }

    #[test]
    fn exposes_and_compares() {
        let a = ImportedSecret::from("a");
        let b = ImportedSecret::from("a");
        let c = ImportedSecret::from("b");
        assert_eq!(a.expose(), "a");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(!a.is_empty());
        assert!(ImportedSecret::from("").is_empty());
    }
}
