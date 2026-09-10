//! The secret-bearing newtype.
//!
//! Everything that must never reach a log, a panic payload, a serialised
//! message or a crash report goes through [`Secret`]. It has a redacting
//! `Debug`, no `Display`, no `Serialize` and no `Clone`, and it zeroes its
//! contents when it is dropped.
//!
//! `Clone` is deliberately absent. Copying a secret doubles the number of
//! places it has to be zeroed from, and every copy is a place a future change
//! could leak it. When a caller genuinely needs a second copy it must build one
//! explicitly from the exposed bytes, which makes the copy visible in review.

use core::fmt;

use zeroize::Zeroize;

/// A value that must never be logged, and is zeroed on drop.
///
/// ```
/// # use remoter_vault::{ExposeSecret, Secret};
/// let s = Secret::new(String::from("hunter2"));
/// assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
/// assert_eq!(s.expose_secret(), "hunter2");
/// ```
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    /// Wraps a value so it cannot be printed and is zeroed on drop.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Borrows the protected value mutably.
    ///
    /// Kept next to [`ExposeSecret::expose_secret`] rather than on the trait so
    /// that the read-only borrow — the common case — is the one that is easy to
    /// reach for.
    pub const fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl<T: Zeroize> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

/// Borrowing the protected value.
///
/// The trait exists so that call sites read as `expose_secret()` — a verb that
/// is easy to grep for during a security review — rather than as an anonymous
/// deref.
pub trait ExposeSecret<T> {
    /// Borrows the protected value.
    fn expose_secret(&self) -> &T;
}

impl<T: Zeroize> ExposeSecret<T> for Secret<T> {
    fn expose_secret(&self) -> &T {
        &self.0
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
    fn debug_is_redacted() {
        let s = Secret::new(vec![1u8, 2, 3]);
        let rendered = format!("{s:?}");
        assert_eq!(rendered, "Secret(<redacted>)");
        assert!(!rendered.contains('1'));
    }

    #[test]
    fn nested_debug_is_redacted() {
        #[derive(Debug)]
        #[allow(dead_code, reason = "the point of the test is the Debug output")]
        struct Holder {
            name: &'static str,
            password: Secret<String>,
        }

        let h = Holder {
            name: "web-01",
            password: Secret::new(String::from("correct horse")),
        };
        let rendered = format!("{h:?}");
        assert!(rendered.contains("web-01"));
        assert!(!rendered.contains("correct horse"));
    }

    #[test]
    fn exposes_the_inner_value() {
        let mut s = Secret::new(String::from("a"));
        assert_eq!(s.expose_secret(), "a");
        s.expose_secret_mut().push('b');
        assert_eq!(s.expose_secret(), "ab");
    }
}
