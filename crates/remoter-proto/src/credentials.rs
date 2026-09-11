//! Credentials, borrowed rather than handed over.
//!
//! This crate must not depend on `remoter-vault` — the dependency direction is
//! downward only, and a protocol adapter has no business knowing what a key
//! slot is. So the vault implements [`CredentialProvider`] and this layer sees
//! nothing but the trait.
//!
//! **Everything here is shaped around one rule: a secret is borrowed for the
//! duration of a call and is never handed out as an owned value.** That is why
//! [`CredentialProviderExt::with_password`] takes a closure instead of returning
//! `Vec<u8>`: an adapter can read the bytes, sign with them, send them — and
//! then the borrow ends. Nothing downstream can keep a copy, stash one in a
//! struct that outlives the handshake, or accidentally include one in a
//! `Debug` derive. The vault stays in control of the lifetime and of the
//! zeroization.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The callback a private key is lent to: the key bytes, and the passphrase
/// where the key has one.
///
/// An alias only because the bare type is unwieldy in four signatures; it names
/// no new behaviour.
pub type KeyBorrow<'f> = dyn FnMut(&[u8], Option<&[u8]>) + 'f;

/// The callback a private key is lent to, returning a value computed from it.
pub type KeyBorrowWith<'f, R> = dyn FnMut(&[u8], Option<&[u8]>) -> R + 'f;

/// What kind of secret a provider holds. Drives which authentication methods an
/// adapter should offer, and in which order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// A password or passphrase for the account.
    Password,
    /// A private key, possibly with a passphrase of its own.
    PrivateKey,
    /// Delegated to the platform SSH agent. The recommended option: the
    /// private key never enters this process's address space at all.
    Agent,
    /// Nothing is available. The adapter should ask, or try a method that
    /// needs no stored secret (GSSAPI, `none`).
    None,
}

impl CredentialKind {
    /// A stable ASCII name, for logs and for the interface's message
    /// catalogue. Not a translated string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::PrivateKey => "private-key",
            Self::Agent => "agent",
            Self::None => "none",
        }
    }
}

impl fmt::Display for CredentialKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Access to one connection's credential, for the duration of one attempt.
///
/// Implemented by `remoter-vault` (backed by a decrypted field), by the
/// interactive prompt path, and by tests. An implementation must never log,
/// format or clone the secret it guards; the closure form is what makes that
/// possible to honour rather than merely intend.
///
/// **Callers do not use the `borrow_*` methods directly.** They call
/// [`CredentialProviderExt::with_password`] and
/// [`CredentialProviderExt::with_private_key`], which are the same borrow with
/// a return value threaded through. The split exists because a method with a
/// generic return type cannot appear in a `dyn` vtable, and
/// [`crate::Protocol::connect`] takes `&dyn CredentialProvider` — the whole
/// point being that an adapter is handed an erased provider and cannot reach
/// behind it. Implementors write the two primitives; everyone else uses the
/// extension trait, which is blanket-implemented and therefore always
/// available.
pub trait CredentialProvider: Send + Sync {
    /// The account name, if one is configured. `None` means the adapter should
    /// fall back to its own default (the local user, typically) or prompt.
    fn username(&self) -> Option<&str>;

    /// What kind of secret is available.
    fn kind(&self) -> CredentialKind;

    /// Lends the password to `f`, returning whether there was one.
    ///
    /// `false` is not an error: it means "this provider holds no password, try
    /// another method". The bytes are valid only inside the call; copying them
    /// out defeats the entire arrangement, and doing so is a review defect.
    fn borrow_password(&self, f: &mut dyn FnMut(&[u8])) -> bool;

    /// Lends the private key, and its passphrase where the key has one, to
    /// `f`, returning whether there was one.
    ///
    /// The key material and the passphrase are lent together because every key
    /// parser needs both at once, and fetching the passphrase in a separate
    /// call would mean keeping it alive longer than the parse.
    fn borrow_private_key(&self, f: &mut KeyBorrow<'_>) -> bool;

    /// The Windows or Kerberos domain, where the protocol has one.
    ///
    /// Defaulted because only RDP and WinRM care; an SSH adapter never calls
    /// it. A domain is not a secret — it appears in the connection editor.
    fn domain(&self) -> Option<&str> {
        None
    }

    /// Restricts which agent identity is used, by comment substring. Only
    /// meaningful for [`CredentialKind::Agent`].
    fn agent_filter(&self) -> Option<&str> {
        None
    }
}

/// The borrowing API adapters actually call.
///
/// Blanket-implemented for every [`CredentialProvider`], including
/// `dyn CredentialProvider`, so `creds.with_password(&mut |bytes| …)` works on
/// the erased provider that [`crate::Protocol::connect`] receives.
pub trait CredentialProviderExt: CredentialProvider {
    /// Borrows the password for the duration of `f`, returning what `f`
    /// computed, or `None` if there is no password.
    ///
    /// The secret is borrowed and never handed out as an owned value: `f` may
    /// read it, sign with it or send it, and when the call returns the borrow
    /// is over. Nothing downstream can retain a copy, stash one in a struct
    /// that outlives the handshake, or pull one into a `Debug` derive — and
    /// the vault keeps control of both the lifetime and the zeroization.
    fn with_password<R>(&self, f: &mut dyn FnMut(&[u8]) -> R) -> Option<R> {
        let mut out = None;
        let had_one = self.borrow_password(&mut |bytes| out = Some(f(bytes)));
        if had_one { out } else { None }
    }

    /// Borrows the private key and its passphrase for the duration of `f`.
    fn with_private_key<R>(&self, f: &mut KeyBorrowWith<'_, R>) -> Option<R> {
        let mut out = None;
        let had_one = self.borrow_private_key(&mut |key, passphrase| {
            out = Some(f(key, passphrase));
        });
        if had_one { out } else { None }
    }
}

impl<T: CredentialProvider + ?Sized> CredentialProviderExt for T {}

/// A provider that holds nothing.
///
/// Used where a protocol needs no credential (a VNC server with security type
/// `None`, an anonymous FTP), and as the honest answer when a connection has no
/// credential resolved yet and the user has not been prompted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoCredentials {
    username: Option<&'static str>,
}

impl NoCredentials {
    /// A provider with neither a username nor a secret.
    #[must_use]
    pub const fn new() -> Self {
        Self { username: None }
    }

    /// A provider with a username but no secret — the ordinary case for agent
    /// authentication that has not been wired up yet, and for `none`.
    #[must_use]
    pub const fn with_username(username: &'static str) -> Self {
        Self {
            username: Some(username),
        }
    }
}

impl CredentialProvider for NoCredentials {
    fn username(&self) -> Option<&str> {
        self.username
    }

    fn kind(&self) -> CredentialKind {
        CredentialKind::None
    }

    fn borrow_password(&self, _f: &mut dyn FnMut(&[u8])) -> bool {
        false
    }

    fn borrow_private_key(&self, _f: &mut KeyBorrow<'_>) -> bool {
        false
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

    /// A provider whose secret exists only inside the closure, exactly as the
    /// vault's does.
    struct Fixture {
        password: Vec<u8>,
    }

    impl CredentialProvider for Fixture {
        fn username(&self) -> Option<&str> {
            Some("ada")
        }

        fn kind(&self) -> CredentialKind {
            CredentialKind::Password
        }

        fn borrow_password(&self, f: &mut dyn FnMut(&[u8])) -> bool {
            f(&self.password);
            true
        }

        fn borrow_private_key(&self, _f: &mut KeyBorrow<'_>) -> bool {
            false
        }
    }

    #[test]
    fn a_password_is_readable_only_inside_the_closure() {
        let creds = Fixture {
            password: b"correct horse battery staple".to_vec(),
        };
        // The closure may compute *over* the secret; it returns a derived
        // value, and the caller never sees the bytes.
        let length = creds.with_password(&mut |bytes| bytes.len());
        assert_eq!(length, Some(28));
        assert_eq!(creds.username(), Some("ada"));
        assert_eq!(creds.kind(), CredentialKind::Password);
    }

    #[test]
    fn an_absent_secret_is_none_rather_than_an_error() {
        let creds = Fixture {
            password: b"x".to_vec(),
        };
        assert!(
            creds
                .with_private_key(&mut |_key, _passphrase| ())
                .is_none()
        );
    }

    #[test]
    fn the_empty_provider_offers_nothing() {
        let creds = NoCredentials::with_username("root");
        assert_eq!(creds.username(), Some("root"));
        assert_eq!(creds.kind(), CredentialKind::None);
        assert!(creds.with_password(&mut |_| ()).is_none());
        assert!(creds.with_private_key(&mut |_, _| ()).is_none());
        assert!(creds.domain().is_none());
        assert!(creds.agent_filter().is_none());
    }

    #[test]
    fn the_borrowing_api_works_through_a_trait_object() {
        // `&dyn CredentialProvider` is what `Protocol::connect` takes, so the
        // borrow must be callable on an erased provider — that is the whole
        // reason `with_password` lives on the extension trait.
        let creds = Fixture {
            password: b"hunter2".to_vec(),
        };
        let erased: &dyn CredentialProvider = &creds;
        assert_eq!(erased.kind(), CredentialKind::Password);
        assert_eq!(erased.with_password(&mut |bytes| bytes.len()), Some(7));
        assert!(erased.with_private_key(&mut |_, _| ()).is_none());
    }
}
