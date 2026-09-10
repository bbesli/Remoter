//! Import failures.
//!
//! Every variant is a whole-file failure: the import produced nothing. Problems
//! that affect one item but not the file are [`Finding`](crate::Finding)s on the
//! report instead, because refusing four hundred connections over one
//! unparseable port number helps nobody.
//!
//! No variant carries content recovered from the file. A malformed ciphertext
//! reports that it was malformed and stops there: quoting the bytes back would
//! put a partially decrypted password into an error message, and error messages
//! reach logs.

use std::fmt;

use remoter_core::ValidationError;

/// Why an import could not be produced at all.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ImportError {
    /// The file is larger than the configured limit.
    #[error("the file is {size} bytes, over the import limit of {limit}")]
    TooLarge {
        /// The file's size in bytes.
        size: usize,
        /// The configured limit.
        limit: usize,
    },

    /// The file is not valid UTF-8. Every format this crate reads is text.
    #[error("the file is not valid UTF-8 (first bad byte at offset {offset})")]
    NotUtf8 {
        /// Byte offset of the first invalid sequence.
        offset: usize,
    },

    /// The XML is syntactically broken.
    ///
    /// The parser's own message is deliberately not included: quick-xml quotes
    /// the offending markup, and markup in a confCons.xml holds ciphertext.
    #[error("the XML is malformed at byte {offset}")]
    MalformedXml {
        /// Byte offset the parser stopped at.
        offset: usize,
    },

    /// The document declares a DTD.
    ///
    /// Refused outright rather than ignored. A DTD is the vehicle for both XXE
    /// and entity expansion, and no connection manager writes one.
    #[error("the document declares a DTD; DTDs and external entities are refused")]
    DoctypeRefused,

    /// The document uses an entity other than the five XML predefines.
    #[error("the document uses a custom XML entity, which is refused")]
    EntityRefused,

    /// The document nests deeper than the configured limit.
    #[error("the document nests deeper than {limit} levels")]
    TooDeep {
        /// The configured limit.
        limit: usize,
    },

    /// The document has more elements, rows or lines than the limit allows.
    #[error("the document has more than {limit} {unit}")]
    TooManyItems {
        /// The configured limit.
        limit: usize,
        /// What was counted: `elements`, `attributes`, `rows` or `lines`.
        unit: &'static str,
    },

    /// A single value is longer than the configured limit.
    #[error("a {unit} is longer than the limit of {limit} bytes")]
    ValueTooLong {
        /// The configured limit.
        limit: usize,
        /// What was measured: `attribute`, `line` or `field`.
        unit: &'static str,
    },

    /// The file ends in the middle of a record, an element or a quoted field.
    #[error("the file ends in the middle of a {unit}")]
    Truncated {
        /// What was left open: `element`, `record` or `quoted field`.
        unit: &'static str,
    },

    /// The file is not the format that was asked of it.
    #[error("this is not {expected}")]
    WrongFormat {
        /// A short description of what was expected.
        expected: &'static str,
    },

    /// The file is encrypted and no password was supplied.
    #[error("the file is encrypted; a password is needed to read it")]
    PasswordRequired,

    /// The supplied password does not open the file.
    ///
    /// Distinct from [`ImportError::MalformedCiphertext`], and only ever
    /// returned after the document's own authenticator has been checked — the
    /// distinction is drawn for the user, never guessed from a decryption
    /// failure deeper in the file.
    #[error("that password does not open this file")]
    WrongPassword,

    /// The file declares a cipher this build cannot read.
    #[error("the file declares the cipher mode {mode}, which is not supported")]
    UnsupportedCipher {
        /// The declared mode, sanitised to ASCII alphanumerics.
        mode: String,
    },

    /// A ciphertext is too short, badly encoded, or fails its authentication
    /// tag after the file's password was already accepted.
    #[error("a ciphertext in the file is malformed")]
    MalformedCiphertext,

    /// The import would create more nodes than the limit allows.
    #[error("the import would create more than {limit} nodes")]
    TooManyNodes {
        /// The configured limit.
        limit: usize,
    },

    /// A CSV file is missing a column the mapping needs.
    #[error("the CSV has no {column} column")]
    MissingColumn {
        /// The missing column's canonical name.
        column: &'static str,
    },

    /// A CSV header names the same column twice.
    #[error("the CSV header names the column {column} twice")]
    DuplicateColumn {
        /// The repeated column name.
        column: String,
    },

    /// A file an `Include` directive named could not be read.
    ///
    /// The path is included because the user needs to know which file to fix,
    /// and a path in an ssh_config is not a secret. The underlying I/O error is
    /// reduced to a [`ReadFailure`] so that no operating-system message reaches
    /// the caller verbatim.
    #[error("could not read {path}: {reason}")]
    ReadFailed {
        /// The path as it appeared, after include resolution.
        path: String,
        /// Why it could not be read.
        reason: ReadFailure,
    },

    /// `Include` directives nest deeper than the configured limit.
    #[error("Include directives nest deeper than {limit} levels")]
    IncludeTooDeep {
        /// The configured limit.
        limit: usize,
    },

    /// A value that survived parsing was still rejected by the domain model.
    ///
    /// Reaching this means the importer built something `remoter-core` will not
    /// accept, which is a bug in the mapping rather than in the file: per-item
    /// problems are reported, not raised.
    #[error("the imported data is not valid: {0}")]
    Validation(#[from] ValidationError),
}

/// Why a file could not be read, reduced to the cases a user can act on.
///
/// `std::io::Error` is not carried through: its `Display` includes the
/// platform's own message, which varies by locale and has, on some platforms,
/// included the full path of a symlink target the user did not know about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReadFailure {
    /// No such file.
    NotFound,
    /// The file exists but is not readable by this process.
    PermissionDenied,
    /// The path resolved outside the directory the import was rooted at.
    OutsideRoot,
    /// Anything else.
    Other,
}

impl fmt::Display for ReadFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotFound => "no such file",
            Self::PermissionDenied => "permission denied",
            Self::OutsideRoot => "the path leaves the directory being imported from",
            Self::Other => "the file could not be read",
        })
    }
}
