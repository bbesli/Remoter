//! Importers for other connection managers.
//!
//! Migration is the highest-leverage feature for adoption: an administrator
//! with four hundred connections in mRemoteNG will not retype them. It is also
//! the largest hostile-input surface in the application, because these are
//! files that colleagues share, that come out of old backups, and that may be
//! deliberately crafted. `docs/features/import-export.md` is the normative
//! specification for both halves of that sentence.
//!
//! # What this crate does and does not do
//!
//! It parses. It produces an [`ImportPreview`]: the tree that *would* be
//! created, plus an [`ImportReport`] naming what came in, what could not be
//! mapped and what needs attention. It writes nothing. The vault is the IPC
//! layer's to open, and nothing touches it until the user has confirmed the
//! preview — step 7 of the import flow, four steps after this crate's work is
//! finished.
//!
//! That is also why a credential in a preview holds its password in plaintext:
//! sealing needs a vault, this crate has none, and inventing a placeholder
//! would put an unsealed secret into a type whose whole contract is that its
//! secrets are sealed. A [`PreviewNode`] becomes a `Node` when the caller hands
//! [`PreviewNode::into_node`] the ciphertext its vault produced.
//!
//! # Security
//!
//! Every parser here is total: no panic, no unbounded allocation and no
//! unbounded loop on any input, including inputs that are not the format at
//! all. The controls behind that claim:
//!
//! - **XXE and entity expansion.** DTDs are refused outright and no entity
//!   beyond XML's five predefines is resolved. See [`xml`].
//! - **Memory exhaustion.** Every input is size-checked before parsing and
//!   every parser works inside a [`Limits`]: document size, element or row
//!   count, nesting depth, attribute and field length, node count, and the
//!   number of findings the report will grow to.
//! - **Filesystem reach.** `ssh_config`'s `Include` is the only directive in
//!   any of these formats that names a file, and it goes through a
//!   [`ssh_config::ConfigFiles`] source that confines it to one directory. The
//!   entry point a fuzz target calls does not follow includes at all.
//! - **Secrets.** A recovered password lives in an [`ImportedSecret`] from the
//!   moment it leaves the cipher: redacting `Debug`, no `Display`, no
//!   `Serialize`, zeroed on drop. Neither [`PreviewNode`] nor the types it
//!   holds are serialisable; [`PreviewNode::summary`] is what crosses the IPC
//!   boundary.
//!
//! # Example
//!
//! ```
//! use remoter_import::{Limits, csv};
//!
//! let file = b"name,host,protocol,port\nweb-01,web-01.example.com,ssh,22\n";
//! let preview = csv::parse(file, &Limits::new())?;
//!
//! assert_eq!(preview.report().counts().connections, 1);
//! assert!(!preview.report().needs_attention());
//! # Ok::<(), remoter_import::ImportError>(())
//! ```

#![doc(html_no_source)]

pub mod csv;
mod error;
mod limits;
mod mapping;
pub mod mremoteng;
mod preview;
mod report;
mod secret;
pub mod ssh_config;
mod xml;

pub use error::{ImportError, ReadFailure, XmlLocation, XmlProblem};
pub use limits::Limits;
pub use preview::{
    ImportPreview, NodeSummary, PreviewCredential, PreviewKind, PreviewNode, PreviewSecret,
};
pub use report::{Finding, ImportCounts, ImportReport, Severity, SkipReason, SourceFormat};
pub use secret::ImportedSecret;

/// Guesses which importer a file belongs to.
///
/// A guess, and named as one: `docs/features/import-export.md` has the source
/// "auto-detected from the file, confirmable", so this decides what to preselect
/// and the user decides whether it was right.
///
/// `None` when nothing recognisable is at the head of the file.
#[must_use]
pub fn detect(bytes: &[u8]) -> Option<SourceFormat> {
    // Only the head is examined: a format marker that is a megabyte into a file
    // is not a format marker.
    let head = &bytes[..bytes.len().min(8192)];
    // Through the same byte-order-mark reading the parsers use, so a file this
    // crate can read is a file this function can name. A UTF-16 document is
    // not valid UTF-8 from its first byte, and sniffing its raw bytes would
    // give up on a file the importer goes on to parse without complaint.
    let head = xml::sniff_head(head);
    let text: &str = &head;

    if opens_connections_element(text) {
        return Some(SourceFormat::MRemoteNg);
    }
    if text.lines().map(str::trim_start).any(|line| {
        let lowered = line.to_ascii_lowercase();
        lowered.starts_with("host ")
            || lowered.starts_with("host\t")
            || lowered.starts_with("match ")
            || lowered.starts_with("include ")
    }) {
        return Some(SourceFormat::OpenSshConfig);
    }
    let header = text.lines().next().unwrap_or_default().to_ascii_lowercase();
    if header.contains("host") && (header.contains(',') || header.contains(';')) {
        return Some(SourceFormat::Csv);
    }
    None
}

/// Whether a start tag anywhere in the head opens a `<Connections>` element,
/// whatever namespace prefix it carries.
///
/// The prefix is the whole point. mRemoteNG has put its root element in its own
/// XML namespace since 1.76 — `XmlRootNodeSerializer.SerializeRootNodeInfo`
/// builds it as `XNamespace "http://mremoteng.org" + "Connections"` and declares
/// the prefix `mrng` beside it — so every export a person has made this decade
/// opens `<mrng:Connections xmlns:mrng="http://mremoteng.org" …>` and not
/// `<Connections …>`. Matching the local name and ignoring the prefix is also
/// what [`xml::BoundedXmlReader`] does when it goes on to parse the file, so the
/// sniffer and the parser agree about what a `confCons.xml` is.
fn opens_connections_element(text: &str) -> bool {
    text.match_indices('<').any(|(at, _)| {
        // Everything after the `<` up to the first character an XML name cannot
        // contain. A `<?xml` declaration, a `<!--` comment and a `</` end tag
        // all stop immediately and yield a name that matches nothing.
        let rest = &text[at + 1..];
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':')))
            .unwrap_or(rest.len());
        let name = &rest[..end];
        name.rsplit(':').next().unwrap_or(name) == "Connections"
    })
}

#[cfg(test)]
#[allow(clippy::panic, reason = "test code")]
mod tests {
    use super::*;

    #[test]
    fn each_format_is_recognised_from_its_head() {
        assert_eq!(
            detect(br#"<?xml version="1.0"?><Connections Name="x">"#),
            Some(SourceFormat::MRemoteNg)
        );
        assert_eq!(
            detect(b"# my config\nHost web-01\n  HostName x\n"),
            Some(SourceFormat::OpenSshConfig)
        );
        assert_eq!(
            detect(b"name,host,protocol\na,b,ssh\n"),
            Some(SourceFormat::Csv)
        );
        assert_eq!(detect(b""), None);
        assert_eq!(detect(b"nothing recognisable here"), None);
    }

    /// The shape a person's own `confCons.xml` is actually in.
    ///
    /// mRemoteNG has written the root element in the `mrng` namespace since
    /// 1.76, so a sniffer looking for the literal `<Connections` matches the
    /// fixtures in mRemoteNG's own test resources — which predate the change —
    /// and nothing a user has exported since. This is that file, and the two
    /// older spellings it has to keep recognising.
    #[test]
    fn the_namespaced_root_a_real_export_carries_is_recognised() {
        for head in [
            br#"<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" ConfVersion="2.7">"#
                .as_slice(),
            // A prefix is a local choice; only the local name is the format.
            br#"<x:Connections xmlns:x="http://mremoteng.org" Name="Connections">"#.as_slice(),
            // Pre-1.76, and mRemoteNG's own checked-in test resources.
            br#"<Connections Name="Connections" ConfVersion="2.6">"#.as_slice(),
        ] {
            assert_eq!(
                detect(head),
                Some(SourceFormat::MRemoteNg),
                "not recognised: {}",
                String::from_utf8_lossy(head)
            );
        }
    }

    /// A UTF-16 `confCons.xml` is not valid UTF-8 from its first byte, so a
    /// sniffer reading the raw bytes gives up on a file the importer parses
    /// without complaint.
    #[test]
    fn a_utf16_document_is_recognised_as_the_format_it_is() {
        let document = r#"<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="x">"#;
        let mut bytes = vec![0xff, 0xfe];
        for unit in document.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(detect(&bytes), Some(SourceFormat::MRemoteNg));
    }

    /// A root element is a start tag, not the word. Nothing else in a document
    /// should make it an mRemoteNG file.
    #[test]
    fn the_word_alone_is_not_a_format() {
        assert_eq!(detect(b"Connections are listed below.\n"), None);
        assert_eq!(
            detect(b"<RoyalDocument><Connections-ish/></RoyalDocument>"),
            None
        );
    }

    #[test]
    fn detection_does_not_panic_on_arbitrary_bytes() {
        for chunk in [
            b"\xff\xfe\x00\x00".as_slice(),
            &[0u8; 64],
            "héllo".as_bytes(),
            &b"\xe2\x82".repeat(4096),
        ] {
            let _ = detect(chunk);
        }
    }

    #[test]
    fn a_multibyte_character_split_by_the_window_is_not_fatal() {
        let mut bytes = vec![b'x'; 8191];
        // The window ends mid-character.
        bytes.extend_from_slice("é".as_bytes());
        assert_eq!(detect(&bytes), None);
    }
}
