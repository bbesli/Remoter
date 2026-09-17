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

pub mod conflicts;
pub mod csv;
mod error;
pub mod export;
pub mod known_hosts;
mod limits;
mod mapping;
pub mod mremoteng;
pub mod native;
mod preview;
pub mod putty;
pub mod rdcman;
pub mod rdp_file;
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

/// How much of a file is read to work out what it is.
///
/// A format marker a megabyte into a file is not a format marker.
const SNIFF_BYTES: usize = 8192;

/// How far in an XML document's own root element is looked for.
///
/// For the root and nothing else. A `confCons.xml` may open with a banner — a
/// licence header, a note from whatever script exported it — and the root is
/// then still the document's first element, just further in than
/// [`SNIFF_BYTES`] reaches. mRemoteNG itself never writes that shape, so this
/// is for files that have been through something else on the way, and the
/// ceiling is what keeps it a sniff rather than a parse: a prolog longer than
/// this leaves [`detect`] answering `None`, which is what the interface turns
/// into "Remoter could not tell what this file is. Choose the format yourself."
const XML_ROOT_BYTES: usize = 256 * 1024;

/// The local name of a `confCons.xml`'s root element.
const MREMOTENG_ROOT: &str = "Connections";

/// Guesses which importer a file belongs to.
///
/// A guess, and named as one: `docs/features/import-export.md` has the source
/// "auto-detected from the file, confirmable", so this decides what to preselect
/// and the user decides whether it was right.
///
/// `None` when nothing recognisable is at the head of the file.
#[must_use]
pub fn detect(bytes: &[u8]) -> Option<SourceFormat> {
    // Two windows, each asked one question, and the order between them is the
    // whole of the precedence rule.
    //
    // The root element goes first because it is a fact about the document,
    // where the two line-shaped tests below are shapes a line happens to have.
    // An `ssh_config` pasted into an XML comment has three hundred `Host …`
    // lines in it and is still an XML document; "host" and a comma in the first
    // line is a sentence as easily as it is a CSV header. So a file whose root
    // element can be read is answered from that root and from nothing else, and
    // only a file with no root element to read reaches the tests below. Asking
    // the line tests first answered "OpenSSH config" for a `confCons.xml` whose
    // banner quoted one, which is what put the order in writing.
    //
    // Through the same encoding reading the parsers use, so a file this crate
    // can read is a file this function can name. A UTF-16 document is not valid
    // UTF-8 from its first byte, and sniffing its raw bytes would give up on a
    // file the importer goes on to parse without complaint.
    let prolog = xml::sniff_head(&bytes[..bytes.len().min(XML_ROOT_BYTES)]);
    if let Some(root) = root_element(&prolog) {
        return match root {
            MREMOTENG_ROOT => Some(SourceFormat::MRemoteNg),
            rdcman::ROOT_ELEMENT => Some(SourceFormat::RdcMan),
            _ => None,
        };
    }

    // No root element within [`XML_ROOT_BYTES`]: either the file is not markup
    // at all, or its prolog outran the window. Either way the questions left
    // are about lines, and a line a quarter of a megabyte into a file says
    // nothing about what the file is — so these read the head only.
    let head = xml::sniff_head(&bytes[..bytes.len().min(SNIFF_BYTES)]);
    let text: &str = &head;
    // Remoter's own JSON export names itself in its first key. Asked before
    // the line tests, because a description inside it can hold a line that
    // opens `Host `.
    if is_remoter_json(text) {
        return Some(SourceFormat::RemoterJson);
    }
    // An `.rdp` file's address line has a shape no other format here has, and
    // its other lines — `screen mode id:i:2` — would otherwise say nothing.
    if rdp_file::looks_like(text) {
        return Some(SourceFormat::RdpFile);
    }
    // A registry export opens with its own header, and a Unix session file is
    // `Key=Value` lines no other format here writes.
    if putty::looks_like_reg(text) || putty::looks_like_session_file(text) {
        return Some(SourceFormat::Putty);
    }
    // A header row naming both required columns is a CSV, whatever its rows
    // say. Asked before the line test below because a quoted description can
    // hold a line that opens `host is behind the NAT`, and the exporter writes
    // exactly that header.
    if is_csv_header(text.lines().next().unwrap_or_default()) {
        return Some(SourceFormat::Csv);
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

/// Whether a document is Remoter's JSON export: an object whose head declares
/// the export's `format`.
fn is_remoter_json(text: &str) -> bool {
    let body = text.trim_start_matches('\u{feff}').trim_start();
    body.starts_with('{') && body.contains("\"format\": \"remoter-tree\"")
}

/// Whether a line is a CSV header with the two columns [`csv`] requires, each
/// a cell of its own.
///
/// Stricter than the fallback test in [`detect`], which only asks whether the
/// word and a delimiter are on the line: a comment in an `ssh_config` can say
/// "host, port and user", and cannot say `name` and `host` as whole cells.
fn is_csv_header(line: &str) -> bool {
    let line = line.trim_start_matches('\u{feff}');
    [',', ';', '\t'].into_iter().any(|delimiter| {
        let mut cells = line
            .split(delimiter)
            .map(|cell| cell.trim().trim_matches('"').trim().to_ascii_lowercase());
        let (mut name, mut host) = (false, false);
        for cell in cells.by_ref() {
            name |= cell == "name";
            host |= cell == "host";
        }
        name && host
    })
}

/// The local name of the document's root element — its *first* element, not
/// the first one that happens to be named something interesting.
///
/// Which is the point of doing it this way. A `<Connections>` somewhere inside
/// a Royal TS or a Devolutions export is a folder called Connections, and a
/// sniffer that matched a start tag anywhere in its window called such a file a
/// `confCons.xml` and preselected an importer that then read nothing out of it.
/// The root is the one element whose name is a statement about the whole
/// document, so it is the only one asked.
///
/// Only the local name comes back, the prefix dropped, and that too is the
/// point. mRemoteNG has put its root element in its own XML namespace since
/// 1.76 — `XmlRootNodeSerializer.SerializeRootNodeInfo` builds it as
/// `XNamespace "http://mremoteng.org" + "Connections"` and declares the prefix
/// `mrng` beside it — so every export a person has made this decade opens
/// `<mrng:Connections xmlns:mrng="http://mremoteng.org" …>` and not
/// `<Connections …>`. Matching the local name and ignoring the prefix is also
/// what [`xml::BoundedXmlReader`] does when it goes on to parse the file, so the
/// sniffer and the parser agree about what a `confCons.xml` is.
///
/// `None` for a file that is not markup — the first thing has to be a `<` — and
/// `None` when the prolog outruns the text it was given, a truncated name
/// included: `<Connectio` at the edge of a window is not evidence of anything,
/// and a caller with more bytes can ask again with more of them.
fn root_element(text: &str) -> Option<&str> {
    // Every pass consumes at least the `<` it matched, so the scan is bounded
    // by the window however malformed the prolog in it is.
    let mut rest = text.trim_start();
    loop {
        let after = rest.strip_prefix('<')?;
        if let Some(comment) = after.strip_prefix("!--") {
            // The banner case, most often. `--` may not appear inside a comment
            // (XML 1.0 §2.5), so the first `-->` is the one that ends it.
            rest = comment.get(comment.find("-->")? + 3..)?.trim_start();
        } else if let Some(instruction) = after.strip_prefix('?') {
            // `<?xml version="1.0"?>`, and any other processing instruction.
            rest = instruction.get(instruction.find("?>")? + 2..)?.trim_start();
        } else if after.starts_with('!') {
            // A `<!DOCTYPE …>`. Skipped to the first `>` rather than parsed:
            // one carrying an internal subset ends the scan with no root found,
            // which is the same "I cannot tell" this answers for any other
            // document whose root it could not reach — and a better answer than
            // a name read out of a DTD, which [`xml`] refuses the file for
            // carrying at all.
            rest = after.get(after.find('>')? + 1..)?.trim_start();
        } else {
            // A name, ended by the first character an XML name cannot contain.
            // `</` and a merge conflict's `<<<<<<<` end it at once and yield an
            // empty name, which is not an element and not a document.
            let name = after.get(..after.find(|c: char| !is_name_char(c))?)?;
            return (!name.is_empty()).then(|| name.rsplit(':').next().unwrap_or(name));
        }
    }
}

/// Whether `c` may appear in an XML name, as far as a sniffer needs to care.
///
/// The ASCII subset of XML 1.0 §2.3's `NameChar`. A root element whose name is
/// outside it is not the one name this asks about, so where exactly a non-ASCII
/// name ends does not matter — only that it ends.
const fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':')
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
        assert_eq!(
            detect(br#"<?xml version="1.0" encoding="utf-8"?><RDCMan programVersion="2.93" schemaVersion="3"><file>"#),
            Some(SourceFormat::RdcMan)
        );
        assert_eq!(
            detect(b"screen mode id:i:2\r\ndesktopwidth:i:1920\r\nfull address:s:dc01\r\n"),
            Some(SourceFormat::RdpFile)
        );
        assert_eq!(
            detect(b"Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\web]\r\n"),
            Some(SourceFormat::Putty)
        );
        assert_eq!(
            detect(b"HostName=web.example.com\nProtocol=ssh\nPortNumber=22\n"),
            Some(SourceFormat::Putty)
        );
        assert_eq!(detect(b""), None);
        assert_eq!(detect(b"nothing recognisable here"), None);
    }

    /// `mstsc` saves as UTF-16 with a mark, and that is the file a person has.
    #[test]
    fn an_rdp_file_as_mstsc_saves_it_is_recognised() {
        let mut bytes = vec![0xff, 0xfe];
        for unit in "screen mode id:i:2\r\nfull address:s:dc01.contoso.com\r\n".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(detect(&bytes), Some(SourceFormat::RdpFile));
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

    /// The same file with nothing at its head to say so.
    ///
    /// Notepad and Windows PowerShell 5 both write the mark, so this is the
    /// rarer half of the UTF-16 case — but a file without one is not a file in
    /// a different format, and answering "I cannot tell what this is" sends the
    /// reader looking for a problem that is not there.
    #[test]
    fn a_utf16_document_with_no_mark_is_recognised_too() {
        let document = r#"<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="x">"#;
        let mut le = Vec::new();
        let mut be = Vec::new();
        for unit in document.encode_utf16() {
            le.extend_from_slice(&unit.to_le_bytes());
            be.extend_from_slice(&unit.to_be_bytes());
        }
        assert_eq!(detect(&le), Some(SourceFormat::MRemoteNg));
        assert_eq!(detect(&be), Some(SourceFormat::MRemoteNg));
    }

    /// A `confCons.xml` with a banner above its root element: a licence header,
    /// a change note, whatever the administrator's export script wrote. The
    /// root is still the document's first element; it is simply further into
    /// the file than a fixed window reaches.
    ///
    /// The banner opens with a blank line and carries a `>` of its own, because
    /// both are what a real one does — a hand-edited file starts with an empty
    /// line as often as not, and a note about how the file was made quotes the
    /// command that made it. A scan that stopped at the first `>` it saw, or
    /// that expected the document to begin at byte zero, would land in the
    /// middle of the prose and answer with whatever was there.
    #[test]
    fn a_root_element_behind_a_long_banner_is_still_found() {
        let mut file = String::from("\n<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<!--\n");
        file.push_str("  Made by: powershell -Command \"Get-Content old.xml > confCons.xml\"\n");
        for run in 0..400 {
            file.push_str(&format!(
                "  Written by the estate inventory script, run {run}.\n"
            ));
        }
        file.push_str("-->\n");
        file.push_str(r#"<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="x">"#);
        assert!(file.len() > 8192, "the banner has to outrun the window");
        assert_eq!(detect(file.as_bytes()), Some(SourceFormat::MRemoteNg));
    }

    /// A `<Connections>` that is not the document's root is not the format.
    ///
    /// Another manager's export can perfectly well hold a folder called
    /// Connections, and a sniffer that matched a start tag anywhere in its
    /// window called such a file a `confCons.xml` — preselecting an importer
    /// that then reads nothing out of it and leaves the user to work out why.
    /// Both sides of the window are checked, because both sides used to match.
    #[test]
    fn a_connections_element_that_is_not_the_root_is_not_the_format() {
        let inside_the_head = r#"<?xml version="1.0"?>
<RoyalDocument>
  <Object Type="Folder" Name="Connections">
    <Connections Name="a folder, not a root"/>
  </Object>
</RoyalDocument>"#;
        assert_eq!(detect(inside_the_head.as_bytes()), None);

        let mut past_the_head = String::from("<?xml version=\"1.0\"?>\n<RoyalDocument>\n");
        for row in 0..400 {
            past_the_head.push_str(&format!(
                "  <Object Name=\"srv-{row}\" Uri=\"srv-{row}.example.com\"/>\n"
            ));
        }
        past_the_head
            .push_str("  <Connections Name=\"a folder, not a root\"/>\n</RoyalDocument>\n");
        assert!(
            past_the_head.len() > SNIFF_BYTES,
            "it has to outrun the head"
        );
        assert_eq!(detect(past_the_head.as_bytes()), None);
    }

    /// Lines that read like an `ssh_config` do not outrank the root element
    /// above them.
    ///
    /// This is the precedence rule in [`detect`] stated as a file: an
    /// administrator's notes with their `~/.ssh/config` pasted into them, kept
    /// in the banner of the `confCons.xml` the connections were moved to. Every
    /// line test in the function matches something in it, three hundred times
    /// over, and it is still an XML document whose root element says what it
    /// is. Asking the line tests first answered "OpenSSH config".
    #[test]
    fn an_ssh_config_quoted_above_the_root_does_not_outrank_it() {
        let mut file = String::from("<?xml version=\"1.0\"?>\n<!-- What this replaces:\n");
        for host in 0..300 {
            file.push_str(&format!(
                "Host bastion-{host}\n  HostName bastion-{host}.example.com\n"
            ));
        }
        file.push_str("-->\n");
        file.push_str(r#"<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="x"/>"#);
        assert!(
            file.len() > SNIFF_BYTES,
            "the banner has to outrun the head"
        );
        assert_eq!(detect(file.as_bytes()), Some(SourceFormat::MRemoteNg));
    }

    /// A prolog longer than the widest window leaves the format unknown, and
    /// unknown is an answer the interface has copy for: "Remoter could not tell
    /// what this file is. Choose the format yourself." A wrong guess would not
    /// be — it preselects an importer, and the user has no reason to doubt it.
    #[test]
    fn a_prolog_longer_than_the_widest_window_leaves_the_format_unknown() {
        let mut file = String::from("<?xml version=\"1.0\"?>\n<!--\n");
        while file.len() < XML_ROOT_BYTES {
            file.push_str("  Written by the estate inventory script.\n");
        }
        file.push_str("-->\n");
        file.push_str(r#"<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="x"/>"#);
        assert_eq!(detect(file.as_bytes()), None);
    }

    /// A character the window cuts in half does not take the document with it.
    ///
    /// The root of a UTF-16 export is at the front of the file, but the window
    /// still has to be decoded to reach it, and a window is a fixed number of
    /// bytes: sooner or later one ends between the two halves of an astral
    /// character — an emoji in a connection's name is all it takes. Decoding
    /// the window strictly would refuse the whole of it over that one cut
    /// character and answer "I cannot tell what this is" for a file whose first
    /// sixty bytes say exactly what it is.
    #[test]
    fn a_character_the_window_cuts_in_half_does_not_hide_the_root() {
        let mut document =
            String::from(r#"<mrng:Connections xmlns:mrng="http://mremoteng.org"><Node Name=""#);
        // The window holds the byte-order mark and then this many code units;
        // the last of them is to be the first half of the emoji below.
        let before_the_cut = (XML_ROOT_BYTES - 2) / 2 - 1;
        document.push_str(&"x".repeat(before_the_cut - document.len()));
        document.push('😀');
        document.push_str(r#"" Hostname="a.example.com"/></mrng:Connections>"#);

        let mut bytes = vec![0xff, 0xfe];
        for unit in document.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(
            &bytes[XML_ROOT_BYTES - 2..XML_ROOT_BYTES],
            // U+1F600's high surrogate, little end first. If this moves, the
            // test is no longer about a cut character.
            &[0x3d, 0xd8],
            "the window has to cut the emoji, or this tests nothing"
        );
        assert_eq!(detect(&bytes), Some(SourceFormat::MRemoteNg));
    }

    /// A root element the window cut in half is not a match for the half it
    /// left behind.
    ///
    /// `<ConnectionsWidget` truncated at its twelfth character is `Connections`,
    /// and a scan that took the end of its window for the end of a name would
    /// call this file a `confCons.xml`. The name has to be terminated by a
    /// character that cannot be in one before it is a name at all.
    #[test]
    fn a_root_element_the_window_cut_in_half_is_not_a_match() {
        let root = "<ConnectionsWidget/>";
        let opening = "<!--\n";
        let closing = "-->\n";
        // Padding sized so the window ends exactly between `<Connections` and
        // the `W` that goes on to spell a different element.
        let cut = XML_ROOT_BYTES - opening.len() - closing.len() - "<Connections".len();
        let mut file = String::from(opening);
        file.push_str(&"x".repeat(cut));
        file.push_str(closing);
        file.push_str(root);
        assert_eq!(
            &file[XML_ROOT_BYTES - "<Connections".len()..XML_ROOT_BYTES],
            "<Connections",
            "the window has to cut the name, or this tests nothing"
        );
        assert_eq!(detect(file.as_bytes()), None);
    }

    /// A `<!DOCTYPE …>` between the declaration and the root does not hide the
    /// root.
    ///
    /// Not because such a file is readable — [`xml`] refuses one outright, and
    /// the second half of this asserts it still does. Because of which refusal
    /// the person gets: naming the format lets the importer say "this document
    /// declares a DTD", where "I cannot tell what this file is" would send them
    /// off to find a format that was never the problem.
    #[test]
    fn a_doctype_before_the_root_does_not_hide_it() {
        let file = br#"<?xml version="1.0"?><!DOCTYPE Connections SYSTEM "conf.dtd"><Connections Name="x"/>"#;
        assert_eq!(detect(file), Some(SourceFormat::MRemoteNg));
        assert!(matches!(
            mremoteng::parse(file, None, &Limits::new()),
            Err(ImportError::DoctypeRefused)
        ));
    }

    /// The wider look is for an XML document's own root, not for a marker
    /// buried in something else: a file that is not markup is read at the head
    /// and nowhere else.
    #[test]
    fn the_wider_look_does_not_reach_into_a_file_that_is_not_xml() {
        let mut file = String::from("name,host\n");
        for row in 0..400 {
            file.push_str(&format!("host-{row},host-{row}.example.com\n"));
        }
        file.push_str("<Connections Name=\"x\">\n");
        assert!(file.len() > 8192);
        assert_eq!(detect(file.as_bytes()), Some(SourceFormat::Csv));
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
