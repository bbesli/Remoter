//! The hardened XML reader every XML importer goes through.
//!
//! `docs/features/import-export.md` gives the controls this module exists to
//! implement: external entities and DTDs disabled, a hard cap on document size,
//! element count and nesting depth, and a streaming parse with bounded buffers.
//! There is one reader so that there is one place to check those, and so that a
//! second XML importer cannot arrive with its own weaker set.
//!
//! Three properties are worth stating plainly, because they are what make the
//! XXE class of attack structurally impossible here rather than merely handled:
//!
//! 1. A `<!DOCTYPE` declaration is a hard error. Not skipped, not ignored — a
//!    file that carries one is refused whole. Nothing legitimate writes one.
//! 2. Only the five predefined XML entities and numeric character references
//!    resolve, in attribute values and in character data alike. Any other name
//!    is [`ImportError::EntityRefused`] rather than an empty string, so a
//!    document whose body is `&xxe;` is refused instead of read as blank.
//!    There is no entity table for a document to add to, so there is nothing
//!    for a billion-laughs expansion to recurse through.
//! 3. The reader borrows from a `&str` that was already length-checked, so the
//!    parse allocates only the values it hands back, each of them bounded.

use quick_xml::Reader;
use quick_xml::errors::{Error as XmlError, SyntaxError};
use quick_xml::events::{BytesRef, Event};

use crate::error::ImportError;
use crate::limits::Limits;

/// One element's start tag, with its attributes already unescaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Element {
    /// The local name, with any namespace prefix stripped.
    pub(crate) name: String,
    /// Attributes in document order. Namespace declarations and prefixed
    /// attributes are dropped: no format this crate reads uses them for data,
    /// and keeping them would let `xmlns:Password` shadow `Password` in a
    /// lookup that compares local names.
    pub(crate) attributes: Vec<(String, String)>,
}

impl Element {
    /// The value of `name`, if the element carries it.
    pub(crate) fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// What the reader hands back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum XmlEvent {
    /// An element started. An empty element yields this and then
    /// [`XmlEvent::End`], so a caller never has to handle both spellings.
    Start(Element),
    /// An element ended.
    End,
    /// Character data.
    Text(String),
}

/// A bounded, DTD-refusing pull parser.
pub(crate) struct BoundedXmlReader<'a> {
    reader: Reader<&'a [u8]>,
    limits: Limits,
    depth: usize,
    elements: usize,
    /// Set when an empty element was reported, so the next call closes it.
    pending_end: bool,
    finished: bool,
}

impl<'a> BoundedXmlReader<'a> {
    /// Wraps `text`, which the caller has already checked against
    /// [`Limits::max_input_bytes`].
    pub(crate) fn new(text: &'a str, limits: Limits) -> Self {
        let mut reader = Reader::from_reader(text.as_bytes());
        let config = reader.config_mut();
        // A start tag whose end tag names a different element is a broken
        // document, not one to guess at.
        config.check_end_names = true;
        // Empty elements are reported as `Empty` and expanded by this module,
        // which keeps the depth counter honest.
        config.expand_empty_elements = false;
        config.trim_text(false);
        Self {
            reader,
            limits,
            depth: 0,
            elements: 0,
            pending_end: false,
            finished: false,
        }
    }

    /// The next event, or `None` at the end of the document.
    ///
    /// # Errors
    ///
    /// Any of the bounded-parse refusals, or [`ImportError::MalformedXml`].
    pub(crate) fn next_event(&mut self) -> Result<Option<XmlEvent>, ImportError> {
        if self.pending_end {
            self.pending_end = false;
            self.depth = self.depth.saturating_sub(1);
            return Ok(Some(XmlEvent::End));
        }
        if self.finished {
            return Ok(None);
        }

        loop {
            let event = self
                .reader
                .read_event()
                .map_err(|err| self.map_error(&err))?;
            match event {
                Event::Start(start) => {
                    let element = self.element(&start)?;
                    self.enter()?;
                    return Ok(Some(XmlEvent::Start(element)));
                }
                Event::Empty(start) => {
                    let element = self.element(&start)?;
                    self.enter()?;
                    self.pending_end = true;
                    return Ok(Some(XmlEvent::Start(element)));
                }
                Event::End(_) => {
                    // `check_end_names` guarantees this matches, so the counter
                    // cannot go negative; `saturating_sub` states that rather
                    // than relying on it.
                    self.depth = self.depth.saturating_sub(1);
                    return Ok(Some(XmlEvent::End));
                }
                Event::Text(text) => {
                    let decoded = text
                        .decode()
                        .map_err(|_| ImportError::MalformedXml { offset: self.at() })?;
                    if decoded.trim().is_empty() {
                        continue;
                    }
                    return Ok(Some(XmlEvent::Text(decoded.into_owned())));
                }
                Event::CData(data) => {
                    let decoded = data
                        .decode()
                        .map_err(|_| ImportError::MalformedXml { offset: self.at() })?;
                    return Ok(Some(XmlEvent::Text(decoded.into_owned())));
                }
                // An entity reference in character data. Skipping it would be
                // the wrong shape of safe: a document whose body is `&xxe;`
                // would parse as an empty body rather than as a refusal.
                Event::GeneralRef(reference) => {
                    return Ok(Some(XmlEvent::Text(resolve_reference(&reference)?.into())));
                }
                // The whole reason this module exists.
                Event::DocType(_) => return Err(ImportError::DoctypeRefused),
                Event::Comment(_) | Event::PI(_) | Event::Decl(_) => {
                    continue;
                }
                Event::Eof => {
                    self.finished = true;
                    if self.depth > 0 {
                        return Err(ImportError::Truncated { unit: "element" });
                    }
                    return Ok(None);
                }
            }
        }
    }

    fn enter(&mut self) -> Result<(), ImportError> {
        self.elements += 1;
        if self.elements > self.limits.max_items {
            return Err(ImportError::TooManyItems {
                limit: self.limits.max_items,
                unit: "elements",
            });
        }
        self.depth += 1;
        if self.depth > self.limits.max_depth {
            return Err(ImportError::TooDeep {
                limit: self.limits.max_depth,
            });
        }
        Ok(())
    }

    fn element(&self, start: &quick_xml::events::BytesStart<'_>) -> Result<Element, ImportError> {
        let name = String::from_utf8_lossy(start.local_name().into_inner()).into_owned();
        let mut attributes = Vec::new();
        for attribute in start.attributes() {
            let attribute =
                attribute.map_err(|_| ImportError::MalformedXml { offset: self.at() })?;
            if attributes.len() >= self.limits.max_attributes {
                return Err(ImportError::TooManyItems {
                    limit: self.limits.max_attributes,
                    unit: "attributes",
                });
            }
            if attribute.value.len() > self.limits.max_value_bytes {
                return Err(ImportError::ValueTooLong {
                    limit: self.limits.max_value_bytes,
                    unit: "attribute",
                });
            }
            let key = attribute.key;
            // `xmlns` and anything prefixed is namespace machinery, not data.
            if key.as_ref().contains(&b':') || key.as_ref() == b"xmlns" {
                continue;
            }
            let key = String::from_utf8_lossy(key.as_ref()).into_owned();
            let value = attribute
                .decode_and_unescape_value(self.reader.decoder())
                .map_err(|err| self.map_error(&err))?
                .into_owned();
            attributes.push((key, value));
        }
        Ok(Element { name, attributes })
    }

    /// The byte the reader stopped at, for an error message.
    fn at(&self) -> usize {
        usize::try_from(self.reader.error_position()).unwrap_or(usize::MAX)
    }

    /// quick-xml's own message is never carried through: it quotes the markup
    /// it choked on, and markup in a confCons.xml is ciphertext.
    fn map_error(&self, err: &XmlError) -> ImportError {
        match err {
            XmlError::Escape(_) => ImportError::EntityRefused,
            XmlError::Syntax(SyntaxError::UnclosedDoctype) => ImportError::DoctypeRefused,
            XmlError::Syntax(_) => ImportError::Truncated { unit: "element" },
            _ => ImportError::MalformedXml { offset: self.at() },
        }
    }
}

/// Resolves an entity reference in character data.
///
/// The five predefined entities and numeric character references, and nothing
/// else. There is no entity table for a document to add to — the DTD that would
/// declare one is refused before the parse gets here — so any other name is a
/// reference to something that was never defined, and the only safe reading of
/// that is a refusal.
fn resolve_reference(reference: &BytesRef<'_>) -> Result<char, ImportError> {
    if let Some(character) = reference
        .resolve_char_ref()
        .map_err(|_| ImportError::EntityRefused)?
    {
        return Ok(character);
    }
    let name = reference.decode().map_err(|_| ImportError::EntityRefused)?;
    match name.as_ref() {
        "amp" => Ok('&'),
        "lt" => Ok('<'),
        "gt" => Ok('>'),
        "quot" => Ok('"'),
        "apos" => Ok('\''),
        _ => Err(ImportError::EntityRefused),
    }
}

/// Checks the size and encoding of an input before any parser sees it.
///
/// # Errors
///
/// [`ImportError::TooLarge`] or [`ImportError::NotUtf8`].
pub(crate) fn as_text<'a>(bytes: &'a [u8], limits: &Limits) -> Result<&'a str, ImportError> {
    if bytes.len() > limits.max_input_bytes {
        return Err(ImportError::TooLarge {
            size: bytes.len(),
            limit: limits.max_input_bytes,
        });
    }
    // A UTF-8 byte-order mark is legal at the head of an XML document and of a
    // CSV written by a spreadsheet, and is not part of the content.
    let bytes = bytes.strip_prefix("\u{feff}".as_bytes()).unwrap_or(bytes);
    core::str::from_utf8(bytes).map_err(|err| ImportError::NotUtf8 {
        offset: err.valid_up_to(),
    })
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code, per docs/development/coding-standards.md"
)]
mod tests {
    use super::*;

    fn events(xml: &str, limits: Limits) -> Result<Vec<XmlEvent>, ImportError> {
        let mut reader = BoundedXmlReader::new(xml, limits);
        let mut out = Vec::new();
        while let Some(event) = reader.next_event()? {
            out.push(event);
        }
        Ok(out)
    }

    #[test]
    fn an_empty_element_yields_a_start_and_an_end() {
        let events = events(r#"<a><b x="1"/></a>"#, Limits::new()).unwrap();
        assert_eq!(events.len(), 4);
        let XmlEvent::Start(b) = &events[1] else {
            panic!("expected a start event");
        };
        assert_eq!(b.name, "b");
        assert_eq!(b.attribute("x"), Some("1"));
        assert_eq!(events[2], XmlEvent::End);
        assert_eq!(events[3], XmlEvent::End);
    }

    #[test]
    fn a_doctype_is_refused_whole() {
        let xxe = r#"<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>"#;
        assert_eq!(events(xxe, Limits::new()), Err(ImportError::DoctypeRefused));
    }

    #[test]
    fn an_unknown_entity_is_refused_rather_than_expanded() {
        // No DTD at all, so the parser reaches the reference itself.
        let xml = r#"<r a="&secret;"/>"#;
        assert_eq!(events(xml, Limits::new()), Err(ImportError::EntityRefused));
    }

    #[test]
    fn the_five_predefined_entities_still_work() {
        let xml = r#"<r a="a&amp;b&lt;c&gt;d&quot;e&apos;f&#65;"/>"#;
        let events = events(xml, Limits::new()).unwrap();
        let XmlEvent::Start(r) = &events[0] else {
            panic!("expected a start event");
        };
        assert_eq!(r.attribute("a"), Some("a&b<c>d\"e'fA"));
    }

    #[test]
    fn an_entity_in_character_data_is_resolved_or_refused_never_ignored() {
        let resolved = events("<r>a&amp;b&#67;</r>", Limits::new()).unwrap();
        let text: String = resolved
            .iter()
            .filter_map(|event| match event {
                XmlEvent::Text(text) => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(text, "a&bC");
        assert_eq!(
            events("<r>&xxe;</r>", Limits::new()),
            Err(ImportError::EntityRefused)
        );
    }

    #[test]
    fn nesting_past_the_limit_is_refused() {
        let limits = Limits {
            max_depth: 4,
            ..Limits::new()
        };
        let deep = format!("{}{}", "<a>".repeat(64), "</a>".repeat(64));
        assert_eq!(
            events(&deep, limits),
            Err(ImportError::TooDeep { limit: 4 })
        );
    }

    #[test]
    fn an_element_flood_is_refused() {
        let limits = Limits {
            max_items: 8,
            ..Limits::new()
        };
        let wide = format!("<a>{}</a>", "<b/>".repeat(64));
        assert_eq!(
            events(&wide, limits),
            Err(ImportError::TooManyItems {
                limit: 8,
                unit: "elements"
            })
        );
    }

    #[test]
    fn an_oversized_attribute_is_refused() {
        let limits = Limits {
            max_value_bytes: 16,
            ..Limits::new()
        };
        let xml = format!(r#"<a b="{}"/>"#, "x".repeat(1024));
        assert_eq!(
            events(&xml, limits),
            Err(ImportError::ValueTooLong {
                limit: 16,
                unit: "attribute"
            })
        );
    }

    #[test]
    fn too_many_attributes_is_refused() {
        let limits = Limits {
            max_attributes: 4,
            ..Limits::new()
        };
        let attrs: String = (0..64).map(|i| format!(r#" a{i}="v""#)).collect();
        assert_eq!(
            events(&format!("<a{attrs}/>"), limits),
            Err(ImportError::TooManyItems {
                limit: 4,
                unit: "attributes"
            })
        );
    }

    #[test]
    fn a_truncated_document_is_reported_as_truncated() {
        assert_eq!(
            events("<a><b>", Limits::new()),
            Err(ImportError::Truncated { unit: "element" })
        );
        assert_eq!(
            events(r#"<a b="unclosed"#, Limits::new()),
            Err(ImportError::Truncated { unit: "element" })
        );
    }

    #[test]
    fn namespace_declarations_are_not_data() {
        let xml = r#"<ns:Connections xmlns:ns="http://mremoteng.org" Name="a"/>"#;
        let events = events(xml, Limits::new()).unwrap();
        let XmlEvent::Start(root) = &events[0] else {
            panic!("expected a start event");
        };
        assert_eq!(root.name, "Connections");
        assert_eq!(root.attributes.len(), 1);
        assert_eq!(root.attribute("Name"), Some("a"));
    }

    #[test]
    fn oversized_and_non_utf8_input_is_refused_before_parsing() {
        let limits = Limits {
            max_input_bytes: 4,
            ..Limits::new()
        };
        assert_eq!(
            as_text(b"aaaaaaaa", &limits),
            Err(ImportError::TooLarge { size: 8, limit: 4 })
        );
        assert_eq!(
            as_text(b"ab\xffcd", &Limits::new()),
            Err(ImportError::NotUtf8 { offset: 2 })
        );
        assert_eq!(
            as_text("\u{feff}<a/>".as_bytes(), &Limits::new()),
            Ok("<a/>")
        );
    }
}
