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
//!    is [`XmlProblem::UnknownEntity`] rather than an empty string, so a
//!    document whose body is `&xxe;` is refused instead of read as blank.
//!    There is no entity table for a document to add to, so there is nothing
//!    for a billion-laughs expansion to recurse through.
//! 3. The reader borrows from a `&str` that was already length-checked, so the
//!    parse allocates only the values it hands back, each of them bounded.
//!
//! Every refusal is located. The reader keeps the document text and the names
//! of the elements it is inside, so a failure is reported as a line, a column
//! and an element rather than as a byte offset — see [`ImportError::XmlNotWellFormed`].
//! That is not cosmetic: quick-xml's `error_position()` is zero for every
//! failure it did not itself raise (an entity this module refuses, for one), so
//! the old message was frequently "malformed at byte 0" for a file broken four
//! hundred lines in.

use quick_xml::errors::{Error as XmlError, IllFormedError, SyntaxError};
use quick_xml::events::{BytesRef, Event};
use quick_xml::{Reader, XmlVersion};
use zeroize::Zeroizing;

use crate::error::{ImportError, XmlLocation, XmlProblem};
use crate::limits::Limits;

/// The longest element or attribute name carried into a message.
const MAX_NAME_IN_MESSAGE: usize = 64;

/// Reduces a name out of the document to something safe to put in a message.
///
/// XML restricts name characters already, but this crate's contract is that no
/// error carries content recovered from the file, and a parser that has already
/// failed is exactly where that contract is easiest to break. Anything outside
/// the ASCII name characters is dropped, and the result is truncated.
fn sanitise_name(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
        .take(MAX_NAME_IN_MESSAGE)
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

/// The same, for a message that needs a name whether or not one survived.
pub(crate) fn name_in_message(raw: &str) -> String {
    sanitise_name(raw).unwrap_or_else(|| "?".to_owned())
}

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
    /// The document itself, kept so a failure can be located by line and
    /// column. It is already in memory and already length-checked; holding the
    /// borrow costs nothing and is the only way to count lines after the fact.
    text: &'a str,
    limits: Limits,
    depth: usize,
    elements: usize,
    /// The names of the elements currently open, innermost last.
    ///
    /// Bounded by `limits.max_depth`, which is checked before anything is
    /// pushed, so this cannot grow past sixty-four short strings.
    open: Vec<String>,
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
            text,
            limits,
            depth: 0,
            elements: 0,
            open: Vec::new(),
            pending_end: false,
            finished: false,
        }
    }

    /// Turns a byte offset into a line, a column and the element around it.
    ///
    /// The prefix is walked rather than sliced: an offset a parser hands back
    /// is not guaranteed to land on a character boundary, and slicing one that
    /// does not would panic inside an error path.
    pub(crate) fn locate(&self, offset: usize, element: Option<&str>) -> XmlLocation {
        let offset = offset.min(self.text.len());
        let mut line = 1usize;
        let mut column = 1usize;
        for (index, character) in self.text.char_indices() {
            if index >= offset {
                break;
            }
            if character == '\n' {
                line += 1;
                column = 1;
            } else {
                column += 1;
            }
        }
        let element = element
            .and_then(sanitise_name)
            .or_else(|| self.open.last().cloned());
        XmlLocation {
            line,
            column,
            offset,
            element,
        }
    }

    /// A located failure at wherever the reader currently is.
    pub(crate) fn refuse(&self, problem: XmlProblem) -> ImportError {
        ImportError::XmlNotWellFormed {
            problem,
            location: self.locate(self.here(), None),
        }
    }

    /// The same, for a problem whose own sentence already names the element.
    ///
    /// "the root element is <RoyalDocument>, not <Connections> (line 2, column
    /// 1, inside <RoyalDocument>)" says it twice; this says it once.
    pub(crate) fn refuse_unplaced(&self, problem: XmlProblem) -> ImportError {
        ImportError::XmlNotWellFormed {
            problem,
            location: XmlLocation {
                element: None,
                ..self.locate(self.here(), None)
            },
        }
    }

    /// The byte the reader has read up to.
    fn here(&self) -> usize {
        usize::try_from(self.reader.buffer_position()).unwrap_or(usize::MAX)
    }

    /// The next event, or `None` at the end of the document.
    ///
    /// # Errors
    ///
    /// Any of the bounded-parse refusals, or [`ImportError::XmlNotWellFormed`].
    pub(crate) fn next_event(&mut self) -> Result<Option<XmlEvent>, ImportError> {
        if self.pending_end {
            self.pending_end = false;
            self.depth = self.depth.saturating_sub(1);
            self.open.pop();
            return Ok(Some(XmlEvent::End));
        }
        if self.finished {
            return Ok(None);
        }

        loop {
            let event = self
                .reader
                .read_event()
                .map_err(|err| self.map_error(&err, None))?;
            match event {
                Event::Start(start) => {
                    let element = self.element(&start)?;
                    self.enter(&element.name)?;
                    return Ok(Some(XmlEvent::Start(element)));
                }
                Event::Empty(start) => {
                    let element = self.element(&start)?;
                    self.enter(&element.name)?;
                    self.pending_end = true;
                    return Ok(Some(XmlEvent::Start(element)));
                }
                Event::End(_) => {
                    // `check_end_names` guarantees this matches, so the counter
                    // cannot go negative; `saturating_sub` states that rather
                    // than relying on it.
                    self.depth = self.depth.saturating_sub(1);
                    self.open.pop();
                    return Ok(Some(XmlEvent::End));
                }
                Event::Text(text) => {
                    let decoded = text
                        .decode()
                        .map_err(|_| self.refuse(XmlProblem::Malformed))?;
                    if decoded.trim().is_empty() {
                        continue;
                    }
                    return Ok(Some(XmlEvent::Text(decoded.into_owned())));
                }
                Event::CData(data) => {
                    let decoded = data
                        .decode()
                        .map_err(|_| self.refuse(XmlProblem::Malformed))?;
                    return Ok(Some(XmlEvent::Text(decoded.into_owned())));
                }
                // An entity reference in character data. Skipping it would be
                // the wrong shape of safe: a document whose body is `&xxe;`
                // would parse as an empty body rather than as a refusal.
                Event::GeneralRef(reference) => {
                    let resolved = resolve_reference(&reference)
                        .map_err(|()| self.refuse(XmlProblem::UnknownEntity { attribute: None }))?;
                    return Ok(Some(XmlEvent::Text(resolved.into())));
                }
                // The whole reason this module exists.
                Event::DocType(_) => return Err(ImportError::DoctypeRefused),
                Event::Comment(_) | Event::PI(_) | Event::Decl(_) => {
                    continue;
                }
                Event::Eof => {
                    self.finished = true;
                    if self.depth > 0 {
                        // The element naming the location is the innermost one
                        // still open, which is the one the user has to go and
                        // close.
                        return Err(self.refuse(XmlProblem::Unclosed));
                    }
                    return Ok(None);
                }
            }
        }
    }

    /// Counts an element in, and records its name for the location of any
    /// failure inside it.
    fn enter(&mut self, name: &str) -> Result<(), ImportError> {
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
        // Pushed after the depth check, so the stack is bounded by `max_depth`
        // rather than by the document.
        self.open.push(name_in_message(name));
        Ok(())
    }

    fn element(&self, start: &quick_xml::events::BytesStart<'_>) -> Result<Element, ImportError> {
        let name = String::from_utf8_lossy(start.local_name().into_inner()).into_owned();
        let mut attributes = Vec::new();
        for attribute in start.attributes() {
            let attribute = attribute.map_err(|_| {
                // The element is not on the open stack yet — this runs while
                // its start tag is being read — so its name is passed in.
                ImportError::XmlNotWellFormed {
                    problem: XmlProblem::BadAttribute,
                    location: self.locate(self.here(), Some(&name)),
                }
            })?;
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
            // `decode_and_unescape_value` is deprecated as of quick-xml 0.41,
            // which this crate had to take for RUSTSEC-2026-0194 and
            // RUSTSEC-2026-0195. The replacement is not a behaviour change: in
            // 0.41 the deprecated method is a thin forwarder to
            // `decoded_and_normalized_value_with(XmlVersion::Implicit1_0,
            // decoder, 1, resolve_predefined_entity)`, which is precisely what
            // `decoded_and_normalized_value(XmlVersion::Implicit1_0, ..)`
            // calls. Passing `Implicit1_0` rather than `Explicit1_1` is the
            // load-bearing part — a confCons.xml is an XML 1.0 document, and
            // 1.1 normalisation folds a different set of characters.
            let value = attribute
                .decoded_and_normalized_value(XmlVersion::Implicit1_0, self.reader.decoder())
                // The attribute this failed on is the single most useful thing
                // the message can name: a stray `&` in `Name="R&D"` is the
                // commonest way a hand-edited confCons.xml stops parsing, and
                // "the Name attribute" is what sends the reader to it.
                .map_err(|err| self.map_error_in(&err, &name, sanitise_name(&key).as_deref()))?
                .into_owned();
            attributes.push((key, value));
        }
        Ok(Element { name, attributes })
    }

    /// The byte a failure should be reported at.
    ///
    /// `error_position()` points at the start of the markup that broke, which
    /// is what a reader wants — but it is zero for any failure quick-xml did
    /// not raise itself, and this module raises several. The read position is
    /// the fallback, and it is never zero once anything has been read.
    fn error_offset(&self) -> usize {
        let reported = usize::try_from(self.reader.error_position()).unwrap_or(usize::MAX);
        if reported == 0 { self.here() } else { reported }
    }

    /// quick-xml's own message is never carried through: it quotes the markup
    /// it choked on, and markup in a confCons.xml is ciphertext. Its *shape*,
    /// on the other hand, is exactly the diagnosis — and element names are
    /// structure, not content.
    fn map_error(&self, err: &XmlError, attribute: Option<&str>) -> ImportError {
        let problem = match err {
            XmlError::Escape(_) => XmlProblem::UnknownEntity {
                attribute: attribute.map(str::to_owned),
            },
            XmlError::Syntax(SyntaxError::UnclosedDoctype) => return ImportError::DoctypeRefused,
            XmlError::Syntax(_) => XmlProblem::Unclosed,
            XmlError::IllFormed(IllFormedError::MismatchedEndTag { expected, found }) => {
                XmlProblem::MismatchedEndTag {
                    expected: name_in_message(expected),
                    found: name_in_message(found),
                }
            }
            XmlError::IllFormed(
                IllFormedError::MissingEndTag(_) | IllFormedError::UnclosedReference,
            ) => XmlProblem::Unclosed,
            XmlError::IllFormed(IllFormedError::UnmatchedEndTag(found)) => {
                XmlProblem::MismatchedEndTag {
                    expected: self.open.last().cloned().unwrap_or_else(|| "?".to_owned()),
                    found: name_in_message(found),
                }
            }
            XmlError::InvalidAttr(_) => XmlProblem::BadAttribute,
            _ => XmlProblem::Malformed,
        };
        ImportError::XmlNotWellFormed {
            problem,
            location: self.locate(self.error_offset(), None),
        }
    }

    /// The same, for a failure inside an element whose start tag is still being
    /// read and so is not yet on the open stack.
    fn map_error_in(&self, err: &XmlError, element: &str, attribute: Option<&str>) -> ImportError {
        match self.map_error(err, attribute) {
            ImportError::XmlNotWellFormed { problem, location } => ImportError::XmlNotWellFormed {
                problem,
                location: XmlLocation {
                    element: sanitise_name(element),
                    ..location
                },
            },
            other => other,
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
///
/// The refusal is returned as `()` and located by the caller, which is the only
/// thing that knows where in the document this reference was.
fn resolve_reference(reference: &BytesRef<'_>) -> Result<char, ()> {
    if let Some(character) = reference.resolve_char_ref().map_err(|_| ())? {
        return Ok(character);
    }
    let name = reference.decode().map_err(|_| ())?;
    match name.as_ref() {
        "amp" => Ok('&'),
        "lt" => Ok('<'),
        "gt" => Ok('>'),
        "quot" => Ok('"'),
        "apos" => Ok('\''),
        _ => Err(()),
    }
}

/// A document's text, however the file spelled it.
///
/// Two cases rather than a `Cow` because the second one holds the file's
/// plaintext — a CSV export carries its passwords in the clear, and an
/// mRemoteNG document carries the base64 its passwords are inside — and the
/// buffer it was transcoded into has to wipe itself the way the buffer it was
/// read from does. `Cow::Owned(String)` would leave a second copy of the file
/// on the heap for the allocator to hand to whatever asks next.
pub(crate) enum SourceText<'a> {
    /// The file was UTF-8 and the text is the caller's own bytes.
    Borrowed(&'a str),
    /// The file was in another encoding and had to be converted.
    Transcoded(Zeroizing<String>),
}

impl core::ops::Deref for SourceText<'_> {
    type Target = str;

    fn deref(&self) -> &str {
        match self {
            Self::Borrowed(text) => text,
            Self::Transcoded(text) => text,
        }
    }
}

/// A byte-order mark, and what it says the file is.
enum ByteOrderMark {
    Utf8,
    Utf16Le,
    Utf16Be,
}

impl ByteOrderMark {
    /// Reads the mark at the head of `bytes`, if there is one.
    ///
    /// Only a mark is honoured, never a guess: an XML declaration's `encoding`
    /// pseudo-attribute is content, and a heuristic over byte frequencies would
    /// make the encoding of a file depend on what its hostnames happen to be.
    const fn read(bytes: &[u8]) -> Option<(Self, usize)> {
        match bytes {
            [0xef, 0xbb, 0xbf, ..] => Some((Self::Utf8, 3)),
            // A UTF-32LE file opens FF FE 00 00, which is a UTF-16LE mark
            // followed by a NUL. Reading it as UTF-16 yields a document whose
            // first character is a NUL, which no parser here accepts — a
            // refusal, which is the right answer for an encoding this does not
            // read.
            [0xff, 0xfe, ..] => Some((Self::Utf16Le, 2)),
            [0xfe, 0xff, ..] => Some((Self::Utf16Be, 2)),
            _ => None,
        }
    }
}

/// Decodes UTF-16 code units into a buffer that wipes itself.
///
/// `lossy` is for the fixed-size window [`crate::detect`] sniffs, which can cut
/// a surrogate pair in half at its edge; a whole document is decoded strictly,
/// so a file that is not the encoding its mark claims is refused rather than
/// filled with replacement characters.
fn decode_utf16(bytes: &[u8], big_endian: bool, lossy: bool) -> Option<Zeroizing<String>> {
    if !lossy && bytes.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| {
            let pair = [pair[0], pair[1]];
            if big_endian {
                u16::from_be_bytes(pair)
            } else {
                u16::from_le_bytes(pair)
            }
        })
        .collect();
    if lossy {
        return Some(Zeroizing::new(String::from_utf16_lossy(&units)));
    }
    String::from_utf16(&units).ok().map(Zeroizing::new)
}

/// Reads the head of a file as text, for format detection.
///
/// Lossy throughout: the window is a fixed number of bytes and will cut a
/// character in half at its edge, which is not a reason to give up on the bytes
/// before it. Nothing here decides whether a file is readable — [`as_text`]
/// does that, strictly, once a format has been chosen.
pub(crate) fn sniff_head(bytes: &[u8]) -> SourceText<'_> {
    match ByteOrderMark::read(bytes) {
        Some((ByteOrderMark::Utf16Le, skip)) => decode_utf16(&bytes[skip..], false, true),
        Some((ByteOrderMark::Utf16Be, skip)) => decode_utf16(&bytes[skip..], true, true),
        Some((ByteOrderMark::Utf8, skip)) => return utf8_head(&bytes[skip..]),
        // No mark means UTF-8, which is what every exporter this crate reads
        // writes.
        None => return utf8_head(bytes),
    }
    .map_or(SourceText::Borrowed(""), SourceText::Transcoded)
}

/// The UTF-8 half of [`sniff_head`], truncated at the first byte that is not
/// part of a character.
fn utf8_head(bytes: &[u8]) -> SourceText<'_> {
    SourceText::Borrowed(
        core::str::from_utf8(bytes)
            .unwrap_or_else(|err| core::str::from_utf8(&bytes[..err.valid_up_to()]).unwrap_or("")),
    )
}

/// Checks the size and encoding of an input before any parser sees it.
///
/// UTF-8 is the encoding every format this crate reads is written in, and is
/// the only one a file gets without saying so. A file that opens with a UTF-16
/// byte-order mark is converted rather than refused: mRemoteNG writes UTF-8,
/// but a `confCons.xml` that has been through a `>` redirect in Windows
/// PowerShell 5 or re-saved from Notepad as "Unicode" arrives as UTF-16, and
/// the file is otherwise perfectly readable.
///
/// # Errors
///
/// [`ImportError::TooLarge`] or [`ImportError::NotUtf8`].
pub(crate) fn as_text<'a>(bytes: &'a [u8], limits: &Limits) -> Result<SourceText<'a>, ImportError> {
    if bytes.len() > limits.max_input_bytes {
        return Err(ImportError::TooLarge {
            size: bytes.len(),
            limit: limits.max_input_bytes,
        });
    }

    let (mark, skip) = match ByteOrderMark::read(bytes) {
        // A file with no mark is UTF-8, which is what every exporter this crate
        // reads actually writes.
        None => (ByteOrderMark::Utf8, 0),
        Some(found) => found,
    };
    let body = &bytes[skip..];

    let text = match mark {
        // A UTF-8 byte-order mark is legal at the head of an XML document and
        // of a CSV written by a spreadsheet, and is not part of the content.
        ByteOrderMark::Utf8 => {
            return core::str::from_utf8(body)
                .map(SourceText::Borrowed)
                .map_err(|err| ImportError::NotUtf8 {
                    offset: err.valid_up_to().saturating_add(skip),
                });
        }
        ByteOrderMark::Utf16Le => decode_utf16(body, false, false),
        ByteOrderMark::Utf16Be => decode_utf16(body, true, false),
    };
    // The mark promised UTF-16 and the bytes are not: an odd length, or a
    // surrogate with no partner. Reported at the mark, which is the claim that
    // turned out to be false.
    let text = text.ok_or(ImportError::NotUtf8 { offset: 0 })?;

    // UTF-16 grows by half when it converts — a three-byte UTF-8 character is
    // one code unit — so a document that was inside the limit as bytes can be
    // outside it as text, and the parsers below work against the text.
    if text.len() > limits.max_input_bytes {
        return Err(ImportError::TooLarge {
            size: text.len(),
            limit: limits.max_input_bytes,
        });
    }
    Ok(SourceText::Transcoded(text))
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
        assert_eq!(
            events(xml, Limits::new()),
            Err(ImportError::XmlNotWellFormed {
                problem: XmlProblem::UnknownEntity {
                    attribute: Some("a".to_owned())
                },
                location: XmlLocation {
                    line: 1,
                    column: 18,
                    offset: 17,
                    element: Some("r".to_owned()),
                },
            })
        );
    }

    /// The case this whole located-error machinery exists for: a `confCons.xml`
    /// that a person edited by hand and left a bare `&` in. Before, this was
    /// reported as a document "written to exhaust memory", with no position at
    /// all — quick-xml raises no error here, so `error_position()` was zero and
    /// the message said byte 0 of a file broken hundreds of lines in.
    #[test]
    fn a_stray_ampersand_names_the_attribute_and_the_line_it_is_on() {
        let xml =
            "<Connections>\n  <Node Name=\"ok\"/>\n  <Node Name=\"R&D box\"/>\n</Connections>";
        let Err(ImportError::XmlNotWellFormed { problem, location }) = events(xml, Limits::new())
        else {
            panic!("expected a located refusal");
        };
        assert_eq!(
            problem,
            XmlProblem::UnknownEntity {
                attribute: Some("Name".to_owned())
            }
        );
        assert_eq!(location.line, 3);
        assert_eq!(location.element.as_deref(), Some("Node"));
        // And the sentence a reader gets says what to do about it.
        let message = ImportError::XmlNotWellFormed { problem, location }.to_string();
        assert!(message.contains("&amp;"), "{message}");
        assert!(message.contains("line 3"), "{message}");
        assert!(message.contains("<Node>"), "{message}");
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
        let Err(ImportError::XmlNotWellFormed { problem, location }) =
            events("<r>&xxe;</r>", Limits::new())
        else {
            panic!("expected a located refusal");
        };
        // In character data there is no attribute to name, only the element.
        assert_eq!(problem, XmlProblem::UnknownEntity { attribute: None });
        assert_eq!(location.element.as_deref(), Some("r"));
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
    fn a_truncated_document_is_reported_as_truncated_and_placed() {
        // The element named is the innermost one still open — the one the
        // reader has to go and close.
        let Err(ImportError::XmlNotWellFormed { problem, location }) =
            events("<a>\n  <b>\n", Limits::new())
        else {
            panic!("expected a located refusal");
        };
        assert_eq!(problem, XmlProblem::Unclosed);
        assert_eq!(location.element.as_deref(), Some("b"));

        let Err(ImportError::XmlNotWellFormed { problem, location }) =
            events("<a>\n<b c=\"unclosed", Limits::new())
        else {
            panic!("expected a located refusal");
        };
        assert_eq!(problem, XmlProblem::Unclosed);
        assert_eq!(location.line, 2);
    }

    #[test]
    fn a_mismatched_end_tag_names_both_elements() {
        let Err(ImportError::XmlNotWellFormed { problem, location }) = events(
            "<Connections>\n  <Node>\n  </Nodes>\n</Connections>",
            Limits::new(),
        ) else {
            panic!("expected a located refusal");
        };
        assert_eq!(
            problem,
            XmlProblem::MismatchedEndTag {
                expected: "Node".to_owned(),
                found: "Nodes".to_owned(),
            }
        );
        assert_eq!(location.line, 3);
    }

    #[test]
    fn a_location_is_counted_in_characters_and_never_splits_one() {
        // A multi-byte character before the break: the column counts characters
        // so it matches what an editor shows, and the prefix is walked rather
        // than sliced so an offset inside a character cannot panic.
        let Err(ImportError::XmlNotWellFormed { location, .. }) =
            events("<a>\n<b名=\"x\" c=\"&nope;\"/>\n</a>", Limits::new())
        else {
            panic!("expected a located refusal");
        };
        assert_eq!(location.line, 2);
        assert!(location.offset > location.column, "offset counts bytes");
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

    /// `SourceText` has no `Debug` on purpose — it holds the file's plaintext
    /// — so a test reads it through the deref rather than comparing `Result`s.
    fn text_of(result: Result<SourceText<'_>, ImportError>) -> Result<String, ImportError> {
        result.map(|text| text.to_string())
    }

    #[test]
    fn oversized_and_non_utf8_input_is_refused_before_parsing() {
        let limits = Limits {
            max_input_bytes: 4,
            ..Limits::new()
        };
        assert_eq!(
            text_of(as_text(b"aaaaaaaa", &limits)),
            Err(ImportError::TooLarge { size: 8, limit: 4 })
        );
        assert_eq!(
            text_of(as_text(b"ab\xffcd", &Limits::new())),
            Err(ImportError::NotUtf8 { offset: 2 })
        );
        assert_eq!(
            text_of(as_text("\u{feff}<a/>".as_bytes(), &Limits::new())),
            Ok("<a/>".to_owned())
        );
    }

    /// mRemoteNG writes UTF-8, but a `confCons.xml` does not always reach
    /// Remoter the way mRemoteNG wrote it: a `>` redirect in Windows
    /// PowerShell 5 and Notepad's "Unicode" both produce UTF-16LE, and the
    /// document inside is unchanged.
    #[test]
    fn a_utf16_document_is_converted_rather_than_refused() {
        let document = r#"<Connections Name="Acme"><Node Name="web-01"/></Connections>"#;

        let mut le = vec![0xff, 0xfe];
        for unit in document.encode_utf16() {
            le.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(
            text_of(as_text(&le, &Limits::new())),
            Ok(document.to_owned())
        );

        let mut be = vec![0xfe, 0xff];
        for unit in document.encode_utf16() {
            be.extend_from_slice(&unit.to_be_bytes());
        }
        assert_eq!(
            text_of(as_text(&be, &Limits::new())),
            Ok(document.to_owned())
        );

        // And the parse that follows sees an ordinary document.
        let events = events(&as_text(&le, &Limits::new()).unwrap(), Limits::new()).unwrap();
        let XmlEvent::Start(root) = &events[0] else {
            panic!("expected a start event");
        };
        assert_eq!(root.name, "Connections");
        assert_eq!(root.attribute("Name"), Some("Acme"));
    }

    #[test]
    fn a_mark_that_lies_about_the_encoding_is_refused_rather_than_mangled() {
        // An odd number of bytes cannot be UTF-16 code units.
        assert_eq!(
            text_of(as_text(&[0xff, 0xfe, b'<', b'\0', b'a'], &Limits::new())),
            Err(ImportError::NotUtf8 { offset: 0 })
        );
        // A high surrogate with no partner is not a character.
        assert_eq!(
            text_of(as_text(
                &[0xff, 0xfe, 0x00, 0xd8, 0x3c, 0x00],
                &Limits::new()
            )),
            Err(ImportError::NotUtf8 { offset: 0 })
        );
    }

    /// The conversion is where a document can cross the size limit it was
    /// inside as bytes, and the parsers below work against the text.
    #[test]
    fn a_transcoded_document_is_measured_again_after_it_grows() {
        // Six UTF-16 code units — twelve bytes plus the mark — that become
        // eighteen bytes of UTF-8.
        let mut bytes = vec![0xff, 0xfe];
        for unit in "日本語日本語".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let limits = Limits {
            max_input_bytes: 14,
            ..Limits::new()
        };
        assert_eq!(
            text_of(as_text(&bytes, &limits)),
            Err(ImportError::TooLarge {
                size: 18,
                limit: 14
            })
        );
    }
}
