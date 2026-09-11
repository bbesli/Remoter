//! mRemoteNG's `confCons.xml`.
//!
//! The most important import target and the best documented one. A tree of
//! `<Node>` elements carrying `Hostname`, `Protocol`, `Port`, `Username`,
//! `Domain`, `Password` and a large set of protocol options, wrapped in a
//! `<Connections>` root that declares how the file is encrypted.
//!
//! ## Why this importer is worth having
//!
//! mRemoteNG's inheritance model is the same shape as Remoter's, and that is
//! the whole reason to write a mapper rather than a flattener. Each inheritable
//! attribute `Foo` has a companion `InheritFoo`; where it is set, the value on
//! the node is meaningless and the effective value comes from the parent
//! container. That maps onto [`Inherited::Inherit`] exactly, and everything
//! else onto [`Inherited::Explicit`]. An estate whose ports and credentials are
//! set once on a folder arrives with them still set once on a folder.
//!
//! The same rule governs what is preserved: an attribute the domain model has
//! no home for is kept verbatim in `custom_fields` under `mremoteng.<Attr>`,
//! but only when the node sets it. Preserving a value the file says is
//! inherited would turn one setting on a folder into four hundred settings on
//! four hundred connections, which is the flattening this importer exists to
//! avoid.
//!
//! ## What is deliberately dropped
//!
//! `RDGatewayPassword` and `VNCProxyPassword` are secrets belonging to fields
//! the domain model does not model. They are not written to `custom_fields`,
//! because `custom_fields` is not an encrypted field: a password there would be
//! a plaintext password in the vault's clear metadata. The report names each
//! one instead.

mod crypto;

use std::collections::HashMap;

use remoter_core::{
    ConnectionProps, FolderProps, GatewayChain, GatewayHop, Inherited, NodeId, ProtocolId,
    validate_host,
};

pub use crypto::{CipherMode, DEFAULT_PASSWORD};

use crate::error::{ImportError, XmlProblem};
use crate::limits::Limits;
use crate::mapping::{
    CredentialPool, clean_description, clean_name, custom_key, parse_bool, parse_port, preserve,
};
use crate::preview::{ImportPreview, PreviewBuilder, PreviewKind, PreviewNode, PreviewSecret};
use crate::report::{Finding, SkipReason, SourceFormat};
use crate::secret::ImportedSecret;
use crate::xml::{BoundedXmlReader, Element, XmlEvent, as_text, name_in_message};

use crypto::Decryptor;

/// Attributes the mapping consumes itself, so the generic preservation pass
/// does not also copy them into `custom_fields`.
const MAPPED: &[&str] = &[
    "Name",
    "Type",
    "Descr",
    "Hostname",
    "Protocol",
    "Port",
    "Username",
    "Domain",
    "Password",
    "SSHTunnelConnectionName",
    "Connected",
];

/// Attributes holding a secret in a field Remoter does not model. Never
/// preserved; always reported.
const UNMAPPED_SECRETS: &[&str] = &["RDGatewayPassword", "VNCProxyPassword"];

/// The element a `confCons.xml` begins with.
const ROOT_ELEMENT: &str = "Connections";

/// What the root element says about the file, without reading its body.
///
/// The import flow in `docs/features/import-export.md` asks for the file
/// password at step 2, before the parse at step 3. This is what step 2 needs in
/// order to know whether to ask at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentInfo {
    /// The root node's name, as the user named their connection file.
    pub name: String,
    /// The `ConfVersion` the file declares, if it declares one.
    pub conf_version: Option<String>,
    /// The scheme the file's secrets are encrypted with.
    pub cipher: CipherMode,
    /// Whether the whole document is encrypted rather than only its passwords.
    pub full_file_encryption: bool,
    /// Whether the file needs a password the user has to supply. False when the
    /// file is on mRemoteNG's published default.
    pub password_required: bool,
}

/// Reads the root element and stops.
///
/// # Errors
///
/// Anything [`parse`] can fail with while reading a root element, plus
/// [`ImportError::XmlNotWellFormed`] with
/// [`XmlProblem::UnexpectedRoot`](crate::XmlProblem::UnexpectedRoot) if the
/// document is not a `<Connections>` one.
pub fn inspect(bytes: &[u8], limits: &Limits) -> Result<DocumentInfo, ImportError> {
    let text = as_text(bytes, limits)?;
    let mut reader = BoundedXmlReader::new(text, *limits);
    let root = read_root(&mut reader)?;
    let cipher = root.cipher()?;
    let default = Decryptor::with_default_password(cipher);
    Ok(DocumentInfo {
        name: clean_name(&root.name),
        conf_version: root.conf_version.clone(),
        cipher,
        full_file_encryption: root.full_file_encryption,
        password_required: default.authenticate(&root.protected).is_err(),
    })
}

/// Parses a `confCons.xml` into the tree it would create.
///
/// `password` is the file password. `None` means the file is expected to be on
/// mRemoteNG's default; if it is not, the error is
/// [`ImportError::PasswordRequired`] rather than a wrong-password one, so the
/// interface can tell "ask the user" from "the user answered wrongly".
///
/// # Errors
///
/// Any [`ImportError`]. Problems affecting a single node are reported on the
/// preview's report and do not fail the import.
pub fn parse(
    bytes: &[u8],
    password: Option<&ImportedSecret>,
    limits: &Limits,
) -> Result<ImportPreview, ImportError> {
    let text = as_text(bytes, limits)?;
    let mut reader = BoundedXmlReader::new(text, *limits);
    let root = read_root(&mut reader)?;
    let cipher = root.cipher()?;

    let decryptor = match password {
        Some(password) => Decryptor::new(cipher, password.expose()),
        None => Decryptor::with_default_password(cipher),
    };
    if let Err(err) = decryptor.authenticate(&root.protected) {
        // A file that will not open on the default password needs one from the
        // user; that is a different thing to tell them than "wrong password".
        return Err(if password.is_none() {
            ImportError::PasswordRequired
        } else {
            err
        });
    }

    let mut builder = PreviewBuilder::new(SourceFormat::MRemoteNg, *limits);
    // The file states which case it is: mRemoteNG writes a different marker
    // into `Protected` when the user never set a password.
    if decryptor.declares_no_protection(&root.protected) {
        builder
            .report_mut()
            .push(limits, Finding::DefaultFilePassword);
    }
    if decryptor.is_legacy() {
        builder
            .report_mut()
            .push(limits, Finding::LegacyCbcEncryption);
    }

    // Full-file encryption puts the whole node tree in the root element's text,
    // so the body has to be decrypted and re-parsed before the walk can start.
    // The decrypted document stays inside an `ImportedSecret` for the length of
    // the parse and is zeroed when this function returns.
    let decrypted;
    let mut walker = Walker::new(&decryptor);
    if root.full_file_encryption {
        builder
            .report_mut()
            .push(limits, Finding::FullFileEncryption);
        let body = collect_text(&mut reader, limits)?;
        decrypted = decryptor.decrypt(&body)?;
        let document = format!("<Connections>{}</Connections>", decrypted.expose());
        if document.len() > limits.max_input_bytes {
            return Err(ImportError::TooLarge {
                size: document.len(),
                limit: limits.max_input_bytes,
            });
        }
        let mut inner = BoundedXmlReader::new(&document, *limits);
        read_root(&mut inner)?;
        walker.walk(&mut inner, &mut builder)?;
    } else {
        walker.walk(&mut reader, &mut builder)?;
    }

    walker.finish(&mut builder);
    Ok(builder.finish())
}

/// The `<Connections>` element's attributes.
struct Root {
    name: String,
    conf_version: Option<String>,
    engine: Option<String>,
    mode: Option<String>,
    kdf_iterations: Option<String>,
    full_file_encryption: bool,
    protected: String,
}

impl Root {
    fn cipher(&self) -> Result<CipherMode, ImportError> {
        CipherMode::from_attributes(
            self.engine.as_deref(),
            self.mode.as_deref(),
            self.kdf_iterations.as_deref(),
        )
    }
}

/// Reads events until the `<Connections>` element opens, and describes it.
///
/// The two refusals here are what a user meets when they choose the wrong file
/// — a Royal TS document, a `.rdg`, last week's screenshot — so both name what
/// was found rather than only what was wanted.
fn read_root(reader: &mut BoundedXmlReader<'_>) -> Result<Root, ImportError> {
    let Some(XmlEvent::Start(element)) = reader.next_event()? else {
        return Err(reader.refuse_unplaced(XmlProblem::NoRootElement {
            expected: ROOT_ELEMENT,
        }));
    };
    if element.name != ROOT_ELEMENT {
        return Err(reader.refuse_unplaced(XmlProblem::UnexpectedRoot {
            found: name_in_message(&element.name),
            expected: ROOT_ELEMENT,
        }));
    }
    Ok(Root {
        name: element
            .attribute("Name")
            .unwrap_or("Connections")
            .to_owned(),
        conf_version: element.attribute("ConfVersion").map(str::to_owned),
        engine: element.attribute("EncryptionEngine").map(str::to_owned),
        mode: element.attribute("BlockCipherMode").map(str::to_owned),
        kdf_iterations: element.attribute("KdfIterations").map(str::to_owned),
        full_file_encryption: element
            .attribute("FullFileEncryption")
            .is_some_and(parse_bool),
        protected: element.attribute("Protected").unwrap_or("").to_owned(),
    })
}

/// Gathers the text of the element the reader is inside.
fn collect_text(reader: &mut BoundedXmlReader<'_>, limits: &Limits) -> Result<String, ImportError> {
    let mut out = String::new();
    while let Some(event) = reader.next_event()? {
        match event {
            XmlEvent::Text(text) => {
                if out.len().saturating_add(text.len()) > limits.max_input_bytes {
                    return Err(ImportError::TooLarge {
                        size: limits.max_input_bytes,
                        limit: limits.max_input_bytes,
                    });
                }
                out.push_str(&text);
            }
            XmlEvent::End => break,
            XmlEvent::Start(_) => {
                return Err(ImportError::WrongFormat {
                    expected: "an encrypted body, not markup",
                });
            }
        }
    }
    Ok(out)
}

/// One level of the `<Node>` tree being walked.
struct Frame {
    /// The container children of this element attach to. For a connection node
    /// this is its own parent, because a connection holds no children.
    container: Option<NodeId>,
    next_sort: i64,
}

/// A gateway that names another connection and has to wait for the second pass.
struct PendingGateway {
    connection: NodeId,
    connection_name: String,
    target: String,
}

/// Walks the `<Node>` tree, building the preview.
struct Walker<'a> {
    decryptor: &'a Decryptor,
    credentials: CredentialPool,
    /// Connection nodes by name, for resolving SSH tunnel references.
    by_name: HashMap<String, NodeId>,
    pending: Vec<PendingGateway>,
    secrets: usize,
}

impl<'a> Walker<'a> {
    fn new(decryptor: &'a Decryptor) -> Self {
        Self {
            decryptor,
            credentials: CredentialPool::new("Imported credentials"),
            by_name: HashMap::new(),
            pending: Vec::new(),
            secrets: 0,
        }
    }

    /// Walks to the end of the document the reader is inside.
    ///
    /// Iterative rather than recursive. Depth is bounded by the reader, so
    /// recursion would be safe, but an explicit stack keeps the bound and the
    /// walk in the same place.
    fn walk(
        &mut self,
        reader: &mut BoundedXmlReader<'_>,
        builder: &mut PreviewBuilder,
    ) -> Result<(), ImportError> {
        let mut stack: Vec<Frame> = vec![Frame {
            container: None,
            next_sort: 0,
        }];

        while let Some(event) = reader.next_event()? {
            match event {
                XmlEvent::Start(element) => {
                    let Some(frame) = stack.last_mut() else {
                        // The root's end tag was already consumed; anything
                        // after it is not part of the tree.
                        return Ok(());
                    };
                    let parent = frame.container;
                    if element.name != "Node" {
                        // Not part of the connection tree, but its children may
                        // be, so the frame keeps the same parent.
                        stack.push(Frame {
                            container: parent,
                            next_sort: 0,
                        });
                        continue;
                    }
                    let sort = frame.next_sort;
                    frame.next_sort += 1;
                    let placed = self.node(builder, &element, parent, sort)?;
                    // A connection holds no children, so anything nested under
                    // one attaches to the nearest container instead of being
                    // dropped.
                    stack.push(Frame {
                        container: placed.or(parent),
                        next_sort: 0,
                    });
                }
                XmlEvent::End => {
                    if stack.pop().is_none() {
                        return Ok(());
                    }
                }
                XmlEvent::Text(_) => {}
            }
        }
        Ok(())
    }

    /// Maps one `<Node>`.
    ///
    /// Returns the id children should attach to: the node's own id for a
    /// container, and `None` for anything else, which leaves the caller's
    /// parent in place.
    fn node(
        &mut self,
        builder: &mut PreviewBuilder,
        element: &Element,
        parent: Option<NodeId>,
        sort: i64,
    ) -> Result<Option<NodeId>, ImportError> {
        let limits = *builder.limits();
        let kind = element.attribute("Type").unwrap_or("Connection");
        let raw_name = element.attribute("Name").unwrap_or("");
        let host = element.attribute("Hostname").unwrap_or("").trim();

        let mut name = clean_name(raw_name);
        if name.is_empty() {
            name = clean_name(host);
        }
        if name.is_empty() {
            builder.report_mut().counts_mut().skipped += 1;
            builder.report_mut().push(
                &limits,
                Finding::SkippedItem {
                    item: clean_name(host),
                    reason: SkipReason::UnusableName,
                },
            );
            return Ok(None);
        }

        if kind.eq_ignore_ascii_case("Container") {
            return self
                .container(builder, element, &name, parent, sort)
                .map(Some);
        }
        if !kind.eq_ignore_ascii_case("Connection") {
            // `PuttySession` and the root marker are the other spellings
            // mRemoteNG writes. Neither is a target this application opens.
            builder.report_mut().counts_mut().skipped += 1;
            builder.report_mut().push(
                &limits,
                Finding::SkippedItem {
                    item: name,
                    reason: SkipReason::UnsupportedKind,
                },
            );
            return Ok(None);
        }

        self.connection(builder, element, name, parent, sort)?;
        Ok(None)
    }

    fn container(
        &mut self,
        builder: &mut PreviewBuilder,
        element: &Element,
        name: &str,
        parent: Option<NodeId>,
        sort: i64,
    ) -> Result<NodeId, ImportError> {
        let mut props = FolderProps {
            port: self.inherited_port(element),
            ..FolderProps::default()
        };
        props.credential = self.inherited_credential(builder, element, name, None)?;

        let mut node = PreviewNode::new(NodeId::new(), name.to_owned(), PreviewKind::Folder(props))
            .under(parent, sort);
        node.description = clean_description(element.attribute("Descr").unwrap_or(""));
        self.preserve_rest(builder, &mut node, element, name);
        builder.push(node)
    }

    fn connection(
        &mut self,
        builder: &mut PreviewBuilder,
        element: &Element,
        name: String,
        parent: Option<NodeId>,
        sort: i64,
    ) -> Result<(), ImportError> {
        let limits = *builder.limits();
        let host = element.attribute("Hostname").unwrap_or("").trim();
        if validate_host(host).is_err() {
            builder.report_mut().counts_mut().skipped += 1;
            builder.report_mut().push(
                &limits,
                Finding::SkippedItem {
                    item: name,
                    reason: SkipReason::UnusableHost,
                },
            );
            return Ok(());
        }

        let raw_protocol = element.attribute("Protocol").unwrap_or("SSH2");
        let Some(protocol) = map_protocol(raw_protocol) else {
            builder.report_mut().counts_mut().skipped += 1;
            builder.report_mut().push(
                &limits,
                Finding::SkippedItem {
                    item: name,
                    reason: SkipReason::UnsupportedKind,
                },
            );
            return Ok(());
        };
        if !is_known_protocol(raw_protocol) {
            builder.report_mut().push(
                &limits,
                Finding::UnknownProtocol {
                    item: name.clone(),
                    protocol: clean_name(raw_protocol),
                    mapped_to: protocol.as_str().to_owned(),
                },
            );
        }

        let mut props = ConnectionProps::new(protocol.as_str(), host)?;
        props.port = self.inherited_port(element);
        props.credential =
            self.inherited_credential(builder, element, &name, Some(protocol.clone()))?;

        let id = NodeId::new();
        let mut node =
            PreviewNode::new(id, name.clone(), PreviewKind::Connection(props)).under(parent, sort);
        node.description = clean_description(element.attribute("Descr").unwrap_or(""));

        // The tunnel reference names another connection, which may not have
        // been read yet, so it is resolved in the second pass.
        let inherits_tunnel = inherits(element, "SSHTunnelConnectionName");
        let tunnel = element
            .attribute("SSHTunnelConnectionName")
            .unwrap_or("")
            .trim();
        if !inherits_tunnel && !tunnel.is_empty() {
            self.pending.push(PendingGateway {
                connection: id,
                connection_name: name.clone(),
                target: tunnel.to_owned(),
            });
        }

        self.preserve_rest(builder, &mut node, element, &name);
        builder.push(node)?;
        self.by_name.entry(name).or_insert(id);
        Ok(())
    }

    /// `InheritPort` decides between the two states; a port that will not parse
    /// is treated as unset rather than as a reason to drop the connection.
    fn inherited_port(&self, element: &Element) -> Inherited<u16> {
        if inherits(element, "Port") {
            return Inherited::Inherit;
        }
        element
            .attribute("Port")
            .and_then(parse_port)
            .map_or(Inherited::Inherit, Inherited::Explicit)
    }

    /// Maps `Username`, `Domain` and `Password` onto a credential reference.
    ///
    /// Remoter has one credential field where mRemoteNG has three, so the three
    /// inheritance flags collapse into one: a node that inherits all of them
    /// inherits its credential, and a node that sets any of them sets it.
    fn inherited_credential(
        &mut self,
        builder: &mut PreviewBuilder,
        element: &Element,
        name: &str,
        protocol: Option<ProtocolId>,
    ) -> Result<Inherited<remoter_core::CredentialRef>, ImportError> {
        let inherits_all = inherits(element, "Username")
            && inherits(element, "Password")
            && inherits(element, "Domain");
        if inherits_all {
            return Ok(Inherited::Inherit);
        }

        let username = if inherits(element, "Username") {
            ""
        } else {
            element.attribute("Username").unwrap_or("")
        };
        let domain = if inherits(element, "Domain") {
            ""
        } else {
            element.attribute("Domain").unwrap_or("")
        };
        let encrypted = if inherits(element, "Password") {
            ""
        } else {
            element.attribute("Password").unwrap_or("")
        };

        let password = if encrypted.is_empty() {
            None
        } else {
            match self.decryptor.decrypt(encrypted) {
                Ok(secret) if secret.is_empty() => None,
                Ok(secret) => {
                    self.secrets += 1;
                    Some(secret)
                }
                Err(_) => {
                    // The file's own authenticator already passed, so a field
                    // that will not decrypt is a damaged field, not a wrong
                    // password. Reported, and the connection keeps everything
                    // else it had.
                    let limits = *builder.limits();
                    builder.report_mut().push(
                        &limits,
                        Finding::SecretNotMapped {
                            item: name.to_owned(),
                            field: "Password".to_owned(),
                        },
                    );
                    None
                }
            }
        };

        if username.is_empty() && domain.is_empty() && password.is_none() {
            return Ok(Inherited::Inherit);
        }

        let secret = password.map_or(
            // No password came across, so nothing is stored. For SSH this is
            // also the recommended arrangement: the agent holds the key and it
            // never enters this process.
            PreviewSecret::Unsealed(remoter_core::SecretKind::Agent {
                comment_filter: None,
            }),
            PreviewSecret::Password,
        );
        let reference = self.credentials.intern(
            builder,
            name,
            username.to_owned(),
            (!domain.is_empty()).then(|| domain.to_owned()),
            secret,
            protocol.into_iter().collect(),
        )?;
        Ok(Inherited::Explicit(reference))
    }

    /// Copies every attribute the mapping did not consume into `custom_fields`,
    /// skipping the ones the file says are inherited.
    fn preserve_rest(
        &self,
        builder: &mut PreviewBuilder,
        node: &mut PreviewNode,
        element: &Element,
        name: &str,
    ) {
        let limits = *builder.limits();
        let mut kept = 0usize;
        let mut dropped = 0usize;
        for (key, value) in &element.attributes {
            if value.is_empty() || MAPPED.contains(&key.as_str()) {
                continue;
            }
            if UNMAPPED_SECRETS.contains(&key.as_str()) {
                // Deliberately not preserved. See the module comment.
                builder.report_mut().push(
                    &limits,
                    Finding::SecretNotMapped {
                        item: name.to_owned(),
                        field: key.clone(),
                    },
                );
                continue;
            }
            // An `Inherit*` flag is inheritance state, which the mapping has
            // already turned into `Inherited::Inherit` where it matters, and
            // which would otherwise be copied as data.
            if key.starts_with("Inherit") {
                continue;
            }
            if inherits(element, key) {
                continue;
            }
            let Some(field) = custom_key("mremoteng", key) else {
                continue;
            };
            if preserve(node, field, value.clone(), limits.max_custom_fields) {
                kept += 1;
            } else if node.custom_fields.len() >= limits.max_custom_fields {
                dropped += 1;
            }
        }
        if kept > 0 {
            builder.report_mut().push(
                &limits,
                Finding::SettingsPreserved {
                    item: name.to_owned(),
                    count: kept,
                },
            );
        }
        if dropped > 0 {
            // The preview is a partial one for this node, and saying so is the
            // difference between a lossy import and a silent one.
            builder.report_mut().push(
                &limits,
                Finding::LimitReached {
                    limit: "custom_fields".to_owned(),
                },
            );
        }
    }

    /// Resolves the SSH tunnel references gathered during the walk.
    fn finish(self, builder: &mut PreviewBuilder) {
        let limits = *builder.limits();
        for pending in self.pending {
            match self.by_name.get(&pending.target) {
                Some(target) if *target != pending.connection => {
                    builder.set_gateway(
                        pending.connection,
                        Inherited::Explicit(GatewayChain {
                            hops: vec![GatewayHop::new(*target)],
                        }),
                    );
                    builder.report_mut().push(
                        &limits,
                        Finding::GatewayMapped {
                            item: pending.connection_name,
                            hops: 1,
                        },
                    );
                }
                _ => {
                    // Either the name matches nothing, or it matches the
                    // connection itself — a tunnel through itself is a loop the
                    // domain model would reject anyway.
                    if let Some(node) = builder.node_mut(pending.connection) {
                        if let Some(key) = custom_key("mremoteng", "SSHTunnelConnectionName") {
                            preserve(node, key, pending.target.clone(), limits.max_custom_fields);
                        }
                    }
                    builder.report_mut().push(
                        &limits,
                        Finding::GatewayUnresolved {
                            item: pending.connection_name,
                            target: clean_name(&pending.target),
                        },
                    );
                }
            }
        }
        if self.secrets > 0 {
            builder.report_mut().push(
                &limits,
                Finding::SecretsRecovered {
                    count: self.secrets,
                },
            );
        }
        self.credentials.finish(builder);
    }
}

/// Whether the file says this attribute's value comes from the parent.
fn inherits(element: &Element, attribute: &str) -> bool {
    element
        .attribute(&format!("Inherit{attribute}"))
        .is_some_and(parse_bool)
}

/// Whether this build recognises the protocol name mRemoteNG wrote.
fn is_known_protocol(raw: &str) -> bool {
    matches!(
        raw.trim(),
        "RDP" | "VNC" | "SSH1" | "SSH2" | "Telnet" | "Rlogin" | "RAW" | "HTTP" | "HTTPS"
    )
}

/// Maps an mRemoteNG protocol name onto a Remoter protocol id.
///
/// `None` for the two entry kinds that launch a local program rather than open
/// a session; those are not connections in Remoter's sense and the report says
/// so rather than inventing an adapter for them.
fn map_protocol(raw: &str) -> Option<ProtocolId> {
    let id = match raw.trim() {
        "RDP" => "rdp",
        "VNC" => "vnc",
        "SSH1" | "SSH2" => "ssh",
        "Telnet" => "telnet",
        "Rlogin" => "rlogin",
        "RAW" => "raw",
        "HTTP" => "http",
        "HTTPS" => "https",
        "IntApp" | "ExtApp" => return None,
        // A protocol a newer mRemoteNG or a plugin added. The id space is
        // deliberately open (`docs/architecture/data-model.md`): a connection
        // whose adapter this build lacks is still worth keeping.
        other => {
            let lowered: String = other
                .chars()
                .filter(char::is_ascii_alphanumeric)
                .map(|c| c.to_ascii_lowercase())
                .collect();
            return ProtocolId::new(lowered).ok();
        }
    };
    ProtocolId::new(id).ok()
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
