//! Remote Desktop Connection Manager's `.rdg` documents.
//!
//! An XML document, read through the same hardened reader as every other XML
//! importer here. The root is `<RDCMan>`; under it `<file>` is the document's
//! own top-level group, and groups hold groups and servers:
//!
//! ```xml
//! <RDCMan programVersion="2.93" schemaVersion="3">
//!   <file>
//!     <properties><name>Lab</name></properties>
//!     <logonCredentials inherit="None">
//!       <profileName scope="Local">Custom</profileName>
//!       <userName>administrator</userName>
//!       <password>AQAAANCMnd8BFdERjHoAwE/Cl+sB…</password>
//!       <domain>CONTOSO</domain>
//!     </logonCredentials>
//!     <group>
//!       <properties><name>Domain controllers</name></properties>
//!       <server>
//!         <properties>
//!           <displayName>DC01</displayName>
//!           <name>dc01.contoso.local</name>
//!         </properties>
//!         <connectionSettings inherit="None"><port>3390</port></connectionSettings>
//!       </server>
//!     </group>
//!   </file>
//! </RDCMan>
//! ```
//!
//! The format is RDCMan's own and has no published specification; what is read
//! is what the application writes, element by element, and nothing is inferred
//! beyond it. Schema version 3 (RDCMan 2.7 and later) keeps a node's name and
//! comment inside `<properties>`; schema version 1 (2.2) puts a server's name
//! beside its settings and a group's settings inside `<properties>`. Both are
//! read: a value is looked for in one place and then the other.
//!
//! ## Inheritance
//!
//! Every settings block carries `inherit="FromParent"` or `inherit="None"`,
//! which is [`Inherited::Inherit`] and [`Inherited::Explicit`] exactly. A port
//! or an account set once on a group arrives set once on the folder that group
//! becomes.
//!
//! ## Credentials
//!
//! `logonCredentials` is one of three things: inline — `profileName` reads
//! `Custom`, or there is no `profileName` at all in schema 1 — a profile the
//! document defines under `credentialsProfiles` (`scope="File"`), or a profile
//! RDCMan kept in its own settings on the machine that wrote the document
//! (`scope="Local"`). The last one is not in the file, and the report says so.
//!
//! **Saved passwords do not come across.** RDCMan encrypts them with Windows
//! data protection to the account that saved them, or with a certificate that
//! stayed on that machine; nothing but that account can open either. Each
//! credential arrives with its account name, and asks for its password the
//! first time it is used. The exception is schema 1's
//! `<password storeAsClearText="True">`, which is the password in the clear and
//! is imported like any other recovered password.
//!
//! ## What is kept and what is not
//!
//! Settings with no home in the domain model are kept verbatim in
//! `custom_fields` as `rdcman.<block>.<setting>`, but only from blocks the node
//! sets itself. A setting whose name mentions a password is never kept, and a
//! gateway password is reported instead. Smart groups are rules over the rest
//! of the document rather than groups of servers, and are left out by name.

use std::collections::{HashMap, HashSet};

use remoter_core::{
    ConnectionProps, CredentialRef, FolderProps, Inherited, NodeId, ProtocolId, ProtocolSettings,
    validate_host,
};
use zeroize::Zeroizing;

use crate::error::ImportError;
use crate::limits::Limits;
use crate::mapping::{
    CredentialPool, clean_description, clean_name, custom_key, parse_bool, parse_port, preserve,
    split_address,
};
use crate::preview::{ImportPreview, PreviewBuilder, PreviewKind, PreviewNode, PreviewSecret};
use crate::report::{Finding, SkipReason, SourceFormat};
use crate::secret::ImportedSecret;
use crate::xml::{BoundedXmlReader, XmlEvent, as_text};

/// The element an `.rdg` document begins with.
pub(crate) const ROOT_ELEMENT: &str = "RDCMan";

/// The adapter every server in the document uses.
const PROTOCOL: &str = "rdp";

/// The desktop sizes the RDP adapter's schema accepts, MS-RDPEDISP §2.2.2.2.1's
/// own bounds.
const DESKTOP_SIZE: core::ops::RangeInclusive<i64> = 200..=8192;

/// The longest start program or working directory the adapter's schema accepts.
const MAX_SHELL_CHARS: usize = 512;

/// Settings blocks whose leftover values are kept in `custom_fields`.
const KEPT_BLOCKS: &[&str] = &[
    "connectionSettings",
    "gatewaySettings",
    "remoteDesktop",
    "localResources",
    "securitySettings",
    "displaySettings",
];

/// One element of the document, with its text and its children.
///
/// The text wipes itself: a password element's text is either the protected
/// blob or, in schema 1's clear-text mode, the password.
struct XmlNode {
    name: String,
    attributes: Vec<(String, String)>,
    text: Zeroizing<String>,
    children: Vec<XmlNode>,
}

impl XmlNode {
    fn child(&self, name: &str) -> Option<&Self> {
        self.children.iter().find(|child| child.name == name)
    }

    fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn text(&self) -> &str {
        self.text.trim()
    }

    /// A value of the node's own: inside `<properties>` in schema 3, beside
    /// the settings in schema 1.
    fn property(&self, name: &str) -> &str {
        self.child("properties")
            .and_then(|properties| properties.child(name))
            .or_else(|| self.child(name))
            .map_or("", Self::text)
    }

    /// A settings block the node sets itself, rather than inheriting.
    fn explicit(&self, block: &str) -> Option<&Self> {
        let found = self.child(block).or_else(|| {
            self.child("properties")
                .and_then(|properties| properties.child(block))
        })?;
        match found.attribute("inherit") {
            Some(inherit) if inherit.eq_ignore_ascii_case("FromParent") => None,
            Some(_) => Some(found),
            // No attribute: explicit when it says anything at all.
            None => (!found.children.is_empty()).then_some(found),
        }
    }
}

/// Parses an `.rdg` document into the tree it would create.
///
/// # Errors
///
/// [`ImportError::WrongFormat`] when the root element is not `<RDCMan>` or
/// there is no `<file>` under it, and the usual bounded-parse refusals.
pub fn parse(bytes: &[u8], limits: &Limits) -> Result<ImportPreview, ImportError> {
    let text = as_text(bytes, limits)?;
    let root = read(&text, limits)?;
    let wrong = || ImportError::WrongFormat {
        expected: "a Remote Desktop Connection Manager document",
    };
    if root.name != ROOT_ELEMENT {
        return Err(wrong());
    }
    let file = root.child("file").ok_or_else(wrong)?;

    let mut builder = PreviewBuilder::new(SourceFormat::RdcMan, *limits);
    let mut walker = Walker::new(file)?;
    walker.group(&mut builder, file, None, 0)?;
    walker.finish(&mut builder);
    Ok(builder.finish())
}

/// Reads the whole document into a tree of elements.
///
/// The reader bounds the element count, the depth and every attribute; the
/// text of one element is bounded here.
fn read(text: &str, limits: &Limits) -> Result<XmlNode, ImportError> {
    let mut reader = BoundedXmlReader::new(text, *limits);
    let mut open: Vec<XmlNode> = Vec::new();
    let mut root = None;
    while let Some(event) = reader.next_event()? {
        match event {
            XmlEvent::Start(element) => open.push(XmlNode {
                name: element.name,
                attributes: element.attributes,
                text: Zeroizing::new(String::new()),
                children: Vec::new(),
            }),
            XmlEvent::Text(text) => {
                let text = Zeroizing::new(text);
                if let Some(node) = open.last_mut() {
                    if node.text.len().saturating_add(text.len()) > limits.max_value_bytes {
                        return Err(ImportError::ValueTooLong {
                            limit: limits.max_value_bytes,
                            unit: "field",
                        });
                    }
                    node.text.push_str(&text);
                }
            }
            XmlEvent::End => {
                let Some(node) = open.pop() else {
                    continue;
                };
                match open.last_mut() {
                    Some(parent) => parent.children.push(node),
                    None => {
                        root = Some(node);
                        // Anything after the root element is not the document.
                        break;
                    }
                }
            }
        }
    }
    root.ok_or(ImportError::WrongFormat {
        expected: "a Remote Desktop Connection Manager document",
    })
}

struct Walker<'a> {
    /// Profiles the document defines, by name. The first definition of a name
    /// is the one used, which is the one RDCMan lists first.
    profiles: HashMap<&'a str, &'a XmlNode>,
    credentials: CredentialPool,
    protocol: ProtocolId,
    /// Distinct protected passwords met, by the digest of what protects them.
    protected: HashSet<[u8; 20]>,
    /// Clear-text passwords recovered.
    secrets: usize,
}

impl<'a> Walker<'a> {
    fn new(file: &'a XmlNode) -> Result<Self, ImportError> {
        let mut profiles = HashMap::new();
        collect_profiles(file, &mut profiles);
        Ok(Self {
            profiles,
            credentials: CredentialPool::new("Imported credentials"),
            protocol: ProtocolId::new(PROTOCOL)?,
            protected: HashSet::new(),
            secrets: 0,
        })
    }

    /// Maps a group — or the document's `<file>`, which is its top group — and
    /// everything under it.
    ///
    /// Recursive, and bounded: the reader refused anything nested deeper than
    /// [`Limits::max_depth`] before this ran.
    fn group(
        &mut self,
        builder: &mut PreviewBuilder,
        node: &XmlNode,
        parent: Option<NodeId>,
        sort: i64,
    ) -> Result<(), ImportError> {
        let limits = *builder.limits();
        let mut name = clean_name(node.property("name"));
        if name.is_empty() {
            name = if parent.is_none() {
                "Remote Desktop Connection Manager".to_owned()
            } else {
                "Unnamed group".to_owned()
            };
        }

        let mut consumed = Vec::new();
        let props = FolderProps {
            port: port(node, &mut consumed),
            credential: self.credential(builder, node, &name)?,
            settings: settings(node, &mut consumed)?,
            ..FolderProps::default()
        };
        gateway(builder, node, &name);

        let id = NodeId::new();
        let mut folder =
            PreviewNode::new(id, name.clone(), PreviewKind::Folder(props)).under(parent, sort);
        folder.description = clean_description(node.property("comment"));
        keep_rest(builder, &mut folder, node, &name, &consumed, &limits);
        builder.push(folder)?;

        let mut next = 0i64;
        for child in &node.children {
            match child.name.as_str() {
                "group" => self.group(builder, child, Some(id), next)?,
                "server" => self.server(builder, child, id, next)?,
                "smartGroup" => {
                    builder.report_mut().counts_mut().skipped += 1;
                    let mut item = clean_name(child.property("name"));
                    if item.is_empty() {
                        item = "Smart group".to_owned();
                    }
                    builder.report_mut().push(
                        &limits,
                        Finding::SkippedItem {
                            item,
                            reason: SkipReason::UnsupportedKind,
                        },
                    );
                }
                _ => continue,
            }
            next += 1;
        }
        Ok(())
    }

    fn server(
        &mut self,
        builder: &mut PreviewBuilder,
        node: &XmlNode,
        parent: NodeId,
        sort: i64,
    ) -> Result<(), ImportError> {
        let limits = *builder.limits();
        let address = node.property("name");
        let mut name = clean_name(node.property("displayName"));
        if name.is_empty() {
            name = clean_name(address);
        }
        let Some((host, address_port)) =
            split_address(address).filter(|(host, _)| validate_host(host).is_ok())
        else {
            builder.report_mut().counts_mut().skipped += 1;
            builder.report_mut().push(
                &limits,
                Finding::SkippedItem {
                    item: if name.is_empty() {
                        "Unnamed server".to_owned()
                    } else {
                        name
                    },
                    reason: if address.is_empty() {
                        SkipReason::Empty
                    } else {
                        SkipReason::UnusableHost
                    },
                },
            );
            return Ok(());
        };
        if name.is_empty() {
            name = clean_name(&host);
        }

        let mut consumed = Vec::new();
        let mut props = ConnectionProps::new(PROTOCOL, host)?;
        props.port = match address_port {
            Some(port) => Inherited::Explicit(port),
            None => port(node, &mut consumed),
        };
        props.credential = self.credential(builder, node, &name)?;
        props.settings = settings(node, &mut consumed)?;
        gateway(builder, node, &name);

        let mut connection =
            PreviewNode::new(NodeId::new(), name.clone(), PreviewKind::Connection(props))
                .under(Some(parent), sort);
        connection.description = clean_description(node.property("comment"));
        keep_rest(builder, &mut connection, node, &name, &consumed, &limits);
        builder.push(connection)?;
        Ok(())
    }

    /// The node's `logonCredentials`, as a credential reference.
    fn credential(
        &mut self,
        builder: &mut PreviewBuilder,
        node: &XmlNode,
        item: &str,
    ) -> Result<Inherited<CredentialRef>, ImportError> {
        let Some(block) = node.explicit("logonCredentials") else {
            return Ok(Inherited::Inherit);
        };
        let limits = *builder.limits();

        let profile = block
            .child("profileName")
            .filter(|profile| !profile.text().eq_ignore_ascii_case("Custom"));
        let (source, identity) = match profile {
            None => (block, None),
            Some(profile) => {
                let profile_name = profile.text();
                let in_file = profile
                    .attribute("scope")
                    .is_some_and(|scope| scope.eq_ignore_ascii_case("File"));
                match self.profiles.get(profile_name).filter(|_| in_file) {
                    Some(found) => (*found, Some(format!("profile:{profile_name}"))),
                    None => {
                        builder.report_mut().push(
                            &limits,
                            Finding::CredentialProfileMissing {
                                item: item.to_owned(),
                                profile: clean_name(profile_name),
                            },
                        );
                        // A credential named after the profile, with nothing
                        // in it: the node chose one, and inheriting instead
                        // would sign in as someone else.
                        let reference = self.credentials.intern(
                            builder,
                            profile_name,
                            String::new(),
                            None,
                            PreviewSecret::not_carried(
                                format!("missing-profile:{profile_name}").as_bytes(),
                            ),
                            vec![self.protocol.clone()],
                        )?;
                        return Ok(Inherited::Explicit(reference));
                    }
                }
            }
        };

        let raw_user = source.child("userName").map_or("", XmlNode::text);
        let written_domain = source.child("domain").map_or("", XmlNode::text);
        let (domain, username) = match raw_user.split_once('\\') {
            Some((domain, user)) if written_domain.is_empty() => (domain.trim(), user.trim()),
            _ => (written_domain, raw_user),
        };
        let password = source.child("password");
        let saved = password.map_or("", XmlNode::text);
        if username.is_empty() && domain.is_empty() && saved.is_empty() && identity.is_none() {
            // An explicit block with nothing in it is RDCMan asking at connect
            // time, which is what a node with no credential does here too.
            return Ok(Inherited::Inherit);
        }

        let clear_text = password
            .and_then(|password| password.attribute("storeAsClearText"))
            .is_some_and(parse_bool);
        let secret = if saved.is_empty() {
            PreviewSecret::not_carried(identity.as_deref().unwrap_or("").as_bytes())
        } else if clear_text {
            self.secrets += 1;
            PreviewSecret::Password(ImportedSecret::from(saved))
        } else {
            // One profile is one saved password however many servers use it;
            // two inline blobs are two, even when they protect the same text.
            let secret = match &identity {
                Some(identity) => PreviewSecret::not_carried(identity.as_bytes()),
                None => PreviewSecret::not_carried(saved.as_bytes()),
            };
            if let PreviewSecret::PasswordNotCarried(digest) = &secret {
                self.protected.insert(*digest);
            }
            secret
        };

        let reference = self.credentials.intern(
            builder,
            item,
            username.to_owned(),
            (!domain.is_empty()).then(|| domain.to_owned()),
            secret,
            vec![self.protocol.clone()],
        )?;
        Ok(Inherited::Explicit(reference))
    }

    fn finish(self, builder: &mut PreviewBuilder) {
        let limits = *builder.limits();
        if self.secrets > 0 {
            builder.report_mut().push(
                &limits,
                Finding::SecretsRecovered {
                    count: self.secrets,
                },
            );
        }
        if !self.protected.is_empty() {
            builder.report_mut().push(
                &limits,
                Finding::ProtectedPasswordsNotCarried {
                    count: self.protected.len(),
                },
            );
        }
        self.credentials.finish(builder);
    }
}

/// Every `credentialsProfile` in the document, by name.
fn collect_profiles<'a>(node: &'a XmlNode, profiles: &mut HashMap<&'a str, &'a XmlNode>) {
    for child in &node.children {
        if child.name == "credentialsProfiles" {
            for profile in child
                .children
                .iter()
                .filter(|profile| profile.name == "credentialsProfile")
            {
                if let Some(name) = profile.child("profileName").map(XmlNode::text) {
                    profiles.entry(name).or_insert(profile);
                }
            }
        } else if matches!(child.name.as_str(), "group" | "properties") {
            collect_profiles(child, profiles);
        }
    }
}

/// The port a node sets in `connectionSettings`.
fn port(node: &XmlNode, consumed: &mut Vec<&'static str>) -> Inherited<u16> {
    let port = node
        .explicit("connectionSettings")
        .and_then(|block| block.child("port"))
        .and_then(|port| parse_port(port.text()));
    match port {
        Some(port) => {
            consumed.push("connectionSettings.port");
            Inherited::Explicit(port)
        }
        None => Inherited::Inherit,
    }
}

/// The adapter settings a node sets, each only when the value is one the
/// adapter's schema accepts.
fn settings(
    node: &XmlNode,
    consumed: &mut Vec<&'static str>,
) -> Result<ProtocolSettings, ImportError> {
    let mut settings = ProtocolSettings::new();
    if let Some(desktop) = node.explicit("remoteDesktop") {
        let follows_window = ["sameSizeAsClientArea", "fullScreen"].iter().any(|flag| {
            desktop
                .child(flag)
                .is_some_and(|flag| parse_bool(flag.text()))
        });
        let size = desktop.child("size").map_or("", XmlNode::text);
        let parsed = size.split_once(['x', 'X']).and_then(|(width, height)| {
            Some((
                width.trim().parse::<i64>().ok()?,
                height.trim().parse::<i64>().ok()?,
            ))
        });
        if let Some((width, height)) = parsed.filter(|_| !follows_window) {
            if DESKTOP_SIZE.contains(&width) && DESKTOP_SIZE.contains(&height) {
                settings.insert("desktop_width", width.to_string())?;
                settings.insert("desktop_height", height.to_string())?;
                consumed.push("remoteDesktop.size");
            }
        }
    }
    if let Some(connection) = node.explicit("connectionSettings") {
        for (element, setting, key) in [
            (
                "startProgram",
                "alternate_shell",
                "connectionSettings.startProgram",
            ),
            ("workingDir", "work_dir", "connectionSettings.workingDir"),
        ] {
            let value = connection.child(element).map_or("", XmlNode::text);
            if !value.is_empty()
                && value.chars().count() <= MAX_SHELL_CHARS
                && !value.chars().any(char::is_control)
            {
                settings.insert(setting, value)?;
                consumed.push(key);
            }
        }
    }
    Ok(settings)
}

/// Warns about a Remote Desktop Gateway the node sets and turns on.
fn gateway(builder: &mut PreviewBuilder, node: &XmlNode, item: &str) {
    let Some(block) = node.explicit("gatewaySettings") else {
        return;
    };
    let enabled = block
        .child("enabled")
        .is_some_and(|enabled| parse_bool(enabled.text()));
    let host = block.child("hostName").map_or("", XmlNode::text);
    if enabled && !host.is_empty() {
        let limits = *builder.limits();
        builder.report_mut().push(
            &limits,
            Finding::RdGatewayNotSupported {
                item: item.to_owned(),
                host: clean_name(host),
            },
        );
    }
}

/// Keeps what the node's own settings blocks hold and nothing above took.
fn keep_rest(
    builder: &mut PreviewBuilder,
    target: &mut PreviewNode,
    node: &XmlNode,
    item: &str,
    consumed: &[&'static str],
    limits: &Limits,
) {
    let mut kept = 0usize;
    let mut dropped = false;
    for block_name in KEPT_BLOCKS {
        let Some(block) = node.explicit(block_name) else {
            continue;
        };
        for setting in &block.children {
            // A nested list — drives to redirect, say — is not one value.
            if !setting.children.is_empty() || setting.text().is_empty() {
                continue;
            }
            let path = format!("{block_name}.{}", setting.name);
            if consumed.contains(&path.as_str()) {
                continue;
            }
            if setting.name.to_ascii_lowercase().contains("password") {
                builder.report_mut().push(
                    limits,
                    Finding::SecretNotMapped {
                        item: item.to_owned(),
                        field: clean_name(&path),
                    },
                );
                continue;
            }
            let Some(key) = custom_key("rdcman", &path) else {
                continue;
            };
            if preserve(
                target,
                key,
                setting.text().to_owned(),
                limits.max_custom_fields,
            ) {
                kept += 1;
            } else if target.custom_fields.len() >= limits.max_custom_fields {
                dropped = true;
            }
        }
    }
    if kept > 0 {
        builder.report_mut().push(
            limits,
            Finding::SettingsPreserved {
                item: item.to_owned(),
                count: kept,
            },
        );
    }
    if dropped {
        builder.report_mut().push(
            limits,
            Finding::LimitReached {
                limit: "custom_fields".to_owned(),
            },
        );
    }
}

#[cfg(test)]
#[path = "rdcman_tests.rs"]
mod tests;
