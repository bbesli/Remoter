//! The generic CSV importer.
//!
//! The one source with no other tool behind it, so the column set is Remoter's
//! own. It is documented here because this is what the exporter writes and what
//! a user assembling a spreadsheet from an inventory has to match.
//!
//! | Column | Required | Meaning |
//! |---|---|---|
//! | `name` | yes | Display name. Falls back to `host` when empty. |
//! | `host` | yes | Hostname, IPv4 address, or bracketed IPv6 literal. |
//! | `folder` | no | `/`-separated path. Folders are created as needed. |
//! | `protocol` | no | Protocol id. Defaults to `ssh`. |
//! | `port` | no | 1–65535. Left inherited when absent. |
//! | `username` | no | Account name for this connection's credential. |
//! | `domain` | no | Windows or Kerberos domain. |
//! | `password` | no | Plaintext. Sealed at commit; never written anywhere. |
//! | `description` | no | Free-form notes. |
//! | `tags` | no | `;`-separated. |
//! | `gateway` | no | The `name` of another row, used as a jump host — or several, joined by `>`, traversed in that order. |
//!
//! Column order does not matter and any optional column may be absent.
//! Anything else in the header is kept: its values go into `custom_fields`
//! under `csv.<column>` and the report names the column.
//!
//! The reader is RFC 4180: `"` quotes a field, `""` is a literal quote inside
//! one, and a quoted field may contain the delimiter and newlines. The
//! delimiter is whichever of `,`, `;` and tab appears most often in the header,
//! because a spreadsheet exported in a locale that uses `,` for decimals
//! writes `;` and the user should not have to know that.
//!
//! A value that starts with `=`, `+`, `-` or `@` is one a spreadsheet runs as a
//! formula, so the exporter writes it behind an apostrophe — the guard OWASP
//! describes for CSV injection, and the one spreadsheets themselves use to
//! mean "this is text". The reader takes one apostrophe back off such a value,
//! in every column but `password`, which is how an exported name like `=prod`
//! comes back as `=prod` and not as `'=prod`. See [`formula_like`].

use std::collections::HashMap;

use remoter_core::{
    ConnectionProps, FolderProps, GatewayChain, GatewayHop, Inherited, NodeId, ProtocolId, Tag,
    validate_host,
};
use zeroize::Zeroizing;

use crate::error::ImportError;
use crate::limits::Limits;
use crate::mapping::{
    CredentialPool, clean_description, clean_name, custom_key, parse_port, preserve,
};
use crate::preview::{ImportPreview, PreviewBuilder, PreviewKind, PreviewNode, PreviewSecret};
use crate::report::{Finding, SkipReason, SourceFormat};
use crate::secret::ImportedSecret;
use crate::xml::as_text;

/// The documented column set, in the order the exporter writes it.
pub const COLUMNS: &[&str] = &[
    "name",
    "folder",
    "protocol",
    "host",
    "port",
    "username",
    "domain",
    "password",
    "description",
    "tags",
    "gateway",
];

/// The delimiters the reader will consider.
const DELIMITERS: [char; 3] = [',', ';', '\t'];

/// Parses a CSV into the tree it would create.
///
/// # Errors
///
/// [`ImportError::MissingColumn`] when a required column is absent,
/// [`ImportError::DuplicateColumn`] when the header repeats one, and the usual
/// bounded-parse refusals. A row that cannot be mapped is reported, not raised.
pub fn parse(bytes: &[u8], limits: &Limits) -> Result<ImportPreview, ImportError> {
    let text = as_text(bytes, limits)?;
    let records = read(&text, limits)?;
    let Some((header, rows)) = records.split_first() else {
        return Err(ImportError::WrongFormat {
            expected: "a CSV with a header row",
        });
    };

    let mut columns: HashMap<String, usize> = HashMap::new();
    let mut unknown: Vec<(usize, String)> = Vec::new();
    for (index, raw) in header.iter().enumerate() {
        let name = raw.trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        if columns.contains_key(&name) {
            return Err(ImportError::DuplicateColumn { column: name });
        }
        if !COLUMNS.contains(&name.as_str()) {
            unknown.push((index, raw.trim().to_owned()));
        }
        columns.insert(name, index);
    }
    for required in ["name", "host"] {
        if !columns.contains_key(required) {
            return Err(ImportError::MissingColumn { column: required });
        }
    }

    let mut builder = PreviewBuilder::new(SourceFormat::Csv, *limits);
    for (_, column) in &unknown {
        builder.report_mut().push(
            limits,
            Finding::UnknownColumn {
                column: clean_name(column),
            },
        );
    }

    let mut credentials = CredentialPool::new("Imported credentials");
    let mut folders = Folders::default();
    let mut by_name: HashMap<String, NodeId> = HashMap::new();
    let mut pending: Vec<(NodeId, String, String)> = Vec::new();
    let mut secrets = 0usize;
    let mut sort = 0i64;

    for row in rows {
        let field = |name: &str| -> &str {
            let value = columns
                .get(name)
                .and_then(|index| row.get(*index))
                .map_or("", |value| value.trim());
            // A password is taken exactly as written: this reader cannot know
            // whether an apostrophe in one is a guard or a character.
            if name == "password" {
                value
            } else {
                unguard(value)
            }
        };

        let host = field("host");
        let mut name = clean_name(field("name"));
        if name.is_empty() {
            name = clean_name(host);
        }
        if name.is_empty() && host.is_empty() {
            // A blank line in a spreadsheet is not an item that was dropped.
            continue;
        }
        if validate_host(host).is_err() {
            builder.report_mut().counts_mut().skipped += 1;
            builder.report_mut().push(
                limits,
                Finding::SkippedItem {
                    item: name,
                    reason: if host.is_empty() {
                        SkipReason::Empty
                    } else {
                        SkipReason::UnusableHost
                    },
                },
            );
            continue;
        }

        let raw_protocol = field("protocol");
        let protocol = if raw_protocol.is_empty() {
            ProtocolId::new("ssh")?
        } else {
            match ProtocolId::new(raw_protocol.to_ascii_lowercase()) {
                Ok(protocol) => protocol,
                Err(_) => {
                    builder.report_mut().counts_mut().skipped += 1;
                    builder.report_mut().push(
                        limits,
                        Finding::SkippedItem {
                            item: name,
                            reason: SkipReason::UnsupportedKind,
                        },
                    );
                    continue;
                }
            }
        };

        let parent = folders.path(&mut builder, field("folder"), limits)?;
        let mut props = ConnectionProps::new(protocol.as_str(), host)?;
        props.port = parse_port(field("port")).map_or(Inherited::Inherit, Inherited::Explicit);

        let username = field("username").to_owned();
        let domain = field("domain");
        let password = field("password");
        if !username.is_empty() || !password.is_empty() {
            let secret = if password.is_empty() {
                PreviewSecret::Unsealed(remoter_core::SecretKind::Agent {
                    comment_filter: None,
                })
            } else {
                secrets += 1;
                PreviewSecret::Password(ImportedSecret::from(password))
            };
            props.credential = Inherited::Explicit(credentials.intern(
                &mut builder,
                &name,
                username,
                (!domain.is_empty()).then(|| domain.to_owned()),
                secret,
                vec![protocol],
            )?);
        }

        let id = NodeId::new();
        let mut node =
            PreviewNode::new(id, name.clone(), PreviewKind::Connection(props)).under(parent, sort);
        sort += 1;
        node.description = clean_description(field("description"));
        node.tags = field("tags")
            .split(';')
            .map(str::trim)
            .filter(|tag| !tag.is_empty())
            .filter_map(|tag| Tag::new(tag).ok())
            .collect();

        for (index, column) in &unknown {
            let Some(value) = row.get(*index).map(|value| value.trim()) else {
                continue;
            };
            if value.is_empty() {
                continue;
            }
            let Some(key) = custom_key("csv", &column.to_ascii_lowercase()) else {
                continue;
            };
            preserve(&mut node, key, value.to_owned(), limits.max_custom_fields);
        }

        let gateway = field("gateway").to_owned();
        builder.push(node)?;
        by_name.insert(name.clone(), id);
        if !gateway.is_empty() {
            pending.push((id, name, gateway));
        }
    }

    for (connection, connection_name, target) in pending {
        match route(&target, &by_name, connection) {
            Some(hops) => {
                let count = hops.len();
                builder.set_gateway(
                    connection,
                    Inherited::Explicit(GatewayChain {
                        hops: hops.into_iter().map(GatewayHop::new).collect(),
                    }),
                );
                builder.report_mut().push(
                    limits,
                    Finding::GatewayMapped {
                        item: connection_name,
                        hops: count,
                    },
                );
            }
            None => {
                if let Some(node) = builder.node_mut(connection) {
                    if let Some(key) = custom_key("csv", "gateway") {
                        preserve(node, key, target.clone(), limits.max_custom_fields);
                    }
                }
                builder.report_mut().push(
                    limits,
                    Finding::GatewayUnresolved {
                        item: connection_name,
                        target: clean_name(&target),
                    },
                );
            }
        }
    }

    if secrets > 0 {
        builder
            .report_mut()
            .push(limits, Finding::SecretsRecovered { count: secrets });
    }
    credentials.finish(&mut builder);
    Ok(builder.finish())
}

/// The hops a `gateway` cell names, or `None` when any of them is not a row.
///
/// The whole cell is tried as one name first, so a connection whose name has a
/// `>` in it still works as a single hop. Otherwise the cell is a `>`-separated
/// route, and every hop has to resolve: a route missing its middle leads
/// somewhere other than where the file says. A hop that is the connection
/// itself, a hop visited twice and a route longer than the domain model allows
/// are refused for the same reason.
fn route(cell: &str, by_name: &HashMap<String, NodeId>, connection: NodeId) -> Option<Vec<NodeId>> {
    let hops: Vec<NodeId> = match by_name.get(cell) {
        Some(hop) => vec![*hop],
        None => cell
            .split('>')
            .map(|name| by_name.get(name.trim()).copied())
            .collect::<Option<Vec<_>>>()?,
    };
    let mut seen = std::collections::HashSet::new();
    let usable = !hops.is_empty()
        && hops.len() <= remoter_core::MAX_GATEWAY_HOPS
        && hops
            .iter()
            .all(|hop| *hop != connection && seen.insert(*hop));
    usable.then_some(hops)
}

/// Whether a spreadsheet would take `value` as a formula once one leading
/// apostrophe is gone.
///
/// Leading apostrophes are looked through, which is what makes the guard
/// reversible for a value that really does start with one: `'=x` is written
/// `''=x` and read back as `'=x`. A tab or a carriage return at the start
/// counts too, because OWASP lists both as ways into a formula.
pub(crate) fn formula_like(value: &str) -> bool {
    value
        .trim_start_matches('\'')
        .starts_with(['=', '+', '-', '@', '\t', '\r'])
}

/// Takes the exporter's guard apostrophe back off a value.
fn unguard(value: &str) -> &str {
    match value.strip_prefix('\'') {
        Some(rest) if formula_like(rest) => rest,
        _ => value,
    }
}

/// Creates folder nodes for `/`-separated paths, once each.
#[derive(Default)]
struct Folders {
    by_path: HashMap<String, NodeId>,
    next_sort: i64,
}

impl Folders {
    /// The node a `/`-separated path names, creating every level that does not
    /// exist yet.
    fn path(
        &mut self,
        builder: &mut PreviewBuilder,
        path: &str,
        limits: &Limits,
    ) -> Result<Option<NodeId>, ImportError> {
        let mut parent = None;
        let mut prefix = String::new();
        let mut depth = 0usize;
        for segment in path.split('/') {
            let name = clean_name(segment);
            if name.is_empty() {
                continue;
            }
            depth += 1;
            if depth > limits.max_depth {
                return Err(ImportError::TooDeep {
                    limit: limits.max_depth,
                });
            }
            prefix.push('/');
            prefix.push_str(&name);
            parent = Some(match self.by_path.get(&prefix) {
                Some(existing) => *existing,
                None => {
                    let node = PreviewNode::new(
                        NodeId::new(),
                        name,
                        PreviewKind::Folder(FolderProps::default()),
                    )
                    .under(parent, self.next_sort);
                    self.next_sort += 1;
                    let id = builder.push(node)?;
                    self.by_path.insert(prefix.clone(), id);
                    id
                }
            });
        }
        Ok(parent)
    }
}

/// Splits a CSV into records.
///
/// Total by construction: every state either consumes a character or ends the
/// parse, and the only growth is the field being built, which is bounded.
///
/// The records wipe themselves, and that is not incidental: a CSV's `password`
/// column is cleartext, so this is a copy of every password in the file and it
/// outlives the mapping that reads it. `Zeroize` for `Vec` reaches each
/// `String` inside, so the final buffers go. What it cannot reach is what a
/// growing `String` left behind as it doubled — a field longer than its first
/// allocation leaves a prefix of itself in freed heap, and nothing short of a
/// bespoke buffer type fixes that. It is recorded here rather than papered
/// over, because reserving `max_value_bytes` per field to avoid it would turn
/// a wide header into 64 KiB of allocation per column per row.
fn read(text: &str, limits: &Limits) -> Result<Zeroizing<Vec<Vec<String>>>, ImportError> {
    let delimiter = delimiter(text);
    let mut records: Zeroizing<Vec<Vec<String>>> = Zeroizing::new(Vec::new());
    let mut record: Zeroizing<Vec<String>> = Zeroizing::new(Vec::new());
    let mut field = Zeroizing::new(String::new());
    let mut quoted = false;
    let mut started = false;
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        if quoted {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    quoted = false;
                }
            } else {
                field.push(c);
            }
            if field.len() > limits.max_value_bytes {
                return Err(ImportError::ValueTooLong {
                    limit: limits.max_value_bytes,
                    unit: "field",
                });
            }
            continue;
        }

        match c {
            '"' if !started => {
                quoted = true;
                started = true;
            }
            c if c == delimiter => {
                record.push(core::mem::take(&mut *field));
                started = false;
            }
            '\r' => {}
            '\n' => {
                record.push(core::mem::take(&mut *field));
                started = false;
                if records.len() >= limits.max_items {
                    return Err(ImportError::TooManyItems {
                        limit: limits.max_items,
                        unit: "rows",
                    });
                }
                records.push(core::mem::take(&mut *record));
            }
            c => {
                field.push(c);
                started = true;
                if field.len() > limits.max_value_bytes {
                    return Err(ImportError::ValueTooLong {
                        limit: limits.max_value_bytes,
                        unit: "field",
                    });
                }
            }
        }
    }

    if quoted {
        return Err(ImportError::Truncated {
            unit: "quoted field",
        });
    }
    if started || !record.is_empty() {
        record.push(core::mem::take(&mut *field));
        records.push(core::mem::take(&mut *record));
    }
    Ok(records)
}

/// Picks the delimiter the header row uses.
fn delimiter(text: &str) -> char {
    let header = text.lines().next().unwrap_or_default();
    DELIMITERS
        .into_iter()
        .max_by_key(|candidate| header.matches(*candidate).count())
        .filter(|candidate| header.contains(*candidate))
        .unwrap_or(',')
}

#[cfg(test)]
#[path = "csv_tests.rs"]
mod tests;
