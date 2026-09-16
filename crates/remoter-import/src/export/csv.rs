//! The CSV writer: one row per connection, in [`crate::csv::COLUMNS`].
//!
//! Every value is the connection's *effective* one — the port, the username and
//! the jump hosts it would actually connect with, wherever in the tree they are
//! set — because a row in a spreadsheet has no parent to inherit from. That is
//! also what makes the file useful as an inventory, which is most of what
//! people want a CSV for.
//!
//! The file opens with a UTF-8 byte-order mark and ends its lines with CRLF.
//! RFC 4180 asks for the line endings; the mark is for Excel, which reads a CSV
//! without one in the system's legacy code page and turns every `ş` and `ü` in
//! a folder name into two characters of noise. The importer skips the mark.

use std::collections::HashMap;

use remoter_core::{CoreError, GatewayChain, Node, Tree};

use super::{ExportNote, ExportReport, GatewayProblem, Scope};
use crate::csv::{COLUMNS, formula_like};

/// The byte-order mark the file opens with.
const BOM: char = '\u{feff}';

/// How the `gateway` column separates hops.
const HOP_SEPARATOR: &str = " > ";

pub(super) fn write(
    tree: &Tree,
    scope: &Scope<'_>,
    report: &mut ExportReport,
) -> Result<Vec<u8>, CoreError> {
    let mut out = String::new();
    out.push(BOM);
    push_row(&mut out, COLUMNS.iter().copied());

    for node in &scope.nodes {
        if node.kind.is_container() && node.name.contains('/') {
            report.note(ExportNote::FolderNameSplits {
                folder: node.name.clone(),
            });
        }
    }

    let names = name_counts(scope);
    for node in scope.connections() {
        let Some(connection) = node.kind.as_connection() else {
            continue;
        };
        let effective = tree.effective_connection(node.id)?;
        let folder = scope.folder_path(tree, node)?.join("/");
        let port = effective
            .port
            .value
            .map(|port| port.to_string())
            .unwrap_or_default();
        let credential = effective
            .credential
            .value
            .as_ref()
            .filter(|reference| !reference.is_deleted())
            .and_then(|reference| tree.get(reference.id()))
            .and_then(|credential| credential.kind.as_credential());
        let tags = node
            .tags
            .iter()
            .map(remoter_core::Tag::as_str)
            .collect::<Vec<_>>()
            .join(";");
        let gateway = gateway(tree, scope, node, &effective.gateway.value, &names, report);

        push_row(
            &mut out,
            COLUMNS.iter().map(|column| match *column {
                "name" => node.name.as_str(),
                "folder" => folder.as_str(),
                "protocol" => connection.protocol.as_str(),
                "host" => connection.host.as_str(),
                "port" => port.as_str(),
                "username" => credential.map_or("", |props| props.username.as_str()),
                "domain" => credential
                    .and_then(|props| props.domain.as_deref())
                    .unwrap_or(""),
                "description" => node.description.as_str(),
                "tags" => tags.as_str(),
                "gateway" => gateway.as_str(),
                // `password` above all: never written. See the module
                // documentation in `export/mod.rs`.
                _ => "",
            }),
        );
        report.written += 1;
    }

    Ok(out.into_bytes())
}

/// How many exported connections carry each name.
///
/// The importer resolves a `gateway` cell by name, so a name two rows share is
/// a name the file cannot use to say which of them is meant.
fn name_counts<'t>(scope: &Scope<'t>) -> HashMap<&'t str, usize> {
    let mut counts = HashMap::new();
    for node in scope.connections() {
        *counts.entry(node.name.as_str()).or_insert(0usize) += 1;
    }
    counts
}

/// The `gateway` cell for a connection: its hops' names, in order.
fn gateway(
    tree: &Tree,
    scope: &Scope<'_>,
    node: &Node,
    chain: &GatewayChain,
    names: &HashMap<&str, usize>,
    report: &mut ExportReport,
) -> String {
    let mut hops: Vec<&str> = Vec::new();
    let mut problems: Vec<GatewayProblem> = Vec::new();
    for hop in &chain.hops {
        let target = tree
            .get(hop.node.id())
            .filter(|target| !hop.node.is_deleted() && target.deleted_at.is_none());
        let Some(target) = target else {
            return refuse(report, node, GatewayProblem::DeletedHop);
        };
        let exported = scope.contains(target.id);
        let shared = names.get(target.name.as_str()).copied().unwrap_or(0);
        // In scope, the name must be the only one of its kind. Outside it, the
        // name must not be one of the exported rows' either, or a re-import
        // would route through the exported namesake instead.
        let ambiguous = if exported { shared > 1 } else { shared > 0 };
        let splits = chain.hops.len() > 1 && target.name.contains('>');
        if ambiguous || splits {
            return refuse(report, node, GatewayProblem::AmbiguousHop);
        }
        if !exported && !problems.contains(&GatewayProblem::HopOutsideExport) {
            problems.push(GatewayProblem::HopOutsideExport);
        }
        if hop.credential.is_some() && !problems.contains(&GatewayProblem::HopCredential) {
            problems.push(GatewayProblem::HopCredential);
        }
        hops.push(target.name.as_str());
    }
    for reason in problems {
        report.note(ExportNote::GatewayNotWritten {
            item: node.name.clone(),
            reason,
        });
    }
    hops.join(HOP_SEPARATOR)
}

fn refuse(report: &mut ExportReport, node: &Node, reason: GatewayProblem) -> String {
    report.note(ExportNote::GatewayNotWritten {
        item: node.name.clone(),
        reason,
    });
    String::new()
}

/// Appends one CRLF-terminated record.
fn push_row<'a>(out: &mut String, fields: impl Iterator<Item = &'a str>) {
    for (index, value) in fields.enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_field(out, value);
    }
    out.push_str("\r\n");
}

/// Appends one field, quoted when it has to be and guarded when a spreadsheet
/// would run it.
///
/// Trimmed first, because the importer trims every field before it reads it:
/// guarding the untrimmed value would put the apostrophe in front of a space,
/// where the importer no longer looks for it once the space is gone.
///
/// Only `,` needs quoting of the three delimiters the importer knows: it takes
/// its delimiter from the header, and this header is written with commas.
fn push_field(out: &mut String, value: &str) {
    let value = value.trim();
    let quoted = value.contains([',', '"', '\n', '\r']);
    if quoted {
        out.push('"');
    }
    if formula_like(value) {
        out.push('\'');
    }
    for c in value.chars() {
        if c == '"' {
            out.push('"');
        }
        out.push(c);
    }
    if quoted {
        out.push('"');
    }
}
