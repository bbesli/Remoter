//! Writing the tree back out: CSV, an OpenSSH config, and Remoter's own JSON.
//!
//! The other half of "you are not locked in". The importers in this crate read
//! other tools' files; these write files other tools — and this crate's own
//! importers — read back. Each writer is a pure function over a [`Tree`]: it
//! opens nothing, writes nothing to disk and needs no vault, which is what lets
//! the round-trip tests below run an export through the importer without any
//! of the machinery around either.
//!
//! # No secret leaves through here
//!
//! Not a password, not a private key, not a passphrase, not a TOTP seed — and
//! not their ciphertext either. The tree this crate sees holds sealed secrets
//! only, and none of the writers so much as reads the sealed fields: the CSV's
//! `password` column is always empty, the OpenSSH config names key *files* the
//! user already had on disk, and the JSON says which kind of secret a
//! credential holds and nothing more. `docs/features/import-export.md` asks for
//! a separately confirmed, audited action before a plaintext secret is written
//! to a file; that action is not built, and nothing here is a step towards it.
//!
//! # What each format can say
//!
//! | Format | Carries | Loses |
//! |---|---|---|
//! | CSV | Every connection's *effective* values, one row each | Inheritance, protocol settings, credentials as shared nodes, per-hop credentials |
//! | OpenSSH config | SSH connections only, effective values | Everything that is not SSH; everything `ssh` has no keyword for |
//! | JSON | The tree as stored: inheritance, settings, custom fields, groups | Secrets |
//!
//! A loss is never silent. Whatever a format could not express is named in the
//! [`ExportReport`], the way an import names what it could not map.

mod archive;
mod csv;
mod json;
mod ssh_config;

pub use archive::{ArchiveSelection, archive_selection};

#[cfg(test)]
mod tests;

use std::collections::HashSet;

use remoter_core::{CoreError, Node, NodeId, Tree};
use serde::Serialize;

/// The most notes a report keeps. A vault of five thousand RDP hosts exported
/// as an OpenSSH config is five thousand identical notes, and a screen cannot
/// show that many usefully; the count past this is still reported.
pub const MAX_NOTES: usize = 500;

/// A file format the tree can be written as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ExportFormat {
    /// The CSV column set [`crate::csv`] reads.
    Csv,
    /// An OpenSSH client configuration.
    OpenSshConfig,
    /// Remoter's own JSON document.
    Json,
}

impl ExportFormat {
    /// Every format, in the order the interface offers them.
    pub const ALL: &'static [Self] = &[Self::Csv, Self::OpenSshConfig, Self::Json];

    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::OpenSshConfig => "ssh-config",
            Self::Json => "json",
        }
    }

    /// Reads back a wire spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|format| format.as_str() == text)
    }
}

/// What an export produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exported {
    /// The file, ready to be written.
    pub bytes: Vec<u8>,
    /// What went into it, and what could not.
    pub report: ExportReport,
}

/// What went into an export, and what could not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportReport {
    /// The format written.
    pub format: ExportFormat,
    /// Folders in the exported part of the tree.
    pub folders: usize,
    /// Connections in the exported part of the tree.
    pub connections: usize,
    /// Credentials in the exported part of the tree.
    pub credentials: usize,
    /// Connections the format had no way to describe, and left out.
    pub skipped: usize,
    /// Rows, `Host` blocks or nodes — whatever this format's unit is.
    pub written: usize,
    /// What could not be written as it is, up to [`MAX_NOTES`].
    pub notes: Vec<ExportNote>,
    /// Notes past [`MAX_NOTES`] that were counted and not kept.
    pub notes_dropped: usize,
}

impl ExportReport {
    fn new(format: ExportFormat) -> Self {
        Self {
            format,
            folders: 0,
            connections: 0,
            credentials: 0,
            skipped: 0,
            written: 0,
            notes: Vec::new(),
            notes_dropped: 0,
        }
    }

    fn note(&mut self, note: ExportNote) {
        if self.notes.len() < MAX_NOTES {
            self.notes.push(note);
        } else {
            self.notes_dropped = self.notes_dropped.saturating_add(1);
        }
    }
}

/// Something an export could not write the way the vault holds it.
///
/// Names and hosts only. Nothing here is ever a secret, and every variant is
/// rendered on screen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ExportNote {
    /// A connection this format cannot describe at all: anything but SSH in an
    /// OpenSSH config.
    #[serde(rename_all = "camelCase")]
    UnsupportedProtocol {
        /// The connection.
        item: String,
        /// Its protocol id.
        protocol: String,
    },
    /// A jump host route written partly, or not at all.
    #[serde(rename_all = "camelCase")]
    GatewayNotWritten {
        /// The connection whose route it is.
        item: String,
        /// Why.
        reason: GatewayProblem,
    },
    /// A name the format could not hold as it is, and what was written instead.
    #[serde(rename_all = "camelCase")]
    Renamed {
        /// The name in the vault.
        item: String,
        /// The name in the file.
        written: String,
    },
    /// A folder whose name has a `/` in it, which the CSV's `folder` column
    /// reads as one folder inside another.
    #[serde(rename_all = "camelCase")]
    FolderNameSplits {
        /// The folder.
        folder: String,
    },
    /// A value the format has no way to quote, left out.
    #[serde(rename_all = "camelCase")]
    ValueNotWritten {
        /// The connection.
        item: String,
        /// Which field — `user`, `identity-file`, and so on.
        field: String,
    },
    /// A reference from inside the export to a node outside it. The JSON keeps
    /// the reference and lists the node it points at by name, without its
    /// contents.
    #[serde(rename_all = "camelCase")]
    OutsideReference {
        /// The node holding the reference.
        item: String,
        /// The node it points at.
        target: String,
    },
}

/// Why a jump host route did not make it into a file whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum GatewayProblem {
    /// A hop has been deleted, so the route no longer leads anywhere.
    DeletedHop,
    /// Two exported connections share a hop's name, so a name in the file
    /// cannot say which one is meant. Left out rather than written: a route
    /// that a re-import resolves to the wrong machine is worse than none.
    AmbiguousHop,
    /// A hop is not in the exported part of the tree. Written by name anyway,
    /// for the reader; a re-import of this file alone will not find it.
    HopOutsideExport,
    /// A hop authenticates with a credential of its own, which this format has
    /// no field for. The route is written; the hop will use its own
    /// credential.
    HopCredential,
    /// A hop is not an SSH connection, and `ProxyJump` only speaks SSH.
    HopNotSsh,
}

/// Why an export produced no file.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExportError {
    /// The part of the tree asked for is not there, or the tree is not one.
    #[error(transparent)]
    Tree(#[from] CoreError),
    /// The document could not be encoded. Not expected: every value in it is
    /// a string, a number or a map with string keys.
    #[error("the export could not be encoded: {0}")]
    Encode(String),
}

/// Writes part of a tree as `format`.
///
/// `root` is the folder or connection to export, with everything under it;
/// `None` is the whole vault. Deleted nodes are never written. `now` is the
/// export time in milliseconds since the Unix epoch, recorded in the JSON; the
/// caller owns the clock, which is also what makes the output reproducible in
/// a test.
///
/// # Errors
///
/// [`ExportError::Tree`] carrying [`CoreError::NodeNotFound`] for a `root`
/// that does not exist or has been deleted, or [`CoreError::CorruptTree`] for a
/// tree whose parent links do not form a tree.
pub fn export(
    tree: &Tree,
    root: Option<NodeId>,
    format: ExportFormat,
    now: i64,
) -> Result<Exported, ExportError> {
    let scope = Scope::of(tree, root)?;
    let mut report = ExportReport::new(format);
    for node in &scope.nodes {
        match &node.kind {
            remoter_core::NodeKind::Folder(_) => report.folders += 1,
            remoter_core::NodeKind::Connection(_) => report.connections += 1,
            remoter_core::NodeKind::Credential(_) => report.credentials += 1,
            _ => {}
        }
    }
    let bytes = match format {
        ExportFormat::Csv => csv::write(tree, &scope, &mut report)?,
        ExportFormat::OpenSshConfig => ssh_config::write(tree, &scope, &mut report)?,
        ExportFormat::Json => json::write(tree, &scope, &mut report, now)?,
    };
    Ok(Exported { bytes, report })
}

/// The part of the tree being exported, in display order.
struct Scope<'t> {
    /// The node the export starts at, if it is not the whole vault.
    root: Option<NodeId>,
    /// Every live node in scope, parents before children, siblings in display
    /// order.
    nodes: Vec<&'t Node>,
    /// The ids in `nodes`.
    ids: HashSet<NodeId>,
}

impl<'t> Scope<'t> {
    fn of(tree: &'t Tree, root: Option<NodeId>) -> Result<Self, CoreError> {
        let mut stack: Vec<NodeId> = match root {
            Some(id) => {
                let live = tree.get(id).is_some_and(|node| node.deleted_at.is_none());
                if !live {
                    return Err(CoreError::NodeNotFound(id));
                }
                vec![id]
            }
            None => tree.roots().iter().rev().copied().collect(),
        };

        let mut nodes = Vec::new();
        let mut ids = HashSet::new();
        while let Some(id) = stack.pop() {
            let Some(node) = tree.get(id) else {
                continue;
            };
            if node.deleted_at.is_some() {
                continue;
            }
            // A node reached twice means the child index is not a tree. The
            // mutating API cannot build one; a damaged store could, and an
            // export must not loop over it.
            if !ids.insert(id) {
                return Err(CoreError::CorruptTree);
            }
            nodes.push(node);
            stack.extend(tree.children(Some(id)).iter().rev().copied());
        }
        Ok(Self { root, nodes, ids })
    }

    fn contains(&self, id: NodeId) -> bool {
        self.ids.contains(&id)
    }

    fn connections(&self) -> impl Iterator<Item = &'t Node> + '_ {
        self.nodes
            .iter()
            .copied()
            .filter(|node| node.kind.as_connection().is_some())
    }

    /// The folders from the export's root down to `node`'s parent, as names.
    ///
    /// The root folder is included, so importing the file recreates it; what
    /// is above the root is not, because it was not exported.
    fn folder_path(&self, tree: &'t Tree, node: &Node) -> Result<Vec<&'t str>, CoreError> {
        // Ancestors come nearest first, so the ones in scope are a prefix of
        // them: everything up to and including the root.
        let mut path: Vec<&'t str> = tree
            .ancestors(node.id)?
            .into_iter()
            .take_while(|ancestor| self.contains(ancestor.id))
            .map(|ancestor| ancestor.name.as_str())
            .collect();
        path.reverse();
        Ok(path)
    }
}
