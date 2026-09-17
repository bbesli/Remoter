//! Which nodes go into a `.rmtr` archive.
//!
//! The archive itself — the envelope, the password slot, the secrets — is
//! `remoter_vault::archive`'s. What this module decides is the set of nodes, and
//! it has one job the flat formats do not: the archive is imported into
//! another vault as nodes, so it has to arrive *whole*. A folder that uses a
//! shared credential kept elsewhere, a connection routed through a jump host in
//! another folder, a connection whose port its folder sets — each would reach
//! the other side unable to connect the way it did here.
//!
//! So the selection is the chosen part of the tree plus everything it depends
//! on, and every node taken out of its place is detached: the folder at the
//! root, and each dependency pulled in from elsewhere, keep what their own
//! folders gave them ([`Tree::detached`]). Dependencies are followed until
//! nothing new turns up, because a pulled-in jump host has a credential of its
//! own.
//!
//! Exporting the whole vault needs none of that: nothing is outside it.

use std::collections::HashSet;

use remoter_core::{Node, NodeId, NodeKind, Tree};

use super::{ExportError, Scope};

/// The nodes an archive carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveSelection {
    /// Parents before children. A node whose parent is not in the selection —
    /// the root of the export, and every dependency — has no parent.
    pub nodes: Vec<Node>,
    /// The names of the nodes pulled in from outside the chosen part of the
    /// tree because something in it depends on them.
    pub dependencies: Vec<String>,
}

/// Selects the nodes for an archive of `root` and everything under it, or of
/// the whole vault when `root` is `None`.
///
/// # Errors
///
/// [`ExportError::Tree`] carrying `CoreError::NodeNotFound` for a `root`
/// that does not exist or has been deleted, and the errors of
/// [`Tree::detached`] for a tree whose parent links are damaged.
pub fn archive_selection(
    tree: &Tree,
    root: Option<NodeId>,
) -> Result<ArchiveSelection, ExportError> {
    let scope = Scope::of(tree, root)?;
    let mut included: HashSet<NodeId> = scope.ids.clone();
    let mut nodes: Vec<Node> = Vec::with_capacity(scope.nodes.len());
    let mut dependencies = Vec::new();

    for node in &scope.nodes {
        let copy = if Some(node.id) == root {
            tree.detached(node.id)?
        } else {
            (*node).clone()
        };
        nodes.push(copy);
    }

    // A worklist over the nodes already chosen, growing as dependencies are
    // found. Every id is added to `included` before it is queued, so each node
    // is visited once and the loop ends however the references are arranged.
    let mut cursor = 0usize;
    while let Some(node) = nodes.get(cursor) {
        cursor += 1;
        let mut wanted: Vec<NodeId> = node
            .references()
            .into_iter()
            .filter(|reference| !reference.is_deleted())
            .map(|reference| reference.id())
            .collect();
        // A connection taken on its own brings the credential it owns, which
        // sits beside it rather than under it.
        if node.kind.as_connection().is_some() {
            wanted.extend(tree.attached_credentials(node.id));
        }

        let mut pulled = Vec::new();
        for id in wanted {
            if included.contains(&id) {
                continue;
            }
            let Some(target) = tree.get(id).filter(|target| target.deleted_at.is_none()) else {
                continue;
            };
            if !matches!(
                target.kind,
                NodeKind::Credential(_) | NodeKind::Connection(_)
            ) {
                continue;
            }
            included.insert(id);
            pulled.push(tree.detached(id)?);
        }
        for dependency in pulled {
            dependencies.push(dependency.name.clone());
            nodes.push(dependency);
        }
    }

    // A dependency's attached credential names a connection that may not have
    // come along; ownership is only meaningful to the owner, so it is dropped.
    for node in &mut nodes {
        if let NodeKind::Credential(credential) = &mut node.kind {
            if credential
                .attached_to
                .is_some_and(|owner| !included.contains(&owner))
            {
                credential.attached_to = None;
            }
        }
    }

    Ok(ArchiveSelection {
        nodes,
        dependencies,
    })
}
