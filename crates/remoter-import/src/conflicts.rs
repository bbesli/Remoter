//! What an import does about what the vault already has.
//!
//! Step 5 of the import flow in `docs/features/import-export.md`. An import
//! that lands in a folder already holding a `web-01` used to make a second
//! `web-01` beside it; a second import of the same file made a second copy of
//! everything. [`resolve`] compares what is arriving with what is there and
//! applies the user's [`ConflictPolicy`] to the whole import:
//!
//! - **Keep both** — everything arrives as new nodes, the way it always did.
//! - **Skip** — a folder that already exists is not made again: what the import
//!   has for it goes into the one that is there. Anything else that already
//!   exists is left as it is and the imported one is dropped; what the import
//!   pointed at it now points at the one in the vault.
//! - **Replace** — folders merge the same way, and anything else that already
//!   exists takes the imported one's properties while keeping its identity, so
//!   every connection, route and group that pointed at it still does.
//!
//! "Already exists" means a live node of the same kind and the same name in the
//! place the imported one would land — the folder a merge has made them share.
//! A credential that belongs to a connection is matched through its connection
//! instead: names of attached credentials repeat their connection's, and a
//! connection's credential is the one attached to it, wherever it sits.
//!
//! Pure: a tree in, a plan out. Nothing here seals, stores or writes.

use std::collections::{HashMap, HashSet};

use remoter_core::{Node, NodeId, NodeKind, Tree, remap};
use serde::{Deserialize, Serialize};

/// What to do with an imported item the vault already has.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConflictPolicy {
    /// Import it anyway, beside the one that is there.
    #[default]
    KeepBoth,
    /// Leave the one that is there, and drop the imported one.
    Skip,
    /// Give the one that is there the imported one's properties.
    Replace,
}

/// An imported item that the vault already has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Conflict {
    /// The item's name.
    pub name: String,
    /// `folder`, `connection`, `credential`, `group` or `separator`.
    pub kind: String,
    /// The id of the node already in the vault.
    pub existing: NodeId,
}

/// Just enough of an imported node to find what it collides with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Its id in the import.
    pub id: NodeId,
    /// Its parent in the import; `None`, or an id not in the import, for a
    /// node at the import's top level.
    pub parent_id: Option<NodeId>,
    /// Its kind's label.
    pub kind: &'static str,
    /// Its name.
    pub name: String,
    /// For a credential, the connection it belongs to.
    pub attached_to: Option<NodeId>,
}

impl Candidate {
    /// The candidate a node is.
    #[must_use]
    pub fn of(node: &Node) -> Self {
        Self {
            id: node.id,
            parent_id: node.parent_id,
            kind: node.kind.label(),
            name: node.name.clone(),
            attached_to: node.kind.as_credential().and_then(|c| c.attached_to),
        }
    }
}

/// The imported items that already exist where they would land, in import
/// order.
///
/// `candidates` are parents before children; `destination` is where the
/// import's top level goes. Folders are matched as a merge would match them, so
/// the contents of a folder that exists are compared with the contents of the
/// folder that is there.
#[must_use]
pub fn find(candidates: &[Candidate], tree: &Tree, destination: Option<NodeId>) -> Vec<Conflict> {
    matches(candidates, tree, destination)
        .into_iter()
        .map(|(index, existing)| Conflict {
            name: candidates[index].name.clone(),
            kind: candidates[index].kind.to_owned(),
            existing,
        })
        .collect()
}

/// Each colliding candidate, by its index in `candidates`, with the vault node
/// it collides with.
fn matches(
    candidates: &[Candidate],
    tree: &Tree,
    destination: Option<NodeId>,
) -> Vec<(usize, NodeId)> {
    let ids: HashSet<NodeId> = candidates.iter().map(|c| c.id).collect();
    // Import id → the vault node it collides with. A child is looked for under
    // what its parent collided with; a child of a new folder cannot collide.
    let mut matched: HashMap<NodeId, NodeId> = HashMap::new();
    let mut out = Vec::new();
    for (index, candidate) in candidates.iter().enumerate() {
        let place = match candidate.parent_id {
            Some(parent) if ids.contains(&parent) => match matched.get(&parent) {
                Some(existing) => Some(*existing),
                None => continue,
            },
            _ => destination,
        };
        let existing = match candidate.attached_to {
            Some(owner) if ids.contains(&owner) => matched.get(&owner).and_then(|existing_owner| {
                tree.attached_credentials(*existing_owner).first().copied()
            }),
            _ => sibling(tree, place, candidate.kind, &candidate.name),
        };
        if let Some(existing) = existing {
            matched.insert(candidate.id, existing);
            out.push((index, existing));
        }
    }
    out
}

/// The plan for an import, once its policy is applied.
#[derive(Debug, Default)]
pub struct Resolution {
    /// Nodes to insert, parents before children.
    pub inserts: Vec<Node>,
    /// Nodes already in the vault, with the imported properties, to update.
    pub updates: Vec<Node>,
    /// Import id → the id the item ends up with in the vault, for every item
    /// that did not keep its own: merged folders, skipped and replaced items.
    /// An import's secrets follow their node through this.
    pub ids: HashMap<NodeId, NodeId>,
    /// Import ids of the items left as they were. Their secrets are not
    /// stored: the vault keeps its own.
    pub skipped: HashSet<NodeId>,
    /// Folders that merged into one already there.
    pub merged: usize,
    /// What collided, whatever the policy did about it.
    pub conflicts: Vec<Conflict>,
}

/// Applies `policy` to imported nodes landing under `destination`.
///
/// `nodes` must be parents before children, with the ids they will have if
/// they are inserted and the import's top level already parented at
/// `destination`.
#[must_use]
pub fn resolve(
    nodes: Vec<Node>,
    tree: &Tree,
    destination: Option<NodeId>,
    policy: ConflictPolicy,
) -> Resolution {
    let candidates: Vec<Candidate> = nodes
        .iter()
        .map(|node| {
            let mut candidate = Candidate::of(node);
            if candidate.parent_id == destination {
                candidate.parent_id = None;
            }
            candidate
        })
        .collect();
    let collided = matches(&candidates, tree, destination);
    let by_import: HashMap<NodeId, NodeId> = collided
        .iter()
        .map(|(index, existing)| (candidates[*index].id, *existing))
        .collect();
    let conflicts: Vec<Conflict> = collided
        .into_iter()
        .map(|(index, existing)| Conflict {
            name: candidates[index].name.clone(),
            kind: candidates[index].kind.to_owned(),
            existing,
        })
        .collect();

    let mut resolution = Resolution {
        conflicts,
        ..Resolution::default()
    };
    for mut node in nodes {
        let existing = by_import.get(&node.id).and_then(|id| tree.get(*id));
        match (existing, policy) {
            (None, _) | (_, ConflictPolicy::KeepBoth) => resolution.inserts.push(node),
            (Some(existing), _) if matches!(node.kind, NodeKind::Folder(_)) => {
                resolution.ids.insert(node.id, existing.id);
                resolution.merged += 1;
            }
            (Some(existing), ConflictPolicy::Skip) => {
                resolution.ids.insert(node.id, existing.id);
                resolution.skipped.insert(node.id);
            }
            (Some(existing), ConflictPolicy::Replace) => {
                resolution.ids.insert(node.id, existing.id);
                node.id = existing.id;
                node.parent_id = existing.parent_id;
                node.sort_order = existing.sort_order;
                node.created_at = existing.created_at;
                node.revision = existing.revision;
                resolution.updates.push(node);
            }
        }
    }
    // Everything that pointed at a merged, skipped or replaced item now points
    // at the one in the vault — including the parents of what goes into a
    // merged folder.
    remap(&mut resolution.inserts, &resolution.ids);
    remap(&mut resolution.updates, &resolution.ids);
    resolution
}

/// A live child of `parent` with this kind and name.
fn sibling(tree: &Tree, parent: Option<NodeId>, kind: &str, name: &str) -> Option<NodeId> {
    tree.children(parent).iter().copied().find(|id| {
        tree.get(*id).is_some_and(|node| {
            node.deleted_at.is_none() && node.kind.label() == kind && node.name == name
        })
    })
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code, per docs/development/coding-standards.md"
)]
mod tests {
    use remoter_core::{
        ConnectionProps, CredentialProps, CredentialRef, GatewayHop, Inherited, SecretKind,
    };

    use super::*;

    fn folder(name: &str, parent: Option<NodeId>) -> Node {
        let mut node = Node::new(NodeKind::folder(), name, 1);
        node.parent_id = parent;
        node
    }

    fn connection(name: &str, host: &str, parent: Option<NodeId>) -> Node {
        let mut node = Node::new(
            NodeKind::Connection(ConnectionProps::new("ssh", host).unwrap()),
            name,
            1,
        );
        node.parent_id = parent;
        node
    }

    fn attached(owner: &Node) -> Node {
        let mut node = Node::new(
            NodeKind::Credential(CredentialProps::attached(
                owner.id,
                "root",
                SecretKind::Password { sealed: vec![0] },
            )),
            owner.name.clone(),
            1,
        );
        node.parent_id = owner.parent_id;
        node
    }

    fn uses(node: &mut Node, credential: NodeId) {
        if let NodeKind::Connection(props) = &mut node.kind {
            props.credential = Inherited::Explicit(CredentialRef::live(credential));
        }
    }

    fn host(node: &Node) -> &str {
        &node.kind.as_connection().unwrap().host
    }

    /// A vault with `Imports / Production / web-01`, web-01 owning a credential.
    fn vault() -> (Tree, NodeId, NodeId, NodeId, NodeId) {
        let imports = folder("Imports", None);
        let production = folder("Production", Some(imports.id));
        let mut web = connection("web-01", "old.example.com", Some(production.id));
        let own = attached(&web);
        uses(&mut web, own.id);
        let ids = (imports.id, production.id, web.id, own.id);
        let tree = Tree::from_nodes([imports, production, web, own]).unwrap();
        (tree, ids.0, ids.1, ids.2, ids.3)
    }

    /// An import of `Production / web-01, web-02`, web-02 routed through web-01.
    fn import(into: NodeId) -> (Vec<Node>, NodeId, NodeId, NodeId) {
        let production = folder("Production", Some(into));
        let mut web1 = connection("web-01", "new.example.com", Some(production.id));
        let own = attached(&web1);
        uses(&mut web1, own.id);
        let mut web2 = connection("web-02", "web-02.example.com", Some(production.id));
        if let NodeKind::Connection(props) = &mut web2.kind {
            props.gateway = Inherited::Explicit([GatewayHop::new(web1.id)].into_iter().collect());
        }
        let ids = (production.id, web1.id, web2.id);
        (vec![production, web1, own, web2], ids.0, ids.1, ids.2)
    }

    #[test]
    fn what_already_exists_is_found_through_the_folders_that_would_merge() {
        let (tree, imports, production, web, own) = vault();
        let (nodes, ..) = import(imports);
        let resolution = resolve(nodes, &tree, Some(imports), ConflictPolicy::KeepBoth);
        let found: Vec<(&str, &str, NodeId)> = resolution
            .conflicts
            .iter()
            .map(|c| (c.name.as_str(), c.kind.as_str(), c.existing))
            .collect();
        assert_eq!(
            found,
            [
                ("Production", "folder", production),
                ("web-01", "connection", web),
                ("web-01", "credential", own),
            ]
        );
        // Keep both changes nothing about the import: all four arrive.
        assert_eq!(resolution.inserts.len(), 4);
        assert!(resolution.updates.is_empty() && resolution.ids.is_empty());
    }

    #[test]
    fn skipping_leaves_the_vault_as_it_is_and_points_the_import_at_it() {
        let (mut tree, imports, production, web, _) = vault();
        let (nodes, _, web1, web2) = import(imports);
        let resolution = resolve(nodes, &tree, Some(imports), ConflictPolicy::Skip);

        assert_eq!(resolution.merged, 1);
        assert!(resolution.skipped.contains(&web1));
        assert_eq!(resolution.inserts.len(), 1, "only web-02 is new");
        let inserted = &resolution.inserts[0];
        assert_eq!(inserted.id, web2);
        // Into the folder that was already there, and through the web-01 that
        // was already there.
        assert_eq!(inserted.parent_id, Some(production));
        let Inherited::Explicit(chain) = &inserted.kind.as_connection().unwrap().gateway else {
            panic!("the route went");
        };
        assert_eq!(chain.hops[0].node.id(), web);

        for node in resolution.inserts {
            tree.insert(node).unwrap();
        }
        assert!(tree.validate_all().is_empty(), "{:?}", tree.validate_all());
        assert_eq!(host(tree.get(web).unwrap()), "old.example.com");
    }

    #[test]
    fn replacing_keeps_the_identity_and_takes_the_imported_properties() {
        let (mut tree, imports, production, web, own) = vault();
        let (nodes, ..) = import(imports);
        let resolution = resolve(nodes, &tree, Some(imports), ConflictPolicy::Replace);

        assert_eq!(
            resolution.updates.len(),
            2,
            "web-01 and the credential it owns"
        );
        let replaced = resolution.updates.iter().find(|n| n.id == web).unwrap();
        assert_eq!(replaced.parent_id, Some(production));
        assert_eq!(host(replaced), "new.example.com");
        // Its credential reference points at the credential it already had,
        // which is replaced in turn.
        assert_eq!(
            replaced.kind.as_connection().unwrap().credential,
            Inherited::Explicit(CredentialRef::live(own))
        );
        let credential = resolution.updates.iter().find(|n| n.id == own).unwrap();
        assert_eq!(
            credential.kind.as_credential().unwrap().attached_to,
            Some(web)
        );

        for node in resolution.updates {
            tree.update(node).unwrap();
        }
        for node in resolution.inserts {
            tree.insert(node).unwrap();
        }
        assert!(tree.validate_all().is_empty(), "{:?}", tree.validate_all());
        assert_eq!(host(tree.get(web).unwrap()), "new.example.com");
        assert_eq!(
            tree.children(Some(production)).len(),
            3,
            "web-01, its credential, web-02"
        );
    }

    #[test]
    fn a_kind_or_a_place_that_differs_is_not_a_conflict() {
        let (tree, imports, _, _, _) = vault();
        // A connection called Production is not the folder called Production,
        // and a web-01 at the top level is not the one inside it.
        let nodes = vec![
            connection("Production", "p.example.com", Some(imports)),
            connection("web-01", "w.example.com", Some(imports)),
        ];
        let resolution = resolve(nodes, &tree, Some(imports), ConflictPolicy::Replace);
        assert!(resolution.conflicts.is_empty());
        assert_eq!(resolution.inserts.len(), 2);
    }
}
