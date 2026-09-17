//! The owned node tree: indexing, navigation, mutation and resolution.
//!
//! A [`Tree`] is the in-memory form of a vault's node table. It owns every
//! node and maintains a parent → children index alongside them so that the
//! interface can render a level without scanning.
//!
//! Structure is `parent_id` plus `sort_order`, never a materialised path.
//! Moving a subtree therefore touches exactly one row — the moved node — no
//! matter how many descendants it has. [`TreePatch`] reports which rows a
//! mutation touched so that the storage layer writes only those, and so that
//! the interface can show what a drag is about to change before it happens.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::MAX_TREE_DEPTH;
use crate::error::CoreError;
use crate::error::ValidationError;
use crate::inherit::{self, Inherited, Provenance, Resolved};
use crate::node::{
    ConnectionProps, CredentialProps, CredentialRef, EffectiveConnection, GatewayChain, Node,
    NodeId, NodeKind, ProtocolId,
};
use crate::validate::{validate_gateway_chain, validate_node};

/// The rows a mutation touched, and the nodes whose resolved values it may
/// have changed.
///
/// Two separate lists on purpose. `updated` and friends are what the storage
/// layer must persist; `resolution_changed` is what the interface must
/// re-render. A move writes one row and re-renders a subtree, and conflating
/// the two is how a connection manager ends up rewriting ten thousand rows to
/// drag a folder.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreePatch {
    /// Nodes added to the tree.
    pub inserted: Vec<NodeId>,
    /// Nodes whose columns changed.
    pub updated: Vec<NodeId>,
    /// Nodes that gained a `deleted_at`.
    pub tombstoned: Vec<NodeId>,
    /// Nodes whose effective, inherited values may now differ. Derived, not
    /// written: no row is touched on their account.
    pub resolution_changed: Vec<NodeId>,
}

impl TreePatch {
    /// How many rows the storage layer has to write.
    #[must_use]
    pub fn rows_touched(&self) -> usize {
        self.inserted.len() + self.updated.len() + self.tombstoned.len()
    }

    /// Whether the patch changes nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows_touched() == 0
    }
}

/// An owned collection of nodes with a parent → children index.
#[derive(Debug, Clone, Default)]
pub struct Tree {
    nodes: HashMap<NodeId, Node>,
    /// Children by parent, `None` for the roots, each list kept in
    /// `(sort_order, id)` order. Ties break on id so that ordering is total
    /// and stable across reloads.
    children: HashMap<Option<NodeId>, Vec<NodeId>>,
}

impl Tree {
    /// An empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            children: HashMap::new(),
        }
    }

    /// Builds a tree from stored nodes, in any order.
    ///
    /// Every invariant the mutating API maintains is re-checked here, because
    /// this is the one entry point that takes structure from outside: a vault
    /// file, an importer, a synchronised peer.
    ///
    /// # Errors
    ///
    /// [`CoreError::Validation`] for a node that fails value validation,
    /// [`CoreError::DuplicateNodeId`], [`CoreError::ParentNotFound`],
    /// [`CoreError::NotAContainer`], [`CoreError::CorruptTree`] for a parent
    /// cycle, or [`CoreError::DepthExceeded`].
    pub fn from_nodes(nodes: impl IntoIterator<Item = Node>) -> Result<Self, CoreError> {
        let mut tree = Self::new();

        for node in nodes {
            validate_node(&node)?;
            let id = node.id;
            if tree.nodes.insert(id, node).is_some() {
                return Err(CoreError::DuplicateNodeId(id));
            }
        }

        let placements: Vec<(NodeId, Option<NodeId>)> = tree
            .nodes
            .values()
            .map(|node| (node.id, node.parent_id))
            .collect();

        for (id, parent) in placements {
            if let Some(parent_id) = parent {
                let parent_node = tree
                    .nodes
                    .get(&parent_id)
                    .ok_or(CoreError::ParentNotFound(parent_id))?;
                if !parent_node.kind.is_container() {
                    return Err(CoreError::NotAContainer(parent_id));
                }
            }
            tree.children.entry(parent).or_default().push(id);
        }

        let parents: Vec<Option<NodeId>> = tree.children.keys().copied().collect();
        for parent in parents {
            tree.sort_siblings(parent);
        }

        // `depth` walks to the root and fails on a chain that does not
        // terminate, so this pass rejects both cycles and over-deep trees.
        let ids: Vec<NodeId> = tree.nodes.keys().copied().collect();
        for id in ids {
            let depth = tree.depth(id)?;
            if depth > MAX_TREE_DEPTH {
                return Err(CoreError::DepthExceeded { depth });
            }
        }

        Ok(tree)
    }

    /// Consumes the tree and yields its nodes, in no particular order.
    #[must_use]
    pub fn into_nodes(self) -> Vec<Node> {
        self.nodes.into_values().collect()
    }

    /// The number of nodes, including soft-deleted ones.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the tree holds no nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Whether `id` is in the tree.
    #[must_use]
    pub fn contains(&self, id: NodeId) -> bool {
        self.nodes.contains_key(&id)
    }

    /// Borrows a node.
    #[must_use]
    pub fn get(&self, id: NodeId) -> Option<&Node> {
        self.nodes.get(&id)
    }

    /// Every node, in no particular order.
    pub fn nodes(&self) -> impl Iterator<Item = &Node> {
        self.nodes.values()
    }

    /// The root nodes, in display order.
    #[must_use]
    pub fn roots(&self) -> &[NodeId] {
        self.children(None)
    }

    /// The children of `parent`, in display order. `None` gives the roots.
    #[must_use]
    pub fn children(&self, parent: Option<NodeId>) -> &[NodeId] {
        self.children
            .get(&parent)
            .map_or(&[], |siblings| siblings.as_slice())
    }

    /// The ancestors of `id`, ordered nearest → root.
    ///
    /// This is the order the resolver walks, and the order the interface reads
    /// a breadcrumb backwards from.
    ///
    /// # Errors
    ///
    /// [`CoreError::NodeNotFound`], [`CoreError::ParentNotFound`] for a
    /// dangling parent, or [`CoreError::CorruptTree`] if the parent chain does
    /// not terminate.
    pub fn ancestors(&self, id: NodeId) -> Result<Vec<&Node>, CoreError> {
        let start = self.nodes.get(&id).ok_or(CoreError::NodeNotFound(id))?;
        let mut out = Vec::new();
        let mut cursor = start.parent_id;
        // A tree with N nodes has at most N-1 ancestors above any node. The
        // mutating API cannot produce a cycle; this bound is what stops a
        // corrupted store from hanging the process instead of erroring.
        let limit = self.nodes.len();
        while let Some(parent_id) = cursor {
            if out.len() >= limit {
                return Err(CoreError::CorruptTree);
            }
            let parent = self
                .nodes
                .get(&parent_id)
                .ok_or(CoreError::ParentNotFound(parent_id))?;
            out.push(parent);
            cursor = parent.parent_id;
        }
        Ok(out)
    }

    /// The path from `id` to the root, starting with `id` itself.
    ///
    /// # Errors
    ///
    /// As [`Tree::ancestors`].
    pub fn path_to_root(&self, id: NodeId) -> Result<Vec<NodeId>, CoreError> {
        let mut path = vec![id];
        path.extend(self.ancestors(id)?.iter().map(|node| node.id));
        Ok(path)
    }

    /// The depth of `id`, counting from 1 for a root.
    ///
    /// # Errors
    ///
    /// As [`Tree::ancestors`].
    pub fn depth(&self, id: NodeId) -> Result<usize, CoreError> {
        Ok(self.ancestors(id)?.len() + 1)
    }

    /// Whether `ancestor` is on the path from `id` to the root.
    ///
    /// A node is not its own ancestor.
    ///
    /// # Errors
    ///
    /// As [`Tree::ancestors`].
    pub fn is_ancestor_of(&self, ancestor: NodeId, id: NodeId) -> Result<bool, CoreError> {
        Ok(self.ancestors(id)?.iter().any(|node| node.id == ancestor))
    }

    /// The descendants of `id` in pre-order, excluding `id`.
    ///
    /// # Errors
    ///
    /// [`CoreError::NodeNotFound`], or [`CoreError::CorruptTree`] if the child
    /// index revisits a node.
    pub fn descendants(&self, id: NodeId) -> Result<Vec<NodeId>, CoreError> {
        if !self.nodes.contains_key(&id) {
            return Err(CoreError::NodeNotFound(id));
        }
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut stack: Vec<NodeId> = self.children(Some(id)).iter().rev().copied().collect();
        while let Some(current) = stack.pop() {
            if !seen.insert(current) {
                return Err(CoreError::CorruptTree);
            }
            out.push(current);
            stack.extend(self.children(Some(current)).iter().rev().copied());
        }
        Ok(out)
    }

    /// `id` followed by its descendants, in pre-order.
    ///
    /// # Errors
    ///
    /// As [`Tree::descendants`].
    pub fn subtree(&self, id: NodeId) -> Result<Vec<NodeId>, CoreError> {
        let mut out = vec![id];
        out.extend(self.descendants(id)?);
        Ok(out)
    }

    /// Adds a node.
    ///
    /// # Errors
    ///
    /// [`CoreError::Validation`], [`CoreError::DuplicateNodeId`],
    /// [`CoreError::ParentNotFound`], [`CoreError::NotAContainer`] or
    /// [`CoreError::DepthExceeded`].
    pub fn insert(&mut self, node: Node) -> Result<TreePatch, CoreError> {
        validate_node(&node)?;
        if self.nodes.contains_key(&node.id) {
            return Err(CoreError::DuplicateNodeId(node.id));
        }
        if let Some(parent_id) = node.parent_id {
            let parent = self
                .nodes
                .get(&parent_id)
                .ok_or(CoreError::ParentNotFound(parent_id))?;
            if !parent.kind.is_container() {
                return Err(CoreError::NotAContainer(parent_id));
            }
            let depth = self.depth(parent_id)? + 1;
            if depth > MAX_TREE_DEPTH {
                return Err(CoreError::DepthExceeded { depth });
            }
        }

        let id = node.id;
        let parent = node.parent_id;
        self.nodes.insert(id, node);
        self.link(parent, id);

        Ok(TreePatch {
            inserted: vec![id],
            ..TreePatch::default()
        })
    }

    /// Replaces a node's contents, keeping its place in the tree.
    ///
    /// The revision is bumped here rather than by the caller: it is bound into
    /// the AAD of every encrypted secret field on the node, so a caller that
    /// forgot to increment it would silently make a rollback undetectable.
    /// `created_at` is likewise preserved against a caller that reconstructed
    /// the node from a form.
    ///
    /// # Errors
    ///
    /// [`CoreError::Validation`], [`CoreError::NodeNotFound`], or
    /// [`CoreError::ParentChanged`] if `parent_id` differs from the stored
    /// one — re-parenting goes through [`Tree::move_node`], which reports the
    /// resolution changes it causes.
    pub fn update(&mut self, node: Node) -> Result<TreePatch, CoreError> {
        validate_node(&node)?;
        let existing = self
            .nodes
            .get(&node.id)
            .ok_or(CoreError::NodeNotFound(node.id))?;
        if existing.parent_id != node.parent_id {
            return Err(CoreError::ParentChanged { node: node.id });
        }

        let id = node.id;
        let parent = node.parent_id;
        let inheritance_changed = existing.inheritance_differs(&node);
        let order_changed = existing.sort_order != node.sort_order;
        let revision = existing.revision.saturating_add(1);
        let created_at = existing.created_at;
        let previous_updated_at = existing.updated_at;

        let mut node = node;
        node.revision = revision;
        node.created_at = created_at;
        node.updated_at = node.updated_at.max(previous_updated_at);
        self.nodes.insert(id, node);

        if order_changed {
            self.sort_siblings(parent);
        }

        let resolution_changed = if inheritance_changed {
            self.subtree(id)?
        } else {
            vec![id]
        };

        Ok(TreePatch {
            updated: vec![id],
            resolution_changed,
            ..TreePatch::default()
        })
    }

    /// Reports what [`Tree::move_node`] would do, without doing it.
    ///
    /// The interface shows this before applying a drag. A move that silently
    /// changes which credential a hundred connections use is exactly the sort
    /// of thing that erodes trust in a tool, so the change is previewable and
    /// the preview is the same code path as the move.
    ///
    /// # Errors
    ///
    /// As [`Tree::move_node`].
    pub fn preview_move(
        &self,
        id: NodeId,
        new_parent: Option<NodeId>,
    ) -> Result<TreePatch, CoreError> {
        if !self.nodes.contains_key(&id) {
            return Err(CoreError::NodeNotFound(id));
        }

        if let Some(parent_id) = new_parent {
            if parent_id == id {
                return Err(CoreError::Cycle {
                    node: id,
                    parent: parent_id,
                });
            }
            if !self.nodes.contains_key(&parent_id) {
                return Err(CoreError::ParentNotFound(parent_id));
            }
            // The move is a cycle exactly when the proposed parent is inside
            // the subtree being moved. Checking the parent's path to the root
            // is O(depth) rather than O(subtree).
            //
            // Checked before the container rule because a drop inside one's
            // own subtree can violate both, and "you cannot put a folder
            // inside itself" is the answer the user needs; "connections do not
            // hold children" would be true and beside the point.
            if self.path_to_root(parent_id)?.contains(&id) {
                return Err(CoreError::Cycle {
                    node: id,
                    parent: parent_id,
                });
            }
            let parent = self
                .nodes
                .get(&parent_id)
                .ok_or(CoreError::ParentNotFound(parent_id))?;
            if !parent.kind.is_container() {
                return Err(CoreError::NotAContainer(parent_id));
            }
        }

        let parent_depth = match new_parent {
            Some(parent_id) => self.depth(parent_id)?,
            None => 0,
        };
        let depth = parent_depth + self.subtree_height(id)?;
        if depth > MAX_TREE_DEPTH {
            return Err(CoreError::DepthExceeded { depth });
        }

        // A credential attached to the moved node travels with it: it is part
        // of that connection, and a connection whose credential stayed behind
        // in the old folder would be one drag away from being deleted with a
        // folder it no longer belongs to.
        let mut updated = vec![id];
        updated.extend(self.attached_credentials(id));

        Ok(TreePatch {
            updated,
            resolution_changed: self.subtree(id)?,
            ..TreePatch::default()
        })
    }

    /// Re-parents a node and gives it a new position among its siblings.
    ///
    /// Exactly one row changes — the moved node's `parent_id` and
    /// `sort_order` — however large the subtree is. That is the whole reason
    /// the model stores a parent pointer instead of a path.
    ///
    /// # Errors
    ///
    /// [`CoreError::NodeNotFound`], [`CoreError::ParentNotFound`],
    /// [`CoreError::NotAContainer`], [`CoreError::Cycle`] if the new parent is
    /// the node itself or one of its descendants, or
    /// [`CoreError::DepthExceeded`].
    pub fn move_node(
        &mut self,
        id: NodeId,
        new_parent: Option<NodeId>,
        sort_order: i64,
    ) -> Result<TreePatch, CoreError> {
        let patch = self.preview_move(id, new_parent)?;

        let old_parent = self
            .nodes
            .get(&id)
            .ok_or(CoreError::NodeNotFound(id))?
            .parent_id;

        self.unlink(old_parent, id);
        if let Some(node) = self.nodes.get_mut(&id) {
            node.parent_id = new_parent;
            node.sort_order = sort_order;
            node.revision = node.revision.saturating_add(1);
        }
        self.link(new_parent, id);

        // Beside its connection, and given its sort order: siblings break ties
        // on id, so the pair stays adjacent wherever it lands.
        for attached in self.attached_credentials(id) {
            let previous = self.nodes.get(&attached).and_then(|node| node.parent_id);
            self.unlink(previous, attached);
            if let Some(node) = self.nodes.get_mut(&attached) {
                node.parent_id = new_parent;
                node.sort_order = sort_order;
                node.revision = node.revision.saturating_add(1);
            }
            self.link(new_parent, attached);
        }

        Ok(patch)
    }

    /// Soft-deletes a node, its whole subtree and every credential attached to
    /// a node in it, and turns every reference into those nodes from elsewhere
    /// in the tree into a tombstone.
    ///
    /// The attached credentials go because they belong to the connections being
    /// deleted and nothing else may point at them: leaving one behind would
    /// leave the user's password in the vault, reachable by nothing and
    /// visible nowhere.
    ///
    /// References become tombstones rather than dangling ids so that a
    /// connection whose credential was deleted reports "credential deleted"
    /// instead of quietly falling back to whatever a parent folder provides.
    /// The patch's `updated` list names every node whose references changed —
    /// the same list the interface shows for confirmation before the delete.
    ///
    /// # Errors
    ///
    /// [`CoreError::NodeNotFound`] or [`CoreError::CorruptTree`].
    pub fn soft_delete(&mut self, id: NodeId, now: i64) -> Result<TreePatch, CoreError> {
        let subtree = self.subtree(id)?;
        let owners: HashSet<NodeId> = subtree.iter().copied().collect();
        let mut subtree = subtree;
        subtree.extend(
            self.nodes
                .values()
                .filter(|node| {
                    node.kind
                        .as_credential()
                        .and_then(|props| props.attached_to)
                        .is_some_and(|owner| owners.contains(&owner))
                })
                .map(|node| node.id)
                // A credential inside the subtree is already on the list;
                // adding it twice would tombstone it twice and bump its
                // revision for nothing.
                .filter(|attached| !owners.contains(attached))
                .collect::<Vec<NodeId>>(),
        );

        let deleted: HashMap<NodeId, String> = subtree
            .iter()
            .filter_map(|node_id| {
                self.nodes
                    .get(node_id)
                    .map(|node| (node.id, node.name.clone()))
            })
            .collect();

        let mut tombstoned = Vec::new();
        for node_id in &subtree {
            if let Some(node) = self.nodes.get_mut(node_id) {
                if node.deleted_at.is_none() {
                    node.deleted_at = Some(now);
                    node.touch(now);
                    tombstoned.push(*node_id);
                }
            }
        }

        let others: Vec<NodeId> = self
            .nodes
            .keys()
            .copied()
            .filter(|node_id| !deleted.contains_key(node_id))
            .collect();
        let mut updated = Vec::new();
        for node_id in others {
            let changed = self
                .nodes
                .get_mut(&node_id)
                .is_some_and(|node| tombstone_refs(node, &deleted));
            if changed {
                if let Some(node) = self.nodes.get_mut(&node_id) {
                    node.touch(now);
                }
                updated.push(node_id);
            }
        }

        updated.sort_unstable();
        Ok(TreePatch {
            tombstoned,
            updated,
            ..TreePatch::default()
        })
    }

    /// Every node holding a live reference to `id`.
    ///
    /// The interface lists these before a delete is confirmed.
    #[must_use]
    pub fn referrers(&self, id: NodeId) -> Vec<NodeId> {
        let mut out: Vec<NodeId> = self
            .nodes
            .values()
            .filter(|node| node.id != id && references(node, id))
            .map(|node| node.id)
            .collect();
        out.sort_unstable();
        out
    }

    /// The credentials belonging to `id`, in id order.
    ///
    /// At most one in practice — a connection has one identity — but a list
    /// rather than an `Option` because a vault written by a future build, or
    /// repaired by hand, must not make this method the one that lies about what
    /// is in the tree.
    #[must_use]
    pub fn attached_credentials(&self, id: NodeId) -> Vec<NodeId> {
        let mut out: Vec<NodeId> = self
            .nodes
            .values()
            .filter(|node| {
                node.kind
                    .as_credential()
                    .is_some_and(|props| props.belongs_to(id))
            })
            .map(|node| node.id)
            .collect();
        out.sort_unstable();
        out
    }

    /// The properties of a live credential a reference points at.
    ///
    /// `None` for a tombstone, for an id that is not in the tree, and for a
    /// reference that turned out to point at something that is not a
    /// credential — all three of which are reported elsewhere, by
    /// [`Tree::validate_references`], rather than by a resolver that has to
    /// return a value.
    fn credential_props(&self, reference: &CredentialRef) -> Option<&CredentialProps> {
        if reference.is_deleted() {
            return None;
        }
        self.nodes
            .get(&reference.id())
            .and_then(|node| node.kind.as_credential())
    }

    /// Resolves one inheritable field, with the node it came from.
    ///
    /// `None` in the value means the walk found no explicit value and the
    /// caller's default applies; the provenance still says where the walk
    /// stopped.
    ///
    /// # Errors
    ///
    /// As [`Tree::ancestors`].
    pub fn resolve_optional<T, F>(
        &self,
        id: NodeId,
        field: F,
    ) -> Result<Resolved<Option<T>>, CoreError>
    where
        T: Clone,
        F: for<'a> Fn(&'a Node) -> Option<&'a Inherited<T>>,
    {
        let node = self.nodes.get(&id).ok_or(CoreError::NodeNotFound(id))?;
        let ancestors = self.ancestors(id)?;
        Ok(inherit::resolve(node, &ancestors, field))
    }

    /// Resolves one inheritable field, substituting the type default when the
    /// walk finds nothing.
    ///
    /// # Errors
    ///
    /// As [`Tree::ancestors`].
    pub fn resolve<T, F>(&self, id: NodeId, field: F) -> Result<Resolved<T>, CoreError>
    where
        T: Clone + Default,
        F: for<'a> Fn(&'a Node) -> Option<&'a Inherited<T>>,
    {
        Ok(self
            .resolve_optional(id, field)?
            .map(|value| value.unwrap_or_default()))
    }

    /// Flattens a connection's inheritance into the form the session pipeline
    /// and the connection editor both consume.
    ///
    /// # Errors
    ///
    /// [`CoreError::NodeNotFound`], [`CoreError::NotAConnection`], or as
    /// [`Tree::ancestors`].
    pub fn effective_connection(&self, id: NodeId) -> Result<EffectiveConnection, CoreError> {
        let node = self.nodes.get(&id).ok_or(CoreError::NodeNotFound(id))?;
        let Some(conn) = node.kind.as_connection() else {
            return Err(CoreError::NotAConnection(id));
        };
        let ancestors = self.ancestors(id)?;

        let port = inherit::resolve(node, &ancestors, Node::port_field)
            .map(|value| value.or_else(|| conn.protocol.default_port()));
        let credential = inherit::resolve(node, &ancestors, Node::credential_field);
        // The username lives on the credential, so it inherits with the
        // credential and carries the credential's provenance. Resolving it
        // separately would let the interface show a username from one node and
        // the password of another.
        let username = Resolved::new(
            credential
                .value
                .as_ref()
                .and_then(|reference| self.credential_props(reference))
                .map(|props| props.username.clone()),
            credential.provenance,
        );
        let credential_attached = credential
            .value
            .as_ref()
            .and_then(|reference| self.credential_props(reference))
            .is_some_and(|props| props.belongs_to(id));
        let gateway = inherit::resolve(node, &ancestors, Node::gateway_field)
            .map(|value| value.unwrap_or_default());
        let connect_timeout_ms = inherit::resolve(node, &ancestors, Node::connect_timeout_field);
        let keepalive_secs = inherit::resolve(node, &ancestors, Node::keepalive_field);
        let on_connect = inherit::resolve(node, &ancestors, Node::on_connect_field)
            .map(|value| value.unwrap_or_default());
        let on_disconnect = inherit::resolve(node, &ancestors, Node::on_disconnect_field)
            .map(|value| value.unwrap_or_default());
        let recording = inherit::resolve(node, &ancestors, Node::recording_field)
            .map(|value| value.unwrap_or_default());
        let auto_reconnect = inherit::resolve(node, &ancestors, Node::auto_reconnect_field)
            .map(|value| value.unwrap_or_default());
        let icon = inherit::resolve_optional_field(node, &ancestors, Node::icon_field);
        let colour = inherit::resolve_optional_field(node, &ancestors, Node::colour_field);

        Ok(EffectiveConnection {
            node: id,
            name: node.name.clone(),
            protocol: conn.protocol.clone(),
            host: conn.host.clone(),
            port,
            credential,
            username,
            credential_attached,
            gateway,
            connect_timeout_ms,
            keepalive_secs,
            settings: merge_settings(node, &ancestors),
            on_connect,
            on_disconnect,
            recording,
            auto_reconnect,
            icon,
            colour,
        })
    }

    /// A copy of a node that behaves the same with no folder above it.
    ///
    /// Every inheritable field the node leaves to an ancestor is pinned to what
    /// that ancestor gives it: a port or a credential a folder sets becomes the
    /// node's own, a folder's "no jump hosts, deliberately" becomes the node's
    /// own `Default`, and protocol settings, icon and colour are merged in the
    /// way resolution merges them. A field nothing above sets stays `Inherit`.
    /// The copy has no parent.
    ///
    /// This is what an export needs for the nodes it takes out of their place
    /// in the tree — the folder at its root, a shared credential or a jump host
    /// that lives elsewhere — so that they connect the same way wherever they
    /// are put down.
    ///
    /// # Errors
    ///
    /// [`CoreError::NodeNotFound`], or as [`Tree::ancestors`].
    pub fn detached(&self, id: NodeId) -> Result<Node, CoreError> {
        fn pin<T: Clone>(
            field: &mut Inherited<T>,
            original: &Node,
            ancestors: &[&Node],
            get: impl for<'a> Fn(&'a Node) -> Option<&'a Inherited<T>>,
        ) {
            if !field.is_inherit() {
                return;
            }
            let resolved = inherit::resolve(original, ancestors, get);
            match (resolved.provenance, resolved.value) {
                (Provenance::Ancestor(_), Some(value)) => *field = Inherited::Explicit(value),
                (Provenance::DefaultAt(_), _) => *field = Inherited::Default,
                _ => {}
            }
        }

        let original = self.nodes.get(&id).ok_or(CoreError::NodeNotFound(id))?;
        let ancestors = self.ancestors(id)?;
        let mut node = original.clone();
        node.parent_id = None;

        match &mut node.kind {
            NodeKind::Folder(props) => {
                pin(&mut props.port, original, &ancestors, Node::port_field);
                pin(
                    &mut props.credential,
                    original,
                    &ancestors,
                    Node::credential_field,
                );
                pin(
                    &mut props.gateway,
                    original,
                    &ancestors,
                    Node::gateway_field,
                );
                pin(
                    &mut props.connect_timeout_ms,
                    original,
                    &ancestors,
                    Node::connect_timeout_field,
                );
                pin(
                    &mut props.keepalive_secs,
                    original,
                    &ancestors,
                    Node::keepalive_field,
                );
                pin(
                    &mut props.on_connect,
                    original,
                    &ancestors,
                    Node::on_connect_field,
                );
                pin(
                    &mut props.on_disconnect,
                    original,
                    &ancestors,
                    Node::on_disconnect_field,
                );
                pin(
                    &mut props.recording,
                    original,
                    &ancestors,
                    Node::recording_field,
                );
                pin(
                    &mut props.auto_reconnect,
                    original,
                    &ancestors,
                    Node::auto_reconnect_field,
                );
                merge_ancestor_settings(&mut props.settings, &ancestors)?;
            }
            NodeKind::Connection(props) => {
                pin(&mut props.port, original, &ancestors, Node::port_field);
                pin(
                    &mut props.credential,
                    original,
                    &ancestors,
                    Node::credential_field,
                );
                pin(
                    &mut props.gateway,
                    original,
                    &ancestors,
                    Node::gateway_field,
                );
                pin(
                    &mut props.connect_timeout_ms,
                    original,
                    &ancestors,
                    Node::connect_timeout_field,
                );
                pin(
                    &mut props.keepalive_secs,
                    original,
                    &ancestors,
                    Node::keepalive_field,
                );
                pin(
                    &mut props.on_connect,
                    original,
                    &ancestors,
                    Node::on_connect_field,
                );
                pin(
                    &mut props.on_disconnect,
                    original,
                    &ancestors,
                    Node::on_disconnect_field,
                );
                pin(
                    &mut props.recording,
                    original,
                    &ancestors,
                    Node::recording_field,
                );
                pin(
                    &mut props.auto_reconnect,
                    original,
                    &ancestors,
                    Node::auto_reconnect_field,
                );
                merge_ancestor_settings(&mut props.settings, &ancestors)?;
            }
            NodeKind::Credential(_) | NodeKind::Group(_) | NodeKind::Separator => {}
        }
        if node.icon.is_none() {
            node.icon = ancestors.iter().find_map(|ancestor| ancestor.icon.clone());
        }
        if node.colour.is_none() {
            node.colour = ancestors
                .iter()
                .find_map(|ancestor| ancestor.colour.clone());
        }
        Ok(node)
    }

    /// Checks the rules that need the whole tree: that every reference points
    /// at something that exists and is the right kind, that no gateway chain
    /// loops, and that a credential restricted to a set of protocols is not
    /// used by a connection speaking another one.
    ///
    /// Called for a connection, this checks the *effective* credential and
    /// gateway chain, not only the ones stored on the node, because an
    /// inherited credential is the one that will actually be used.
    ///
    /// # Errors
    ///
    /// [`CoreError::NodeNotFound`], or [`CoreError::Validation`] carrying the
    /// rule that was broken.
    pub fn validate_references(&self, id: NodeId) -> Result<(), CoreError> {
        let node = self.nodes.get(&id).ok_or(CoreError::NodeNotFound(id))?;

        if let Some(Inherited::Explicit(credential)) = node.credential_field() {
            self.check_credential(credential, None, id)?;
        }
        if let Some(props) = node.kind.as_credential() {
            self.check_attachment(id, props)?;
        }
        if let Some(Inherited::Explicit(chain)) = node.gateway_field() {
            validate_gateway_chain(chain)?;
            self.check_chain(chain, id)?;
        }
        if let NodeKind::Group(group) = &node.kind {
            for member in &group.members {
                if !member.is_deleted() && !self.nodes.contains_key(&member.id()) {
                    return Err(ValidationError::GroupMemberUnknown {
                        member: member.id(),
                    }
                    .into());
                }
            }
        }

        if let Some(conn) = node.kind.as_connection() {
            self.check_effective(id, conn)?;
        }

        Ok(())
    }

    /// Runs [`Tree::validate_references`] over every node, collecting the
    /// failures instead of stopping at the first.
    ///
    /// This is what an importer reports: a partial import with a list of
    /// rejected rows is more useful than a single error about row 4,812.
    #[must_use]
    pub fn validate_all(&self) -> Vec<(NodeId, CoreError)> {
        let mut ids: Vec<NodeId> = self.nodes.keys().copied().collect();
        ids.sort_unstable();
        ids.into_iter()
            .filter_map(|id| match self.validate_references(id) {
                Ok(()) => None,
                Err(error) => Some((id, error)),
            })
            .collect()
    }

    fn check_effective(&self, id: NodeId, conn: &ConnectionProps) -> Result<(), CoreError> {
        let credential = self.resolve_optional(id, Node::credential_field)?;
        if let Some(credential) = credential.value {
            self.check_credential(&credential, Some(&conn.protocol), id)?;
        }
        let gateway = self.resolve_optional(id, Node::gateway_field)?;
        if let Some(chain) = gateway.value {
            validate_gateway_chain(&chain)?;
            self.check_chain(&chain, id)?;
        }
        Ok(())
    }

    /// Checks that an attached credential is attached to something that is
    /// there and is a connection.
    ///
    /// A dangling attachment means the connection was removed without its
    /// credential, which would leave secret material in the vault owned by
    /// nothing — so it is a corruption to report, not a state to tolerate.
    fn check_attachment(
        &self,
        credential: NodeId,
        props: &CredentialProps,
    ) -> Result<(), ValidationError> {
        let Some(connection) = props.attached_to else {
            return Ok(());
        };
        let Some(owner) = self.nodes.get(&connection) else {
            return Err(ValidationError::CredentialAttachmentUnknown {
                credential,
                connection,
            });
        };
        if owner.kind.as_connection().is_none() {
            return Err(ValidationError::CredentialAttachmentNotAConnection {
                credential,
                connection,
            });
        }
        Ok(())
    }

    /// Checks one credential reference held by `referrer`.
    fn check_credential(
        &self,
        credential: &CredentialRef,
        protocol: Option<&ProtocolId>,
        referrer: NodeId,
    ) -> Result<(), ValidationError> {
        // A tombstone is not a validation failure. It is a deletion the user
        // already confirmed, and it is reported at connect time with a message
        // that names what is missing.
        if credential.is_deleted() {
            return Ok(());
        }
        let target =
            self.nodes
                .get(&credential.id())
                .ok_or(ValidationError::CredentialUnknown {
                    credential: credential.id(),
                })?;
        let Some(props) = target.kind.as_credential() else {
            return Err(ValidationError::CredentialNotACredential {
                credential: credential.id(),
            });
        };
        // An attached credential is one connection's own. Letting a second
        // node point at it would put two connections behind one password
        // without either of them saying so, and editing it from one would
        // change the other — the exact failure attaching exists to prevent.
        if let Some(owner) = props.attached_to {
            if owner != referrer {
                return Err(ValidationError::CredentialAttachedElsewhere {
                    credential: credential.id(),
                    connection: owner,
                });
            }
        }
        if let Some(protocol) = protocol {
            if !props.permits(protocol) {
                return Err(ValidationError::CredentialPurpose {
                    credential: credential.id(),
                    protocol: protocol.as_str().to_owned(),
                });
            }
        }
        Ok(())
    }

    fn check_chain(&self, chain: &GatewayChain, owner: NodeId) -> Result<(), ValidationError> {
        for hop in &chain.hops {
            let hop_id = hop.node.id();
            if hop_id == owner {
                return Err(ValidationError::GatewayCycle { hop: hop_id });
            }
            if hop.node.is_deleted() {
                continue;
            }
            let target = self
                .nodes
                .get(&hop_id)
                .ok_or(ValidationError::GatewayHopUnknown { hop: hop_id })?;
            let Some(hop_conn) = target.kind.as_connection() else {
                return Err(ValidationError::GatewayHopNotAConnection { hop: hop_id });
            };
            if let Some(credential) = &hop.credential {
                self.check_credential(credential, Some(&hop_conn.protocol), owner)?;
            }
        }
        Ok(())
    }

    /// The number of levels in the subtree rooted at `id`, counting `id`
    /// itself as one.
    fn subtree_height(&self, id: NodeId) -> Result<usize, CoreError> {
        let mut height = 1;
        let mut level = vec![id];
        let mut seen: HashSet<NodeId> = HashSet::new();
        seen.insert(id);
        loop {
            let mut next = Vec::new();
            for parent in &level {
                for child in self.children(Some(*parent)) {
                    if !seen.insert(*child) {
                        return Err(CoreError::CorruptTree);
                    }
                    next.push(*child);
                }
            }
            if next.is_empty() {
                return Ok(height);
            }
            height += 1;
            level = next;
        }
    }

    fn link(&mut self, parent: Option<NodeId>, id: NodeId) {
        self.children.entry(parent).or_default().push(id);
        self.sort_siblings(parent);
    }

    fn unlink(&mut self, parent: Option<NodeId>, id: NodeId) {
        if let Some(siblings) = self.children.get_mut(&parent) {
            siblings.retain(|sibling| *sibling != id);
            if siblings.is_empty() {
                self.children.remove(&parent);
            }
        }
    }

    fn sort_siblings(&mut self, parent: Option<NodeId>) {
        let Some(mut siblings) = self.children.remove(&parent) else {
            return;
        };
        siblings.sort_by_key(|id| {
            (
                self.nodes.get(id).map_or(i64::MAX, |node| node.sort_order),
                *id,
            )
        });
        self.children.insert(parent, siblings);
    }
}

/// Merges protocol settings from the root down, nearest node winning per key.
///
/// Per-key rather than whole-map, so that a folder setting a terminal type and
/// a connection setting a colour depth end up with both, each labelled with
/// where it came from.
/// Adds to `settings` every key an ancestor sets and it does not, nearest
/// ancestor first — the precedence [`merge_settings`] resolves with.
fn merge_ancestor_settings(
    settings: &mut crate::node::ProtocolSettings,
    ancestors: &[&Node],
) -> Result<(), CoreError> {
    for ancestor in ancestors {
        if let Some(inherited) = ancestor.settings_field() {
            for (key, value) in inherited.iter() {
                if !settings.contains_key(key) {
                    settings.insert(key, value)?;
                }
            }
        }
    }
    Ok(())
}

/// Gives a set of nodes new identities, rewriting every reference among them.
///
/// For nodes that come from somewhere else and are about to be put beside the
/// ones already here — an archive of another vault, or a second import of the
/// same one — whose ids may already be taken. Parents, credentials, gateway
/// hops and their credentials, group members and the owner of an attached
/// credential all follow their node to its new id. A reference to a node that
/// is not in the set is left exactly as it is: whether it still means
/// something where the nodes are going is the caller's to decide.
///
/// Returns the map from each old id to its new one.
pub fn rekey(nodes: &mut [Node]) -> HashMap<NodeId, NodeId> {
    let map: HashMap<NodeId, NodeId> = nodes.iter().map(|node| (node.id, NodeId::new())).collect();
    for node in nodes.iter_mut() {
        if let Some(new) = map.get(&node.id) {
            node.id = *new;
        }
        if let Some(new) = node.parent_id.and_then(|parent| map.get(&parent)) {
            node.parent_id = Some(*new);
        }
        for reference in node.references_mut() {
            reference.retarget(&map);
        }
        if let NodeKind::Credential(credential) = &mut node.kind {
            if let Some(new) = credential.attached_to.and_then(|owner| map.get(&owner)) {
                credential.attached_to = Some(*new);
            }
        }
    }
    map
}

fn merge_settings(node: &Node, ancestors: &[&Node]) -> BTreeMap<String, Resolved<String>> {
    let mut merged = BTreeMap::new();
    for ancestor in ancestors.iter().rev() {
        if let Some(settings) = ancestor.settings_field() {
            for (key, value) in settings.iter() {
                merged.insert(
                    key.to_owned(),
                    Resolved::from_ancestor(ancestor.id, value.to_owned()),
                );
            }
        }
    }
    if let Some(settings) = node.settings_field() {
        for (key, value) in settings.iter() {
            merged.insert(key.to_owned(), Resolved::own(node.id, value.to_owned()));
        }
    }
    merged
}

/// Whether `node` holds a live reference to `target`.
fn references(node: &Node, target: NodeId) -> bool {
    if let Some(Inherited::Explicit(credential)) = node.credential_field() {
        if !credential.is_deleted() && credential.id() == target {
            return true;
        }
    }
    if let Some(Inherited::Explicit(chain)) = node.gateway_field() {
        for hop in &chain.hops {
            if !hop.node.is_deleted() && hop.node.id() == target {
                return true;
            }
            if let Some(credential) = &hop.credential {
                if !credential.is_deleted() && credential.id() == target {
                    return true;
                }
            }
        }
    }
    if let NodeKind::Group(group) = &node.kind {
        if group
            .members
            .iter()
            .any(|member| !member.is_deleted() && member.id() == target)
        {
            return true;
        }
    }
    false
}

/// Rewrites every reference from `node` into a deleted node as a tombstone.
/// Returns whether anything changed.
fn tombstone_refs(node: &mut Node, deleted: &HashMap<NodeId, String>) -> bool {
    let mut changed = false;
    match &mut node.kind {
        NodeKind::Folder(props) => {
            changed |= tombstone_credential_field(&mut props.credential, deleted);
            changed |= tombstone_gateway_field(&mut props.gateway, deleted);
        }
        NodeKind::Connection(props) => {
            changed |= tombstone_credential_field(&mut props.credential, deleted);
            changed |= tombstone_gateway_field(&mut props.gateway, deleted);
        }
        NodeKind::Group(props) => {
            for member in &mut props.members {
                if let Some(name) = deleted.get(&member.id()) {
                    changed |= member.tombstone(name);
                }
            }
        }
        NodeKind::Credential(_) | NodeKind::Separator => {}
    }
    changed
}

fn tombstone_credential_field(
    field: &mut Inherited<CredentialRef>,
    deleted: &HashMap<NodeId, String>,
) -> bool {
    let Inherited::Explicit(credential) = field else {
        return false;
    };
    match deleted.get(&credential.id()) {
        Some(name) => credential.tombstone(name),
        None => false,
    }
}

fn tombstone_gateway_field(
    field: &mut Inherited<GatewayChain>,
    deleted: &HashMap<NodeId, String>,
) -> bool {
    let Inherited::Explicit(chain) = field else {
        return false;
    };
    let mut changed = false;
    for hop in &mut chain.hops {
        if let Some(name) = deleted.get(&hop.node.id()) {
            changed |= hop.node.tombstone(name);
        }
        if let Some(credential) = &mut hop.credential {
            if let Some(name) = deleted.get(&credential.id()) {
                changed |= credential.tombstone(name);
            }
        }
    }
    changed
}
