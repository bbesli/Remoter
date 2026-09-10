//! Querying the append-only audit log.
//!
//! The log is written by `storage.rs` and never edited; this module only reads
//! it. The screen it backs — `ui_parts/project_ui_design/07 Audit and
//! Recording.dc.html` — is a filtered, paginated table over a log that reaches
//! thousands of rows, so filtering and counting happen in SQL rather than by
//! loading everything and discarding most of it.
//!
//! Nothing here decrypts anything. An audit row holds a timestamp, an event
//! name, an outcome, two identifiers and a short plain-text detail; a secret
//! must never reach the `detail` column in the first place, which is a rule the
//! writers keep and `tests/audit_query.rs` checks by running a lifecycle and
//! searching the rendered rows for the credentials it used.

use uuid::Uuid;

use crate::storage::{AuditEvent, AuditOutcome};

/// The filter groups the audit screen offers.
///
/// Four of them are a partition of the event names: every event belongs to
/// exactly one. [`AuditCategory::Warning`] is the exception and deliberately
/// cuts across the others — it is what someone reviewing an incident scrolls
/// for, which is a question about outcomes and about three specific events, not
/// about which subsystem wrote the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuditCategory {
    /// The vault file itself: unlocks, saves, key slots, settings.
    Vault,
    /// The tree: nodes created, changed, moved, deleted.
    Node,
    /// Secret fields: stored, used, revealed, exported.
    Secret,
    /// Sessions and the trust store.
    Connection,
    /// Anything that did not succeed, plus the events an incident review looks
    /// for whether or not they succeeded: a refused host key, a plaintext
    /// export, a failed unlock.
    Warning,
}

/// Events that are a warning however they ended.
///
/// A plaintext export that *succeeded* is exactly the row an incident review
/// wants; so is a host key that was refused. Outcome alone would miss both.
const ALWAYS_A_WARNING: &[AuditEvent] = &[
    AuditEvent::TrustRejected,
    AuditEvent::SecretExported,
    AuditEvent::VaultUnlockFailed,
];

impl AuditCategory {
    /// Every category, in the order the screen lists them.
    pub const ALL: &'static [Self] = &[
        Self::Connection,
        Self::Secret,
        Self::Vault,
        Self::Node,
        Self::Warning,
    ];

    /// The stable spelling, for the interface and for settings.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Vault => "vault",
            Self::Node => "node",
            Self::Secret => "secret",
            Self::Connection => "connection",
            Self::Warning => "warning",
        }
    }

    /// Reads back a spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.as_str() == text)
    }

    /// Whether an entry belongs in this category.
    ///
    /// `event` is `None` for a row written by a newer build, whose event name
    /// this build does not know. Such a row is still shown — the log is
    /// append-only and hiding rows would defeat its purpose — and it counts as
    /// a warning if it did not succeed.
    #[must_use]
    pub fn matches(self, event: Option<AuditEvent>, outcome: Option<AuditOutcome>) -> bool {
        match self {
            Self::Warning => {
                outcome.is_none_or(|o| o != AuditOutcome::Success)
                    || event.is_some_and(|e| ALWAYS_A_WARNING.contains(&e))
            }
            other => event.is_some_and(|e| e.category() == other),
        }
    }
}

impl core::fmt::Display for AuditCategory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One row of the audit log, as the interface reads it.
///
/// `Debug` is derived, and safe: every field here is either an identifier, a
/// timestamp or the plain-text `detail`, which must never carry secret
/// material. See the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// Row identifier. Monotonic, so it also orders rows written in the same
    /// millisecond.
    pub id: i64,
    /// Milliseconds since the Unix epoch.
    pub at: i64,
    /// The event name as stored. Kept as text rather than as [`AuditEvent`] so
    /// that a row written by a newer build survives being read by this one.
    pub event: String,
    /// The outcome as stored.
    pub outcome: String,
    /// The node the entry is about, if any.
    pub node: Option<Uuid>,
    /// The session the entry is about, if any.
    pub session: Option<Uuid>,
    /// A short plain-language note. Never a secret.
    pub detail: Option<String>,
}

impl AuditRecord {
    /// The event, if this build knows the name.
    #[must_use]
    pub fn event_kind(&self) -> Option<AuditEvent> {
        AuditEvent::parse(&self.event)
    }

    /// The outcome, if this build knows the name.
    #[must_use]
    pub fn outcome_kind(&self) -> Option<AuditOutcome> {
        AuditOutcome::parse(&self.outcome)
    }

    /// The category this row is filed under, ignoring
    /// [`AuditCategory::Warning`], which is not exclusive.
    #[must_use]
    pub fn category(&self) -> Option<AuditCategory> {
        self.event_kind().map(AuditEvent::category)
    }

    /// Whether the incident-review filter would show this row.
    #[must_use]
    pub fn is_warning(&self) -> bool {
        AuditCategory::Warning.matches(self.event_kind(), self.outcome_kind())
    }
}

/// Which entries to read, and how many.
///
/// Built rather than constructed as a literal so that a filter with nothing set
/// means "everything", and stays meaning that when a field is added.
///
/// ```
/// # use remoter_vault::{AuditCategory, AuditQuery};
/// let query = AuditQuery::new()
///     .since(1_760_000_000_000)
///     .category(AuditCategory::Secret)
///     .page(0, 50);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditQuery {
    since: Option<i64>,
    until: Option<i64>,
    categories: Vec<AuditCategory>,
    outcomes: Vec<AuditOutcome>,
    node: Option<Uuid>,
    session: Option<Uuid>,
    limit: Option<usize>,
    offset: usize,
}

impl AuditQuery {
    /// Everything, newest first, unpaginated.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Only entries at or after this time, in milliseconds since the epoch.
    #[must_use]
    pub const fn since(mut self, at: i64) -> Self {
        self.since = Some(at);
        self
    }

    /// Only entries strictly before this time, in milliseconds since the epoch.
    ///
    /// Half-open so that paging by day cannot show one entry twice.
    #[must_use]
    pub const fn until(mut self, at: i64) -> Self {
        self.until = Some(at);
        self
    }

    /// Adds a category to the filter. Several categories are combined with
    /// "or", which is what the screen's chips do.
    #[must_use]
    pub fn category(mut self, category: AuditCategory) -> Self {
        if !self.categories.contains(&category) {
            self.categories.push(category);
        }
        self
    }

    /// Adds an outcome to the filter.
    #[must_use]
    pub fn outcome(mut self, outcome: AuditOutcome) -> Self {
        if !self.outcomes.contains(&outcome) {
            self.outcomes.push(outcome);
        }
        self
    }

    /// Only entries about this node.
    #[must_use]
    pub const fn for_node(mut self, node: Uuid) -> Self {
        self.node = Some(node);
        self
    }

    /// Only entries about this session.
    #[must_use]
    pub const fn for_session(mut self, session: Uuid) -> Self {
        self.session = Some(session);
        self
    }

    /// At most this many entries.
    #[must_use]
    pub const fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Skips this many entries before returning any.
    #[must_use]
    pub const fn offset(mut self, offset: usize) -> Self {
        self.offset = offset;
        self
    }

    /// Page `index`, counting from zero, of `size` entries each.
    #[must_use]
    pub const fn page(self, index: usize, size: usize) -> Self {
        self.limit(size).offset(index.saturating_mul(size))
    }

    pub(crate) const fn since_at(&self) -> Option<i64> {
        self.since
    }

    pub(crate) const fn until_at(&self) -> Option<i64> {
        self.until
    }

    pub(crate) fn categories(&self) -> &[AuditCategory] {
        &self.categories
    }

    pub(crate) fn outcomes(&self) -> &[AuditOutcome] {
        &self.outcomes
    }

    pub(crate) const fn node(&self) -> Option<Uuid> {
        self.node
    }

    pub(crate) const fn session(&self) -> Option<Uuid> {
        self.session
    }

    pub(crate) const fn limit_value(&self) -> Option<usize> {
        self.limit
    }

    pub(crate) const fn offset_value(&self) -> usize {
        self.offset
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]
mod tests {
    use super::*;

    #[test]
    fn every_event_has_exactly_one_ordinary_category() {
        for event in AuditEvent::ALL {
            let category = event.category();
            assert_ne!(
                category,
                AuditCategory::Warning,
                "{} must be filed under a subsystem, not under the cross-cutting filter",
                event.as_str()
            );
            let matching: Vec<AuditCategory> = AuditCategory::ALL
                .iter()
                .copied()
                .filter(|c| *c != AuditCategory::Warning)
                .filter(|c| c.matches(Some(*event), Some(AuditOutcome::Success)))
                .collect();
            assert_eq!(matching, vec![category], "for {}", event.as_str());
        }
    }

    #[test]
    fn a_failure_is_a_warning_whatever_it_was_about() {
        assert!(
            AuditCategory::Warning
                .matches(Some(AuditEvent::VaultSaved), Some(AuditOutcome::Failure))
        );
        assert!(
            AuditCategory::Warning
                .matches(Some(AuditEvent::SecretUsed), Some(AuditOutcome::Denied))
        );
        assert!(
            !AuditCategory::Warning
                .matches(Some(AuditEvent::SecretUsed), Some(AuditOutcome::Success))
        );
    }

    #[test]
    fn a_successful_plaintext_export_is_still_a_warning() {
        // The row an incident review is looking for. Outcome alone would hide
        // it, because the export worked.
        for event in ALWAYS_A_WARNING {
            assert!(
                AuditCategory::Warning.matches(Some(*event), Some(AuditOutcome::Success)),
                "{} must show under the warnings filter",
                event.as_str()
            );
        }
    }

    #[test]
    fn a_row_from_a_newer_build_is_classified_by_its_outcome_alone() {
        let record = AuditRecord {
            id: 1,
            at: 0,
            event: "something_this_build_does_not_know".into(),
            outcome: "failure".into(),
            node: None,
            session: None,
            detail: None,
        };
        assert_eq!(record.event_kind(), None);
        assert_eq!(record.category(), None);
        assert!(record.is_warning());
    }

    #[test]
    fn paging_turns_into_a_limit_and_an_offset() {
        let query = AuditQuery::new().page(3, 25);
        assert_eq!(query.limit_value(), Some(25));
        assert_eq!(query.offset_value(), 75);
    }

    #[test]
    fn category_names_round_trip() {
        for category in AuditCategory::ALL {
            assert_eq!(AuditCategory::parse(category.as_str()), Some(*category));
        }
        assert_eq!(AuditCategory::parse("nonsense"), None);
    }
}
