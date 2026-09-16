//! Who the process writing audit rows is running as.
//!
//! The identity is decided once per process, by the application, and every
//! audit row any vault writes after that carries it. It is a property of the
//! process rather than of a vault or a call: the same operating-system account
//! on the same machine opens every vault this process opens, and the rows that
//! most need attributing — an unlock, a creation — are written inside
//! [`crate::Vault::open`] and [`crate::Vault::create`], before a caller holding
//! the vault could have told it anything.
//!
//! This crate does not detect the identity itself. How a machine name and an
//! account are read differs on every operating system and has nothing to do
//! with encryption; the application reads them and hands them over through
//! [`set_audit_actor`], which also keeps every test in this crate independent of
//! the machine it happens to run on.
//!
//! Attribution, not authentication: see `migrations/003_audit_actor.sql`.

use std::sync::OnceLock;

/// The longest machine, account or domain name kept, in characters.
///
/// Well beyond any real one — Windows caps a NetBIOS name at 15 and an account
/// at 20, POSIX hostnames at 255 bytes — and small enough that a malformed
/// environment cannot put a megabyte into every save.
const MAX_NAME_CHARS: usize = 255;

/// The operating-system identity an audit row was written under.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuditActor {
    /// The machine's name as its operating system reports it.
    pub machine: String,
    /// The account the process runs as, without its domain.
    pub user: String,
    /// The account's domain, when the operating system has one to report and it
    /// is not simply the machine's own name. Windows reports `USERDOMAIN` equal
    /// to the computer name for a local account; that is kept out, so a domain
    /// appears only when it says something the machine name does not.
    pub domain: Option<String>,
    /// `"linux" | "windows" | "macos"` and so on — `std::env::consts::OS`.
    pub os: String,
}

impl AuditActor {
    /// Builds an identity, cleaning each part and refusing one that names
    /// nobody.
    ///
    /// Control characters are removed and each part is trimmed and capped at
    /// [`MAX_NAME_CHARS`]. The names come from the process environment, which
    /// is ordinary data a user controls, and they end up in a table cell and a
    /// CSV file. `None` when the machine, the account or the operating system is
    /// empty once cleaned: a row attributed to an empty name would read as
    /// though somebody had been identified.
    #[must_use]
    pub fn new(machine: &str, user: &str, domain: Option<&str>, os: &str) -> Option<Self> {
        let machine = clean(machine)?;
        let user = clean(user)?;
        let os = clean(os)?;
        let domain = domain
            .and_then(clean)
            .filter(|domain| !domain.eq_ignore_ascii_case(&machine));
        Some(Self {
            machine,
            user,
            domain,
            os,
        })
    }

    /// `DOMAIN\user` when there is a domain, the bare account otherwise — the
    /// way each operating system writes its own accounts.
    #[must_use]
    pub fn account(&self) -> String {
        match &self.domain {
            Some(domain) => format!("{domain}\\{}", self.user),
            None => self.user.clone(),
        }
    }
}

/// An identity as stored, with the row identifier a filter refers to it by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditActorRecord {
    /// The row in `audit_actor`.
    pub id: i64,
    /// Who.
    pub actor: AuditActor,
}

/// One identity that has written to this vault, with how much and how
/// recently — what the audit screen's "who" filter lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditActorSummary {
    /// The identity and its row.
    pub record: AuditActorRecord,
    /// How many audit rows carry it.
    pub entries: usize,
    /// The newest of those rows, in milliseconds since the epoch. `None` only
    /// for an identity whose rows have all gone, which the append-only log does
    /// not do today.
    pub last_at: Option<i64>,
}

static PROCESS_ACTOR: OnceLock<AuditActor> = OnceLock::new();

/// Sets the identity every audit row written by this process carries.
///
/// Call it once, early, before the first vault is opened. It can be set only
/// once: the account a process runs as does not change while it runs, and a
/// second value would split one person's rows across two identities. Returns
/// `false`, and changes nothing, when an identity was already set.
///
/// A process that never calls it writes rows with no identity, which the
/// interface shows as not recorded.
pub fn set_audit_actor(actor: AuditActor) -> bool {
    PROCESS_ACTOR.set(actor).is_ok()
}

/// The identity set by [`set_audit_actor`], if any.
#[must_use]
pub fn audit_actor() -> Option<&'static AuditActor> {
    PROCESS_ACTOR.get()
}

fn clean(text: &str) -> Option<String> {
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(MAX_NAME_CHARS)
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
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
    fn a_local_windows_account_does_not_repeat_the_machine_as_its_domain() {
        // Windows sets USERDOMAIN to the computer name for a local account.
        // Showing `DESKTOP-7\burak` beside the machine `DESKTOP-7` says nothing
        // twice.
        let actor = AuditActor::new("DESKTOP-7", "burak", Some("desktop-7"), "windows").unwrap();
        assert_eq!(actor.domain, None);
        assert_eq!(actor.account(), "burak");
    }

    #[test]
    fn a_domain_account_is_written_the_way_windows_writes_it() {
        let actor = AuditActor::new("DESKTOP-7", "burak", Some("DEVOPLUS"), "windows").unwrap();
        assert_eq!(actor.account(), "DEVOPLUS\\burak");
    }

    #[test]
    fn an_empty_name_is_not_an_identity() {
        assert_eq!(AuditActor::new("host", "  ", None, "linux"), None);
        assert_eq!(AuditActor::new("", "burak", None, "linux"), None);
        assert_eq!(AuditActor::new("host", "burak", None, ""), None);
    }

    #[test]
    fn names_lose_control_characters_and_are_capped() {
        let long = "a".repeat(1000);
        let actor = AuditActor::new("ho\nst\u{7}", &long, Some("\t"), "linux").unwrap();
        assert_eq!(actor.machine, "host");
        assert_eq!(actor.user.chars().count(), MAX_NAME_CHARS);
        assert_eq!(
            actor.domain, None,
            "a domain of nothing but whitespace is no domain"
        );
    }
}
