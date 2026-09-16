//! Reading and exporting the audit log — the Audit screen.
//!
//! The log is append-only and lives inside the encrypted body. Nothing here
//! writes to it except the export, which is itself recorded: a copy of the log
//! leaving the vault is exactly the kind of event someone reviewing an incident
//! wants to find, and an export that erased its own trace would be worse than
//! no export at all.
//!
//! Filtering and counting happen in SQL, one page at a time. The screen reaches
//! thousands of rows and loading all of them to discard most is how a table
//! stops scrolling.
//!
//! No row here carries a secret: an entry holds a timestamp, an event name, an
//! outcome, two identifiers and a short plain-text note, and the rule that
//! `detail` never carries secret material is kept by the writers in
//! `remoter-vault`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use remoter_vault::{
    AuditActorRecord, AuditCategory, AuditEvent, AuditOutcome, AuditQuery, AuditRecord, Vault,
};
use tauri::State;
use uuid::Uuid;

use crate::commands::{read_tree, save};
use crate::dto::{
    AuditActorDto, AuditActorSummaryDto, AuditEntryDto, AuditExportDto, AuditExportResultDto,
    AuditFiltersDto, AuditPageDto, AuditQueryDto,
};
use crate::error::IpcError;
use crate::recents::write_atomic;
use crate::state::AppState;

/// Entries per page when the request does not say.
const DEFAULT_PAGE_SIZE: usize = 100;

/// The most entries one page may carry. Past this the table is virtualised
/// against a list the interface cannot draw anyway.
const MAX_PAGE_SIZE: usize = 1000;

/// The most entries one export writes. An export is a file someone opens in a
/// spreadsheet; beyond this it is a database, and the vault is already that.
const MAX_EXPORT_ENTRIES: usize = 200_000;

/// One page of the audit log, newest first.
#[tauri::command]
pub(crate) fn audit_query(
    state: State<'_, AppState>,
    query: AuditQueryDto,
) -> Result<AuditPageDto, IpcError> {
    audit_query_impl(&state, query)
}

fn audit_query_impl(state: &AppState, query: AuditQueryDto) -> Result<AuditPageDto, IpcError> {
    let page = query.page.unwrap_or(0);
    let page_size = query
        .page_size
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_PAGE_SIZE);
    let filter = build_query(&query)?;

    let mut guard = state.lock();
    let vault = guard.vault_ref()?;

    // Counted without the paging, so the screen can say "8 of 4,182 shown".
    let total = vault
        .audit_count(&filter)
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
    let records = vault
        .audit_query(&filter.clone().page(page, page_size))
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;

    Ok(AuditPageDto {
        entries: entries_with_names(vault, &records)?,
        total,
        page,
        page_size,
    })
}

/// The filter vocabulary, so the screen's chips cannot drift from the log's own
/// spellings.
#[tauri::command]
pub(crate) fn audit_filters() -> Result<AuditFiltersDto, IpcError> {
    Ok(AuditFiltersDto {
        categories: AuditCategory::ALL
            .iter()
            .map(|category| category.as_str().to_owned())
            .collect(),
        outcomes: [
            AuditOutcome::Success,
            AuditOutcome::Failure,
            AuditOutcome::Denied,
        ]
        .iter()
        .map(|outcome| outcome.as_str().to_owned())
        .collect(),
        events: AuditEvent::ALL
            .iter()
            .map(|event| event.as_str().to_owned())
            .collect(),
    })
}

/// Every operating-system account and machine that has written to this vault's
/// log, most recently active first — the choices the screen's "who" filter
/// offers.
///
/// Read from the vault rather than from the page on screen, so that a filter
/// can pick someone whose entries are all on later pages.
#[tauri::command]
pub(crate) fn audit_actors(
    state: State<'_, AppState>,
) -> Result<Vec<AuditActorSummaryDto>, IpcError> {
    audit_actors_impl(&state)
}

fn audit_actors_impl(state: &AppState) -> Result<Vec<AuditActorSummaryDto>, IpcError> {
    let mut guard = state.lock();
    let vault = guard.vault_ref()?;
    let actors = vault
        .audit_actors()
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
    Ok(actors
        .into_iter()
        .map(|summary| AuditActorSummaryDto {
            actor: actor_dto(&summary.record),
            entries: summary.entries,
            last_at: summary.last_at,
        })
        .collect())
}

fn actor_dto(record: &AuditActorRecord) -> AuditActorDto {
    AuditActorDto {
        id: record.id,
        machine: record.actor.machine.clone(),
        user: record.actor.user.clone(),
        domain: record.actor.domain.clone(),
        account: record.actor.account(),
        os: record.actor.os.clone(),
    }
}

/// Writes the filtered log to a file, and records that it was written.
///
/// Exporting copies entries; it never removes them. The paging in the request
/// is ignored — an export of page three of a filter is not what anybody means
/// by "export" — so what lands in the file is every entry the filter matches.
#[tauri::command]
pub(crate) fn audit_export(
    state: State<'_, AppState>,
    req: AuditExportDto,
) -> Result<AuditExportResultDto, IpcError> {
    audit_export_impl(&state, req)
}

fn audit_export_impl(
    state: &AppState,
    req: AuditExportDto,
) -> Result<AuditExportResultDto, IpcError> {
    let AuditExportDto {
        path,
        format,
        query,
    } = req;

    let format = match format.as_str() {
        "json" | "csv" => format,
        other => {
            return Err(IpcError::invalid_request(
                "format",
                format!("`{other}` is not an export format; expected json or csv"),
            ));
        }
    };
    let path = PathBuf::from(path);
    if path.is_dir() {
        return Err(IpcError::bad_path(
            &path,
            "it is a folder, and an export is written as one file",
        ));
    }

    let filter = build_query(&query.unwrap_or_default())?.limit(MAX_EXPORT_ENTRIES);

    let mut guard = state.lock();
    let vault = guard.vault_mut()?;
    let records = vault
        .audit_query(&filter)
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
    let entries = entries_with_names(vault, &records)?;

    let bytes = match format.as_str() {
        "csv" => render_csv(&entries).into_bytes(),
        _ => serde_json::to_vec_pretty(&entries).map_err(|err| {
            IpcError::new(
                "audit.export-encode",
                "The audit entries could not be encoded, so nothing was written.",
            )
            .with_detail(err.to_string())
        })?,
    };
    let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    write_atomic(&path, &bytes)?;

    // The log records that a copy of it left the vault. `remoter-vault` has no
    // event of its own for this, and `SecretExported` is the one that carries
    // the meaning that matters — data left the vault, deliberately, and an
    // incident review should see it. The detail says what was exported, so the
    // row cannot be misread as credentials leaving in plaintext.
    let detail = format!(
        "audit log exported: {} entries, {format}, to {}",
        entries.len(),
        path.display()
    );
    if let Err(err) = vault.audit(
        AuditEvent::SecretExported,
        AuditOutcome::Success,
        Some(&detail),
    ) {
        return Err(IpcError::from_vault(&err, "this vault"));
    }
    save(vault)?;

    Ok(AuditExportResultDto {
        path: path.display().to_string(),
        format,
        entries: entries.len(),
        bytes: size,
    })
}

// =================================================================== helpers

/// Builds the query, without the paging.
fn build_query(dto: &AuditQueryDto) -> Result<AuditQuery, IpcError> {
    let mut query = AuditQuery::new();

    if let Some(since) = dto.since {
        query = query.since(since);
    }
    if let Some(until) = dto.until {
        query = query.until(until);
    }
    if let (Some(since), Some(until)) = (dto.since, dto.until) {
        if until <= since {
            return Err(IpcError::invalid_request(
                "until",
                "it is at or before `since`, which selects nothing",
            ));
        }
    }
    for name in dto.categories.iter().flatten() {
        let category = AuditCategory::parse(name).ok_or_else(|| {
            IpcError::invalid_request(
                "categories",
                format!(
                    "`{name}` is not one of {}",
                    AuditCategory::ALL
                        .iter()
                        .map(|category| category.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
        })?;
        query = query.category(category);
    }
    for name in dto.outcomes.iter().flatten() {
        let outcome = AuditOutcome::parse(name).ok_or_else(|| {
            IpcError::invalid_request(
                "outcomes",
                format!("`{name}` is not one of success, failure, denied"),
            )
        })?;
        query = query.outcome(outcome);
    }
    if let Some(id) = &dto.node_id {
        query = query.for_node(parse_uuid(id, "nodeId")?);
    }
    if let Some(id) = &dto.session_id {
        query = query.for_session(parse_uuid(id, "sessionId")?);
    }
    if let Some(actor) = dto.actor_id {
        query = query.by_actor(actor);
    }
    Ok(query)
}

fn parse_uuid(text: &str, field: &str) -> Result<Uuid, IpcError> {
    Uuid::parse_str(text).map_err(|err| IpcError::invalid_request(field, err.to_string()))
}

/// Maps rows to DTOs, filling in the node names the "where" column shows.
///
/// The tree is read once, and only when a row names a node: an audit page over
/// vault-level events should not pay for decoding every record in the vault.
fn entries_with_names(
    vault: &Vault,
    records: &[AuditRecord],
) -> Result<Vec<AuditEntryDto>, IpcError> {
    let names = if records.iter().any(|record| record.node.is_some()) {
        let tree = read_tree(vault)?;
        tree.nodes()
            .map(|node| (*node.id.as_uuid(), node.name.clone()))
            .collect::<BTreeMap<Uuid, String>>()
    } else {
        BTreeMap::new()
    };

    Ok(records
        .iter()
        .map(|record| AuditEntryDto {
            id: record.id,
            at: record.at,
            event: record.event.clone(),
            outcome: record.outcome.clone(),
            category: record
                .category()
                .map(|category| category.as_str().to_owned()),
            warning: record.is_warning(),
            node_id: record.node.map(|id| id.to_string()),
            // Absent for a node that has since been deleted: the log keeps the
            // identifier, and inventing a name for a row it no longer has one
            // for would be a guess.
            node_name: record.node.and_then(|id| names.get(&id).cloned()),
            session_id: record.session.map(|id| id.to_string()),
            detail: record.detail.clone(),
            actor: record.actor.as_ref().map(actor_dto),
        })
        .collect())
}

/// The export's CSV rendering.
fn render_csv(entries: &[AuditEntryDto]) -> String {
    // The identity columns go last, so a spreadsheet or a script written against
    // an export from before they existed still finds every older column where
    // it was.
    let mut out = String::from(
        "id,at,event,outcome,category,warning,nodeId,nodeName,sessionId,detail,machine,account,os\n",
    );
    for entry in entries {
        let row = [
            entry.id.to_string(),
            entry.at.to_string(),
            entry.event.clone(),
            entry.outcome.clone(),
            entry.category.clone().unwrap_or_default(),
            entry.warning.to_string(),
            entry.node_id.clone().unwrap_or_default(),
            entry.node_name.clone().unwrap_or_default(),
            entry.session_id.clone().unwrap_or_default(),
            entry.detail.clone().unwrap_or_default(),
            entry
                .actor
                .as_ref()
                .map(|actor| actor.machine.clone())
                .unwrap_or_default(),
            entry
                .actor
                .as_ref()
                .map(|actor| actor.account.clone())
                .unwrap_or_default(),
            entry
                .actor
                .as_ref()
                .map(|actor| actor.os.clone())
                .unwrap_or_default(),
        ];
        out.push_str(
            &row.iter()
                .map(|field| csv_field(field))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push('\n');
    }
    out
}

/// One CSV field: quoted when it has to be, and never handed to a spreadsheet
/// as a formula.
///
/// A node name is the user's own text, and a spreadsheet reads a cell starting
/// with `=`, `+`, `-` or `@` as a formula to run. Prefixing it with an
/// apostrophe is the standard defence and costs nothing on re-import.
fn csv_field(value: &str) -> String {
    let neutralised = if value.starts_with(['=', '+', '-', '@']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };

    if neutralised.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", neutralised.replace('"', "\"\""))
    } else {
        neutralised
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_csv_field_is_quoted_only_when_it_has_to_be() {
        assert_eq!(csv_field("session opened"), "session opened");
        assert_eq!(csv_field("web-01, web-02"), "\"web-01, web-02\"");
        assert_eq!(csv_field("he said \"no\""), "\"he said \"\"no\"\"\"");
        assert_eq!(csv_field("line\nbreak"), "\"line\nbreak\"");
    }

    #[test]
    fn a_csv_field_never_reaches_a_spreadsheet_as_a_formula() {
        // A node name is the user's own text, and a name beginning with `=` is
        // a formula the moment the export is double-clicked.
        assert_eq!(csv_field("=1+1"), "'=1+1");
        assert_eq!(csv_field("@HYPERLINK"), "'@HYPERLINK");
        assert_eq!(csv_field("-cmd"), "'-cmd");
    }

    #[test]
    fn the_csv_has_a_header_and_one_row_an_entry() {
        let entries = vec![
            AuditEntryDto {
                id: 2,
                at: 1_760_000_000_000,
                event: String::from("session_started"),
                outcome: String::from("success"),
                category: Some(String::from("connection")),
                warning: false,
                node_id: None,
                node_name: Some(String::from("db-01")),
                session_id: None,
                detail: Some(String::from("ssh")),
                actor: Some(AuditActorDto {
                    id: 1,
                    machine: String::from("LAPTOP-9"),
                    user: String::from("ayse"),
                    domain: Some(String::from("DEVOPLUS")),
                    account: String::from("DEVOPLUS\\ayse"),
                    os: String::from("windows"),
                }),
            },
            AuditEntryDto {
                id: 1,
                at: 1_759_000_000_000,
                event: String::from("vault_unlocked"),
                outcome: String::from("success"),
                category: Some(String::from("vault")),
                warning: false,
                node_id: None,
                node_name: None,
                session_id: None,
                detail: None,
                actor: None,
            },
        ];

        let csv = render_csv(&entries);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 3, "csv: {csv}");
        assert!(lines[0].starts_with("id,at,event,outcome"), "csv: {csv}");
        assert!(lines[1].contains("session_started"), "csv: {csv}");
        assert!(lines[1].contains("db-01"), "csv: {csv}");
        assert!(
            lines[0].ends_with(",detail,machine,account,os"),
            "the identity columns come after every older one: {csv}"
        );
        assert!(
            lines[1].ends_with(",ssh,LAPTOP-9,DEVOPLUS\\ayse,windows"),
            "csv: {csv}"
        );
        // An absent field is empty rather than the word "None" — including an
        // identity that was not recorded.
        assert!(lines[2].ends_with(",,,,,,,"), "csv: {csv}");
    }

    #[test]
    fn a_window_that_selects_nothing_is_refused_rather_than_returned_empty() {
        let query = AuditQueryDto {
            since: Some(200),
            until: Some(100),
            ..AuditQueryDto::default()
        };
        let failure = build_query(&query);
        assert!(failure.is_err_and(|err| err.code == "request.invalid"));
    }

    #[test]
    fn an_unknown_category_names_the_ones_that_exist() {
        let query = AuditQueryDto {
            categories: Some(vec![String::from("everything")]),
            ..AuditQueryDto::default()
        };
        let failure = build_query(&query);
        assert!(
            failure
                .as_ref()
                .is_err_and(|err| err.code == "request.invalid")
        );
        if let Err(err) = failure {
            assert!(
                err.message.contains("connection"),
                "message: {}",
                err.message
            );
            assert!(err.message.contains("warning"), "message: {}", err.message);
        }
    }

    #[test]
    fn the_filter_vocabulary_is_the_logs_own() {
        let filters = audit_filters().ok();
        assert!(filters.is_some());
        if let Some(filters) = filters {
            assert!(filters.categories.contains(&String::from("warning")));
            assert_eq!(filters.outcomes.len(), 3);
            // Every event the log can write is offered as a filter, including
            // the two the slot screen added.
            assert!(filters.events.contains(&String::from("password_changed")));
            assert!(filters.events.contains(&String::from("master_key_rotated")));
            assert_eq!(filters.events.len(), AuditEvent::ALL.len());
        }
    }
}

#[cfg(test)]
mod vault_tests {
    use super::*;
    use crate::dto::AuditExportDto;
    use crate::test_support::{Scratch, exists, open_vault, why};

    #[test]
    #[expect(
        clippy::panic,
        reason = "an audit test without a vault has nothing left to assert"
    )]
    fn the_log_is_paged_filtered_and_counted_without_the_paging() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };

        let all = audit_query_impl(&state, AuditQueryDto::default());
        assert!(all.is_ok(), "querying failed: {}", why(&all));
        let Ok(all) = all else {
            panic!("querying failed");
        };
        assert!(all.total > 0, "creating a vault writes to its own log");
        assert!(
            all.entries
                .iter()
                .any(|entry| entry.event == "vault_created"),
            "entries: {:?}",
            all.entries
        );
        assert_eq!(all.page_size, DEFAULT_PAGE_SIZE);

        // A page smaller than the log still reports the whole count, which is
        // what "8 of 4,182 shown" is made of.
        let paged = audit_query_impl(
            &state,
            AuditQueryDto {
                page_size: Some(1),
                ..AuditQueryDto::default()
            },
        );
        let Ok(paged) = paged else {
            panic!("querying failed");
        };
        assert_eq!(paged.entries.len(), 1);
        assert_eq!(paged.total, all.total);

        // A filter that matches nothing is empty rather than everything.
        let filtered = audit_query_impl(
            &state,
            AuditQueryDto {
                categories: Some(vec![String::from("connection")]),
                ..AuditQueryDto::default()
            },
        );
        assert_eq!(filtered.ok().map(|page| page.total), Some(0));
    }

    #[test]
    #[expect(
        clippy::panic,
        reason = "an export test without a vault has nothing left to assert"
    )]
    fn an_export_writes_the_file_and_is_itself_recorded() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let target = scratch.join("audit.csv");

        let exported = audit_export_impl(
            &state,
            AuditExportDto {
                path: target.display().to_string(),
                format: String::from("csv"),
                query: None,
            },
        );
        assert!(exported.is_ok(), "exporting failed: {}", why(&exported));
        let Ok(exported) = exported else {
            panic!("exporting failed");
        };
        assert!(exported.entries > 0);
        assert!(exported.bytes > 0);
        assert!(exists(&target), "the export should be on disk");

        let written = std::fs::read_to_string(&target).unwrap_or_default();
        assert!(written.starts_with("id,at,event,outcome"), "{written}");
        assert!(written.contains("vault_created"), "{written}");

        // Exporting copies entries; it does not remove them, and it leaves a
        // row of its own saying a copy left the vault.
        let after = audit_query_impl(&state, AuditQueryDto::default());
        let Ok(after) = after else {
            panic!("querying failed");
        };
        assert!(after.total > exported.entries);
        let export_row = after.entries.iter().find(|entry| {
            entry
                .detail
                .as_deref()
                .is_some_and(|d| d.starts_with("audit log exported"))
        });
        assert!(
            export_row.is_some(),
            "the export must be audited: {:?}",
            after.entries
        );
        assert!(
            export_row.is_some_and(|entry| entry.warning),
            "an export is what an incident review scrolls for"
        );

        // JSON is the same entries in the shape the screen already reads.
        let json_target = scratch.join("audit.json");
        let exported = audit_export_impl(
            &state,
            AuditExportDto {
                path: json_target.display().to_string(),
                format: String::from("json"),
                query: None,
            },
        );
        assert!(exported.is_ok(), "exporting failed: {}", why(&exported));
        let written = std::fs::read_to_string(&json_target).unwrap_or_default();
        let parsed = serde_json::from_str::<Vec<AuditEntryDto>>(&written);
        assert!(parsed.is_ok_and(|entries| !entries.is_empty()), "{written}");
    }

    #[test]
    fn an_unknown_export_format_is_refused_before_anything_is_written() {
        let scratch = Scratch::new();
        let state = AppState::with_config_dir(scratch.join("config"));
        let target = scratch.join("audit.pdf");

        let refused = audit_export_impl(
            &state,
            AuditExportDto {
                path: target.display().to_string(),
                format: String::from("pdf"),
                query: None,
            },
        );
        assert!(refused.is_err_and(|err| err.code == "request.invalid"));
        assert!(!exists(&target));
    }

    #[test]
    fn the_audit_commands_say_no_vault_is_open() {
        let scratch = Scratch::new();
        let state = AppState::with_config_dir(scratch.join("config"));
        let failure = audit_query_impl(&state, AuditQueryDto::default());
        assert!(failure.is_err_and(|err| err.code == "vault.locked"));
    }
}
