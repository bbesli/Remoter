//! What the import found, and what the user has to know about it.
//!
//! `docs/features/import-export.md`: "The report names what could not be mapped
//! rather than silently discarding it." A [`Finding`] is therefore not a log
//! line — it is the record of a decision the importer made on the user's
//! behalf, and every one of them has a matching value preserved somewhere in
//! the preview.
//!
//! Nothing here holds secret material. Findings are serialised to the interface
//! and end up on screen; a password that reached one would be on screen too.

use serde::{Deserialize, Serialize};

use crate::Limits;

/// Which tool the file came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SourceFormat {
    /// mRemoteNG's `confCons.xml`.
    MRemoteNg,
    /// OpenSSH's `ssh_config`.
    OpenSshConfig,
    /// The documented CSV column set.
    Csv,
    /// A `.rmtr` archive written by Remoter itself.
    RemoterArchive,
    /// The JSON document Remoter's export writes: the tree, without secrets.
    RemoterJson,
    /// A Remote Desktop Connection `.rdp` file.
    RdpFile,
    /// A Remote Desktop Connection Manager `.rdg` document.
    RdcMan,
}

impl SourceFormat {
    /// A short, stable, untranslated name for logs and telemetry.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MRemoteNg => "mremoteng",
            Self::OpenSshConfig => "ssh_config",
            Self::Csv => "csv",
            Self::RemoterArchive => "remoter_archive",
            Self::RemoterJson => "remoter_json",
            Self::RdpFile => "rdp_file",
            Self::RdcMan => "rdcman",
        }
    }
}

/// How much attention a finding needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Something worth knowing that cost nothing: a mapping that worked.
    Info,
    /// Something was not carried across as-is. Nothing was lost, but the
    /// result differs from the source and the user should look.
    Warning,
    /// A security fact about the file the user may not have known.
    Alert,
}

/// One thing the import wants to tell the user.
///
/// Ordered roughly by how much they need to hear it: the security facts first,
/// then what could not be mapped, then what was mapped well.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
#[non_exhaustive]
pub enum Finding {
    /// The file was encrypted with mRemoteNG's built-in default password, which
    /// is a published constant.
    ///
    /// This is the finding `docs/features/import-export.md` calls for by name:
    /// "a user who believed their file was protected should learn that it was
    /// not."
    DefaultFilePassword,

    /// The file used the pre-1.75 AES-CBC scheme, whose key is an unsalted MD5
    /// of the password and whose ciphertext is unauthenticated.
    LegacyCbcEncryption,

    /// The whole document was encrypted rather than only its password fields.
    FullFileEncryption,

    /// A connection carried a password. Recorded so the count of secrets in the
    /// preview is visible before anything is written.
    SecretsRecovered {
        /// How many distinct secrets came across.
        count: usize,
    },

    /// Identical username, domain and secret appeared on several connections
    /// and became one credential node.
    CredentialsDeduplicated {
        /// How many credential nodes the preview holds.
        credentials: usize,
        /// How many connections reference them.
        connections: usize,
    },

    /// The source names a protocol this build has no adapter for.
    UnknownProtocol {
        /// The item it was on.
        item: String,
        /// The protocol as the file spelled it.
        protocol: String,
        /// The protocol id it was mapped to.
        mapped_to: String,
    },

    /// An item could not be represented and was left out. Nothing else in the
    /// preview refers to it.
    SkippedItem {
        /// The item's name in the source.
        item: String,
        /// Why it was skipped.
        reason: SkipReason,
    },

    /// A `ProxyCommand` that is not one of the recognised bastion idioms. The
    /// command is preserved verbatim in the node's `custom_fields` under
    /// `openssh.proxycommand`.
    UnmappedProxyCommand {
        /// The host it was on.
        item: String,
        /// The command, as written.
        command: String,
    },

    /// A `ProxyJump` or an mRemoteNG SSH tunnel became a gateway chain.
    GatewayMapped {
        /// The connection that gained the chain.
        item: String,
        /// How many hops it has.
        hops: usize,
    },

    /// A gateway target was named but no connection in the file defines it, so
    /// a connection node was synthesised for it.
    GatewaySynthesised {
        /// The connection that referred to it.
        item: String,
        /// The target as written.
        target: String,
    },

    /// A gateway target was named and could not be resolved or synthesised.
    /// The name is preserved in the node's `custom_fields`.
    GatewayUnresolved {
        /// The connection that referred to it.
        item: String,
        /// The target as written.
        target: String,
    },

    /// The source held a secret in a field with no home in the domain model —
    /// an RD Gateway password, a VNC proxy password — and it was dropped
    /// rather than written somewhere it does not belong.
    ///
    /// Dropped, not preserved: a secret in `custom_fields` would be a
    /// plaintext password in a field the vault does not encrypt.
    SecretNotMapped {
        /// The item it was on.
        item: String,
        /// Which field held it.
        field: String,
    },

    /// A `Match` block was read but not applied. Its conditions are evaluated
    /// by `ssh` at connect time against things an importer cannot know — the
    /// local user, the command being run, whether the first connection
    /// attempt failed.
    MatchBlockNotApplied {
        /// The block's criteria, as written.
        criteria: String,
        /// How many options it held.
        options: usize,
    },

    /// A wildcard `Host` block whose options were folded into the connections
    /// it matches.
    PatternBlockApplied {
        /// The pattern, as written.
        pattern: String,
        /// How many connections it contributed to.
        connections: usize,
    },

    /// Settings with no home in the domain model, kept verbatim in the node's
    /// `custom_fields`.
    SettingsPreserved {
        /// The item they were on.
        item: String,
        /// How many were kept.
        count: usize,
    },

    /// A CSV column that is not in the documented set. Its values are kept in
    /// `custom_fields` under `csv.<column>`.
    UnknownColumn {
        /// The column's header, as written.
        column: String,
    },

    /// Saved passwords the file holds in a form only Windows can open — Windows
    /// data protection, bound to the account that saved them, or a certificate
    /// that stayed on that machine. The credentials arrive with their account
    /// names and without the passwords, and each asks for its password the
    /// first time it is used.
    ProtectedPasswordsNotCarried {
        /// How many saved passwords.
        count: usize,
    },

    /// A connection that goes through a Remote Desktop Gateway, which this
    /// build does not speak. The connection is imported and connects directly;
    /// the gateway's host is kept in its `custom_fields`.
    RdGatewayNotSupported {
        /// The connection or folder it was set on.
        item: String,
        /// The gateway's host, as written.
        host: String,
    },

    /// A credential profile the file refers to and does not contain. Remote
    /// Desktop Connection Manager keeps a "Local" profile in its own settings
    /// on the machine that wrote the file, not in the file.
    CredentialProfileMissing {
        /// The connection or folder that used it.
        item: String,
        /// The profile's name.
        profile: String,
    },

    /// Credentials that arrive without the secret they hold — a Remoter JSON
    /// export carries which kind of secret each one has and never the secret.
    /// They are imported as they are, and each asks for its password or key
    /// the first time it is used.
    SecretsNotCarried {
        /// How many credentials.
        count: usize,
    },

    /// A limit was reached and the rest of something was not read. The preview
    /// is a partial one.
    LimitReached {
        /// What ran out: `custom_fields`, `findings` or `nodes`.
        limit: String,
    },
}

impl Finding {
    /// How much attention this finding needs.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        match self {
            Self::DefaultFilePassword | Self::LegacyCbcEncryption => Severity::Alert,
            Self::SkippedItem { .. }
            | Self::UnknownProtocol { .. }
            | Self::UnmappedProxyCommand { .. }
            | Self::GatewaySynthesised { .. }
            | Self::GatewayUnresolved { .. }
            | Self::SecretNotMapped { .. }
            | Self::MatchBlockNotApplied { .. }
            | Self::UnknownColumn { .. }
            | Self::SecretsNotCarried { .. }
            | Self::ProtectedPasswordsNotCarried { .. }
            | Self::RdGatewayNotSupported { .. }
            | Self::CredentialProfileMissing { .. }
            | Self::LimitReached { .. } => Severity::Warning,
            Self::FullFileEncryption
            | Self::SecretsRecovered { .. }
            | Self::CredentialsDeduplicated { .. }
            | Self::GatewayMapped { .. }
            | Self::PatternBlockApplied { .. }
            | Self::SettingsPreserved { .. } => Severity::Info,
        }
    }
}

/// Why an item did not make it into the preview.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SkipReason {
    /// No hostname, or one the domain model rejects: not a DNS name, not an
    /// IPv4 address, not a bracketed IPv6 literal.
    UnusableHost,
    /// No name, or a name the domain model rejects.
    UnusableName,
    /// The item is a kind this importer does not produce — an mRemoteNG
    /// external-application entry, for instance, which launches a local
    /// program rather than opening a session.
    UnsupportedKind,
    /// The row or element held nothing to import.
    Empty,
}

/// Counts of what the preview holds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportCounts {
    /// Folder nodes.
    pub folders: usize,
    /// Connection nodes.
    pub connections: usize,
    /// Credential nodes.
    pub credentials: usize,
    /// Credential nodes carrying a recovered password.
    pub secrets: usize,
    /// Items the source held that did not become nodes.
    pub skipped: usize,
}

/// What came in, what could not be mapped, and what needs attention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportReport {
    source: SourceFormat,
    counts: ImportCounts,
    findings: Vec<Finding>,
    truncated: bool,
}

impl ImportReport {
    pub(crate) fn new(source: SourceFormat) -> Self {
        Self {
            source,
            counts: ImportCounts::default(),
            findings: Vec::new(),
            truncated: false,
        }
    }

    /// Which importer produced this.
    #[must_use]
    pub const fn source(&self) -> SourceFormat {
        self.source
    }

    /// Counts of what the preview holds.
    #[must_use]
    pub const fn counts(&self) -> ImportCounts {
        self.counts
    }

    /// Everything the import wants to say, in the order it was found.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Whether the findings list stopped growing before the import finished.
    ///
    /// A file crafted to produce one finding per element would otherwise turn a
    /// bounded parse into an unbounded report.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// The findings at or above `severity`.
    pub fn at_least(&self, severity: Severity) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(move |f| f.severity() >= severity)
    }

    /// Whether anything in the file needs the user's attention before they
    /// commit the import.
    #[must_use]
    pub fn needs_attention(&self) -> bool {
        self.at_least(Severity::Warning).next().is_some()
    }

    pub(crate) fn counts_mut(&mut self) -> &mut ImportCounts {
        &mut self.counts
    }

    /// Records a finding, up to the configured ceiling.
    pub(crate) fn push(&mut self, limits: &Limits, finding: Finding) {
        if self.findings.len() >= limits.max_findings {
            self.truncated = true;
            return;
        }
        self.findings.push(finding);
    }
}

#[cfg(test)]
#[allow(clippy::panic, reason = "test code")]
mod tests {
    use super::*;

    #[test]
    fn findings_stop_at_the_limit_and_say_so() {
        let limits = Limits {
            max_findings: 2,
            ..Limits::new()
        };
        let mut report = ImportReport::new(SourceFormat::Csv);
        for i in 0..5 {
            report.push(
                &limits,
                Finding::UnknownColumn {
                    column: format!("c{i}"),
                },
            );
        }
        assert_eq!(report.findings().len(), 2);
        assert!(report.is_truncated());
    }

    #[test]
    fn severity_ordering_drives_needs_attention() {
        let limits = Limits::new();
        let mut report = ImportReport::new(SourceFormat::OpenSshConfig);
        assert!(!report.needs_attention());
        report.push(&limits, Finding::SecretsRecovered { count: 1 });
        assert!(!report.needs_attention());
        report.push(
            &limits,
            Finding::UnknownColumn {
                column: "x".to_owned(),
            },
        );
        assert!(report.needs_attention());
        assert_eq!(report.at_least(Severity::Alert).count(), 0);
        assert_eq!(report.at_least(Severity::Info).count(), 2);
    }
}
