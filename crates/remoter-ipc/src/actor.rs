//! Reading which account and machine this process runs as, the way each
//! operating system says it.
//!
//! The answer goes on every audit row a vault writes (see `remoter_vault`'s
//! `actor` module and `migrations/003_audit_actor.sql`), so that a vault shared
//! between colleagues can say which of them did what, and from where.
//!
//! Each platform has one place that is its own source of truth, and that is
//! where this reads first:
//!
//! - **Windows** — `COMPUTERNAME`, `USERNAME` and `USERDOMAIN`, which Winlogon
//!   sets for every interactive session. `USERDOMAIN` is the NetBIOS domain for
//!   an Active Directory account, `AzureAD` for an Entra ID one, and the
//!   computer name for a local account — the last is dropped by
//!   `AuditActor::new`, since it repeats the machine.
//! - **macOS** — `scutil --get ComputerName`, the name the Sharing pane shows
//!   and the one a person recognises as their Mac, rather than the
//!   `Name.local` Bonjour host name. The account comes from `id -un`, which
//!   resolves the process's real user ID through Directory Services.
//! - **Linux and the other Unixes** — `/proc/sys/kernel/hostname`, which is the
//!   kernel's own node name and what `uname -n` prints, then `/etc/hostname`.
//!   The account is `id -un` for the same reason as on macOS: it follows the
//!   real user ID through NSS, so an LDAP or SSSD account resolves too.
//!
//! Environment variables are the fallback everywhere except Windows, where they
//! are the platform's own mechanism. Every command is run by absolute path, so
//! a `PATH` entry cannot substitute a different `id`.
//!
//! None of this is authentication. A user controls their own environment, and
//! anybody who can unlock a vault can write any row into it; the names answer
//! "which of the people who can open this did that", not "prove it".

use std::path::Path;
use std::process::Command;

use remoter_vault::AuditActor;

/// Where the identity is read from, so every platform's branch can be tested
/// on whichever platform the tests happen to run.
pub(crate) struct Sources<'a> {
    pub env: &'a dyn Fn(&str) -> Option<String>,
    pub read_file: &'a dyn Fn(&Path) -> Option<String>,
    pub run: &'a dyn Fn(&str, &[&str]) -> Option<String>,
}

/// The identity this process runs as, or `None` when the platform would not
/// say.
pub(crate) fn detect() -> Option<AuditActor> {
    detect_with(
        std::env::consts::OS,
        &Sources {
            env: &|name| std::env::var(name).ok(),
            read_file: &|path| std::fs::read_to_string(path).ok(),
            run: &run_command,
        },
    )
}

pub(crate) fn detect_with(os: &str, sources: &Sources<'_>) -> Option<AuditActor> {
    // Tried in order and stopped at the first that answers, so a Mac that
    // reports its ComputerName does not also spawn three more processes to be
    // told the same thing less well.
    let first = |candidates: &[&dyn Fn() -> Option<String>]| -> Option<String> {
        candidates
            .iter()
            .filter_map(|candidate| candidate())
            .map(|value| value.trim().to_owned())
            .find(|value| !value.is_empty())
    };
    let env = |name: &'static str| move || (sources.env)(name);
    let run =
        |program: &'static str, args: &'static [&'static str]| move || (sources.run)(program, args);
    let file = |path: &'static str| move || (sources.read_file)(Path::new(path));

    match os {
        "windows" => {
            let machine = first(&[&env("COMPUTERNAME")])?;
            let user = first(&[&env("USERNAME")])?;
            let domain = first(&[&env("USERDOMAIN")]);
            AuditActor::new(&machine, &user, domain.as_deref(), os)
        }
        "macos" => {
            let machine = first(&[
                &run("/usr/sbin/scutil", &["--get", "ComputerName"]),
                &run("/usr/sbin/scutil", &["--get", "LocalHostName"]),
                &run("/bin/hostname", &[]),
                &env("HOSTNAME"),
            ])?;
            let user = first(&[&run("/usr/bin/id", &["-un"]), &env("USER"), &env("LOGNAME")])?;
            AuditActor::new(&machine, &user, None, os)
        }
        _ => {
            let machine = first(&[
                &file("/proc/sys/kernel/hostname"),
                &file("/etc/hostname"),
                &env("HOSTNAME"),
                &run("/bin/hostname", &[]),
            ])?;
            let user = first(&[
                &run("/usr/bin/id", &["-un"]),
                &run("/bin/id", &["-un"]),
                &env("USER"),
                &env("LOGNAME"),
            ])?;
            AuditActor::new(&machine, &user, None, os)
        }
    }
}

fn run_command(program: &str, args: &[&str]) -> Option<String> {
    if !Path::new(program).is_file() {
        return None;
    }
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use super::*;

    struct Machine {
        env: HashMap<&'static str, &'static str>,
        files: HashMap<PathBuf, &'static str>,
        commands: HashMap<String, &'static str>,
    }

    impl Machine {
        fn new() -> Self {
            Self {
                env: HashMap::new(),
                files: HashMap::new(),
                commands: HashMap::new(),
            }
        }

        fn env(mut self, name: &'static str, value: &'static str) -> Self {
            self.env.insert(name, value);
            self
        }

        fn file(mut self, path: &str, value: &'static str) -> Self {
            self.files.insert(PathBuf::from(path), value);
            self
        }

        fn command(mut self, line: &str, output: &'static str) -> Self {
            self.commands.insert(line.to_owned(), output);
            self
        }

        fn detect(&self, os: &str) -> Option<AuditActor> {
            detect_with(
                os,
                &Sources {
                    env: &|name| self.env.get(name).map(|v| (*v).to_owned()),
                    read_file: &|path| self.files.get(path).map(|v| (*v).to_owned()),
                    run: &|program, args| {
                        let line = std::iter::once(program)
                            .chain(args.iter().copied())
                            .collect::<Vec<_>>()
                            .join(" ");
                        self.commands.get(&line).map(|v| (*v).to_owned())
                    },
                },
            )
        }
    }

    #[test]
    fn windows_reads_its_session_variables_and_keeps_a_real_domain() {
        let actor = Machine::new()
            .env("COMPUTERNAME", "DESKTOP-7")
            .env("USERNAME", "burak")
            .env("USERDOMAIN", "DEVOPLUS")
            .detect("windows")
            .unwrap();
        assert_eq!(actor.machine, "DESKTOP-7");
        assert_eq!(actor.account(), "DEVOPLUS\\burak");
        assert_eq!(actor.os, "windows");
    }

    #[test]
    fn a_local_windows_account_is_not_shown_as_its_own_domain() {
        let actor = Machine::new()
            .env("COMPUTERNAME", "DESKTOP-7")
            .env("USERNAME", "burak")
            .env("USERDOMAIN", "DESKTOP-7")
            .detect("windows")
            .unwrap();
        assert_eq!(actor.account(), "burak");
    }

    #[test]
    fn macos_prefers_the_name_a_person_gave_their_mac() {
        let actor = Machine::new()
            .command(
                "/usr/sbin/scutil --get ComputerName",
                "Burak’s MacBook Pro\n",
            )
            .command(
                "/usr/sbin/scutil --get LocalHostName",
                "Buraks-MacBook-Pro\n",
            )
            .command("/usr/bin/id -un", "burak\n")
            .env("USER", "someone-else")
            .detect("macos")
            .unwrap();
        assert_eq!(actor.machine, "Burak’s MacBook Pro");
        assert_eq!(
            actor.user, "burak",
            "the real user ID wins over the environment"
        );
        assert_eq!(actor.domain, None);
    }

    #[test]
    fn linux_reads_the_kernel_node_name_and_the_real_user_id() {
        let actor = Machine::new()
            .file("/proc/sys/kernel/hostname", "cachyos-box\n")
            .file("/etc/hostname", "stale-name\n")
            .command("/usr/bin/id -un", "bbesli\n")
            .env("USER", "not-me")
            .detect("linux")
            .unwrap();
        assert_eq!(actor.machine, "cachyos-box");
        assert_eq!(actor.user, "bbesli");
        assert_eq!(actor.os, "linux");
    }

    #[test]
    fn linux_falls_back_to_the_environment_when_nothing_better_answers() {
        let actor = Machine::new()
            .env("HOSTNAME", "container")
            .env("USER", "builder")
            .detect("linux")
            .unwrap();
        assert_eq!(actor.machine, "container");
        assert_eq!(actor.user, "builder");
    }

    #[test]
    fn no_identity_is_invented_when_the_platform_gives_none() {
        assert_eq!(Machine::new().detect("linux"), None);
        assert_eq!(
            Machine::new()
                .env("COMPUTERNAME", "DESKTOP-7")
                .detect("windows"),
            None,
            "a machine with no account is not somebody"
        );
    }

    #[test]
    fn this_machine_answers() {
        // The one test that touches the real platform: whatever it runs on
        // must be able to say who it is, or every row it writes is unattributed.
        let actor = detect().expect("this machine should report an account and a name");
        assert_eq!(actor.os, std::env::consts::OS);
    }
}
