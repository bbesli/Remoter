//! Reading an `ssh_config` the way `ssh` reads it.
//!
//! `readconf.c` accepts a keyword and its arguments separated by whitespace or
//! by `=` with optional surrounding whitespace, treats `#` as a comment to end
//! of line, keeps double-quoted arguments together, and matches keywords
//! case-insensitively while leaving argument case alone. All four of those
//! matter in real files, and a line-splitting parser gets at least two of them
//! wrong.

use crate::error::ImportError;
use crate::limits::Limits;

/// One directive: a keyword, lowercased, and its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Directive {
    /// The keyword, lowercased for comparison.
    pub(crate) keyword: String,
    /// The keyword as it was written, for preserving and for reports.
    pub(crate) written: String,
    /// The arguments, with quotes removed.
    pub(crate) arguments: Vec<String>,
    /// The 1-based line the directive was on.
    pub(crate) line: usize,
}

impl Directive {
    /// The arguments joined back into one string, for the keywords whose value
    /// is the whole rest of the line — `ProxyCommand` above all.
    pub(crate) fn value(&self) -> String {
        self.arguments.join(" ")
    }
}

/// Splits a config into directives.
///
/// # Errors
///
/// [`ImportError::TooManyItems`] or [`ImportError::ValueTooLong`] when the file
/// exceeds the configured bounds.
pub(crate) fn tokenise(text: &str, limits: &Limits) -> Result<Vec<Directive>, ImportError> {
    let mut out = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        if index >= limits.max_items {
            return Err(ImportError::TooManyItems {
                limit: limits.max_items,
                unit: "lines",
            });
        }
        if raw.len() > limits.max_value_bytes {
            return Err(ImportError::ValueTooLong {
                limit: limits.max_value_bytes,
                unit: "line",
            });
        }
        if let Some(directive) = tokenise_line(raw, index + 1) {
            out.push(directive);
        }
    }
    Ok(out)
}

fn tokenise_line(raw: &str, line: usize) -> Option<Directive> {
    let trimmed = raw.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let mut chars = trimmed.char_indices().peekable();
    let mut keyword = String::new();
    // The keyword ends at whitespace or at the `=` form of the separator.
    while let Some(&(_, c)) = chars.peek() {
        if c.is_whitespace() || c == '=' {
            break;
        }
        keyword.push(c);
        chars.next();
    }
    if keyword.is_empty() {
        return None;
    }

    let rest_start = chars.peek().map_or(trimmed.len(), |(index, _)| *index);
    let mut rest = trimmed[rest_start..].trim_start();
    // Exactly one `=` may stand in for the whitespace separator.
    if let Some(stripped) = rest.strip_prefix('=') {
        rest = stripped.trim_start();
    }

    Some(Directive {
        written: keyword.clone(),
        keyword: keyword.to_ascii_lowercase(),
        arguments: split_arguments(rest),
        line,
    })
}

/// Splits arguments on whitespace, keeping double-quoted runs together and
/// stopping at an unquoted `#`.
fn split_arguments(rest: &str) -> Vec<String> {
    let mut arguments = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut started = false;

    for c in rest.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                started = true;
            }
            '#' if !quoted => break,
            c if c.is_whitespace() && !quoted => {
                if started {
                    arguments.push(core::mem::take(&mut current));
                    started = false;
                }
            }
            c => {
                current.push(c);
                started = true;
            }
        }
    }
    if started {
        arguments.push(current);
    }
    arguments
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code, per docs/development/coding-standards.md"
)]
mod tests {
    use super::*;

    fn one(line: &str) -> Directive {
        let directives = tokenise(line, &Limits::new()).unwrap();
        let [only] = directives.as_slice() else {
            panic!("expected exactly one directive from {line:?}");
        };
        only.clone()
    }

    #[test]
    fn keywords_are_case_insensitive_but_arguments_are_not() {
        let d = one("HostName Web-01.Example.COM");
        assert_eq!(d.keyword, "hostname");
        assert_eq!(d.written, "HostName");
        assert_eq!(d.arguments, ["Web-01.Example.COM"]);
    }

    #[test]
    fn the_equals_form_of_the_separator_is_accepted() {
        assert_eq!(one("Port=2222").arguments, ["2222"]);
        assert_eq!(one("Port = 2222").arguments, ["2222"]);
        assert_eq!(one("Port  =  2222").arguments, ["2222"]);
        // Only the first `=` is the separator; the rest belongs to the value.
        assert_eq!(one("SetEnv=FOO=bar").arguments, ["FOO=bar"]);
    }

    #[test]
    fn quoted_arguments_stay_together() {
        let d = one(r#"IdentityFile "/home/a b/.ssh/id_ed25519""#);
        assert_eq!(d.arguments, ["/home/a b/.ssh/id_ed25519"]);
        let d = one(r#"Host "a b" c"#);
        assert_eq!(d.arguments, ["a b", "c"]);
    }

    #[test]
    fn comments_end_a_line_but_not_a_quoted_argument() {
        assert_eq!(one("Port 22 # the default").arguments, ["22"]);
        assert_eq!(one(r#"ProxyCommand "a#b""#).arguments, ["a#b"]);
        assert!(
            tokenise("# all comment", &Limits::new())
                .unwrap()
                .is_empty()
        );
        assert!(tokenise("   \n\n  ", &Limits::new()).unwrap().is_empty());
    }

    #[test]
    fn a_proxy_command_keeps_its_whole_line() {
        let d = one("ProxyCommand ssh -W %h:%p bastion.example.com");
        assert_eq!(d.value(), "ssh -W %h:%p bastion.example.com");
        assert_eq!(d.arguments.len(), 4);
    }

    #[test]
    fn line_numbers_survive_blank_lines_and_comments() {
        let text = "# a\n\nHost x\n  Port 22\n";
        let directives = tokenise(text, &Limits::new()).unwrap();
        assert_eq!(directives.len(), 2);
        assert_eq!(directives[0].line, 3);
        assert_eq!(directives[1].line, 4);
    }

    #[test]
    fn a_keyword_with_no_arguments_is_still_a_directive() {
        let d = one("Compression");
        assert_eq!(d.keyword, "compression");
        assert!(d.arguments.is_empty());
        assert_eq!(d.value(), "");
    }

    #[test]
    fn the_line_and_item_ceilings_are_enforced() {
        let limits = Limits {
            max_items: 4,
            max_value_bytes: 32,
            ..Limits::new()
        };
        let many = "Port 22\n".repeat(64);
        assert_eq!(
            tokenise(&many, &limits),
            Err(ImportError::TooManyItems {
                limit: 4,
                unit: "lines"
            })
        );
        let long = format!("Port {}", "2".repeat(1024));
        assert_eq!(
            tokenise(&long, &limits),
            Err(ImportError::ValueTooLong {
                limit: 32,
                unit: "line"
            })
        );
    }
}
