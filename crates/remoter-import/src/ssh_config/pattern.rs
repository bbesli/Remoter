//! OpenSSH's pattern matching, as `match_pattern` in `match.c` implements it.
//!
//! `*` matches any run of characters including none, `?` matches exactly one,
//! and everything else matches itself. A pattern list is comma-separated and a
//! leading `!` negates: a subject matches the list when it matches a positive
//! pattern and no negated one. There is no character class and no escaping,
//! which is what makes a total, allocation-free matcher possible.
//!
//! The matcher is iterative with a single backtracking point. The recursive
//! form is the obvious one and is quadratic on `a*a*a*a*b` against `aaaa…`; a
//! config is a file a colleague sends you, so a pattern that costs seconds is a
//! pattern worth not supporting.

/// Whether `subject` matches one pattern.
pub(crate) fn matches(pattern: &str, subject: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let subject: Vec<char> = subject.chars().collect();

    let mut p = 0usize;
    let mut s = 0usize;
    // Where to resume if the current attempt fails: the `*` that was last
    // stretched, and how far the subject had been consumed at that point.
    let mut star: Option<(usize, usize)> = None;

    loop {
        if p < pattern.len() && pattern[p] == '*' {
            star = Some((p, s));
            p += 1;
            continue;
        }
        if s < subject.len() && p < pattern.len() && (pattern[p] == '?' || pattern[p] == subject[s])
        {
            p += 1;
            s += 1;
            continue;
        }
        if p == pattern.len() && s == subject.len() {
            return true;
        }
        // Stretch the last `*` by one and try again.
        match star {
            Some((star_p, star_s)) if star_s < subject.len() => {
                p = star_p + 1;
                s = star_s + 1;
                star = Some((star_p, star_s + 1));
            }
            _ => return false,
        }
    }
}

/// Whether `subject` matches a comma-separated pattern list.
pub(crate) fn matches_list<'a>(patterns: impl IntoIterator<Item = &'a str>, subject: &str) -> bool {
    let mut positive = false;
    for pattern in patterns {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            continue;
        }
        if let Some(negated) = pattern.strip_prefix('!') {
            if matches(negated, subject) {
                // A negated match wins outright, whatever else matched.
                return false;
            }
        } else if matches(pattern, subject) {
            positive = true;
        }
    }
    positive
}

/// Splits a `Host` or `Match host` argument list into patterns.
///
/// Both the comma-separated form on one argument and the whitespace-separated
/// form across several are accepted, because `ssh` accepts both.
pub(crate) fn split(arguments: &[String]) -> impl Iterator<Item = &str> {
    arguments
        .iter()
        .flat_map(|argument| argument.split(','))
        .map(str::trim)
        .filter(|pattern| !pattern.is_empty())
}

/// Whether a pattern names exactly one host rather than a set of them.
pub(crate) fn is_literal(pattern: &str) -> bool {
    !pattern.is_empty() && !pattern.contains(['*', '?', '!'])
}

#[cfg(test)]
#[allow(clippy::panic, reason = "test code")]
mod tests {
    use super::*;

    #[test]
    fn literal_patterns_match_themselves() {
        assert!(matches("web-01", "web-01"));
        assert!(!matches("web-01", "web-02"));
        assert!(!matches("web-01", "web-010"));
        assert!(matches("", ""));
        assert!(!matches("", "a"));
    }

    #[test]
    fn star_and_question_behave_as_openssh_documents_them() {
        assert!(matches("*", ""));
        assert!(matches("*", "anything"));
        assert!(matches("*.example.com", "web-01.example.com"));
        assert!(!matches("*.example.com", "example.com"));
        assert!(matches("web-??", "web-01"));
        assert!(!matches("web-??", "web-001"));
        assert!(matches("a*b*c", "azzbzzc"));
        assert!(!matches("a*b*c", "azzbzz"));
        assert!(matches("*x", "x"));
        assert!(matches("x*", "x"));
    }

    #[test]
    fn a_pathological_pattern_terminates() {
        // The recursive matcher takes exponential time on this; the iterative
        // one is linear in the product of the two lengths.
        let subject = "a".repeat(64);
        assert!(!matches("a*a*a*a*a*a*a*b", &subject));
        assert!(matches("a*a*a*a*a*a*a*a", &subject));
    }

    #[test]
    fn negation_beats_any_positive_match() {
        assert!(matches_list(["*.example.com"], "web-01.example.com"));
        assert!(!matches_list(
            ["*.example.com", "!db-*.example.com"],
            "db-01.example.com"
        ));
        assert!(matches_list(
            ["*.example.com", "!db-*.example.com"],
            "web-01.example.com"
        ));
        // A list of only negations matches nothing: there is no positive.
        assert!(!matches_list(["!a"], "b"));
        assert!(!matches_list([], "b"));
    }

    #[test]
    fn patterns_split_on_commas_and_on_whitespace() {
        let arguments = vec!["a,b".to_owned(), "c".to_owned(), " , ".to_owned()];
        assert_eq!(split(&arguments).collect::<Vec<_>>(), ["a", "b", "c"]);
    }

    #[test]
    fn a_literal_pattern_names_one_host() {
        assert!(is_literal("web-01.example.com"));
        assert!(!is_literal("*"));
        assert!(!is_literal("web-?"));
        assert!(!is_literal("!web-01"));
        assert!(!is_literal(""));
    }
}
