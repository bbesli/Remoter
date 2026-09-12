# ADR-0008: Ten languages from v1.0, ICU MessageFormat, RTL support

- **Status**: Accepted
- **Date**: 2026-09-10
- **Implementation**: ◐ The ten catalogues, ICU MessageFormat and RTL are built.
  Two pieces of tooling this decision assumed are not: there is no Weblate
  project — translations arrive as pull requests — and no pseudo-localisation
  anywhere, in CI or locally.
  [i18n.md](../../features/i18n.md#locale-specific-hazards) tracks both.

## Context

Server administration is a global occupation, and the incumbent tools are
overwhelmingly English-only. Localisation is one of the clearest ways a new
open-source entrant can be immediately more useful than the established option
— and it is far cheaper to design in than to retrofit, particularly
right-to-left layout.

## Decision

Ship **ten languages** in v1.0, English being the source of truth:

| Locale | Language | Direction |
|---|---|---|
| `en` | English | LTR |
| `zh-Hans` | 简体中文 | LTR |
| `es` | Español | LTR |
| `hi` | हिन्दी | LTR |
| `ar` | العربية | **RTL** |
| `pt-BR` | Português (Brasil) | LTR |
| `ru` | Русский | LTR |
| `fr` | Français | LTR |
| `de` | Deutsch | LTR |
| `tr` | Türkçe | LTR |

Chosen for speaker population weighted towards the professional IT community,
with Turkish included as the project's origin language.

Technical choices:

- **ICU MessageFormat** via `i18next` — not string concatenation. Plurals in
  Russian (4 forms) and Arabic (6 forms) cannot be expressed by an `n === 1`
  check, and gendered and ordinal forms need real selectors
- **`Intl` APIs** for dates, times, numbers and relative times. No hand-rolled
  formatting anywhere
- **CSS logical properties** throughout — `margin-inline-start`, not
  `margin-left` — so RTL is a `dir` attribute rather than a parallel stylesheet
- **JSON catalogs** at `locales/<locale>/<namespace>.json`, namespaced by feature
- **Weblate** for the translation workflow, so translators never touch Git

Rules enforced in review:

- No user-visible string literal in JSX or Rust. `t()` everywhere
- Only `locales/en/*.json` is edited by contributors; other locales come from
  translators
- Every string gets a translator comment where the context is not obvious from
  the key
- Security-critical copy — the recovery key warning, changed-host-key warnings,
  plaintext-export warnings — is flagged in the catalog and must not be softened
  in translation. The i18n review checklist names these strings explicitly
- Turkish dotted/dotless İ/ı: never use locale-dependent `toLowerCase()` for
  comparison. Rust's `to_lowercase` and JavaScript's `toLocaleLowerCase('tr')`
  differ, and this is a classic source of subtle bugs
- The layout must survive German compound nouns (~35 % longer than English) and
  Arabic's greater line height. Pseudo-localisation to catch overflow was part
  of this decision and was never built: nothing expands strings by 40 % or wraps
  them in markers, in CI or on a developer's machine, so overflow is still found
  by a translator or a user

## Consequences

**Positive.** A genuinely wider audience than the incumbents. Translation is an
excellent first contribution, which broadens the contributor base. Designing for
RTL early costs little; retrofitting it is a rewrite.

**Negative.** Ten catalogs to keep in step; a lagging translation is visible to
its users. RTL doubles layout testing. Terminal and framebuffer content is never
translated — it comes from the remote host — which can feel inconsistent, and
the UI should not pretend otherwise.

**Neutral.** Additional languages are cheap once the pipeline exists; the
threshold for adding one is a committed translator, not a technical change.

## Revisit if

A locale's translation falls badly behind with no maintainer, in which case it
should be marked incomplete in the UI rather than silently showing a mixture of
languages.
