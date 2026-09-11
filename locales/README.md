# Translation catalogues

`locales/<code>/<namespace>.json`. One directory per language, one file per
namespace. English is the source; every other language comes from translators
through Weblate.

The design is in [`docs/features/i18n.md`](../docs/features/i18n.md). This file
is the working detail — what to do when you are extracting a feature's strings.

---

## Extracting a feature

1. **Write the catalogue first.** Create `locales/en/<namespace>.json`. The
   namespace is your directory under `apps/desktop/ui/src/features/`; the list
   is declared in `apps/desktop/ui/src/i18n/locales.ts`.
2. **Add it to the type augmentation** in `src/i18n/i18next.d.ts`. Until you do,
   `useT("<namespace>")` will not compile — deliberately: a screen written
   against a catalogue nobody has written renders humanised keys and looks
   finished.
3. **Replace the copy.** `const t = useT("<namespace>")`, then
   `t("section.key")`. Delete the file's `TEXT` constant.
4. **Delete your feature's line** from `apps/desktop/ui/eslint-rules/i18n-baseline.js`.
   The two i18n rules are now errors in your directory. That is the point.
5. `npx tsc --noEmit && npx eslint . && npx vitest run`.

`features/shell` and `features/settings` are done, and are the worked example.
`shell/Footer.tsx` shows plurals, `shell/StatusBar.tsx` shows bidi isolation,
`settings/TerminalSection.tsx` shows an interpolated `Intl` number and the one
legitimate use of an `eslint-disable` here.

---

## Writing a message

**Keys are semantic.** `vault.recovery_warning`, never
`"This is your only way back in"`. A key names what the string is for, so
changing the wording is not a key change.

**No concatenation.** `"Connected to " + host` breaks in every language whose
word order differs. Interpolate:

```json
{ "connected": "Connected to {host} as {user}" }
```

```tsx
t("connected", { host: isolate(host), user: isolate(user) })
```

**Plurals are ICU, always.** Not `n === 1`:

```json
{ "sessions": "{count, plural, =0 {no sessions} one {# session} other {# sessions}}" }
```

`=0` is an exact match and beats the plural category, which is what lets
English say "no sessions" instead of "0 sessions". `other` is mandatory — it is
the fallback for every category a translator does not supply. Russian needs
four categories and Arabic six; the formatter uses `Intl.PluralRules`, so the
translator supplies whichever their language has and the code does not change.

**Every non-obvious key gets a translator comment** as a sibling
`_comment_<key>` entry. Translators cannot see the interface. Say what the
placeholders hold, what must not be softened, and what is a product name:

```json
{
  "_comment_needsVault": "{action} is one of the four labels above. Interpolated rather than concatenated: languages differ on where the subject of this sentence goes.",
  "needsVault": "{action} needs an unlocked vault."
}
```

A `_comment_foo` whose `foo` no longer exists is a test failure
(`src/i18n/catalogues.test.ts`), because Weblate would show it against the
wrong string. `_comment_file` annotates the file and `_comment_` on its own
annotates the object it sits in.

**Security-critical strings are flagged in their comment, in capitals.** A
warning about permanent data loss that a translator has softened into something
gentler is a real and entirely foreseeable source of harm, and the flag is what
gets those strings a second reader.

---

## Never translated

Protocol names (SSH, RDP, VNC, SFTP), key names (Ctrl, Esc, F4), hostnames, IP
addresses, ports, file paths, version strings, terminal and framebuffer output,
licence names, and the product name. The full list is in
`docs/features/i18n.md`. Each of these is a defensible `eslint-disable` with a
reason; none is a reason to weaken the rule.

---

## What the code does with these files

- **English is compiled into the bundle.** It is the fallback for every missing
  key in every language, so it has to be there before anything can be missing.
- **Every other language is fetched when a screen asks for its namespace.**
  That is what the per-feature split buys.
- **A missing key** falls back to the chosen language, then English, then the
  humanised key marked `⟦ ⟧` in development. A user never sees a raw key.
- **A message that will not parse** falls back to the English source of the same
  key rather than putting ICU syntax on screen. `catalogues.test.ts` checks
  every English message parses, so that path should only ever be reached by a
  translation.
- **A language becomes selectable** when its directory holds every namespace
  English ships. Nothing has to be edited to make that happen.
