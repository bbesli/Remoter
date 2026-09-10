# Contributing to Remoter

Thank you for considering it. Remoter is a security tool, so the bar for changes
to the core is high — but there is a great deal of valuable work that is not in
the core, and every kind of contribution listed below is genuinely wanted.

## Project status

**Design phase.** This repository currently contains specifications, not code.
The most useful contributions right now are review and discussion of the design
documents in [`docs/`](docs/) — particularly
[the threat model](docs/security/threat-model.md) and
[the vault format](docs/security/vault-format.md).

## Ways to contribute

| | What it involves |
|---|---|
| **Design review** | Read the docs, argue with them, open issues. Cryptography and protocol experience especially welcome |
| **Code** | See the [roadmap](docs/roadmap.md) for what is being built now |
| **Translation** | Ten languages need maintaining. No Git knowledge required |
| **Testing** | Try builds on your platform, against your servers, and report what breaks |
| **Documentation** | Clarity, accuracy, examples |
| **Packaging** | Distribution packaging, Flatpak, Homebrew |

## Before you start

**For anything beyond a small fix, open an issue first.** A design discussion
before implementation saves everyone the disappointment of a rejected pull
request. This is especially true for anything touching `remoter-vault` or a
protocol adapter.

Read [`CLAUDE.md`](CLAUDE.md) — despite the name it is the general engineering
guide for this repository, covering layering rules, secret handling, error
conventions and commit format.

## Development setup

[`docs/development/getting-started.md`](docs/development/getting-started.md) has
per-platform prerequisites and the build commands.

## The rules that are not negotiable

1. **Never log a secret.** Passwords, keys, passphrases and tokens must never
   reach stdout, a log, an error message or a trace span. Secret-bearing values
   use the `Secret<T>` wrapper, which redacts its own `Debug`
2. **Never weaken the cryptographic design to make something work.** If a KDF
   cost or a nonce policy is inconvenient, raise it as a design question
3. **Never add a dependency without a licence check.** GPL-3.0 permits MIT,
   Apache-2.0, BSD, ISC and MPL-2.0, and not much else. Record it in `deny.toml`
4. **Never commit a credential, key file or vault** — not even a test one
5. **Cite the specification** when implementing a wire-level protocol detail

## Pull requests

**Before opening one:**

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
npm run typecheck --prefix apps/desktop/ui
npm run lint --prefix apps/desktop/ui
npm test --prefix apps/desktop/ui
```

**In the description**, say:

- What problem this solves, and why this approach
- What you tested, and on which platform
- **What you did not do** — missing tests, an untested platform, a known
  limitation. Stating it is far better than having it found in review

**Keep pull requests focused.** One change per pull request. A refactor bundled
with a feature is difficult to review and difficult to revert.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/):

```
feat(vault): add FIDO2 hmac-secret key slot
fix(ssh): reset PTY window size after a tab is detached
docs(security): document recovery key rotation
test(import): add fuzz target for confCons.xml
```

Scopes are crate names without the `remoter-` prefix: `vault`, `core`, `ssh`,
`rdp`, `vnc`, `sftp`, `tunnel`, `import`, `record`, `plugin`, `ipc`, `ui`,
`deps`, `ci`.

Explain **why** in the body. The diff already shows what.

Commits must be authored by the person contributing them, under their own name
and email. We do not accept commits attributed to automated tools or third
parties.

## Code review

You can expect a reviewer to check:

- Correctness, and whether the tests actually prove it
- Whether any secret could escape into a log, a panic or an error
- Whether error paths clean up and zeroize
- Whether the layering rules hold
- Whether the documentation matches the new behaviour
- Whether user-visible strings are translatable

Review may be slow, particularly on cryptographic or protocol code. That is
deliberate.

## Translation

Translations go through Weblate — no Git knowledge needed. Only `locales/en/`
is edited directly, by contributors adding new strings.

If you translate: **security-critical strings are flagged in the catalogs and
must not be softened.** A warning about permanent, unrecoverable data loss has
to land as hard in your language as it does in English. If a literal translation
would be unnatural, find a natural phrasing with the same force — do not make it
gentler.

## Reporting bugs

Include: what you did, what you expected, what happened, your platform and
version, the protocol and — where relevant — the remote server's software and
version. Logs help; **check them for hostnames and credentials before posting**.

Do not report security vulnerabilities as public issues. See
[SECURITY.md](SECURITY.md).

## Licence

Contributions are licensed under GPL-3.0-or-later, the project's licence. By
submitting a pull request you confirm you have the right to license your
contribution under those terms.

There is no Contributor Licence Agreement, which means the project cannot be
relicensed without every contributor's agreement. That is intentional.

## Conduct

Be decent. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
