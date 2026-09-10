# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report it privately through
[GitHub Security Advisories](https://github.com/bbesli/Remoter/security/advisories/new),
which creates a private channel with the maintainers.

Please include:

- A description of the vulnerability and its impact
- Steps to reproduce, or a proof of concept
- Affected version, platform and configuration
- Any suggested fix

**What to expect**

| | Target |
|---|---|
| Acknowledgement | 48 hours |
| Initial assessment | 7 days |
| Fix or mitigation plan | 30 days for high severity |
| Public disclosure | Coordinated, after a fix is available |

You will be credited in the advisory unless you prefer otherwise.

## Scope

**In scope**

- Anything that discloses vault contents without the correct credentials
- Weaknesses in the cryptographic design or its implementation
- Memory-safety issues in protocol parsing
- Secrets leaking into logs, error messages, crash dumps, `argv` or temporary
  files
- Sandbox escapes from the plugin system
- Missing or bypassable host key and certificate verification
- Anything in the import parsers reachable by a crafted file

**Out of scope** — stated in the
[threat model](docs/security/threat-model.md), not dismissively but because no
user-space application can address them:

- Attacks requiring root, kernel access or physical memory capture
- Malware already running as the user
- Weak master passwords chosen by the user
- Social engineering
- Denial of service against a remote host

## Design review

The project actively wants review of its cryptographic design **before** it is
implemented. The specifications are public for that reason:

- [Threat model](docs/security/threat-model.md)
- [Vault format](docs/security/vault-format.md)
- [Key management](docs/security/key-management.md)
- [Transport security](docs/security/transport-security.md)

If you have applied-cryptography experience and are willing to look at these,
that is among the most valuable contributions the project can receive right now.
An independent review of the vault format is a **release gate for v1.0**.

Design feedback is welcome as a public issue — a design discussion is not a
vulnerability report.

## Supported versions

The project is pre-release. Once v1.0 ships, the latest minor release will
receive security fixes.

## Our commitments

- Security issues are prioritised over features
- Fixes are released promptly, with an advisory explaining the issue
- We will not quietly patch a vulnerability without disclosing it
- We will state plainly when something cannot be fixed, and why
