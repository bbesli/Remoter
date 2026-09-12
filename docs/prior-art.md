# Prior Art

What the existing tools do well, where they fall short, and what Remoter takes
from each. Written with respect: these are mature products that solved real
problems, and several have been maintained for well over a decade.

## mRemoteNG

Open source (GPL), Windows only, .NET.

**Does well**

- **Property inheritance** through the folder tree. The single best idea in this
  product category, and the reason it remains in use fifteen years on
- One tabbed window for RDP, SSH, VNC, Telnet and more
- A portable XML connection file
- Free, and genuinely open

**Falls short**

- Windows only, with no realistic path to other platforms
- The interface shows its age
- A history of cryptographic weakness: a well-known default file password,
  legacy AES-CBC with an MD5-derived key, and full-file encryption that could be
  silently downgraded on upgrade
- Development has been intermittent
- Protocol support depends on Windows components

**Remoter takes**: the inheritance model, almost wholesale — and adds visible
provenance, which is the piece mRemoteNG lacks.

**Remoter avoids**: the cryptography. Every weakness above is specifically
addressed in [vault-format.md](security/vault-format.md).

## Royal TS / Royal TSX

Commercial, Windows and macOS, .NET and native.

**Does well**

- The most polished interface in the category
- A genuinely broad protocol range, including web, cloud and database consoles
- Excellent credential management, with credentials as first-class objects
- Dashboards, key sequences, task automation
- Good team features through shared documents

**Falls short**

- Commercial, per-seat licensing
- No Linux client — a notable gap for the audience that administers Linux
- Closed source, so the cryptography cannot be independently reviewed
- Substantial feature surface with a correspondingly steep learning curve

**Remoter takes**: credentials as first-class, independently organised objects;
the standard of interface polish; the breadth ambition, staged over time.

## Termius

Commercial, cross-platform, Electron.

**Does well**

- Genuinely good design and onboarding
- Real cross-platform, including mobile
- Cloud synchronisation that works
- SFTP and snippets integrated well

**Falls short**

- SSH-focused; RDP and VNC arrived late and are thinner
- Cloud-first, subscription-gated; core features sit behind a paywall
- Electron: large binary, heavy memory use
- Closed source, and the sync model requires trusting a vendor with a key path

**Remoter takes**: the interface standard, and the lesson that professional
tools do not have to look like they were built in 2006.

**Remoter avoids**: the cloud-first, subscription model.

## SecureCRT / SecureFX

Commercial, cross-platform, native.

**Does well**: rock-solid terminal emulation, extremely broad terminal support,
excellent scripting, a long track record with network engineers.

**Falls short**: no RDP or VNC, dated interface, expensive, closed source.

**Remoter takes**: the seriousness about terminal emulation correctness — the
reason xterm.js was chosen over lighter alternatives.

## PuTTY

Free, open source, Windows-first.

**Does well**: universally available, tiny, absolutely dependable, the de facto
standard for a generation of Windows administrators.

**Falls short**: registry-based session storage, no organisation beyond a flat
list, no credential storage, one window per session, a deliberately minimal
interface.

**Remoter takes**: the dependability standard, and an import path — PuTTY
sessions are where a great many administrators' connection lists still live.

## Remmina

Free, open source (GPL), Linux.

**Does well**: the best open-source remote desktop client on Linux, good RDP via
FreeRDP, a plugin architecture, genuinely lightweight.

**Falls short**: Linux only, limited organisation and credential management,
inconsistent interface, no inheritance.

**Remoter takes**: the plugin architecture idea, and the confirmation that a
free tool can hold its own on protocol quality.

## Apache Guacamole

Free, open source, web-based, server-side.

**Does well**: clientless access from a browser, strong multi-user and audit
features, protocol translation done well, genuinely enterprise-capable.

**Falls short**: requires a server; that server terminates protocols and holds
credentials, which is a large attack surface; browser-based input has latency;
substantial operational burden.

**Remoter takes**: the recording and audit model, and the confirmation that
protocol translation is architecturally possible.

**Remoter avoids**: the gateway architecture entirely, for the reasons in
[ADR-0003](architecture/decisions/0003-protocol-embedding.md).

## Devolutions Remote Desktop Manager

Commercial, cross-platform.

**Does well**: the broadest protocol and integration support in the category,
strong enterprise features, extensive vault integrations. Devolutions also
maintains IronRDP, which Remoter depends on.

**Falls short**: commercial and expensive; a very large feature surface;
Windows-strongest.

**Remoter takes**: the integration ambition — and, directly, IronRDP.

## Where Remoter fits

The Remoter column is what Remoter *does today*, not what it intends to do.
Every other column describes a shipping product, so a column of intentions
beside them would be a lie by table layout.

| | mRemoteNG | Royal TS | Termius | Remmina | Guacamole | **Remoter** |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Open source | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ |
| Free | ✅ | ❌ | Partial | ✅ | ✅ | ✅ |
| Linux | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| Windows | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ |
| macOS | ❌ | ✅ | ✅ | ❌ | ✅ | Builds and is tested in CI; unused by anyone |
| Inheritance | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ |
| Modern UI | ❌ | ✅ | ✅ | ❌ | Partial | ✅ |
| Audited crypto design | ❌ | Unknown | Unknown | ❌ | Partial | ⏳ specified in public; not reviewed |
| Hardware key unlock | ❌ | ❌ | ❌ | ❌ | ❌ | ⏳ not built |
| No server required | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ |
| Sandboxed plugins | ❌ | ❌ | ❌ | ❌ | ❌ | ⏳ ABI only; no host |
| 10 languages | ❌ | Partial | Partial | ✅ | ✅ | ✅ |
| Session recording | ✅ | ✅ | ✅ | ❌ | ✅ | ⏳ not built |

The gap Remoter aims at: **open source, genuinely cross-platform, with
inheritance, a modern interface, and cryptography specified in public.** No
existing tool occupies all five at once, and Remoter occupies all five today.

The honest counterweight, which matters more than the table: every product above
is mature and shipping, and several have a decade's worth of protocol edge cases
handled that Remoter will have to learn the hard way. Remoter is alpha, unsigned
and unreviewed, and three of the rows above are still empty. Being new is not by
itself a virtue.
