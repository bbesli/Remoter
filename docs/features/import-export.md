# Import and Export

> **What ships: four importers and four of the five export formats.** Remoter's
> own `.rmtr` archive, mRemoteNG `confCons.xml`, `~/.ssh/config` and CSV are
> imported, each with format detection, a preview the user selects from, an
> all-or-nothing commit and a findings report; the three foreign ones parse
> boundedly under a `cargo-fuzz` target. ✅ Export writes the encrypted `.rmtr`
> archive, secrets included, for another Remoter, and CSV, an OpenSSH config and
> JSON — never with a secret in them — for other tools; the archive, the CSV and
> the OpenSSH config are read back by their importers under test. ⏳ Not built:
> the structure-only archive, plaintext secret export, anything that reads the
> JSON back, per-item conflict resolution against what the vault already holds
> (step 5 of the flow), `known_hosts` into the trust store, and every source in
> the table marked ⏳. Each is marked in place below.

Migration is the highest-leverage feature for adoption: an administrator with
four hundred connections in mRemoteNG will not retype them, and no amount of
better design will overcome that.

It is also the largest hostile-input surface in the application. Every parser
here reads files that may be crafted or corrupted, so every parser is fuzzed and
none of them touches the vault until the user confirms a preview.

## Supported sources

Three of these are built. The parser for anything marked ⏳ does not exist, and
`import_parse` refuses its name — asking for `royalts` is answered with
"`royalts` is not an importer; expected mremoteng, ssh-config or csv".

| Source | Format | Secrets | Status |
|---|---|---|---|
| **Remoter** | `.rmtr` archive | ✅ with the archive password | ✅ shipped |
| **mRemoteNG** | `confCons.xml` | ✅ with the file password | ✅ shipped |
| **OpenSSH** | `~/.ssh/config` | Key references | ✅ shipped |
| **Generic** | CSV | Depends | ✅ shipped |
| **Royal TS / Royal TSX** | `.rtsz`, `.rtsx` | ✅ with the document password | ⏳ v0.5 |
| **PuTTY** | Registry (Windows), `~/.putty/sessions` (Unix) | Keys only | ⏳ v0.5 — though `.ppk` key *files* are read today, by the SSH adapter |
| **Generic** | JSON | Depends | ⏳ v0.5 |
| **Remote Desktop Connection Manager** | `.rdg` | ✅ where not DPAPI-bound | ⏳ v1.0 |
| **Windows RDP** | `.rdp` files | — | ⏳ v1.0 |
| **Termius** | JSON export | ✅ | ⏳ v1.1 |
| **SecureCRT** | Session folder | Partial | ⏳ v1.1 |
| **Devolutions RDM** | XML export | ✅ | ⏳ v1.1 |

### mRemoteNG — ✅ shipped

The most important target, and the best documented. `confCons.xml` stores a tree
of `Node` elements carrying `Hostname`, `Protocol`, `Port`, `Username`,
`Domain`, `Password` and a large set of protocol options.

**The root element is namespaced**, and has been since mRemoteNG 1.76:
`XmlRootNodeSerializer` builds it as `XNamespace "http://mremoteng.org" +
"Connections"` and declares the prefix beside it, so a real export opens

```xml
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" … ConfVersion="2.7">
```

and not `<Connections …>`. Both spellings are the same document: format
detection and the parser match the element's *local* name and ignore the prefix.
mRemoteNG's own checked-in test resources predate the change and carry the
unprefixed form, which is why a fixture taken from them is not evidence that a
user's file will be recognised.

`ConfVersion` is the serialiser's version, not the application's: 2.6 through
1.76, 2.7 in 1.77, 2.8 in 1.78. Nothing in the importer branches on it — the
attributes it reads are present in all three.

**Encoding.** mRemoteNG writes UTF-8 without a byte-order mark
(`File.WriteAllText`), and UTF-8 is what a file gets when it says nothing. A
file that opens with a byte-order mark is read as the mark says: UTF-8 marks are
stripped, and UTF-16 — which is what a `>` redirect in Windows PowerShell 5 or a
"save as Unicode" in Notepad makes of a document that passed through them — is
converted rather than refused.

A file with **no mark** whose first bytes carry a NUL at every second position
is converted as UTF-16 as well. That is a fact about the bytes rather than a
guess about the content: U+0000 is forbidden in XML 1.0 (§2.2) and has no place
in a CSV or an `ssh_config` either, so those bytes cannot be the file in any
encoding this reads. Without the check the interleaved NULs are valid UTF-8, the
file reaches the XML reader whole, and the refusal the user is shown is about
their markup — which is the one thing not wrong with it.

Nothing beyond that is guessed. The declared `encoding` in the XML declaration
is content, and a heuristic over byte frequencies would make a file's encoding
depend on what its hostnames happen to be.

**Detection** asks two questions in a fixed order, and the order is the rule.

First: what is the document's **root element**? Its *first* element, skipping
the XML declaration, comments and a doctype — looked for as far as 256 KiB in,
because a `confCons.xml` that has been through an export script can carry a
banner above its root, and the root is then still the document's first element,
just further in than a head-sized window reaches. A root whose local name is
`Connections` is an mRemoteNG file; any other root is an XML document this build
does not read, and neither answer is revised by anything further into the file.
A `<Connections>` that is *not* the root is a folder called Connections in
somebody else's export, and is not evidence of anything.

Second, and only for a file with no root element to read: the line-shaped tests
— `Host`, `Match` or `Include` at the start of a line for an OpenSSH config, a
first line carrying "host" and a separator for a CSV. Those read the first 8 KiB
only, since a line a quarter of a megabyte into a file says nothing about what
the file is. They come second because a root element is a fact about a document
where a line shape is a coincidence any file can contain: an `ssh_config` pasted
into a banner has three hundred `Host …` lines in it and the file around them is
still XML. Asked first, they called such a `confCons.xml` an OpenSSH config.

A prolog longer than 256 KiB, or a root element the window cuts in half, leaves
the format unknown — and unknown is a usable answer, because detection is a
preselection the user can overrule, never a gate: the wizard says so and offers
the three formats, and any file can be imported as any format by choosing one.

Encryption varies by version, and the file declares which it uses:

| Attribute | Scheme |
|---|---|
| `BlockCipherMode="GCM"` | AES-GCM, key from PBKDF2-SHA1 with `KdfIterations` |
| `BlockCipherMode="CBC"` (legacy) | AES-CBC, key from an MD5 hash of the password |
| `FullFileEncryption="true"` | The entire document is encrypted |
| No password set | A well-known default password is used |

Remoter reads all of these. Where the file used the default password, the import
report says so explicitly, because a user who believed their file was protected
should learn that it was not.

mRemoteNG's inheritance model maps almost directly onto Remoter's, which is
fortunate: `Inherit*` attributes become `Inherited::Inherit`, and everything
else becomes `Inherited::Explicit`. Structure is preserved, not flattened.

### Royal TS — ⏳ not built

`.rtsz` is a compressed XML document; `.rtsx` is its uncompressed form.
Connections, folders, credential objects and the credential *links* between them
all map cleanly onto Remoter's model, including Royal TS's own inheritance.

### PuTTY — ⏳ not built

The `.ppk` half of this is done, in a different place: `remoter-proto-ssh`'s key
reader parses PuTTY v2 and v3 key files, encrypted or not, and identifies a
container by its contents rather than by its file name. What is missing is the
*session* importer — the registry and `~/.putty/sessions` halves below.

On Windows, sessions live in the registry under
`HKCU\Software\SimonTatham\PuTTY\Sessions`; KiTTY uses
`HKCU\Software\9bis.com\KiTTY`. On Unix, `~/.putty/sessions`. Remoter reads
both, and imports `.ppk` private keys (v2 and v3), decrypting them with a
passphrase if one is supplied.

PuTTY stores no session passwords, so only key material comes across.

### OpenSSH config — ✅ shipped

`~/.ssh/config` is parsed properly rather than line-by-line: `Host` and `Match`
blocks, `Include` directives, wildcards, and `ProxyJump`/`ProxyCommand`.

`ProxyJump` maps directly onto Remoter's gateway chains, which is the most
satisfying part of this importer — an existing bastion setup arrives fully
configured. `ProxyCommand` cannot always be mapped; where it cannot, the command
is preserved in a custom field and flagged in the report rather than dropped.

⏳ `known_hosts` is **not** imported into the trust store. The design — each
entry marked `accepted_by: import`, so it is distinguishable from a key the user
personally verified — still stands; the importer reads the config file and
nothing beside it, so every host is trusted on first use as though it were new.

## The import flow

```
1  Choose source        auto-detected from the file, confirmable       ✅
2  Supply secrets       file password, key passphrases                 ✅
3  Parse                in a bounded parser; nothing written yet       ✅
4  Preview              the full tree as it will be created            ✅  per-item selection
5  Resolve conflicts    per-item: skip, replace, keep both, merge      ⏳
6  Choose destination   the vault folder to import into                ✅
7  Commit               one transaction; all or nothing                ✅
8  Report               what came in, what was dropped, what needs attention  ✅
```

Nothing touches the vault before step 7. The preview is the whole point: a user
importing four hundred connections needs to see what they are about to get, and
they can deselect any of it before committing.

⏳ Step 5 is the gap. There is no conflict resolution against what is already in
the vault: an import creates nodes under the chosen folder, and a name that
already exists there is simply created again.

The report names what could not be mapped rather than silently discarding it.
Unmappable settings are preserved verbatim in `custom_fields`, so nothing is
lost even when it cannot be interpreted.

## Security of importers

Import parsers are the classic weak point of connection managers — they read
files that colleagues share, that come from old backups, and that may be
deliberately crafted.

| Risk | Control | |
|---|---|---|
| XXE / entity expansion | A `<!DOCTYPE` declaration is a hard error, not a skipped one, and there is no entity table for a document to add to — an unknown entity is a named failure rather than an empty string | ✅ |
| Memory exhaustion | Bounded parse with an explicit `Limits` struct: input bytes, depth, item count, attribute count, value bytes, node count, findings, custom fields, included files and include depth | ✅ |
| Malformed input | `cargo-fuzz` targets for all four shipped importers — `import_archive`, `import_csv`, `import_mremoteng`, `import_sshconfig` | ✅ |
| Credential misuse | Imported credentials carry a `Purpose` restriction matching their source protocol | ✅ |
| Zip slip | Archive entries with absolute paths, `..` segments or symlinks rejected | ⏳ — no importer reads an archive yet; this is for Royal TS |
| Decompression bombs | Hard cap on decompressed size and entry count | ⏳ — same |

Imported passwords are written straight into the vault's encrypted fields.
Plaintext never touches disk, and no temporary decrypted copy is created.

## Export — ◐ four formats of five

✅ **The connection tree, or one folder of it, exports as a `.rmtr` archive for
another Remoter, or as CSV, an OpenSSH config or JSON for other tools.** The
dialog asks first who the file is for, because that decides whether secrets go
into it. It is reached from the title bar, the command palette, and the tree's
menu on a folder, a connection or empty space. `tree_export` in `remoter-ipc`
writes the file atomically and readable by its owner only, and records the
export in the audit log as `data_exported`, under the warnings filter; an
archive's secrets are each recorded as `secret_exported` too.

| Format | Secrets | Use | |
|---|---|---|---|
| **Remoter archive** (`.rmtr`) | Encrypted with a password you set | Moving connections to another Remoter, backup, sharing a folder with a colleague | ✅ |
| **Remoter archive, structure only** | Excluded | Sharing a topology without credentials | ⏳ — the JSON carries the structure; nothing imports it yet |
| **JSON** | Excluded — always, not by default | Scripting, version control, review | ✅ |
| **CSV** | Excluded — always, not by default | Spreadsheets, inventory | ✅ |
| **`~/.ssh/config` fragment** | References only | Using the same hosts from the command line | ✅ |

**What each one carries.**

- **The `.rmtr` archive** is the chosen nodes and everything they depend on,
  with their passwords, private keys, passphrases and certificates, sealed
  under a password the user sets — the vault's own envelope with one password
  slot ([vault-format.md](../security/vault-format.md#the-rmtr-archive)). A
  folder that uses a shared credential kept elsewhere, or a connection routed
  through a jump host in another folder, brings that credential and that host
  along, and the dialog lists them; the folder at the root and each node pulled
  in keep what their old folders gave them — a port, an account, "no jump
  hosts" — so they connect the same way wherever the archive is imported. The
  password passes the same strength gate a vault's master password does, in the
  core. Only Remoter opens the file, and only with that password. Selection is
  `remoter_import::export::archive_selection`; the envelope is
  `remoter_vault::archive`.
- **CSV** is one row per connection in the column set the CSV importer
  documents, with each connection's *effective* values: a port or an account a
  folder sets is written into every row under it, because a spreadsheet row has
  no folder to inherit from. The `password` column is always empty. A route
  through several jump hosts is written as their names joined by `>`, which the
  importer reads back as the same route. A value a spreadsheet would run as a
  formula — one starting `=`, `+`, `-` or `@` — is written behind an apostrophe,
  OWASP's CSV-injection guard, and the importer takes it back off. The file opens
  with a UTF-8 byte-order mark, so Excel reads `ş` and `ü` as themselves.
- **OpenSSH config** is one `Host` block per SSH or SFTP connection, with
  `HostName`, `Port`, `User`, `IdentityFile`, `ProxyJump`, `ConnectTimeout` and
  `ServerAliveInterval` from the effective values. There is no `Host *` block: a
  file of defaults would also apply to every host in whatever config it is
  `Include`d beside. The alias is the connection's name reduced to what a `Host`
  pattern holds literally and `ssh` can select — lowercase, no spaces, accents
  folded — and made unique. An `IdentityFile` line is written only for a
  credential that is a key file *path*; a key stored in the vault is not
  written, as a key or as anything else.
- **JSON** is the tree as the vault stores it: inheritance states, protocol
  settings, custom fields, groups, icons and colours, every value spelled the way
  `remoter-core` serialises it. A credential says which kind of secret it holds
  and nothing of it. References to nodes outside an exported folder are kept, and
  the nodes they point at are listed by id, kind and name alone.

**A loss is never silent.** Whatever a format could not say the way the vault
says it comes back as a note the dialog shows: an RDP connection an OpenSSH
config has no place for, a route whose hop shares its name with another exported
connection — left out, rather than written in a way a re-import would resolve to
the wrong machine — a hop outside the exported folder, a hop's own credential, a
renamed alias, a folder name with a `/` in it.

⏳ **Plaintext secret export does not exist.** When it is built it requires an
explicit, separately confirmed action; the resulting file carries a warning
header, and the export is written to the audit log. This is deliberately made
slightly awkward: a plaintext export of every credential in an estate is the
single most damaging artefact this application can produce.

✅ **Importing an archive** asks for its password on the wizard's secrets step,
opens it before anything is shown, previews its nodes with which of them carry
a secret, and on commit gives every node a new identity — so an archive can go
back into the very vault it came from — with every reference among them
following, the archive's top level under the chosen folder, and anything they
point at that neither came with them nor exists in the vault turned into a
tombstone naming what is missing. Each secret is then sealed under the
destination vault's key, and only into a field its node's kind holds. See
`remoter_import::native`.

## Round-tripping — ◐ archive, CSV and OpenSSH config

Export followed by import must reproduce the original exactly, including
inheritance states, custom fields, tags and protocol settings that the running
version does not itself understand. A round-trip property test is to enforce
this, because it is the guarantee that makes "you are not locked in" more than a
slogan.

✅ What is tested today is the round trip each flat format can make: an estate
exported as CSV and read back by the CSV importer gives connections with the
same folder path, protocol, host, port, account, domain, route, description and
tags; one exported as an OpenSSH config and read back gives the same hosts,
ports, accounts, key file references, timeouts and multi-hop routes; and a
property test sends arbitrary descriptions — delimiters, quotes, newlines,
formula characters, apostrophes in front of them — through the CSV and back.
These are in `crates/remoter-import/src/export/tests.rs`.

✅ The archive goes further, because it carries nodes rather than values: a
folder exported from one vault with a password credential and imported into
another arrives with the same connection and the same password, readable only
under the new vault's key (`an_archive_moves_a_folder_and_its_passwords_into_another_vault`
in `crates/remoter-ipc/src/import.rs`), and a selection put down on its own
resolves every connection the way it resolved in place
(`crates/remoter-import/src/export/tests.rs`, `crates/remoter-core/tests/transplant.rs`).

⏳ A property test over arbitrary trees for the archive is not written, and the
lossless round trip for the JSON needs something to read the JSON back. The three property tests
of the kind this section asks for cover inheritance resolution, moves and the
importers — see
[testing-strategy.md](../development/testing-strategy.md#property-tests).
