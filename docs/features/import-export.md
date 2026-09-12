# Import and Export

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
converted rather than refused. Nothing is guessed: the declared `encoding` in
the XML declaration is content, and a heuristic over byte frequencies would make
a file's encoding depend on what its hostnames happen to be.

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
| Malformed input | `cargo-fuzz` targets for all three shipped importers — `import_csv`, `import_mremoteng`, `import_sshconfig` | ✅ |
| Credential misuse | Imported credentials carry a `Purpose` restriction matching their source protocol | ✅ |
| Zip slip | Archive entries with absolute paths, `..` segments or symlinks rejected | ⏳ — no importer reads an archive yet; this is for Royal TS |
| Decompression bombs | Hard cap on decompressed size and entry count | ⏳ — same |

Imported passwords are written straight into the vault's encrypted fields.
Plaintext never touches disk, and no temporary decrypted copy is created.

## Export — ⏳ not built

**Nothing exports.** There is no export command in `remoter-ipc`, no archive
writer and no serialiser for any of the formats below. The only thing that
leaves the vault as a file today is the audit log, as JSON or CSV, and the
recovery sheet written at vault creation.

This is the single largest gap between this document and the software, and it
matters more than most: "you are not locked in" is a promise the README makes
and the code does not yet keep.

| Format | Secrets | Use |
|---|---|---|
| **Remoter archive** (`.rmtr`) | Encrypted with a password you set | Backup, sharing a subtree with a colleague |
| **Remoter archive, structure only** | Excluded | Sharing a topology without credentials |
| **JSON** | Excluded by default | Scripting, version control, review |
| **CSV** | Excluded by default | Spreadsheets, inventory |
| **`~/.ssh/config` fragment** | References only | Using the same hosts from the command line |

Exporting secrets in plaintext requires an explicit, separately confirmed
action; the resulting file carries a warning header, and the export is written
to the audit log. This is deliberately made slightly awkward: a plaintext export
of every credential in an estate is the single most damaging artefact this
application can produce.

The `.rmtr` archive uses the same envelope construction as the vault
([vault-format.md](../security/vault-format.md)) with a single password slot, so
there is one cryptographic design to review rather than two.

## Round-tripping — ⏳ blocked on export

Export followed by import must reproduce the original exactly, including
inheritance states, custom fields, tags and protocol settings that the running
version does not itself understand. A round-trip property test enforces this,
because it is the guarantee that makes "you are not locked in" more than a
slogan.
