# Import and Export

Migration is the highest-leverage feature for adoption: an administrator with
four hundred connections in mRemoteNG will not retype them, and no amount of
better design will overcome that.

It is also the largest hostile-input surface in the application. Every parser
here reads files that may be crafted or corrupted, so every parser is fuzzed and
none of them touches the vault until the user confirms a preview.

## Supported sources

| Source | Format | Secrets | Milestone |
|---|---|---|---|
| **mRemoteNG** | `confCons.xml` | ✅ with the file password | v0.5 |
| **Royal TS / Royal TSX** | `.rtsz`, `.rtsx` | ✅ with the document password | v0.5 |
| **PuTTY** | Registry (Windows), `~/.putty/sessions` (Unix) | Keys only | v0.5 |
| **OpenSSH** | `~/.ssh/config` | Key references | v0.5 |
| **Remote Desktop Connection Manager** | `.rdg` | ✅ where not DPAPI-bound | v1.0 |
| **Windows RDP** | `.rdp` files | — | v1.0 |
| **Termius** | JSON export | ✅ | v1.1 |
| **SecureCRT** | Session folder | Partial | v1.1 |
| **Devolutions RDM** | XML export | ✅ | v1.1 |
| **Generic** | CSV, JSON | Depends | v0.5 |

### mRemoteNG

The most important target, and the best documented. `confCons.xml` stores a tree
of `Node` elements carrying `Hostname`, `Protocol`, `Port`, `Username`,
`Domain`, `Password` and a large set of protocol options.

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

### Royal TS

`.rtsz` is a compressed XML document; `.rtsx` is its uncompressed form.
Connections, folders, credential objects and the credential *links* between them
all map cleanly onto Remoter's model, including Royal TS's own inheritance.

### PuTTY

On Windows, sessions live in the registry under
`HKCU\Software\SimonTatham\PuTTY\Sessions`; KiTTY uses
`HKCU\Software\9bis.com\KiTTY`. On Unix, `~/.putty/sessions`. Remoter reads
both, and imports `.ppk` private keys (v2 and v3), decrypting them with a
passphrase if one is supplied.

PuTTY stores no session passwords, so only key material comes across.

### OpenSSH config

`~/.ssh/config` is parsed properly rather than line-by-line: `Host` and `Match`
blocks, `Include` directives, wildcards, and `ProxyJump`/`ProxyCommand`.

`ProxyJump` maps directly onto Remoter's gateway chains, which is the most
satisfying part of this importer — an existing bastion setup arrives fully
configured. `ProxyCommand` cannot always be mapped; where it cannot, the command
is preserved in a custom field and flagged in the report rather than dropped.

`known_hosts` is imported into the vault's trust store, with each entry marked
as `accepted_by: import` so it is distinguishable from keys the user personally
verified.

## The import flow

```
1  Choose source        auto-detected from the file, confirmable
2  Supply secrets       file password, key passphrases, registry access
3  Parse                in a sandboxed parser; nothing written yet
4  Preview              the full tree as it will be created, with a report
5  Resolve conflicts    per-item: skip, replace, keep both, merge
6  Choose destination   the vault folder to import into
7  Commit               one transaction; all or nothing
8  Report               what came in, what was dropped, what needs attention
```

Nothing touches the vault before step 7. The preview is the whole point: a user
importing four hundred connections needs to see what they are about to get.

The report names what could not be mapped rather than silently discarding it.
Unmappable settings are preserved verbatim in `custom_fields`, so nothing is
lost even when it cannot be interpreted.

## Security of importers

Import parsers are the classic weak point of connection managers — they read
files that colleagues share, that come from old backups, and that may be
deliberately crafted.

| Risk | Control |
|---|---|
| XXE / entity expansion | External entities and DTDs disabled in every XML parser |
| Zip slip | Archive entries with absolute paths, `..` segments or symlinks rejected |
| Decompression bombs | Hard cap on decompressed size and entry count |
| Memory exhaustion | Streaming parse with bounded buffers; documents over a size limit refused |
| Malformed input | Every parser has a `cargo-fuzz` target and a corpus of real files |
| Credential misuse | Imported credentials carry a `Purpose` restriction matching their source protocol |

Imported passwords are written straight into the vault's encrypted fields.
Plaintext never touches disk, and no temporary decrypted copy is created.

## Export

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

## Round-tripping

Export followed by import must reproduce the original exactly, including
inheritance states, custom fields, tags and protocol settings that the running
version does not itself understand. A round-trip property test enforces this,
because it is the guarantee that makes "you are not locked in" more than a
slogan.
