# ADR-0013: Own the RFB handshake, bound the RFB server stream, and negotiate only encodings we can bound

- **Status**: Accepted
- **Date**: 2026-09-11
- **Deciders**: Remoter maintainers

## Context

`CLAUDE.md` §8 pins `vnc-rs` 0.5 and says it must not be swapped without an ADR.
Three independent reviews of `crates/remoter-proto-vnc` found defects with one
root: **`vnc-rs` is trusted with input from a server that
`docs/security/threat-model.md` assumes may be hostile** (T3, an attacker on the
path; T4, a compromised host). SSH already has the opposite posture —
`remoter-proto/src/hostkey.rs` and `remoter-proto-ssh/src/hostkey.rs` make the
*client* decide what it will accept and then say what it accepted. The graphical
protocols were meant to copy that trust model and did not.

What the library actually does, read from `vnc-rs` 0.5.3's source:

1. **The RFB version is a ceiling with no floor.** `VncState::try_start` computes
   `min(ours, theirs)` (RFC 6143 §7.1.1) and applies no lower limit. Any peer can
   answer `RFB 003.003\n` and move the conversation into the 3.3 shape — the one
   in which the *server* chooses the security type and the client has no reply to
   send.
2. **Security type `None` is preferred.** The very next branch is
   `if security_types.contains(&SecurityType::None)`. A server that offers `None`
   gets an unauthenticated session, the `auth_method` future is never polled, and
   **the configured password is never read**. Nothing tells the user: the
   adapter's warning was derived from the *offered* list and the library's
   preference, so it described the outcome by reproducing the bug.
3. **`AuthResult::from(u32)` is `std::mem::transmute`** into a two-variant
   `#[repr(u32)]` enum. RFC 6143 §7.2.2's `SecurityResult` is a `U32` with two
   defined values; a server sending `2` is **remote undefined behaviour**, and
   the branch it produces is the one that decides whether authentication *failed*.
4. **Lengths from the wire size allocations before the bytes arrive.**
   `ServerInit`'s `U32` name-length, `ServerCutText`'s `U32` length, each
   rectangle's `width * height * bytes-per-pixel`, and the Cursor
   pseudo-encoding's size (which is not bounded by the framebuffer, because its
   `x` and `y` are a hot spot rather than a position) all reach
   `Vec::with_capacity` / `vec![0; n]` / `uninit_vec(n)` directly. Two of these —
   the desktop name and the clipboard length — were not in the defect list
   `lib.rs` carried.
5. **ZRLE run lengths are unbounded**, and they are written *inside* the zlib
   stream: a run length is a sequence of `0xff` bytes, accumulated with no
   ceiling, so a few kilobytes of compressed input can ask the decoder to grow a
   buffer to terabytes.

The distinction that had been missed matters more than any individual item.
`lib.rs` said every one of these was containable to a single tab, citing
ADR-0011. That is true of a **panic**: `panic = "unwind"`, each session is its
own `tokio::spawn`ed task, and a panic there ends one tab. It is **not** true of
an allocation failure, which calls `handle_alloc_error` and **aborts the
process** — taking every other session and the unlocked vault with it. Items 4
and 5 are aborts. The comment was wrong, and a wrong containment claim is worse
than no claim, because it is the sentence a reviewer stops at.

Doing nothing means a product in daily use against a production server can be
talked out of authenticating, into undefined behaviour, and into an abort, by a
peer whose hostility the threat model already assumes.

## Options considered

### Option A — perform the handshake ourselves; let `vnc-rs` decode pixels

RFC 6143 §7.1 and §7.2 are short and completely specified. Read the version,
apply a floor as well as a ceiling, read the offered security types, select one
under our own policy, and read the `SecurityResult` word ourselves.

`vnc-rs` cannot be handed a stream with those bytes already consumed — it starts
at the version string — so the library is given a **synthetic** handshake by a
`Transport` shim while the real one has already happened: a fixed
`RFB 003.008\n`, a one-entry security list holding exactly the type that was
really selected, and a synthetic `SecurityResult` of zero.

- **Pros.** Puts defects 1, 2 and 3 in code we own and test. The library's
  floorless `min` has nowhere to go and its `None` preference has nothing to
  prefer. `AuthResult::from` only ever sees `0`, so the transmute becomes
  unreachable rather than merely unlikely. The large, dull work — DES, and pixel
  decoding — stays in the library.
- **Cons.** A byte-exact shim. It must swallow the thirteen bytes the library
  writes in reply (version and selection) and pass the thirty-two bytes of DES
  challenge and response through, because `vnc-rs`'s DES is `pub(crate)` and
  cannot be called directly. Getting the count wrong desynchronises the wire.

### Option B — bound every length taken from the wire before `vnc-rs` acts on it

Parse the server message stream (RFC 6143 §7.6) in the same shim and withhold
every byte until the length governing it has been checked.

- **Pros.** Closes every abort vector in item 4, including the two that were
  undisclosed. Also closes `SetColorMapEntries` (§7.6.2, where the library
  reaches `unimplemented!()`) and a rectangle in an encoding that was never
  promised (which the library folds onto `Raw` and then over-reads).
- **Cons.** Only works if every negotiated encoding is self-delimiting to a
  parser that knows the rectangle's size. Tight is not: its rectangles are
  delimited by a compression control byte, optional filters, palettes and a
  7-bit continuation length, and framing it means reimplementing it. And a
  length written inside a compressed stream — ZRLE's run length — is invisible
  to any parser in front of the library, however tightly the *compressed* length
  is bounded.

### Option C — vendor and patch `vnc-rs`

- **Pros.** Fixes the defects at source, including the ones inside the decoders.
- **Cons.** A permanent fork of 3,300 lines nobody here wrote, with no upstream
  to take fixes from. `CLAUDE.md` §8 prefers a maintained dependency, and a
  vendored copy is the shape that rots quietly.

### Option D — replace `vnc-rs`

- **Pros.** The only option that makes the compressed decoders ours.
- **Cons.** It is the whole of RFB, not the handshake: ZRLE, TRLE, Tight, the
  cursor and copy-rect pseudo-encodings, and a zlib stream held for the life of
  the connection. Not a change to make while the defects above are open.

## Decision

**A plus B, with the encoding set reduced to exactly what B can bound.**

- `crates/remoter-proto-vnc/src/negotiate.rs` performs RFC 6143 §7.1.1 and
  §7.1.2. The version is bracketed by a floor (`rfb_version_min`, new, default
  `3.8`) as well as the existing ceiling (`rfb_version`, default `3.8`). The
  security type is **selected** under one policy, written once, in one pure
  function: *a configured credential means authentication happens* — `None` is
  refused outright when a password is available, whatever the server prefers —
  and *no credential means `None` or nothing*.
- `crates/remoter-proto-vnc/src/gate.rs` is the `Transport` between the socket
  and `vnc-rs`. It replays the synthetic handshake, reads the real
  `SecurityResult` itself and matches it on a plain `u32`, and then parses the
  server message stream, checking `ServerInit`'s framebuffer size and
  name-length, `ServerCutText`'s length, every rectangle's encoding number and
  every rectangle's dimensions against the framebuffer the server declared,
  before any of it reaches the library.
- **Tight, ZRLE and TRLE are no longer negotiated.** `SetEncodings`
  (RFC 6143 §7.5.2) now carries Raw, CopyRect, and the Cursor, DesktopSize and
  LastRect pseudo-encodings, and nothing else. Tight because the gate cannot
  frame it; ZRLE and TRLE because the gate can frame them and still cannot see
  the run length inside the zlib stream, and that run length is an abort.

The reasoning that actually drove the last point: a bound that holds for four of
five vectors is not a guarantee, and this crate's guarantee is the one thing
worth having. Every encoding on the wire must be one the gate can bound, or the
gate is decoration. Compression is worth a great deal; it is not worth a
remotely triggered abort in the process that holds the vault.

The choice is also what makes Option D cheap later. With the handshake and the
framing already ours, replacing `vnc-rs` is a decoder swap rather than a
protocol rewrite.

## Consequences

**Positive.**

- No server response can cause undefined behaviour: the transmute is
  unreachable, because the library is handed a constant.
- No server response can cause an abort: every length the library allocates from
  is checked first, and the encodings whose lengths cannot be checked are not
  promised.
- A configured password is used or the connection fails. There is no third
  outcome, and no silent one.
- The security type and version in force are *reported* rather than inferred, so
  the warnings a user sees describe their session rather than the library's
  preferences.
- Two failure modes that used to be panics — `SetColorMapEntries`, and a
  rectangle in an unpromised encoding — are now named protocol violations with a
  next action.
- The gate can see a `FramebufferUpdate` boundary, which `vnc-rs` gives no event
  for. That is what makes the session's "one outstanding update request" rule
  (RFC 6143 §7.5.3) true rather than aspirational.

**Negative.**

- **Bandwidth.** A desktop over a slow or high-latency link now sends raw
  pixels; CopyRect is the only saving left. This is a real regression for remote
  administration over a WAN, and the honest mitigation today is the one
  `docs/security/transport-security.md` already recommends for a different
  reason: tunnel it, and let SSH compression do what ZRLE was doing.
- **A user-visible setting changed.** `encoding` no longer offers `tight`,
  `zrle` or `trle`. A stored connection carrying one of those values falls back
  to the default and is logged as an unknown value rather than silently mapped,
  because silently mapping it would leave a user believing a compressed session
  had been negotiated.
- **The version floor is a behaviour change.** A genuinely old RFB 3.3 or 3.7
  server now fails to connect until `rfb_version_min` is lowered deliberately.
  That is the point — it is a decision the user makes once rather than one any
  peer makes for them on every connection — but it will look like a regression
  to whoever meets it first.
- **The clipboard capability is now `None`.** `ClipboardSupport` has no
  one-direction value, the session cannot answer `ClipboardOp::Request`, and a
  capability that promises a control the session refuses is a button that fails
  in the user's hand. Pasting into a session still works through
  `ClipboardOp::Offer`; the interface no longer advertises the other direction.
- **The gate is code we now maintain**: an RFB framer, roughly 250 lines, that
  must stay byte-exact. Every encoding added to `crate::encoding` needs a length
  rule beside it, and the framer's final arm refuses anything without one rather
  than guessing.

**Neutral.**

- `HandshakeObserver` and `ObservingTransport` are gone. Watching the handshake
  go past was only ever a way to *describe* a failure; performing it describes
  the same facts and can also prevent one.
- The gate adds one memcpy for the tail of a payload run and none for the rest,
  because when the remaining payload is at least as large as the caller's buffer
  it reads straight into it.

## Revisit if

- `vnc-rs` gains a version floor, a security-type policy, a checked
  `SecurityResult`, and bounds on its decoders' allocations. Then the gate's
  first job becomes redundant and its second becomes belt and braces.
- `remoter-proto`'s `SessionEvent` grows a variant that carries clipboard
  content, or `ClipboardSupport` grows a one-direction value. Either makes
  `capabilities().clipboard` honest at `Text` again.
- The bandwidth cost becomes the dominant complaint. The answer is Option D —
  an RFB decoder we own, with the framing and handshake already written — and
  not re-promising an encoding whose decoder a hostile server can aim at this
  process's allocator.
