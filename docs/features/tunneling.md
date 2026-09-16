# Tunnelling and Jump Hosts

Reaching machines that are not directly reachable — which, in any serious
network, is most of them.

> **What ships.** Local, remote and dynamic forwarding, against a node, with or
> without a shell; the loopback default and its opt-in; the live tunnel list.
> Jump host chains work in the core, are honoured by every protocol, and are
> set in the connection editor or imported from an `ssh_config`'s `ProxyJump`.
> ⏳ Not built: persistent tunnels with auto-start, reconnect and health checks; SOCKS5
> `UDP ASSOCIATE`; and every entry in the *Proxy support* table.

## Jump host chains

A connection can specify an ordered list of hops. Each hop is another connection
node in the tree, reused rather than redefined, with its own credentials and its
own host key verification.

```
  Laptop                bastion.acme.io        jump-eu.internal        db-01.internal
     │                        │                       │                      │
     │  SSH + auth #1         │                       │                      │
     ├───────────────────────▶│                       │                      │
     │  direct-tcpip ─────────┤──── TCP ─────────────▶│                      │
     │  SSH + auth #2 over that channel ─────────────▶│                      │
     │  direct-tcpip ────────────────────────────────┤──── TCP ────────────▶│
     │  target protocol handshake over that channel ────────────────────────▶│
```

**Any protocol can use a chain**, not just SSH. Because the `Protocol` trait
receives an already-connected transport
([ADR-0003](../architecture/decisions/0003-protocol-embedding.md)), an RDP
session through two SSH bastions runs the identical code path as an RDP session
on the LAN. No adapter contains gateway logic.

Chains are inheritable. Set the bastion once on the `Datacentre EU-West` folder
and every connection beneath it routes through it — which is exactly how the
real network is shaped, and why inheritance and tunnelling belong together.

**Limits and validation**: maximum 8 hops; cycles rejected at edit time and
re-validated at connect time; each hop authenticated independently. A failure
names the hop that failed — "could not reach the target through `jump-eu`,
hop 2 of 3" — rather than reporting a generic connection error.

## Port forwarding

| Type | Syntax | Effect |
|---|---|---|
| **Local** | `-L [bind:]port:host:hostport` | A port on this machine forwards to `host:hostport` as seen from the remote |
| **Remote** | `-R [bind:]port:host:hostport` | A port on the remote forwards back to `host:hostport` as seen from here |
| **Dynamic** | `-D [bind:]port` | A SOCKS5 proxy on this machine, routing through the remote |

A forward is opened from the session panel against a node — the same stages a
session runs, ending in a forward instead of a PTY, so a forward does not need a
shell tab to exist. ⏳ Forwards are **not** yet stored on a connection, so they
are not inherited from a folder and none starts automatically; each one is
created for the session and closed with it.

**A tunnel has no tab, so it cannot ask anything.** Without a prompt channel an
unknown host key is refused rather than accepted — a machine that cannot ask a
human has not obtained consent — and the refusal says to open a session to that
node first, which is where the fingerprint can be reviewed.

```
┌─ Port forwards ─────────────────────────────────────────────────┐
│                                                                  │
│  ● Local    127.0.0.1:5432  →  db-01.internal:5432    1.2 MB     │
│  ● Local    127.0.0.1:8080  →  grafana.internal:3000  340 KB     │
│  ○ Dynamic  127.0.0.1:1080     SOCKS5                 inactive   │
│  ● Remote   0.0.0.0:9000    ←  127.0.0.1:9000         exposed !  │
│                                                                  │
│                                            [+ Add forward]       │
└──────────────────────────────────────────────────────────────────┘
```

**Bind address defaults to loopback.** Binding a forward to `0.0.0.0` exposes it
to the local network, and in the remote case exposes a path back into your
machine. It requires an explicit setting and carries the warning badge shown
above.

Status is live to the extent that the listener is either open or gone, and a
bind failure is reported with its reason (a port already in use is the common
case, and the message says so). ⏳ Bytes transferred and the current connection
count are not tracked, so the mock-up above draws two columns that do not exist.

## Persistent tunnels — ◐ partly built

A tunnel **is** already defined independently of any session: `tunnel_open` takes
a node, not a session, so a forward can be held open all day without a shell.
That much works.

⏳ What does not: auto-start on vault unlock, auto-reconnect with exponential
backoff, and health checks. A tunnel whose connection drops is gone, and
reopening it is a manual act.

## SOCKS proxy

Dynamic forwarding runs a SOCKS5 server locally. Common uses:

- Point a browser at it to reach internal web applications
- Route other tools through it with `proxychains` or an application-level proxy
  setting
- Chain it into another Remoter connection: a connection can use a SOCKS proxy
  as its transport, including one Remoter itself provides

Only `CONNECT` is supported. ⏳ `UDP ASSOCIATE` and `BIND` are both parsed —
specifically so that they can be refused with the right SOCKS5 reply rather than
by dropping the connection — and then refused. SSH carries `direct-tcpip` and
`direct-streamlocal` and nothing that carries UDP, so `UDP ASSOCIATE` is not a
missing feature so much as a thing the transport cannot do.

## Proxy support — ⏳ not built

None of this exists. `TransportKind` names `Socks5` and `HttpConnect` so that
the VNC adapter can answer "does my transport encrypt me?" correctly — the
answer for both is *no* — but there is no dialler for either, and no proxy
setting on a connection.

Independently of SSH tunnelling, a connection would route through:

| Proxy | Notes |
|---|---|
| SOCKS5 | With optional username/password authentication |
| SOCKS4 / 4a | Legacy support |
| HTTP CONNECT | With Basic and Digest authentication |
| System proxy | Reads the platform's configured proxy |

Proxy settings are inheritable, so an organisation with a mandatory egress proxy
configures it once at the vault root.

## Interaction with agent forwarding

Agent forwarding and jump hosts are frequently confused. They are different
mechanisms with very different risk profiles:

- **A jump host chain** authenticates each hop separately from the vault. The
  intermediate machines never see credentials for anything beyond themselves.
- **Agent forwarding** exposes your local agent's signing capability to the
  remote machine. Anyone with root on that machine can use your agent to
  impersonate you on every host that key opens, for as long as you are connected.

Remoter prefers chains and keeps agent forwarding off by default, with the risk
stated inline where it is enabled — turning it on raises a session warning the
user sees. ⏳ The editor does not yet point out that a connection with a gateway
chain probably does not need agent forwarding.
