# Tunnelling and Jump Hosts

Reaching machines that are not directly reachable — which, in any serious
network, is most of them.

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

Forwards are defined per connection and can be inherited from a folder. They can
be configured to start automatically with the session or to be toggled manually
from the session panel.

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

Status is live: active or inactive, bytes transferred, current connection count,
and the error if a listener failed to bind (a port already in use is the common
case, and the message says so).

## Persistent tunnels

A tunnel can be defined independently of any session — a "tunnel-only"
connection that establishes forwards and holds them open without a shell.
Useful for a database port you want available all day.

Persistent tunnels support auto-start on vault unlock, auto-reconnect with
exponential backoff, and a health check. They appear in a dedicated panel with
their state.

## SOCKS proxy

Dynamic forwarding runs a SOCKS5 server locally. Common uses:

- Point a browser at it to reach internal web applications
- Route other tools through it with `proxychains` or an application-level proxy
  setting
- Chain it into another Remoter connection: a connection can use a SOCKS proxy
  as its transport, including one Remoter itself provides

CONNECT and UDP ASSOCIATE are supported; BIND is not.

## Proxy support

Independently of SSH tunnelling, a connection can route through:

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

Remoter prefers chains, keeps agent forwarding off by default, and states the
risk inline where it is enabled. When a user configures agent forwarding on a
connection that already has a gateway chain, the editor points out that the
chain probably already does what they wanted.
