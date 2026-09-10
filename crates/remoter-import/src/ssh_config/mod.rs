//! OpenSSH's `ssh_config`.
//!
//! Parsed the way `ssh` parses it rather than line by line: `Host` and `Match`
//! blocks, `Include` directives, wildcard patterns, and first-match-wins
//! resolution across every block that matches a host.
//!
//! ## What makes this importer worth having
//!
//! `ProxyJump` maps directly onto [`GatewayChain`]. An administrator whose
//! bastion setup is already described in `~/.ssh/config` gets it back as
//! configured gateway chains rather than as a note to set them up again, and
//! `ProxyJump a,b,c` becomes three hops in the order `ssh` would traverse them.
//! Where a jump target is itself a `Host` block in the file, the chain
//! references that connection node, so editing the bastion once changes every
//! route through it — which is the property `docs/architecture/data-model.md`
//! gives as the reason hops are node references and not copied hostnames.
//!
//! ## Inheritance
//!
//! A `Host *` block is what an ssh_config uses for "everything, unless
//! overridden", which is what a Remoter folder is. So one becomes the other:
//! the block's options go on a folder, every imported connection becomes a
//! child of it, and a connection whose value came only from that block leaves
//! its own field [`Inherited::Inherit`]. Options from a narrower block are
//! [`Inherited::Explicit`] on the connection, because `ssh` would apply them to
//! that host and not to its neighbours.
//!
//! ## What cannot be mapped
//!
//! `Match` blocks are read and reported, not applied. Their conditions —
//! `Match exec`, `Match originalhost`, `Match final` — are evaluated by `ssh`
//! against things an importer cannot know: which user is running, which command
//! is being run, whether a first connection attempt failed. Applying them
//! anyway would produce connections that differ from what `ssh` does, which is
//! worse than saying so.
//!
//! A `ProxyCommand` that is one of the two bastion idioms — `ssh -W %h:%p host`
//! and `ssh host nc %h %p` — becomes a gateway chain. Anything else is an
//! arbitrary program and is preserved verbatim in `custom_fields` under
//! `openssh.proxycommand`, and flagged, rather than dropped.

mod files;
mod lexer;
mod pattern;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use remoter_core::{
    ConnectionProps, FolderProps, GatewayChain, GatewayHop, Inherited, NodeId, ProtocolId,
    SecretKind, validate_host,
};

pub use files::{ConfigFiles, MemoryConfigFiles, OsConfigFiles};

use crate::error::ImportError;
use crate::limits::Limits;
use crate::mapping::{CredentialPool, clean_name, custom_key, parse_port, preserve};
use crate::preview::{ImportPreview, PreviewBuilder, PreviewKind, PreviewNode, PreviewSecret};
use crate::report::{Finding, SkipReason, SourceFormat};
use crate::xml::as_text;

use lexer::Directive;

/// Keywords whose value accumulates rather than being taken first-wins.
const MULTI_VALUED: &[&str] = &[
    "identityfile",
    "certificatefile",
    "localforward",
    "remoteforward",
    "dynamicforward",
    "setenv",
    "sendenv",
    "permitremoteopen",
    "userknownhostsfile",
    "globalknownhostsfile",
];

/// Keywords the mapping consumes itself.
const MAPPED: &[&str] = &[
    "hostname",
    "port",
    "user",
    "connecttimeout",
    "serveraliveinterval",
    "proxyjump",
    "proxycommand",
    "identityfile",
    "host",
    "match",
    "include",
];

/// The name of the folder a `Host *` block becomes.
const DEFAULTS_FOLDER: &str = "ssh_config defaults";

/// The name of the folder synthesised jump hosts go into.
const JUMP_FOLDER: &str = "Jump hosts";

/// Parses a config that has no `Include` directives to follow.
///
/// An `Include` in this form is reported rather than followed: nothing is read
/// from the filesystem, which is what makes this the entry point a fuzz target
/// can call.
///
/// # Errors
///
/// Any [`ImportError`]. Per-host problems are reported, not raised.
pub fn parse(bytes: &[u8], limits: &Limits) -> Result<ImportPreview, ImportError> {
    let text = as_text(bytes, limits)?;
    let directives = lexer::tokenise(text, limits)?;
    build(directives, limits)
}

/// Parses a config, following its `Include` directives through `files`.
///
/// # Errors
///
/// Any [`ImportError`], including [`ImportError::ReadFailed`] for a file an
/// `Include` names that cannot be read and
/// [`ImportError::IncludeTooDeep`] for a chain that nests too far.
pub fn parse_files(
    entry: &Path,
    files: &dyn ConfigFiles,
    limits: &Limits,
) -> Result<ImportPreview, ImportError> {
    let mut directives = Vec::new();
    let mut budget = limits.max_included_files;
    load(entry, files, limits, 0, &mut budget, &mut directives)?;
    build(directives, limits)
}

/// Reads one file and splices in everything its `Include` directives name.
///
/// Splicing in place rather than appending is what makes an `Include` inside a
/// `Host` block behave the way `ssh` makes it behave: the included options
/// belong to the block the directive appeared in.
fn load(
    path: &Path,
    files: &dyn ConfigFiles,
    limits: &Limits,
    depth: usize,
    budget: &mut usize,
    out: &mut Vec<Directive>,
) -> Result<(), ImportError> {
    if depth > limits.max_include_depth {
        return Err(ImportError::IncludeTooDeep {
            limit: limits.max_include_depth,
        });
    }
    if *budget == 0 {
        return Err(ImportError::TooManyItems {
            limit: limits.max_included_files,
            unit: "included files",
        });
    }
    *budget -= 1;

    let bytes = files.read(path)?;
    let text = as_text(&bytes, limits)?;
    for directive in lexer::tokenise(text, limits)? {
        if directive.keyword != "include" {
            if out.len() >= limits.max_items {
                return Err(ImportError::TooManyItems {
                    limit: limits.max_items,
                    unit: "lines",
                });
            }
            out.push(directive);
            continue;
        }
        for argument in &directive.arguments {
            let resolved = files::resolve(argument, files);
            for candidate in files.expand(&resolved) {
                load(&candidate, files, limits, depth + 1, budget, out)?;
            }
        }
    }
    Ok(())
}

/// What a block applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Selector {
    /// A `Host` block's pattern list.
    Host(Vec<String>),
    /// A `Match` block's criteria, as written.
    Match(String),
}

/// A run of directives under one selector.
#[derive(Debug, Clone)]
struct Block {
    selector: Selector,
    directives: Vec<Directive>,
}

impl Block {
    /// Whether this is the universal block: `Host *` and nothing else.
    fn is_defaults(&self) -> bool {
        matches!(&self.selector, Selector::Host(patterns) if patterns.as_slice() == ["*"])
    }
}

/// Groups directives into blocks.
///
/// Directives before the first `Host` or `Match` apply to every host, which is
/// what `Host *` means, so they start life in exactly that block.
fn group(directives: Vec<Directive>) -> Vec<Block> {
    let mut blocks = vec![Block {
        selector: Selector::Host(vec!["*".to_owned()]),
        directives: Vec::new(),
    }];
    for directive in directives {
        match directive.keyword.as_str() {
            "host" => blocks.push(Block {
                selector: Selector::Host(
                    pattern::split(&directive.arguments)
                        .map(str::to_owned)
                        .collect(),
                ),
                directives: Vec::new(),
            }),
            "match" => blocks.push(Block {
                selector: Selector::Match(directive.value()),
                directives: Vec::new(),
            }),
            _ => {
                if let Some(block) = blocks.last_mut() {
                    block.directives.push(directive);
                }
            }
        }
    }
    // The leading implicit block is only real if something was written before
    // the first `Host`.
    if blocks
        .first()
        .is_some_and(|block| block.directives.is_empty())
    {
        blocks.remove(0);
    }
    blocks
}

/// The options that apply to one host, and which block supplied each.
#[derive(Debug, Default)]
struct Effective {
    /// keyword → (value, index of the block that supplied it).
    single: BTreeMap<String, (String, usize)>,
    /// keyword → values, in the order they were written.
    multi: BTreeMap<String, (Vec<String>, usize)>,
}

impl Effective {
    fn get(&self, keyword: &str) -> Option<&str> {
        self.single.get(keyword).map(|(value, _)| value.as_str())
    }

    /// Whether the value for `keyword` came from the defaults block, which is
    /// what decides `Inherit` against `Explicit`.
    fn supplied_by_defaults(&self, keyword: &str, defaults: Option<usize>) -> bool {
        let Some(defaults) = defaults else {
            return false;
        };
        self.single
            .get(keyword)
            .is_some_and(|(_, block)| *block == defaults)
            || self
                .multi
                .get(keyword)
                .is_some_and(|(_, block)| *block == defaults)
    }
}

/// Resolves the options that apply to `alias`, first match wins.
fn effective(blocks: &[Block], alias: &str) -> Effective {
    let mut out = Effective::default();
    for (index, block) in blocks.iter().enumerate() {
        let Selector::Host(patterns) = &block.selector else {
            // A `Match` block's conditions cannot be evaluated here; see the
            // module comment.
            continue;
        };
        if !pattern::matches_list(patterns.iter().map(String::as_str), alias) {
            continue;
        }
        for directive in &block.directives {
            if MULTI_VALUED.contains(&directive.keyword.as_str()) {
                let entry = out
                    .multi
                    .entry(directive.keyword.clone())
                    .or_insert_with(|| (Vec::new(), index));
                entry.0.push(directive.value());
            } else {
                out.single
                    .entry(directive.keyword.clone())
                    .or_insert_with(|| (directive.value(), index));
            }
        }
    }
    out
}

/// A gateway that has to wait until every host in the file has a node.
struct PendingGateway {
    connection: NodeId,
    connection_name: String,
    /// The jump specifications, in the order `ssh` traverses them.
    targets: Vec<JumpTarget>,
}

/// One `[user@]host[:port]` from a `ProxyJump`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct JumpTarget {
    user: Option<String>,
    host: String,
    port: Option<u16>,
}

/// Builds the preview from a flattened, grouped config.
fn build(directives: Vec<Directive>, limits: &Limits) -> Result<ImportPreview, ImportError> {
    let blocks = group(directives);
    let defaults = blocks.iter().position(Block::is_defaults);
    let mut builder = PreviewBuilder::new(SourceFormat::OpenSshConfig, *limits);
    let mut credentials = CredentialPool::new("Imported credentials");

    for block in &blocks {
        if let Selector::Match(criteria) = &block.selector {
            builder.report_mut().counts_mut().skipped += 1;
            builder.report_mut().push(
                limits,
                Finding::MatchBlockNotApplied {
                    criteria: clean_name(criteria),
                    options: block.directives.len(),
                },
            );
        }
    }

    // The defaults block becomes a folder, so that a value it supplies is
    // stored once and inherited rather than copied onto every connection.
    let defaults_folder = match defaults {
        Some(index) => Some(defaults_folder(
            &mut builder,
            &mut credentials,
            &blocks[index],
            limits,
        )?),
        None => None,
    };

    let aliases = literal_aliases(&blocks);
    let mut by_name: HashMap<String, NodeId> = HashMap::new();
    let mut pending: Vec<PendingGateway> = Vec::new();
    let mut sort = 0i64;

    for alias in &aliases {
        let options = effective(&blocks, alias);
        let host = resolve_hostname(&options, alias);
        if validate_host(&host).is_err() {
            builder.report_mut().counts_mut().skipped += 1;
            builder.report_mut().push(
                limits,
                Finding::SkippedItem {
                    item: clean_name(alias),
                    reason: SkipReason::UnusableHost,
                },
            );
            continue;
        }

        let mut props = ConnectionProps::new("ssh", &host)?;
        props.port = inherited(
            options.get("port").and_then(parse_port),
            options.supplied_by_defaults("port", defaults),
        );
        props.connect_timeout_ms = inherited(
            options
                .get("connecttimeout")
                .and_then(|value| value.trim().parse::<u32>().ok())
                .filter(|seconds| *seconds > 0)
                .map(|seconds| seconds.saturating_mul(1000)),
            options.supplied_by_defaults("connecttimeout", defaults),
        );
        props.keepalive_secs = inherited(
            options
                .get("serveraliveinterval")
                .and_then(|value| value.trim().parse::<u32>().ok())
                .filter(|seconds| *seconds > 0),
            options.supplied_by_defaults("serveraliveinterval", defaults),
        );
        props.credential =
            connection_credential(&mut builder, &mut credentials, &options, alias, defaults)?;

        let id = NodeId::new();
        let mut node = PreviewNode::new(id, clean_name(alias), PreviewKind::Connection(props))
            .under(defaults_folder, sort);
        sort += 1;

        let targets = gateway_targets(&mut builder, &mut node, &options, alias, defaults, limits);
        if !targets.is_empty() {
            pending.push(PendingGateway {
                connection: id,
                connection_name: clean_name(alias),
                targets,
            });
        }

        preserve_rest(&mut builder, &mut node, &options, alias, defaults, limits);
        builder.push(node)?;
        by_name.insert(alias.clone(), id);
    }

    report_pattern_blocks(&mut builder, &blocks, defaults, &aliases, limits);
    resolve_gateways(&mut builder, pending, &by_name, limits)?;
    credentials.finish(&mut builder);
    Ok(builder.finish())
}

/// Every literal host pattern in the file, in order, without repeats.
fn literal_aliases(blocks: &[Block]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for block in blocks {
        let Selector::Host(patterns) = &block.selector else {
            continue;
        };
        for candidate in patterns {
            if pattern::is_literal(candidate) && seen.insert(candidate.clone()) {
                out.push(candidate.clone());
            }
        }
    }
    out
}

/// `HostName` with the `%h` token expanded, or the alias when there is none.
fn resolve_hostname(options: &Effective, alias: &str) -> String {
    options
        .get("hostname")
        .map_or_else(|| alias.to_owned(), |name| name.replace("%h", alias))
}

/// A value that came from the defaults block is inherited from the folder that
/// block became; anything else is set on the node itself.
fn inherited<T>(value: Option<T>, from_defaults: bool) -> Inherited<T> {
    match value {
        Some(value) if !from_defaults => Inherited::Explicit(value),
        _ => Inherited::Inherit,
    }
}

/// Builds the folder a `Host *` block becomes.
fn defaults_folder(
    builder: &mut PreviewBuilder,
    credentials: &mut CredentialPool,
    block: &Block,
    limits: &Limits,
) -> Result<NodeId, ImportError> {
    let mut options = Effective::default();
    for (index, directive) in block.directives.iter().enumerate() {
        if MULTI_VALUED.contains(&directive.keyword.as_str()) {
            options
                .multi
                .entry(directive.keyword.clone())
                .or_insert_with(|| (Vec::new(), index))
                .0
                .push(directive.value());
        } else {
            options
                .single
                .entry(directive.keyword.clone())
                .or_insert_with(|| (directive.value(), index));
        }
    }

    let mut props = FolderProps {
        port: options
            .get("port")
            .and_then(parse_port)
            .map_or(Inherited::Inherit, Inherited::Explicit),
        connect_timeout_ms: options
            .get("connecttimeout")
            .and_then(|value| value.trim().parse::<u32>().ok())
            .filter(|seconds| *seconds > 0)
            .map(|seconds| seconds.saturating_mul(1000))
            .map_or(Inherited::Inherit, Inherited::Explicit),
        keepalive_secs: options
            .get("serveraliveinterval")
            .and_then(|value| value.trim().parse::<u32>().ok())
            .filter(|seconds| *seconds > 0)
            .map_or(Inherited::Inherit, Inherited::Explicit),
        ..FolderProps::default()
    };
    props.credential = match credential(builder, credentials, &options, DEFAULTS_FOLDER)? {
        Some(reference) => Inherited::Explicit(reference),
        None => Inherited::Inherit,
    };

    let mut node = PreviewNode::new(
        NodeId::new(),
        DEFAULTS_FOLDER.to_owned(),
        PreviewKind::Folder(props),
    );
    preserve_options(&mut node, &options, limits.max_custom_fields);
    builder.push(node)
}

/// A connection's credential, left inherited when it would only repeat the
/// folder's.
fn connection_credential(
    builder: &mut PreviewBuilder,
    credentials: &mut CredentialPool,
    options: &Effective,
    alias: &str,
    defaults: Option<usize>,
) -> Result<Inherited<remoter_core::CredentialRef>, ImportError> {
    // Nothing this connection carries that the defaults folder does not
    // already carry: the folder's credential is the one to use.
    let user_inherited =
        options.get("user").is_none() || options.supplied_by_defaults("user", defaults);
    let identity_inherited = !options.multi.contains_key("identityfile")
        || options.supplied_by_defaults("identityfile", defaults);
    if user_inherited && identity_inherited {
        return Ok(Inherited::Inherit);
    }
    // A `User` from the defaults block with an `IdentityFile` from a narrower
    // one still has to become a credential of its own: the pair is one field
    // in Remoter and cannot be half-inherited.
    match credential(builder, credentials, options, alias)? {
        Some(reference) => Ok(Inherited::Explicit(reference)),
        None => Ok(Inherited::Inherit),
    }
}

/// Interns the credential an ssh_config describes.
///
/// `ssh_config` never holds a password. What it holds is a username and,
/// usually, a path to a key file — a reference, not material. The key stays on
/// disk and unread: importing it would put a private key into the vault that
/// the user did not ask to move, and `docs/features/import-export.md` lists
/// this source as "key references" for that reason.
fn credential(
    builder: &mut PreviewBuilder,
    credentials: &mut CredentialPool,
    options: &Effective,
    name: &str,
) -> Result<Option<remoter_core::CredentialRef>, ImportError> {
    let user = options.get("user").unwrap_or("").trim().to_owned();
    let identity = options
        .multi
        .get("identityfile")
        .and_then(|(paths, _)| paths.first())
        .map(|path| path.trim().to_owned())
        .filter(|path| !path.is_empty());

    if user.is_empty() && identity.is_none() {
        return Ok(None);
    }

    let secret = match identity {
        Some(path) => PreviewSecret::Unsealed(SecretKind::External {
            provider: "openssh-identity-file".to_owned(),
            reference: path,
        }),
        // No key named, so the agent is what will answer. That is also the
        // arrangement `docs/architecture/data-model.md` recommends: the private
        // key never enters this process.
        None => PreviewSecret::Unsealed(SecretKind::Agent {
            comment_filter: None,
        }),
    };

    let ssh = ProtocolId::new("ssh")?;
    credentials
        .intern(builder, name, user, None, secret, vec![ssh])
        .map(Some)
}

/// Reads `ProxyJump` and `ProxyCommand` into a list of hops.
fn gateway_targets(
    builder: &mut PreviewBuilder,
    node: &mut PreviewNode,
    options: &Effective,
    alias: &str,
    defaults: Option<usize>,
    limits: &Limits,
) -> Vec<JumpTarget> {
    if let Some(jump) = options.get("proxyjump") {
        if jump.trim().eq_ignore_ascii_case("none") {
            set_direct(node);
            return Vec::new();
        }
        if options.supplied_by_defaults("proxyjump", defaults) {
            // A jump host set for every host belongs on the folder, not on each
            // connection. Left inherited; the folder carries it.
            return Vec::new();
        }
        let targets: Vec<JumpTarget> = jump.split(',').filter_map(parse_jump).collect();
        if !targets.is_empty() {
            return targets;
        }
    }

    let Some(command) = options.get("proxycommand") else {
        return Vec::new();
    };
    if command.trim().eq_ignore_ascii_case("none") {
        set_direct(node);
        return Vec::new();
    }
    if let Some(target) = proxy_command_target(command) {
        return vec![target];
    }

    // Not one of the recognised idioms: an arbitrary program. Kept verbatim
    // rather than dropped, and named on the report.
    if let Some(key) = custom_key("openssh", "proxycommand") {
        preserve(node, key, command.to_owned(), limits.max_custom_fields);
    }
    builder.report_mut().push(
        limits,
        Finding::UnmappedProxyCommand {
            item: clean_name(alias),
            command: clean_name(command),
        },
    );
    Vec::new()
}

/// `ProxyJump none` and `ProxyCommand none` mean "direct, whatever the parent
/// says", which is what pinning the type default expresses.
fn set_direct(node: &mut PreviewNode) {
    if let PreviewKind::Connection(props) = &mut node.kind {
        props.gateway = Inherited::Default;
    }
}

/// Parses `[user@]host[:port]`, accepting a bracketed IPv6 literal.
fn parse_jump(spec: &str) -> Option<JumpTarget> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    let (user, rest) = match spec.rsplit_once('@') {
        Some((user, rest)) if !user.is_empty() && !rest.is_empty() => (Some(user.to_owned()), rest),
        _ => (None, spec),
    };

    let (host, port) = if let Some(closing) = rest.find(']') {
        // `[::1]:2222` — the colon that matters is the one after the bracket.
        let (address, tail) = rest.split_at(closing + 1);
        (address, tail.strip_prefix(':'))
    } else {
        match rest.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (rest, None),
        }
    };

    if host.is_empty() {
        return None;
    }
    Some(JumpTarget {
        user,
        host: host.to_owned(),
        port: port.and_then(parse_port),
    })
}

/// Recognises the two `ProxyCommand` forms that are really a jump host.
///
/// `ssh -W %h:%p bastion` and `ssh bastion nc %h %p` are the idioms that
/// predate `ProxyJump` and are still in every second config. Anything else is
/// an arbitrary program and is not guessed at.
fn proxy_command_target(command: &str) -> Option<JumpTarget> {
    /// Short options that consume the token after them.
    const WITH_ARGUMENT: &[char] = &[
        'W', 'o', 'p', 'i', 'l', 'b', 'c', 'D', 'e', 'F', 'I', 'J', 'L', 'm', 'O', 'Q', 'R', 'S',
        'w',
    ];

    let mut tokens = command.split_whitespace();
    let program = tokens.next()?;
    let program = program.rsplit(['/', '\\']).next().unwrap_or(program);
    if program != "ssh" {
        return None;
    }

    let mut is_tunnel = false;
    let mut destination: Option<&str> = None;
    let mut skip_next = false;
    let mut rest = Vec::new();
    for token in tokens {
        if skip_next {
            skip_next = false;
            if token == "%h:%p" {
                is_tunnel = true;
            }
            continue;
        }
        if let Some(flags) = token.strip_prefix('-') {
            if flags.contains('W') {
                is_tunnel = true;
            }
            if flags
                .chars()
                .last()
                .is_some_and(|f| WITH_ARGUMENT.contains(&f))
            {
                skip_next = true;
            }
            continue;
        }
        if destination.is_none() {
            destination = Some(token);
        } else {
            rest.push(token);
        }
    }

    // The netcat idiom: the tokens after the destination are a command that
    // pipes to the real target.
    if matches!(rest.first().copied(), Some("nc" | "netcat"))
        && rest.iter().any(|token| token.contains("%h"))
    {
        is_tunnel = true;
    }

    is_tunnel
        .then(|| destination.and_then(parse_jump))
        .flatten()
}

/// Turns the pending jump targets into gateway chains.
///
/// A target that names a host defined in the file becomes a reference to that
/// connection node. A target that names something the file does not define gets
/// a connection node of its own, because a hop has to be a node — and because a
/// bastion nobody wrote a `Host` block for is still a machine the user connects
/// to.
fn resolve_gateways(
    builder: &mut PreviewBuilder,
    pending: Vec<PendingGateway>,
    by_name: &HashMap<String, NodeId>,
    limits: &Limits,
) -> Result<(), ImportError> {
    let mut synthesised: HashMap<String, NodeId> = HashMap::new();
    let mut jump_folder: Option<NodeId> = None;
    let mut jump_sort = 0i64;

    for entry in pending {
        let mut hops: Vec<GatewayHop> = Vec::new();
        // A chain that visits the same jump host twice is the same chain, and
        // the domain model rejects it as a loop. `ProxyJump a,a` is a typo, not
        // a longer route.
        let push = |hops: &mut Vec<GatewayHop>, node: NodeId| {
            if !hops.iter().any(|hop| hop.node.id() == node) {
                hops.push(GatewayHop::new(node));
            }
        };
        for target in &entry.targets {
            if hops.len() >= remoter_core::MAX_GATEWAY_HOPS {
                builder.report_mut().push(
                    limits,
                    Finding::GatewayUnresolved {
                        item: entry.connection_name.clone(),
                        target: clean_name(&target.host),
                    },
                );
                continue;
            }
            if let Some(existing) = by_name.get(&target.host) {
                if *existing != entry.connection {
                    push(&mut hops, *existing);
                }
                continue;
            }
            if let Some(existing) = synthesised.get(&target.host) {
                push(&mut hops, *existing);
                continue;
            }
            if validate_host(&target.host).is_err() {
                builder.report_mut().push(
                    limits,
                    Finding::GatewayUnresolved {
                        item: entry.connection_name.clone(),
                        target: clean_name(&target.host),
                    },
                );
                continue;
            }

            let folder = match jump_folder {
                Some(folder) => folder,
                None => {
                    let node = PreviewNode::new(
                        NodeId::new(),
                        JUMP_FOLDER.to_owned(),
                        PreviewKind::Folder(FolderProps::default()),
                    )
                    .under(None, i64::MAX - 1);
                    let id = builder.push(node)?;
                    jump_folder = Some(id);
                    id
                }
            };

            let mut props = ConnectionProps::new("ssh", &target.host)?;
            props.port = target.port.map_or(Inherited::Inherit, Inherited::Explicit);
            let id = NodeId::new();
            let mut node =
                PreviewNode::new(id, clean_name(&target.host), PreviewKind::Connection(props))
                    .under(Some(folder), jump_sort);
            jump_sort += 1;
            if let Some(user) = &target.user {
                if let Some(key) = custom_key("openssh", "user") {
                    preserve(&mut node, key, user.clone(), limits.max_custom_fields);
                }
            }
            builder.push(node)?;
            synthesised.insert(target.host.clone(), id);
            builder.report_mut().push(
                limits,
                Finding::GatewaySynthesised {
                    item: entry.connection_name.clone(),
                    target: clean_name(&target.host),
                },
            );
            push(&mut hops, id);
        }

        if hops.is_empty() {
            continue;
        }
        let hops_len = hops.len();
        builder.set_gateway(entry.connection, Inherited::Explicit(GatewayChain { hops }));
        builder.report_mut().push(
            limits,
            Finding::GatewayMapped {
                item: entry.connection_name,
                hops: hops_len,
            },
        );
    }
    Ok(())
}

/// Copies the options the mapping did not consume onto a connection, skipping
/// anything the defaults folder already carries.
fn preserve_rest(
    builder: &mut PreviewBuilder,
    node: &mut PreviewNode,
    options: &Effective,
    alias: &str,
    defaults: Option<usize>,
    limits: &Limits,
) {
    let mut kept = 0usize;
    let mut dropped = 0usize;
    for (keyword, (value, block)) in &options.single {
        if MAPPED.contains(&keyword.as_str()) || Some(*block) == defaults {
            continue;
        }
        let Some(key) = custom_key("openssh", keyword) else {
            continue;
        };
        if preserve(node, key, value.clone(), limits.max_custom_fields) {
            kept += 1;
        } else if node.custom_fields.len() >= limits.max_custom_fields {
            dropped += 1;
        }
    }
    for (keyword, (values, block)) in &options.multi {
        if MAPPED.contains(&keyword.as_str()) || Some(*block) == defaults {
            continue;
        }
        let Some(key) = custom_key("openssh", keyword) else {
            continue;
        };
        if preserve(node, key, values.join("\n"), limits.max_custom_fields) {
            kept += 1;
        } else if node.custom_fields.len() >= limits.max_custom_fields {
            dropped += 1;
        }
    }
    // Every identity file after the first: the credential took one, and the
    // rest are still information about how this host is reached.
    if let Some((identities, block)) = options.multi.get("identityfile") {
        if identities.len() > 1 && Some(*block) != defaults {
            if let Some(key) = custom_key("openssh", "identityfile") {
                if preserve(node, key, identities.join("\n"), limits.max_custom_fields) {
                    kept += 1;
                }
            }
        }
    }
    if kept > 0 {
        builder.report_mut().push(
            limits,
            Finding::SettingsPreserved {
                item: clean_name(alias),
                count: kept,
            },
        );
    }
    if dropped > 0 {
        builder.report_mut().push(
            limits,
            Finding::LimitReached {
                limit: "custom_fields".to_owned(),
            },
        );
    }
}

/// Copies a block's options onto the folder it became.
fn preserve_options(node: &mut PreviewNode, options: &Effective, max_fields: usize) {
    for (keyword, (value, _)) in &options.single {
        if MAPPED.contains(&keyword.as_str()) {
            continue;
        }
        if let Some(key) = custom_key("openssh", keyword) {
            preserve(node, key, value.clone(), max_fields);
        }
    }
    for (keyword, (values, _)) in &options.multi {
        if let Some(key) = custom_key("openssh", keyword) {
            preserve(node, key, values.join("\n"), max_fields);
        }
    }
}

/// Names the wildcard blocks that contributed to a connection, so a user can
/// see that a `Host *.example.com` block was folded in rather than lost.
fn report_pattern_blocks(
    builder: &mut PreviewBuilder,
    blocks: &[Block],
    defaults: Option<usize>,
    aliases: &[String],
    limits: &Limits,
) {
    for (index, block) in blocks.iter().enumerate() {
        let Selector::Host(patterns) = &block.selector else {
            continue;
        };
        if Some(index) == defaults || patterns.iter().all(|p| pattern::is_literal(p)) {
            continue;
        }
        let count = aliases
            .iter()
            .filter(|alias| pattern::matches_list(patterns.iter().map(String::as_str), alias))
            .count();
        builder.report_mut().push(
            limits,
            Finding::PatternBlockApplied {
                pattern: clean_name(&patterns.join(" ")),
                connections: count,
            },
        );
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
