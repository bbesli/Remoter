/**
 * Turning the core's findings into sentences.
 *
 * Every branch here says what happened and what it means for the person
 * reading it. Two of them are the reason the report exists at all:
 *
 *   - `default_file_password` — mRemoteNG encrypts with a published default
 *     when no password is set. Someone who believed the file was protected is
 *     entitled to learn that it was not, while they are looking at what came
 *     out of it, not in a changelog later.
 *   - the gateway findings — a `ProxyJump` in an ssh_config becomes a real
 *     gateway chain in the vault. It is the most valuable thing the importer
 *     does and it is completely invisible unless the report says so.
 *
 * Where a setting has no home in the domain model it is kept verbatim in a
 * custom field rather than dropped, and that is said out loud: it is reassuring
 * and it is true.
 */

import type { FindingSeverity, ImportFinding, SkipReason } from "@/lib/ipc";

export interface FindingView {
  severity: FindingSeverity;
  title: string;
  /** The consequence, in plain words. Empty when the title says everything. */
  body: string;
  /** The verbatim scrap the finding came from — a command, a column, a host. */
  code: string | null;
}

const SKIP_REASON: Record<SkipReason, string> = {
  unusable_host: "its host name was not usable",
  unusable_name: "its name was empty or not usable",
  unsupported_kind: "its type has no equivalent here",
  empty: "it was empty",
};

const LIMIT: Record<string, string> = {
  custom_fields: "custom fields",
  findings: "findings",
  nodes: "nodes",
};

export function describeFinding(finding: ImportFinding): FindingView {
  const severity = finding.severity;
  switch (finding.kind) {
    case "default_file_password":
      return {
        severity,
        title: "This file was protected with mRemoteNG's well-known default password.",
        body: "It was not really protected. Anyone who has ever held a copy of it could read every credential inside without knowing anything you know. Treat the passwords coming across as exposed and change them on the servers.",
        code: null,
      };
    case "legacy_cbc_encryption":
      return {
        severity,
        title: "This file uses the legacy AES-CBC scheme with an MD5-derived key.",
        body: "Remoter can read it. So could anyone else with a copy, without much effort, because the key came from an unsalted hash and the ciphertext carried nothing to detect tampering. Consider the credentials inside it exposed.",
        code: 'BlockCipherMode="CBC"',
      };
    case "full_file_encryption":
      return {
        severity,
        title: "The whole document was encrypted, not just its passwords.",
        body: "The structure was hidden as well as the credentials. Nothing changes about the import; it is noted because it tells you how the file was configured.",
        code: 'FullFileEncryption="true"',
      };
    case "secrets_recovered":
      return {
        severity,
        title: `${finding.count} ${plural(finding.count, "password", "passwords")} came out of the file.`,
        body: "They are sealed into the vault at the moment you commit. They are never written to disk in the clear and never leave the core.",
        code: null,
      };
    case "credentials_deduplicated":
      return {
        severity,
        title: `${finding.credentials} credential ${plural(finding.credentials, "object", "objects")} cover ${finding.connections} ${plural(finding.connections, "connection", "connections")}.`,
        body: "The same username and password repeated across connections became one credential each, linked from the connections that used it. Changing it once now changes it everywhere.",
        code: null,
      };
    case "unknown_protocol":
      return {
        severity,
        title: `${finding.item} used a protocol Remoter does not have.`,
        body: `It was imported as ${finding.mapped_to}. The original value is kept in a custom field, so nothing about it is lost.`,
        code: finding.protocol,
      };
    case "skipped_item":
      return {
        severity,
        title: `${finding.item} was not imported.`,
        body: `It was left out because ${SKIP_REASON[finding.reason]}.`,
        code: null,
      };
    case "unmapped_proxy_command":
      return {
        severity,
        title: `${finding.item} uses a ProxyCommand that has no direct equivalent.`,
        body: "The command is kept verbatim in a custom field rather than dropped. The connection will import; it will not use the proxy until you wire up a gateway for it by hand.",
        code: finding.command,
      };
    case "gateway_mapped":
      return {
        severity,
        title: `${finding.item} arrives with its jump-host chain intact.`,
        body: `ProxyJump became a real gateway chain of ${finding.hops} ${plural(finding.hops, "hop", "hops")}, so the connection works from the first attempt without any further setup.`,
        code: null,
      };
    case "gateway_synthesised":
      return {
        severity,
        title: `A gateway for ${finding.item} was created from its ProxyJump.`,
        body: `The jump host ${finding.target} was not a connection in the file, so it became one here and is now shared by everything that jumps through it.`,
        code: finding.target,
      };
    case "gateway_unresolved":
      return {
        severity,
        title: `${finding.item} jumps through a host that could not be resolved.`,
        body: `The chain names ${finding.target}, which is not in the file and could not be built from it. The connection imports without its gateway and will not reach the host until you add one.`,
        code: finding.target,
      };
    case "secret_not_mapped":
      return {
        severity,
        title: `A secret on ${finding.item} had nowhere to go.`,
        body: "It was in a field the domain model has no home for, and a secret is the one thing that is never kept in a custom field. It was dropped rather than stored somewhere it would not be protected.",
        code: finding.field,
      };
    case "match_block_not_applied":
      return {
        severity,
        title: "A Match block was read but not applied.",
        body: `Its criteria depend on how the connection is being made, which is not known at import time, so its ${finding.options} ${plural(finding.options, "option", "options")} were left out rather than applied to hosts they may not be meant for.`,
        code: finding.criteria,
      };
    case "pattern_block_applied":
      return {
        severity,
        title: `A wildcard Host block was applied to ${finding.connections} ${plural(finding.connections, "connection", "connections")}.`,
        body: "Its options were folded into every connection whose name it matched, the same way ssh itself would apply them.",
        code: finding.pattern,
      };
    case "settings_preserved":
      return {
        severity,
        title: `${finding.count} ${plural(finding.count, "setting", "settings")} on ${finding.item} were kept but not interpreted.`,
        body: "They are in custom fields, verbatim. Nothing was discarded — if a later version of Remoter learns to read them, they will be there.",
        code: null,
      };
    case "unknown_column":
      return {
        severity,
        title: "A column in the file was not recognised.",
        body: "Its values were kept in a custom field on each row rather than thrown away.",
        code: finding.column,
      };
    case "limit_reached":
      return {
        severity,
        title: `A safety limit stopped the parse: too many ${LIMIT[finding.limit] ?? finding.limit}.`,
        body: "What you see is everything Remoter read before the limit. Importing it is safe; it will not be the whole file. Split the file, or import it in parts.",
        code: finding.limit,
      };
    default:
      // remoter-import marks Finding and SkipReason #[non_exhaustive], so a
      // variant added upstream arrives here as a shape this switch has never
      // seen. Without this arm the function returns undefined and the report
      // step throws — an import that the core parsed perfectly would fail at
      // the last screen. Show the raw tag instead: unhelpful, but honest and
      // survivable.
      return {
        severity: "info",
        title: "This file produced a note this version does not recognise.",
        body: "It came from a newer part of the importer than this build knows about. Nothing is wrong with your file; the note simply cannot be explained here.",
        code: (finding as { kind?: string }).kind ?? "unknown",
      };
  }
}

const SEVERITY_RANK: Record<FindingSeverity, number> = { alert: 0, warning: 1, info: 2 };

/** Findings of one severity, worst first, keeping the core's own order within a level. */
export function bySeverity(
  findings: readonly ImportFinding[],
  severity: FindingSeverity,
): ImportFinding[] {
  return findings.filter((f) => f.severity === severity);
}

export function sortedBySeverity(findings: readonly ImportFinding[]): ImportFinding[] {
  return [...findings].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
}

/** True when the file's own protection was the published default or the broken one. */
export function fileWasExposed(findings: readonly ImportFinding[]): boolean {
  return findings.some(
    (f) => f.kind === "default_file_password" || f.kind === "legacy_cbc_encryption",
  );
}

export function usedDefaultPassword(findings: readonly ImportFinding[]): boolean {
  return findings.some((f) => f.kind === "default_file_password");
}

/** How many connections arrive with a gateway chain the importer built for them. */
export function gatewayFindingCount(findings: readonly ImportFinding[]): number {
  return findings.filter((f) => f.kind === "gateway_mapped" || f.kind === "gateway_synthesised")
    .length;
}

export interface PreservedLine {
  field: string;
  detail: string;
}

/**
 * The "kept but not interpreted" list: what was preserved, where, and how much
 * of it. Built from the findings rather than from a dedicated command, because
 * the findings are what the core actually reports.
 */
export function preservedLines(findings: readonly ImportFinding[]): PreservedLine[] {
  let proxyCommands = 0;
  let settingItems = 0;
  let settingCount = 0;
  const columns = new Set<string>();
  let unknownProtocols = 0;

  for (const finding of findings) {
    if (finding.kind === "unmapped_proxy_command") proxyCommands += 1;
    else if (finding.kind === "settings_preserved") {
      settingItems += 1;
      settingCount += finding.count;
    } else if (finding.kind === "unknown_column") columns.add(finding.column);
    else if (finding.kind === "unknown_protocol") unknownProtocols += 1;
  }

  const lines: PreservedLine[] = [];
  if (proxyCommands > 0) {
    lines.push({
      field: "custom_fields.ProxyCommand",
      detail: `${proxyCommands} ${plural(proxyCommands, "connection", "connections")} · verbatim`,
    });
  }
  if (settingCount > 0) {
    lines.push({
      field: "custom_fields.*",
      detail: `${settingCount} ${plural(settingCount, "setting", "settings")} on ${settingItems} ${plural(settingItems, "item", "items")} · verbatim`,
    });
  }
  if (unknownProtocols > 0) {
    lines.push({
      field: "custom_fields.Protocol",
      detail: `${unknownProtocols} ${plural(unknownProtocols, "connection", "connections")} · verbatim`,
    });
  }
  for (const column of columns) {
    lines.push({ field: `custom_fields.${column}`, detail: "every row · verbatim" });
  }
  return lines;
}

function plural(n: number, one: string, many: string): string {
  return n === 1 ? one : many;
}
