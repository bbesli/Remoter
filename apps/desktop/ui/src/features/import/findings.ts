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
 *
 * The sentences themselves are in `locales/en/import.json` under `finding.*`
 * and `preserved.*`; both functions here take `t` as a parameter rather than
 * calling `useT`, because they are pure functions called from a render loop and
 * `useT` is a hook. Counts go through ICU plurals and the file's own values —
 * a host name, a `ProxyCommand`, a column heading — are interpolated as data
 * and isolated, so a value in a right-to-left script cannot reorder the
 * sentence it lands in.
 */

import type { TFunction } from "i18next";

import { isolate, isolateLtr } from "@/i18n";
import type { FindingSeverity, ImportFinding } from "@/lib/ipc";

export interface FindingView {
  severity: FindingSeverity;
  title: string;
  /** The consequence, in plain words. Empty when the title says everything. */
  body: string;
  /** The verbatim scrap the finding came from — a command, a column, a host. */
  code: string | null;
}

/**
 * Attribute text quoted out of the file being imported.
 *
 * Not copy: this is what an mRemoteNG document literally contains, shown so the
 * reader can find it in their own file. It is never translated
 * (docs/features/i18n.md, "What is never translated").
 */
const CBC_ATTRIBUTE = 'BlockCipherMode="CBC"';
const FULL_FILE_ATTRIBUTE = 'FullFileEncryption="true"';

export function describeFinding(t: TFunction<"import">, finding: ImportFinding): FindingView {
  const severity = finding.severity;
  switch (finding.kind) {
    case "default_file_password":
      return {
        severity,
        title: t("finding.defaultFilePasswordTitle"),
        body: t("finding.defaultFilePasswordBody"),
        code: null,
      };
    case "legacy_cbc_encryption":
      return {
        severity,
        title: t("finding.legacyCbcEncryptionTitle"),
        body: t("finding.legacyCbcEncryptionBody"),
        code: CBC_ATTRIBUTE,
      };
    case "full_file_encryption":
      return {
        severity,
        title: t("finding.fullFileEncryptionTitle"),
        body: t("finding.fullFileEncryptionBody"),
        code: FULL_FILE_ATTRIBUTE,
      };
    case "secrets_recovered":
      return {
        severity,
        title: t("finding.secretsRecoveredTitle", { count: finding.count }),
        body: t("finding.secretsRecoveredBody"),
        code: null,
      };
    case "secrets_not_carried":
      return {
        severity,
        title: t("finding.secretsNotCarriedTitle", { count: finding.count }),
        body: t("finding.secretsNotCarriedBody"),
        code: null,
      };
    case "protected_passwords_not_carried":
      return {
        severity,
        title: t("finding.protectedPasswordsNotCarriedTitle", { count: finding.count }),
        body: t("finding.protectedPasswordsNotCarriedBody"),
        code: null,
      };
    case "proxy_not_supported":
      return {
        severity,
        title: t("finding.proxyNotSupportedTitle", { item: isolate(finding.item) }),
        body: t("finding.proxyNotSupportedBody"),
        // The proxy's kind and address are both the file's own text.
        code: finding.host === "" ? finding.proxy : `${finding.proxy} ${finding.host}`,
      };
    case "rd_gateway_not_supported":
      return {
        severity,
        title: t("finding.rdGatewayNotSupportedTitle", { item: isolate(finding.item) }),
        body: t("finding.rdGatewayNotSupportedBody"),
        code: finding.host,
      };
    case "credential_profile_missing":
      return {
        severity,
        title: t("finding.credentialProfileMissingTitle", {
          item: isolate(finding.item),
          profile: isolate(finding.profile),
        }),
        body: t("finding.credentialProfileMissingBody"),
        code: null,
      };
    case "credentials_deduplicated":
      return {
        severity,
        title: t("finding.credentialsDeduplicatedTitle", {
          credentials: finding.credentials,
          connections: finding.connections,
        }),
        body: t("finding.credentialsDeduplicatedBody"),
        code: null,
      };
    case "unknown_protocol":
      return {
        severity,
        title: t("finding.unknownProtocolTitle", { item: isolate(finding.item) }),
        // A protocol name — SSH, RDP, VNC, SFTP — is never translated, and is
        // left-to-right whatever the sentence around it is doing.
        body: t("finding.unknownProtocolBody", { mappedTo: isolateLtr(finding.mapped_to) }),
        code: finding.protocol,
      };
    case "skipped_item":
      return {
        severity,
        title: t("finding.skippedItemTitle", { item: isolate(finding.item) }),
        // The reason arrives as a wire value and selects a whole sentence, so a
        // language that puts the cause first is not stuck with English's order.
        // `remoter_import::SkipReason` is #[non_exhaustive]; the message's
        // `other` branch is what a reason this build has never seen lands on.
        body: t("finding.skippedItemBody", { reason: finding.reason }),
        code: null,
      };
    case "unmapped_proxy_command":
      return {
        severity,
        title: t("finding.unmappedProxyCommandTitle", { item: isolate(finding.item) }),
        body: t("finding.unmappedProxyCommandBody"),
        code: finding.command,
      };
    case "gateway_mapped":
      return {
        severity,
        title: t("finding.gatewayMappedTitle", { item: isolate(finding.item) }),
        body: t("finding.gatewayMappedBody", { hops: finding.hops }),
        code: null,
      };
    case "gateway_synthesised":
      return {
        severity,
        title: t("finding.gatewaySynthesisedTitle", { item: isolate(finding.item) }),
        body: t("finding.gatewaySynthesisedBody", { target: isolateLtr(finding.target) }),
        code: finding.target,
      };
    case "gateway_unresolved":
      return {
        severity,
        title: t("finding.gatewayUnresolvedTitle", { item: isolate(finding.item) }),
        body: t("finding.gatewayUnresolvedBody", { target: isolateLtr(finding.target) }),
        code: finding.target,
      };
    case "secret_not_mapped":
      return {
        severity,
        title: t("finding.secretNotMappedTitle", { item: isolate(finding.item) }),
        body: t("finding.secretNotMappedBody"),
        code: finding.field,
      };
    case "match_block_not_applied":
      return {
        severity,
        title: t("finding.matchBlockNotAppliedTitle"),
        body: t("finding.matchBlockNotAppliedBody", { options: finding.options }),
        code: finding.criteria,
      };
    case "pattern_block_applied":
      return {
        severity,
        title: t("finding.patternBlockAppliedTitle", { connections: finding.connections }),
        body: t("finding.patternBlockAppliedBody"),
        code: finding.pattern,
      };
    case "settings_preserved":
      return {
        severity,
        title: t("finding.settingsPreservedTitle", {
          count: finding.count,
          item: isolate(finding.item),
        }),
        body: t("finding.settingsPreservedBody"),
        code: null,
      };
    case "unknown_column":
      return {
        severity,
        title: t("finding.unknownColumnTitle"),
        body: t("finding.unknownColumnBody"),
        code: finding.column,
      };
    case "limit_reached":
      return {
        severity,
        // The limit's name selects a whole sentence rather than being spliced
        // into one: "too many nodes" does not inflect the same way everywhere.
        title: t("finding.limitReachedTitle", { limit: finding.limit }),
        body: t("finding.limitReachedBody"),
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
        title: t("finding.unknownTitle"),
        body: t("finding.unknownBody"),
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

/**
 * The items the parser refused: in the file, not in the vault.
 *
 * Distinct from the nodes the user unticked in the preview, which are also
 * "skipped" and which the result screen counts separately. These are the ones
 * nobody chose to leave behind — a connection with no usable hostname, an
 * mRemoteNG external-application entry — and they are the difference between an
 * import that succeeded and one that half-succeeded.
 */
export function refusedItems(findings: readonly ImportFinding[]): ImportFinding[] {
  return findings.filter((f) => f.kind === "skipped_item");
}

/** How many connections arrive with a gateway chain the importer built for them. */
export function gatewayFindingCount(findings: readonly ImportFinding[]): number {
  return findings.filter((f) => f.kind === "gateway_mapped" || f.kind === "gateway_synthesised")
    .length;
}

export interface PreservedLine {
  /**
   * The custom field the value landed in — `custom_fields.ProxyCommand`. A
   * field path, never translated.
   */
  field: string;
  detail: string;
}

/**
 * The "kept but not interpreted" list: what was preserved, where, and how much
 * of it. Built from the findings rather than from a dedicated command, because
 * the findings are what the core actually reports.
 */
export function preservedLines(
  t: TFunction<"import">,
  findings: readonly ImportFinding[],
): PreservedLine[] {
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
      detail: t("preserved.connections", { count: proxyCommands }),
    });
  }
  if (settingCount > 0) {
    lines.push({
      field: "custom_fields.*",
      detail: t("preserved.settings", { count: settingCount, items: settingItems }),
    });
  }
  if (unknownProtocols > 0) {
    lines.push({
      field: "custom_fields.Protocol",
      detail: t("preserved.connections", { count: unknownProtocols }),
    });
  }
  for (const column of columns) {
    // The column heading came out of the file, in whatever script it was
    // written in; the path around it is ASCII. Pinned left-to-right rather
    // than left to first-strong inference, so one right-to-left heading cannot
    // reorder `custom_fields.` around itself.
    lines.push({
      field: `custom_fields.${isolateLtr(column)}`,
      detail: t("preserved.everyRow"),
    });
  }
  return lines;
}
