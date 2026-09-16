/**
 * Jump hosts: the SSH servers a session is forwarded through before it reaches
 * its own host.
 *
 * The core has resolved and dialled these chains for as long as sessions have
 * existed — each hop authenticated with its own credential, each hop's host key
 * asked about on its own — but nothing could create one except importing an
 * `ssh_config` with `ProxyJump`. This is that missing control.
 *
 * It follows the rest of the editor: a chain set on a folder is inherited by
 * everything beneath it, shown with where it comes from, and a connection can
 * override it — with a chain of its own, or with none at all, which is a
 * different instruction from inheriting. The order is the order of travel: the
 * first hop is reached directly and the last one reaches this host.
 *
 * Only SSH connections are offered as hops, because forwarding is done over SSH
 * and the core refuses anything else when it saves. Hop credentials the core
 * already holds — an imported chain can name one per hop — are kept exactly as
 * they were: this control changes the hops, not how each hop logs in.
 */

import { Button } from "@/components/Button";
import { Field } from "@/components/Field";
import { Icon } from "@/components/Icon";
import { compareInLocale, isolate, isolateChain, isolateLtr, useLocale, useT } from "@/i18n";
import type { GatewayHop, TreeNode } from "@/lib/ipc";

import s from "./ConnectionEditor.module.css";
import g from "./GatewayField.module.css";

/** The gateway chain as the form holds it. `own: false` inherits whatever is above. */
export interface GatewayDraft {
  own: boolean;
  hops: GatewayHop[];
}

export interface GatewayInheritance {
  /** The chain this node would use if it set none, by name, outermost first. */
  chain: string[] | null;
  /** The folder it comes from; `null` when nothing above sets one. */
  source: string | null;
}

interface GatewayFieldProps {
  /** The node being edited; `null` while it is still being created. */
  nodeId: string | null;
  /** The folder the node is in, so a hop inside a folder it applies to can be flagged. */
  kind: "connection" | "folder";
  draft: GatewayDraft;
  inheritance: GatewayInheritance;
  nodes: readonly TreeNode[];
  onChange: (draft: GatewayDraft) => void;
  disabled?: boolean;
}

export function GatewayField({
  nodeId,
  kind,
  draft,
  inheritance,
  nodes,
  onChange,
  disabled = false,
}: GatewayFieldProps) {
  const t = useT("connections");
  const tCommon = useT("common");
  const { code: locale } = useLocale();

  const byId = new Map(nodes.map((node) => [node.id, node]));
  const candidates = nodes
    .filter((node) => node.kind === "connection" && node.protocol === "ssh" && node.id !== nodeId)
    .slice()
    .sort((a, b) => compareInLocale(a.name, b.name, locale));

  // The catalogue's own separator for a jump-host chain; see its comment for
  // why it is not flipped in a right-to-left interface.
  const arrow = tCommon("punctuation.chainSeparator");
  const inherited = inheritance.chain;
  const canInherit = inheritance.source !== null || (inherited !== null && inherited.length > 0);

  const setHops = (hops: GatewayHop[]) => onChange({ own: true, hops });
  const move = (index: number, by: -1 | 1) => {
    const next = draft.hops.slice();
    const [hop] = next.splice(index, 1);
    if (hop === undefined) return;
    next.splice(index + by, 0, hop);
    setHops(next);
  };

  // A folder chain whose hop is a connection inside that same folder routes
  // that connection through itself, which the session refuses. Said here, where
  // it is set, rather than when somebody opens the jump host.
  const insideThisFolder =
    kind === "folder" && nodeId !== null
      ? draft.hops
          .map((hop) => byId.get(hop.nodeId))
          .filter((hop): hop is TreeNode => hop !== undefined && isInside(hop, nodeId, byId))
      : [];

  return (
    <Field label={t("editor.gatewayLabel")} help={t("editor.gatewayHelp")}>
      {!draft.own ? (
        <div className={s.control}>
          <span className={s.inheritedBox}>
            {inherited === null || inherited.length === 0 ? (
              <span className={s.inheritedEmpty}>{t("editor.gatewayDirect")}</span>
            ) : (
              isolateChain(inherited, arrow)
            )}
          </span>
          <Button size="sm" disabled={disabled} onClick={() => setHops([])}>
            {t("editor.overrideHere")}
          </Button>
        </div>
      ) : (
        <div className={g.chain}>
          {draft.hops.length === 0 ? (
            <p className={g.direct}>{t("editor.gatewayDirect")}</p>
          ) : (
            <ol className={g.hops}>
              {draft.hops.map((hop, index) => {
                const chosen = byId.get(hop.nodeId);
                return (
                  <li key={`${hop.nodeId}-${String(index)}`} className={g.hop}>
                    <span className={g.position} aria-hidden="true">
                      {index + 1}
                    </span>
                    <select
                      className={g.select}
                      aria-label={t("editor.gatewayHop", { position: index + 1 })}
                      value={hop.nodeId}
                      disabled={disabled}
                      onChange={(event) => {
                        const next = draft.hops.slice();
                        // A different jump host logs in its own way; a
                        // credential chosen for the old one does not carry over.
                        next[index] = { nodeId: event.target.value, credentialId: null };
                        setHops(next);
                      }}
                    >
                      {chosen === undefined && (
                        <option value={hop.nodeId}>{t("editor.gatewayMissing")}</option>
                      )}
                      {candidates.map((candidate) => (
                        <option key={candidate.id} value={candidate.id}>
                          {candidate.host === null || candidate.host === ""
                            ? candidate.name
                            : t("editor.gatewayOption", {
                                name: isolate(candidate.name),
                                host: isolateLtr(candidate.host),
                              })}
                        </option>
                      ))}
                    </select>
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={disabled || index === 0}
                      ariaLabel={t("editor.gatewayMoveUp", { position: index + 1 })}
                      title={t("editor.gatewayMoveUp", { position: index + 1 })}
                      onClick={() => move(index, -1)}
                    >
                      <span className={g.up}>
                        <Icon name="chevron-down" size={12} />
                      </span>
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={disabled || index === draft.hops.length - 1}
                      ariaLabel={t("editor.gatewayMoveDown", { position: index + 1 })}
                      title={t("editor.gatewayMoveDown", { position: index + 1 })}
                      onClick={() => move(index, 1)}
                    >
                      <Icon name="chevron-down" size={12} />
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={disabled}
                      ariaLabel={t("editor.gatewayRemove", { position: index + 1 })}
                      title={t("editor.gatewayRemove", { position: index + 1 })}
                      onClick={() => setHops(draft.hops.filter((_hop, at) => at !== index))}
                    >
                      <Icon name="x" size={12} />
                    </Button>
                  </li>
                );
              })}
            </ol>
          )}

          <div className={s.control}>
            <Button
              size="sm"
              disabled={disabled || candidates.length === 0}
              onClick={() => {
                const used = new Set(draft.hops.map((hop) => hop.nodeId));
                const next = candidates.find((candidate) => !used.has(candidate.id)) ?? candidates[0];
                if (next !== undefined) setHops([...draft.hops, { nodeId: next.id, credentialId: null }]);
              }}
            >
              <Icon name="plus" size={12} />
              {t("editor.gatewayAdd")}
            </Button>
            {canInherit && (
              <Button size="sm" disabled={disabled} onClick={() => onChange({ own: false, hops: [] })}>
                {inherited === null || inherited.length === 0
                  ? t("editor.revertPlain")
                  : t("editor.revertTo", { value: isolateChain(inherited, arrow) })}
              </Button>
            )}
          </div>

          {candidates.length === 0 && <p className={g.note}>{t("editor.gatewayNoSsh")}</p>}
          {insideThisFolder.map((hop) => (
            <p key={hop.id} className={g.warning}>
              {t("editor.gatewayInsideFolder", { name: isolate(hop.name) })}
            </p>
          ))}
        </div>
      )}

      <span className={s.provenance}>
        {draft.own
          ? t("editor.setHere")
          : inheritance.source === null
            ? t("editor.gatewayNoneAbove")
            : t("editor.inheritedFrom", { source: isolate(inheritance.source) })}
      </span>
    </Field>
  );
}

/** Whether `node` sits somewhere under the folder `folderId`. */
function isInside(node: TreeNode, folderId: string, byId: ReadonlyMap<string, TreeNode>): boolean {
  let parent = node.parentId;
  const seen = new Set<string>();
  while (parent !== null && !seen.has(parent)) {
    if (parent === folderId) return true;
    seen.add(parent);
    parent = byId.get(parent)?.parentId ?? null;
  }
  return false;
}

/** Whether two chains are the same instruction, credentials included. */
export function sameHops(a: readonly GatewayHop[], b: readonly GatewayHop[]): boolean {
  return (
    a.length === b.length &&
    a.every((hop, index) => hop.nodeId === b[index]?.nodeId && hop.credentialId === b[index]?.credentialId)
  );
}
