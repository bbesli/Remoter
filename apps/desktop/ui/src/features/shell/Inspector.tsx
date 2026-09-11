/**
 * The right-hand inspector: the effective value of every field, and where it
 * came from.
 *
 * Inheritance is the feature most likely to surprise someone — a connection
 * can pick up a credential and a gateway from a folder two levels up. So the
 * provenance line is not a tooltip: it sits under every value, always, and it
 * names the ancestor by the name the user gave it.
 */

import type { TFunction } from "i18next";
import type { ReactNode } from "react";

import { Badge } from "@/components/Badge";
import { FailureNotice } from "@/components/FailureNotice";
import { Icon } from "@/components/Icon";
import { Spinner } from "@/components/Spinner";
import { isolate, useT } from "@/i18n";
import type { EffectiveConnection, IpcFailure, ResolvedField, TreeNode } from "@/lib/ipc";
import s from "./Inspector.module.css";


interface InspectorProps {
  node: TreeNode | undefined;
  effective: EffectiveConnection | undefined;
  loading: boolean;
  /**
   * False when the query was never started — a locked vault, say. Without it
   * the panel cannot tell "still resolving" from "never asked", and shows a
   * spinner that never resolves.
   */
  enabled?: boolean | undefined;
  error: IpcFailure | null;
  onRetry?: (() => void) | undefined;
  onClose: () => void;
}

/**
 * The provenance line, in the design's words.
 *
 * `overrides` is set by the core when this node shadows an inherited value —
 * that is the case worth calling out, because it is the one where the tree
 * above says something different from what will actually be used.
 *
 * The username resolves with the credential that holds it, so it carries that
 * credential's provenance and needs no special case: "set here" when the
 * credential belongs to this connection, "from 📁 Datacentre EU-West" when it
 * comes from a folder. The credential itself does need one — "set here" is
 * true of a login this connection owns and of a shared credential alike, and
 * the difference is the whole reason editing one is safe and editing the other
 * would change what every connection using it logs in as.
 */
function provenance(
  f: ResolvedField,
  credentialAttached: boolean,
  // Passed in rather than looked up: this is a pure function called from a
  // map, and `useT` is a hook.
  t: TFunction<"shell">,
): string {
  if (f.overrides !== null && f.overrides !== "") {
    return t("inspector.overridesInherited", { field: f.overrides });
  }
  if (f.field === "credential" && f.origin === "own" && f.value !== null) {
    return credentialAttached ? t("inspector.credentialOwn") : t("inspector.credentialShared");
  }
  switch (f.origin) {
    case "own":
      return t("inspector.setHere");
    case "inherited":
      return f.sourceName === null
        ? t("inspector.inherited")
        : // A folder name is user data in an unknown script.
          t("inspector.fromSource", { source: isolate(f.sourceName) });
    case "default":
      return t("inspector.fromDefault");
  }
}

function Panel({ children }: { children: ReactNode }) {
  return <div className={s.panel}>{children}</div>;
}

export function Inspector({
  node,
  effective,
  loading,
  enabled = true,
  error,
  onRetry,
  onClose,
}: InspectorProps) {
  const t = useT("shell");
  const isConnection = node?.kind === "connection";
  const protocol = node?.protocol ?? null;

  return (
    <aside className={s.inspector} aria-label={t("inspector.title")}>
      <div className={s.head}>
        {/* The node's own name: user data, isolated so a Hebrew or Arabic
            connection name does not reverse the header around it. */}
        <span
          className={s.headName}
          title={node === undefined ? t("inspector.nothingSelected") : isolate(node.name)}
        >
          {node === undefined ? t("inspector.nothingSelected") : isolate(node.name)}
        </span>
        {protocol !== null && (
          <Badge tone="neutral" mono>
            {protocol}
          </Badge>
        )}
        <div className={s.headSpacer} />
        <button
          type="button"
          className={s.closeButton}
          onClick={onClose}
          title={t("inspector.close")}
          aria-label={t("inspector.close")}
        >
          <Icon name="x" size={13} />
        </button>
      </div>

      <div className={s.body}>
        {node === undefined ? (
          <Panel>
            <p className={s.emptyTitle}>{t("inspector.nothingSelected")}</p>
            <p className={s.emptyBody}>{t("inspector.nothingSelectedBody")}</p>
          </Panel>
        ) : !isConnection ? (
          <Panel>
            <p className={s.emptyTitle}>{t("inspector.notAConnection")}</p>
            <p className={s.emptyBody}>{t("inspector.notAConnectionBody")}</p>
          </Panel>
        ) : error !== null ? (
          <FailureNotice
            failure={error}
            title={t("inspector.failed")}
            {...(onRetry === undefined ? {} : { onRetry, retryLabel: t("inspector.retry") })}
          />
        ) : loading || (enabled && effective === undefined) ? (
          <div className={s.loading}>
            <Spinner size={14} label={t("inspector.resolving")} />
            <span>{t("inspector.resolving")}…</span>
          </div>
        ) : effective === undefined ? (
          // Not loading, not failed, and still nothing to show: the query was
          // never started. A spinner here would wait for something that is not
          // coming.
          <Panel>
            <p className={s.emptyTitle}>{t("inspector.notAsked")}</p>
            <p className={s.emptyBody}>{t("inspector.notAskedBody")}</p>
          </Panel>
        ) : (
          <>
            <section className={s.section}>
              <h2 className={s.sectionTitle}>{t("inspector.title")}</h2>
              {effective.fields.length === 0 ? (
                <p className={s.emptyBody}>{t("inspector.noFields")}</p>
              ) : (
                <div className={s.fields}>
                  {effective.fields.map((f) => (
                    <div className={s.field} key={f.field}>
                      <div className={s.fieldRow}>
                        <span className={s.fieldName}>{f.field}</span>
                        <span
                          className={f.value === null ? s.fieldUnset : s.fieldValue}
                          title={f.value ?? t("inspector.unset")}
                        >
                          {f.value ?? t("inspector.unset")}
                        </span>
                      </div>
                      <div className={s.origin}>
                        {f.origin === "inherited" ? (
                          <span className={s.originIcon} aria-hidden="true">
                            <Icon name="folder" size={10} />
                          </span>
                        ) : (
                          <span
                            className={f.origin === "own" ? s.originDotOwn : s.originDotDefault}
                            aria-hidden="true"
                          />
                        )}
                        <span className={s.originText}>
                          {provenance(f, effective.credentialAttached, t)}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>

            {effective.gatewayChain.length > 0 && (
              <section className={s.section}>
                <h2 className={s.sectionTitle}>{t("inspector.gateway")}</h2>
                <ol className={s.chain}>
                  {effective.gatewayChain.map((hop, i) => (
                    <li className={s.hop} key={`${String(i)}-${hop}`}>
                      <span className={s.hopIndex}>{i + 1}</span>
                      <span className={s.hopName}>{isolate(hop)}</span>
                    </li>
                  ))}
                </ol>
              </section>
            )}

            {effective.tags.length > 0 && (
              <section className={s.section}>
                <h2 className={s.sectionTitle}>{t("inspector.tags")}</h2>
                <div className={s.tags}>
                  {effective.tags.map((tag) => (
                    <Badge key={tag} tone="info">
                      {isolate(tag)}
                    </Badge>
                  ))}
                </div>
              </section>
            )}
          </>
        )}
      </div>
    </aside>
  );
}
