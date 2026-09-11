/**
 * The warnings a session raised, on screen at last.
 *
 * `store.ts` has collected `SessionWarning`s since the session feature was
 * written and nothing rendered them. The adapters raise real ones: a VNC server
 * that negotiated no authentication at all, an RDP connection running without
 * Network Level Authentication, a clear-text RFB session to a routable address,
 * a server that refused the channel smart resize needs. Every one of those was
 * produced, stored and thrown away when the tab closed.
 *
 * Three rules decide how they are drawn.
 *
 * **They sit over the session, not beside it.** A warning in a panel the user
 * has to open is a warning nobody reads. This is the same position the
 * refused-keystroke notice takes.
 *
 * **A `danger` one cannot be collapsed.** The set folds to a single line once
 * it is read — a bell that rang and a clipboard that was transcoded are not
 * worth a permanent panel — but "this session is not authenticated" does not
 * fold. See `canCollapse` in `warnings.ts`.
 *
 * **The server's own words are quarantined.** A banner is remote text of
 * arbitrary length in an arbitrary script: it goes in its own preformatted
 * block, as text, never spliced into a translated sentence and never as markup.
 */

import { useState } from "react";

import { Callout } from "@/components/Callout";
import { Icon } from "@/components/Icon";
import { isolate, useT } from "@/i18n";
import type { SessionRecord } from "./store";
import { canCollapse, describeWarning, loudestTone } from "./warnings";

import s from "./SessionWarnings.module.css";

export function SessionWarnings({ record }: { record: SessionRecord }) {
  const t = useT("sessions");
  const [open, setOpen] = useState(true);

  if (record.warnings.length === 0) return null;

  // Newest first: the last thing that happened is the thing being reacted to.
  const views = record.warnings.map(describeWarning).reverse();
  const collapsible = canCollapse(views);
  const showing = open || !collapsible;

  return (
    <div className={s.bar}>
      <div className={s.head}>
        <span className={s.summary} data-tone={loudestTone(views)}>
          <Icon name="alert" size={13} />
          {t("warning.count", { count: views.length })}
        </span>
        {collapsible && (
          <button type="button" className={s.toggle} onClick={() => setOpen(!open)}>
            {open ? t("warning.hide") : t("warning.show")}
          </button>
        )}
      </div>

      {showing && (
        <ul className={s.list}>
          {views.map((view, index) => (
            <li key={`${view.key}-${String(index)}`}>
              <Callout tone={view.tone}>
                <p className={s.text}>
                  {view.algorithm === null
                    ? t(view.key)
                    : // The algorithm is a wire name from the far end. Isolated
                      // so one right-to-left character in it cannot reorder the
                      // sentence around it.
                      t(view.key, { algorithm: isolate(view.algorithm) })}
                </p>
                {view.unnamedDetail !== null && (
                  <p className={s.unnamed}>
                    {t("warning.unnamedDetail", { key: isolate(view.unnamedDetail) })}
                  </p>
                )}
                {view.remoteText !== null && view.remoteText !== "" && (
                  /* The server's own text. Untrusted, and rendered as text. */
                  <pre className={s.remoteText}>{view.remoteText}</pre>
                )}
              </Callout>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
