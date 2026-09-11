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
 * **They sit in the session's chrome, above the picture — never on it.** They
 * used to float at the bottom inline-start of the session area, which is the
 * Start button on a remote Windows desktop and the taskbar on a maximised one.
 * A remote desktop uses all four of its edges, so there is nowhere over the
 * picture that is safe. What replaces the overlay is a count, always visible in
 * the chrome, which opens the list in the flow above the session: noticeable,
 * one click from the whole text, and covering nothing. Hiding them silently was
 * never the alternative.
 *
 * **A `danger` one cannot be collapsed.** The set folds to a single line once
 * it is read — a bell that rang and a clipboard that was transcoded are not
 * worth a permanent panel — but "this session is not authenticated" does not
 * fold. See `canCollapse` in `warnings.ts`.
 *
 * **The server's own words are quarantined.** A banner is remote text of
 * arbitrary length in an arbitrary script: it goes in its own preformatted
 * block, as text, never spliced into a translated sentence and never as markup.
 * See {@link BannerText} for the half of that quarantine which is not about
 * markup at all.
 */

import { Fragment, useState } from "react";

import { Callout } from "@/components/Callout";
import { Icon } from "@/components/Icon";
import { isolate, useT } from "@/i18n";
import type { SessionRecord } from "./store";
import { canCollapse, describeWarning, loudestTone } from "./warnings";

import s from "./SessionWarnings.module.css";

/**
 * Splits remote text into the lines it claims to have.
 *
 * All three line endings, because the far end chooses them and an SSH banner
 * carries CRLF (RFC 4253 §11.3 sends the text as the server wrote it). Splitting
 * on the pair as well as on each character alone means a lone carriage return —
 * which a preformatted block renders as nothing at all, while still sitting in
 * the DOM as a control character — is consumed here rather than shown as
 * nothing.
 */
function bannerLines(text: string): string[] {
  return text.split(/\r\n|\r|\n/);
}

/**
 * A login banner or keyboard-interactive instruction, drawn as the server's
 * own text.
 *
 * # This is the direction problem, not the markup problem
 *
 * Markup is already handled and always was: React escapes text children, so
 * nothing in a banner can become an element. What was not handled is the
 * Unicode bidirectional algorithm, and a banner is the worst input it can get —
 * arbitrary text from an unauthenticated peer, shown *before* the session has
 * authenticated, in a block the user is being asked to read and trust.
 *
 * Two defences, and they are different:
 *
 * - **`dir="ltr"` on the block.** Without it the banner inherits the interface's
 *   direction, so under an Arabic or Hebrew interface an ASCII banner is drawn
 *   right-aligned with its trailing punctuation moved to the front, and any
 *   box-drawing or aligned columns in it collapse. The banner is not interface
 *   copy and does not follow the interface. `surfaces.ts` pins the same
 *   attribute on the framebuffer canvas for the same reason.
 * - **One isolate per line.** Each line is wrapped in `<bdi>`, whose direction
 *   is resolved from its own first strong character and whose resolution cannot
 *   escape it. So a line of Hebrew renders right-to-left as the server meant,
 *   and a line carrying a stray directional mark cannot reorder the line above
 *   it, the interface text around the block, or the count in the header.
 *
 * The separators are text nodes between the isolates rather than block elements,
 * so selecting the banner and copying it yields the banner — line breaks
 * included — and not one run-on line.
 *
 * # What this cannot do, and who has to
 *
 * Isolation bounds where a directional character takes effect. It does not
 * neutralise one: an explicit override inside a line still reorders that line,
 * and a C0 control or a zero-width character inside it is still invisible.
 * Every other piece of remote text in this application is defended against
 * those by an **escaped twin** computed in Rust —
 * `remoter_proto_ssh::sftp::escape_untrusted`, which every SFTP name, path,
 * user and group goes through. `SessionWarning::Banner { text }` is the one DTO
 * that crosses IPC without one, so this is the one surface that has to make do
 * with isolation. The escaping is deliberately *not* duplicated here: a second
 * table in TypeScript would drift from the first, and would double-escape the
 * moment the twin lands. The DTO change is written up in the hand-off.
 */
function BannerText({ text }: { text: string }) {
  const lines = bannerLines(text);
  return (
    <pre className={s.remoteText} dir="ltr">
      {lines.map((line, index) => (
        <Fragment key={index}>
          {index > 0 ? "\n" : null}
          <bdi>{line}</bdi>
        </Fragment>
      ))}
    </pre>
  );
}

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
                  /* The server's own text. Untrusted: rendered as text, and
                     isolated line by line. See BannerText. */
                  <BannerText text={view.remoteText} />
                )}
              </Callout>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
