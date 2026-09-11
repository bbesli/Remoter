/**
 * The session area for a tab whose session *is* a file session.
 *
 * `session_open` takes an `sftp` connection like any other — the pipeline, the
 * host key check and the credential are the same ones a shell gets — and the
 * core reports `capabilities.kind === "file_transfer"` for what comes back.
 * `an_sftp_connection_opens_a_file_session_of_its_own` in
 * `crates/remoter-ipc/src/live_tests.rs` pins that end of it: one session in the
 * list, closed by the same supervisor as everything else, with a pane that
 * browses. This is the other end — the tab that session fills.
 *
 * It mirrors `TerminalHost` and `FramebufferHost` deliberately: one host per
 * open tab, all of them mounted at once, the inactive ones hidden rather than
 * unmounted. For a terminal that is about the scrollback and the fit addon; for
 * a file pane it is about the transfer queue. Unmounting closes the pane in the
 * core, and closing the pane stops the drain task — so a tab switch during a
 * 2 GB download would cancel the download. Staying mounted is what makes
 * "switch to the shell while that copies" true.
 *
 * Information architecture: `docs/ui/information-architecture.md` gives the
 * session area three kinds of content — "terminal / framebuffer / file grid".
 * This is the third.
 */

import { isolate, useT } from "@/i18n";

import { FilePane } from "./FilePane";

import s from "./FileSessionHost.module.css";

export interface FileSessionHostProps {
  /** The core's id for this tab's session. Null until it has authenticated. */
  sessionId: number | null;
  /** The connection's own name, from the vault. */
  name: string;
  /** Whether this is the tab in front. */
  active: boolean;
}

export function FileSessionHost({ sessionId, name, active }: FileSessionHostProps) {
  const t = useT("files");

  return (
    <div
      className={active ? s.host : [s.host, s.hidden].join(" ")}
      // Hidden tabs are hidden from assistive technology too: two file
      // browsers in the accessibility tree, one of them unreachable, is worse
      // than one.
      aria-hidden={active ? undefined : true}
      aria-label={t("host.label", { name: isolate(name) })}
    >
      <FilePane sessionId={sessionId} name={name} />
    </div>
  );
}
