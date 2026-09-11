/**
 * A file pane's lifetime, tied to the component that shows it.
 *
 * A pane is not data — it is a channel on a live connection, a queue, and two
 * tasks draining it — so it is not a query. It is opened when this hook is
 * given a session and closed when it is taken away, and `sftp_close` is
 * awaited on the way out because the core returns from it only once the drain
 * task has stopped: "the pane is closed" and "nothing is still writing to
 * disk" are meant to be the same moment, and a component that fired the close
 * and forgot about it would give that up.
 *
 * # Two ways a pane outlives its owner, and what stops each
 *
 * **The effect runs twice.** React's development mode mounts, unmounts and
 * mounts again to catch exactly this class of bug. The open is already in
 * flight when the cleanup runs, so the cleanup cannot close what it has not
 * got — instead the resolved pane finds its generation stale and closes
 * itself. Without that, every mount in development leaks a channel.
 *
 * **The session ends underneath it.** A pane's cancellation token is a child of
 * its session's, so closing the tab closes the pane in the core whatever this
 * hook does. `sftp_close` on an id the core has already dropped fails, and that
 * failure is swallowed on the unmount path: there is nobody left to tell, and
 * the thing it would report has already happened.
 */

import { useCallback, useEffect, useRef, useState } from "react";

import { asFailure, ipc, type IpcFailure, type SftpPane } from "@/lib/ipc";

export interface PaneHandle {
  /** The pane, once it is attached. */
  pane: SftpPane | null;
  /** True while `sftp_open` is in flight. */
  opening: boolean;
  /** Why it could not be attached. Rendered through the failure layer. */
  problem: IpcFailure | null;
  /** Tries again on the same session. */
  retry: () => void;
}

export function usePane(sessionId: number | null): PaneHandle {
  const [pane, setPane] = useState<SftpPane | null>(null);
  const [opening, setOpening] = useState(false);
  const [problem, setProblem] = useState<IpcFailure | null>(null);
  const [attempt, setAttempt] = useState(0);

  // Bumped by every effect run. A resolved open compares it and closes itself
  // if it has been superseded, which is what makes the double mount safe.
  const generation = useRef(0);

  useEffect(() => {
    generation.current += 1;
    const mine = generation.current;

    if (sessionId === null) {
      setPane(null);
      setOpening(false);
      setProblem(null);
      return;
    }

    setOpening(true);
    setProblem(null);
    let opened: SftpPane | null = null;

    void ipc
      .openPane(sessionId)
      .then((result) => {
        if (generation.current !== mine) {
          // Superseded while the open was in flight. Nothing is looking at this
          // pane, so it is closed rather than left holding a channel.
          void ipc.closePane(result.paneId).catch(() => undefined);
          return;
        }
        opened = result;
        setPane(result);
        setOpening(false);
      })
      .catch((error: unknown) => {
        if (generation.current !== mine) return;
        setPane(null);
        setOpening(false);
        setProblem(asFailure(error));
      });

    return () => {
      generation.current += 1;
      setPane(null);
      if (opened !== null) {
        // Not awaited — a cleanup function cannot be async — but the core's
        // own close still waits for the drain before it returns, so the
        // sequence is unchanged. A refusal here means the session already took
        // the pane with it.
        void ipc.closePane(opened.paneId).catch(() => undefined);
      }
    };
  }, [sessionId, attempt]);

  const retry = useCallback(() => {
    setAttempt((n) => n + 1);
  }, []);

  return { pane, opening, problem, retry };
}
