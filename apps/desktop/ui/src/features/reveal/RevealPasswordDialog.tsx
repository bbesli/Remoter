/**
 * Shows a server's stored password, after the vault's password is confirmed.
 *
 * Opened from the tree's right-click menu. The core decides everything that
 * matters — whether the vault password is right, whether the ten-minute window
 * from an earlier confirmation is still open, which credential a connection
 * resolves to through inheritance — and this dialog only asks and shows:
 *
 *  - If the window looks open, it asks the core straight away with no
 *    password. The look is the store's mirror of the core's clock; when it is
 *    stale the core answers `secret.reveal-confirm` and the dialog asks for the
 *    vault password after all. A stale mirror can cost a prompt, never skip
 *    one.
 *  - Otherwise it asks for the vault password first.
 *
 * **The password lives in this component's state and nowhere else** — not in
 * TanStack Query's cache (which is why this calls `ipc` directly rather than
 * through `useMutation`, whose result outlives the component), not in the
 * store. Closing the dialog drops it; so does the vault locking, because the
 * shell unmounts the main window's dialogs when it does.
 *
 * It is rendered without the bidi isolation characters `isolateLtr` would add:
 * those are invisible, and a password copied out of the dialog with three
 * extra code points in it no longer opens anything. `dir="ltr"` and CSS
 * isolation do the same job without touching the text.
 */

import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";

import { BusyButton, BusyStatus } from "@/components/Busy";
import { Button } from "@/components/Button";
import { FailureNotice } from "@/components/FailureNotice";
import { Field } from "@/components/Field";
import { Icon } from "@/components/Icon";
import { TextInput } from "@/components/TextInput";
import { auditKeys } from "@/features/audit/queryKeys";
import { useFocusTrap } from "@/features/connections/focusTrap";
import { useModalRegistration } from "@/hooks/useModalRegistration";
import { isolate, useT } from "@/i18n";
import { asFailure, ipc } from "@/lib/ipc";
import type { IpcFailure, RevealedSecret } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";
import { useApp } from "@/stores/app";

import s from "./RevealPasswordDialog.module.css";

export const REVEAL_MODAL_ID = "tree.reveal";

/** The core's cue that the vault password has to be asked for. */
const CONFIRM_CODE = "secret.reveal-confirm";

/**
 * Failures that leave the question standing: the password was wrong, or the
 * backoff wants a moment. Anything else means there is nothing to show, and
 * the form gives way to the reason.
 */
const RETRYABLE = new Set(["secret.reveal-refused", "vault.unlock-throttled"]);

type Phase =
  | { name: "asking-core" }
  | { name: "confirm" }
  | { name: "shown"; secret: RevealedSecret }
  | { name: "failed"; failure: IpcFailure };

interface RevealPasswordDialogProps {
  nodeId: string;
  onClose: () => void;
}

export function RevealPasswordDialog({ nodeId, onClose }: RevealPasswordDialogProps) {
  const t = useT("connections");
  const tCommon = useT("common");
  const queryClient = useQueryClient();
  const setRevealUntil = useApp((st) => st.setRevealUntil);
  const nodes = useQuery({ queryKey: qk.nodes(), queryFn: () => ipc.listNodes() });
  const name = nodes.data?.find((node) => node.id === nodeId)?.name ?? "";

  // Read once, at mount: whether to try without asking is decided by how the
  // window looked when the dialog opened, not by every tick of the countdown.
  const [phase, setPhase] = useState<Phase>(() => {
    const until = useApp.getState().revealUntil;
    return until !== null && until > Date.now() ? { name: "asking-core" } : { name: "confirm" };
  });
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<IpcFailure | null>(null);

  const dialogRef = useRef<HTMLDivElement | null>(null);
  // StrictMode runs a mount effect twice. Asking twice would write two audit
  // rows for one look, so the first ask is the only one.
  const asked = useRef(false);

  useFocusTrap(true, dialogRef);
  useModalRegistration(REVEAL_MODAL_ID, true);

  const shown = (secret: RevealedSecret) => {
    setRevealUntil(Date.now() + secret.windowRemainingMs);
    setPhase({ name: "shown", secret });
    void queryClient.invalidateQueries({ queryKey: auditKeys.all() });
  };

  useEffect(() => {
    if (phase.name !== "asking-core" || asked.current) return;
    asked.current = true;
    ipc.revealSecret(nodeId, null).then(shown, (error: unknown) => {
      const failed = asFailure(error);
      if (failed.code === CONFIRM_CODE) {
        // The mirror was stale: the core's window had already closed.
        setRevealUntil(null);
        setPhase({ name: "confirm" });
      } else {
        setPhase({ name: "failed", failure: failed });
      }
    });
    // `shown` is recreated every render and only ever calls stable setters.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodeId, phase.name, setRevealUntil]);

  useEffect(() => {
    const onKeyDown = (e: globalThis.KeyboardEvent) => {
      if (e.key !== "Escape") return;
      // A confirmation in flight is let finish, so its outcome — a refusal,
      // or a window that has just opened — is seen rather than lost.
      if (busy) return;
      e.preventDefault();
      e.stopPropagation();
      onClose();
    };
    document.addEventListener("keydown", onKeyDown, true);
    return () => document.removeEventListener("keydown", onKeyDown, true);
  }, [busy, onClose]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (busy || password === "") return;
    setBusy(true);
    setFailure(null);
    const typed = password;
    // Out of the field as soon as it has been handed over: a wrong one is
    // typed again, and a right one has no further use here.
    setPassword("");
    ipc
      .revealSecret(nodeId, typed)
      .then(shown, (error: unknown) => {
        const failed = asFailure(error);
        if (RETRYABLE.has(failed.code)) setFailure(failed);
        else setPhase({ name: "failed", failure: failed });
      })
      .finally(() => setBusy(false));
  };

  return (
    <div className={s.backdrop}>
      <div
        ref={dialogRef}
        className={s.dialog}
        role="dialog"
        aria-modal="true"
        aria-label={t("reveal.title")}
        tabIndex={-1}
      >
        <h2 className={s.title}>
          <Icon name="key" size={16} />
          {t("reveal.title")}
        </h2>
        {name !== "" && <p className={s.subject}>{isolate(name)}</p>}

        <p className={s.audited}>
          <Icon name="alert" size={14} />
          {t("reveal.audited")}
        </p>

        {phase.name === "asking-core" && <BusyStatus label={t("reveal.checking")} />}

        {phase.name === "confirm" && (
          <form className={s.form} onSubmit={submit}>
            <p className={s.intro}>
              {t("reveal.intro", { name: isolate(name) })} {t("reveal.window")}
            </p>
            <Field label={t("reveal.vaultPassword")} htmlFor="reveal-vault-password">
              <TextInput
                id="reveal-vault-password"
                type="password"
                value={password}
                onChange={setPassword}
                autoFocus
                disabled={busy}
                invalid={failure !== null}
              />
            </Field>
            {failure !== null && <FailureNotice failure={failure} />}
            <div className={s.actions}>
              <Button variant="ghost" onClick={onClose} disabled={busy}>
                {tCommon("action.cancel")}
              </Button>
              <BusyButton
                type="submit"
                variant="primary"
                busy={busy}
                busyLabel={t("reveal.checking")}
                disabled={password === ""}
              >
                {t("reveal.confirm")}
              </BusyButton>
            </div>
          </form>
        )}

        {phase.name === "shown" && (
          <>
            <dl className={s.values}>
              {phase.secret.username !== null && (
                <>
                  <dt>{t("reveal.username")}</dt>
                  <dd className={s.value} dir="ltr">
                    {phase.secret.username}
                  </dd>
                </>
              )}
              <dt>{t("reveal.password")}</dt>
              <dd className={s.secret} dir="ltr" data-testid="revealed-password">
                {phase.secret.password}
              </dd>
            </dl>
            {phase.secret.shared && (
              <p className={s.note}>
                {t("reveal.shared", { name: isolate(phase.secret.credentialName) })}
              </p>
            )}
            <div className={s.actions}>
              <Button variant="primary" onClick={onClose}>
                {tCommon("action.close")}
              </Button>
            </div>
          </>
        )}

        {phase.name === "failed" && (
          <>
            <FailureNotice failure={phase.failure} title={t("reveal.failed")} />
            <div className={s.actions}>
              <Button variant="secondary" onClick={onClose}>
                {tCommon("action.close")}
              </Button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
