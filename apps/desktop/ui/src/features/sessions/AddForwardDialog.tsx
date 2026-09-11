/**
 * Opening a port forward.
 *
 * A tunnel is opened against a *node*, not against a session: the core runs
 * stages 1 to 6 itself and starts a forward on a connection of its own, so a
 * forward can outlive any tab. That is why this asks which connection rather
 * than assuming the one in front.
 *
 * The exposure tick is not a formality. `ForwardBind` refuses a non-loopback
 * bind unless it is asked for explicitly, because a warning shown on a
 * listener that is already open has arrived too late
 * (docs/security/transport-security.md). The dialog therefore says what the
 * tick does in the sentence next to it, not in a tooltip.
 */

import { useEffect, useId, useMemo, useRef, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";

import { Button } from "@/components/Button";
import { Field } from "@/components/Field";
import { FailureNotice } from "@/components/FailureNotice";
import { TextInput } from "@/components/TextInput";
import { asFailure, ipc, type ForwardDirection, type TunnelSpec } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";
import { useFocusTrap } from "@/features/connections/focusTrap";
import { useModalRegistration } from "@/hooks/useModalRegistration";
import { useT } from "@/i18n";

import s from "./AddForwardDialog.module.css";

/**
 * The three kinds of forward, in the order the select offers them.
 *
 * A record rather than a key built from the value, so a direction added to
 * `ForwardDirection` without a description is a compile error rather than an
 * option nobody can read.
 */
const DIRECTION_KEYS = {
  local: "forward.directionOption.local",
  remote: "forward.directionOption.remote",
  dynamic: "forward.directionOption.dynamic",
} as const satisfies Record<ForwardDirection, string>;

const DIRECTIONS: readonly ForwardDirection[] = ["local", "remote", "dynamic"];

/** A port as the core wants it, or null when the text is not one. */
function parsePort(text: string): number | null {
  if (!/^\d{1,5}$/.test(text.trim())) return null;
  const value = Number(text.trim());
  return value >= 1 && value <= 65_535 ? value : null;
}

interface AddForwardDialogProps {
  defaultNodeId: string | null;
  onClose: () => void;
  onOpened: () => void;
}

export function AddForwardDialog({ defaultNodeId, onClose, onOpened }: AddForwardDialogProps) {
  const t = useT("sessions");
  const tCommon = useT("common");
  const dialogRef = useRef<HTMLDivElement>(null);
  const ids = useId();

  const [nodeId, setNodeId] = useState(defaultNodeId ?? "");
  const [direction, setDirection] = useState<ForwardDirection>("local");
  const [bindAddress, setBindAddress] = useState("");
  const [bindPort, setBindPort] = useState("");
  const [destinationHost, setDestinationHost] = useState("");
  const [destinationPort, setDestinationPort] = useState("");
  const [exposed, setExposed] = useState(false);

  useFocusTrap(true, dialogRef);
  useModalRegistration("add-forward", true);

  // This dialog sits inside the session panel, which also closes on Escape.
  // Stopping propagation here is what keeps one press from closing both.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      event.stopPropagation();
      onClose();
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [onClose]);

  const nodesQuery = useQuery({ queryKey: qk.nodes(), queryFn: () => ipc.listNodes() });
  const connections = useMemo(
    () => (nodesQuery.data ?? []).filter((n) => n.kind === "connection"),
    [nodesQuery.data],
  );

  const open = useMutation({
    mutationFn: (spec: TunnelSpec) => ipc.openTunnel(nodeId, spec),
    onSuccess: onOpened,
  });

  const bind = parsePort(bindPort);
  const destPort = parsePort(destinationPort);
  const needsDestination = direction !== "dynamic";
  const ready =
    nodeId !== "" &&
    bind !== null &&
    (!needsDestination || (destinationHost.trim() !== "" && destPort !== null));

  const submit = () => {
    if (bind === null) return;
    const address = bindAddress.trim() === "" ? null : bindAddress.trim();
    if (direction === "dynamic") {
      open.mutate({ direction: "dynamic", bindAddress: address, bindPort: bind, exposed });
      return;
    }
    if (destPort === null || destinationHost.trim() === "") return;
    open.mutate({
      direction,
      bindAddress: address,
      bindPort: bind,
      destinationHost: destinationHost.trim(),
      destinationPort: destPort,
      exposed,
    });
  };

  const failure = open.error === null ? null : asFailure(open.error);
  const titleId = `${ids}-title`;
  const portInvalid = t("forward.portInvalid");

  return (
    <div
      className={s.backdrop}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        ref={dialogRef}
        className={s.dialog}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <header className={s.header}>
          <h2 className={s.title} id={titleId}>
            {t("forward.title")}
          </h2>
          <p className={s.lead}>{t("forward.lead")}</p>
        </header>

        <div className={s.body}>
          {connections.length === 0 ? (
            <p className={s.empty}>{t("forward.noConnections")}</p>
          ) : (
            <>
              <Field
                label={t("forward.connection")}
                help={t("forward.connectionHelp")}
                htmlFor={`${ids}-node`}
              >
                <select
                  id={`${ids}-node`}
                  className={s.select}
                  value={nodeId}
                  onChange={(event) => setNodeId(event.target.value)}
                >
                  <option value="">—</option>
                  {connections.map((node) => (
                    <option key={node.id} value={node.id}>
                      {node.name}
                    </option>
                  ))}
                </select>
              </Field>

              <Field label={t("forward.direction")} htmlFor={`${ids}-direction`}>
                <select
                  id={`${ids}-direction`}
                  className={s.select}
                  value={direction}
                  onChange={(event) => setDirection(event.target.value as ForwardDirection)}
                >
                  {DIRECTIONS.map((value) => (
                    <option key={value} value={value}>
                      {t(DIRECTION_KEYS[value])}
                    </option>
                  ))}
                </select>
              </Field>

              <div className={s.pair}>
                <Field
                  label={t("forward.bindAddress")}
                  help={t("forward.bindAddressHelp")}
                  htmlFor={`${ids}-bind-address`}
                >
                  <TextInput
                    id={`${ids}-bind-address`}
                    value={bindAddress}
                    onChange={setBindAddress}
                    placeholder="127.0.0.1"
                    mono
                  />
                </Field>
                <Field
                  label={t("forward.bindPort")}
                  htmlFor={`${ids}-bind-port`}
                  {...(bindPort !== "" && bind === null ? { error: portInvalid } : {})}
                >
                  <TextInput
                    id={`${ids}-bind-port`}
                    value={bindPort}
                    onChange={setBindPort}
                    placeholder="5432"
                    mono
                    invalid={bindPort !== "" && bind === null}
                  />
                </Field>
              </div>

              {needsDestination && (
                <div className={s.pair}>
                  <Field
                    label={t("forward.destinationHost")}
                    help={t("forward.destinationHostHelp")}
                    htmlFor={`${ids}-dest-host`}
                  >
                    <TextInput
                      id={`${ids}-dest-host`}
                      value={destinationHost}
                      onChange={setDestinationHost}
                      placeholder={t("forward.destinationHostPlaceholder")}
                      mono
                    />
                  </Field>
                  <Field
                    label={t("forward.destinationPort")}
                    htmlFor={`${ids}-dest-port`}
                    {...(destinationPort !== "" && destPort === null
                      ? { error: portInvalid }
                      : {})}
                  >
                    <TextInput
                      id={`${ids}-dest-port`}
                      value={destinationPort}
                      onChange={setDestinationPort}
                      placeholder="5432"
                      mono
                      invalid={destinationPort !== "" && destPort === null}
                    />
                  </Field>
                </div>
              )}

              <label className={s.check} htmlFor={`${ids}-exposed`}>
                <input
                  id={`${ids}-exposed`}
                  type="checkbox"
                  checked={exposed}
                  onChange={(event) => setExposed(event.target.checked)}
                />
                <span>
                  <span className={s.checkLabel}>{t("forward.exposed")}</span>
                  <span className={s.checkHelp}>{t("forward.exposedHelp")}</span>
                </span>
              </label>

              {failure !== null && (
                <div className={s.failure}>
                  <FailureNotice failure={failure} title={t("forward.failed")} />
                </div>
              )}
            </>
          )}
        </div>

        <footer className={s.footer}>
          <Button variant="ghost" onClick={onClose}>
            {tCommon("action.cancel")}
          </Button>
          <Button variant="primary" onClick={submit} disabled={!ready || open.isPending}>
            {open.isPending ? tCommon("action.opening") : t("forward.open")}
          </Button>
        </footer>
      </div>
    </div>
  );
}
