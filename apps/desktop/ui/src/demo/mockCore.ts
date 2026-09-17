/**
 * Answers the IPC commands the demo's screens call, from `fixtures.ts`.
 *
 * A command nothing here knows is recorded on `window.__demoUnmocked` and
 * answered with `null`, so a screen that grows a new call shows up as a gap to
 * fill rather than as a silent difference from the real application.
 */

import type { AppSettings, AuditQuery, SessionOpened } from "@/lib/ipc";

import {
  AUDIT,
  AUDIT_ACTORS,
  NODES,
  TERMINAL_OUTPUT,
  VAULT,
  effective,
  settings,
} from "./fixtures";

declare global {
  interface Window {
    __demoUnmocked?: string[];
  }
}

interface ChannelLike {
  onmessage: (message: unknown) => void;
}

const params = new URLSearchParams(window.location.search);
const theme = (params.get("theme") ?? "dark") as AppSettings["theme"];

let nextSession = 1;

export function handle(cmd: string, args: Record<string, unknown> | undefined): unknown {
  switch (cmd) {
    case "vault_state":
      return VAULT;
    case "vault_list_recent":
      return [
        {
          path: VAULT.path,
          label: VAULT.label,
          lastOpened: Date.now() - 3600_000,
          slots: ["password", "recovery"],
          reachable: true,
          unreachableReason: null,
          unreachableKind: null,
          unreachableDetail: null,
          unreachableCode: null,
          syncWarning: null,
          syncProvider: null,
          sizeBytes: 184_320,
        },
      ];
    case "settings_get":
    case "settings_set":
      return settings(theme);
    case "tree_list":
      return NODES;
    case "tree_search":
      return [];
    case "node_resolve":
      return effective(String(args?.["nodeId"] ?? args?.["id"] ?? ""));
    case "protocol_schemas":
    case "shortcuts_list":
    case "session_list":
    case "tunnel_list":
      return [];
    case "vault_settings_get":
      return {
        autoLockMinutes: 15,
        lockOnScreenLock: true,
        lockOnSuspend: true,
        lockOnMinimise: false,
        sessionOnLock: "keep",
        recording: "never",
        backupCount: 3,
      };
    case "audit_query": {
      const query = (args?.["query"] ?? {}) as AuditQuery;
      const entries = query.categories?.includes("warning")
        ? AUDIT.filter((entry) => entry.warning)
        : AUDIT;
      return { entries, total: entries.length, page: 0, pageSize: 200 };
    }
    case "audit_filters":
      return {
        categories: ["connection", "secret", "vault", "node", "warning"],
        outcomes: ["success", "failure", "denied"],
        events: [...new Set(AUDIT.map((entry) => entry.event))],
      };
    case "audit_actors":
      return AUDIT_ACTORS;
    case "password_strength":
      return {
        score: 4,
        entropyBits: 96,
        label: "Strong",
        explanation: "",
        acceptable: true,
      };
    case "session_open":
      return openSession(String(args?.["nodeId"] ?? ""), args?.["channel"] as ChannelLike);
    case "session_resize":
    case "session_input":
    case "session_key":
    case "clipboard_write_text":
      return null;
    default:
      (window.__demoUnmocked ??= []).push(cmd);
      return null;
  }
}

function openSession(nodeId: string, channel: ChannelLike): SessionOpened {
  const node = NODES.find((candidate) => candidate.id === nodeId);
  const opened: SessionOpened = {
    sessionId: nextSession++,
    nodeId,
    name: node?.name ?? "session",
    protocol: node?.protocol ?? "ssh",
    target: `${node?.host ?? "localhost"}:22`,
    username: "deploy",
    authMethod: "publickey",
    via: node?.gateway?.length ? ["bastion"] : [],
    capabilities: {
      kind: "terminal",
      resizable: true,
      clipboard: "text",
      fileTransfer: true,
      audio: false,
      printing: false,
      multiMonitor: false,
      recordable: true,
    },
    startedAtMs: Date.now() - 4 * 60 * 1000,
    recording: "never",
  };
  window.setTimeout(() => {
    channel.onmessage({ event: "opening", sessionId: opened.sessionId });
    channel.onmessage({ event: "ready", ...opened });
    channel.onmessage(new TextEncoder().encode(TERMINAL_OUTPUT).buffer);
  }, 50);
  return opened;
}
