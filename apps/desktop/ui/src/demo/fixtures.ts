/**
 * An invented estate for the screenshots.
 *
 * Every address is from the ranges RFC 5737 reserves for documentation
 * (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and every name is under
 * `example.com`, so nothing on a screenshot points at a machine that exists.
 */

import type {
  AppSettings,
  AuditActor,
  AuditEntry,
  EffectiveConnection,
  TreeNode,
  VaultState,
} from "@/lib/ipc";

const NOW = Date.UTC(2026, 8, 17, 9, 30);

let order = 0;

function base(id: string, parentId: string | null, name: string): TreeNode {
  order += 1;
  return {
    id,
    parentId,
    sortOrder: order,
    kind: "folder",
    name,
    description: "",
    tags: [],
    colour: null,
    protocol: null,
    host: null,
    port: null,
    username: null,
    secretKind: null,
    keyFormat: null,
    hasPassphrase: false,
    agentCommentFilter: null,
    credentialId: null,
    attachedCredentialId: null,
    gateway: null,
    attachedTo: null,
    credentialChange: null,
    inheritedFieldCount: 0,
    updatedAt: NOW,
  };
}

function folder(id: string, parentId: string | null, name: string, colour?: string): TreeNode {
  return { ...base(id, parentId, name), colour: colour ?? null };
}

function connection(
  id: string,
  parentId: string,
  name: string,
  protocol: string,
  host: string,
  extra: Partial<TreeNode> = {},
): TreeNode {
  return {
    ...base(id, parentId, name),
    kind: "connection",
    protocol,
    host,
    port: null,
    inheritedFieldCount: 2,
    ...extra,
  };
}

function credential(id: string, parentId: string, name: string, username: string): TreeNode {
  return {
    ...base(id, parentId, name),
    kind: "credential",
    username,
    secretKind: "password",
  };
}

export const NODES: TreeNode[] = [
  folder("f-prod", null, "Production", "#3b82f6"),
  folder("f-web", "f-prod", "Web tier"),
  connection("c-web1", "f-web", "web-01", "ssh", "203.0.113.11", {
    tags: ["favourite", "nginx"],
    username: "deploy",
    gateway: [{ nodeId: "c-bastion", credentialId: null }],
  }),
  connection("c-web2", "f-web", "web-02", "ssh", "203.0.113.12", { tags: ["nginx"] }),
  connection("c-lb", "f-web", "lb-01", "ssh", "203.0.113.10"),
  folder("f-db", "f-prod", "Databases"),
  connection("c-dbp", "f-db", "db-primary", "ssh", "203.0.113.21", {
    tags: ["favourite", "postgres"],
    gateway: [{ nodeId: "c-bastion", credentialId: null }],
  }),
  connection("c-dbr", "f-db", "db-replica", "ssh", "203.0.113.22", { tags: ["postgres"] }),
  connection("c-bastion", "f-prod", "bastion", "ssh", "bastion.example.com", {
    port: 2222,
    inheritedFieldCount: 1,
  }),
  folder("f-win", null, "Windows servers", "#8b5cf6"),
  connection("c-dc", "f-win", "dc-01", "rdp", "198.51.100.20", { tags: ["favourite"] }),
  connection("c-file", "f-win", "file-01", "rdp", "198.51.100.21"),
  connection("c-build", "f-win", "build-agent", "vnc", "198.51.100.30"),
  folder("f-stg", null, "Staging", "#10b981"),
  connection("c-stgweb", "f-stg", "stg-web", "ssh", "192.0.2.11"),
  connection("c-stgdb", "f-stg", "stg-db", "ssh", "192.0.2.12"),
  connection("c-files", "f-stg", "stg-files", "sftp", "192.0.2.13"),
  folder("f-cred", null, "Credentials"),
  credential("k-deploy", "f-cred", "svc-deploy", "deploy"),
  credential("k-admin", "f-cred", "Domain admin", "EXAMPLE\\administrator"),
];

export const VAULT: VaultState = {
  unlocked: true,
  path: "/home/you/Documents/work.rvault",
  label: "Work",
  connectionCount: NODES.filter((node) => node.kind === "connection").length,
  credentialCount: NODES.filter((node) => node.kind === "credential").length,
  locksInSeconds: 14 * 60,
  kdfUpgradeAvailable: false,
};

export function settings(theme: AppSettings["theme"]): AppSettings {
  return {
    theme,
    locale: "en",
    autoLockMinutes: 15,
    lockOnScreenLock: true,
    lockOnSuspend: true,
    sidebarWidth: 280,
    inspectorOpen: true,
    updateCheckEnabled: false,
    updateChannel: "stable",
    updateLastCheckedAt: null,
    terminalPrefix: "",
    shortcuts: {},
    terminal: {
      palette: "remoter-dark",
      overrides: {},
      fontFamily: "",
      fontSize: 13,
    },
    fileDownloadFolder: null,
  };
}

export function effective(id: string): EffectiveConnection {
  const node = NODES.find((candidate) => candidate.id === id);
  const inProduction = node?.parentId === "f-web" || node?.parentId === "f-db";
  return {
    nodeId: id,
    protocol: node?.protocol ?? "ssh",
    tags: node?.tags ?? [],
    credentialAttached: false,
    gatewayChain: node?.gateway?.length ? ["bastion"] : [],
    fields: [
      { field: "host", value: node?.host ?? null, origin: "own", sourceName: null, sourceId: null, overrides: null },
      {
        field: "port",
        value: node?.port !== null && node?.port !== undefined ? String(node.port) : "22",
        origin: node?.port ? "own" : "default",
        sourceName: null,
        sourceId: null,
        overrides: null,
      },
      {
        field: "username",
        value: inProduction ? "deploy" : null,
        origin: inProduction ? "inherited" : "default",
        sourceName: inProduction ? "Production" : null,
        sourceId: inProduction ? "f-prod" : null,
        overrides: null,
      },
      {
        field: "credential",
        value: inProduction ? "svc-deploy" : null,
        origin: inProduction ? "inherited" : "default",
        sourceName: inProduction ? "Production" : null,
        sourceId: inProduction ? "f-prod" : null,
        overrides: null,
      },
      {
        field: "keepalive_secs",
        value: "30",
        origin: "inherited",
        sourceName: "Production",
        sourceId: "f-prod",
        overrides: null,
      },
    ],
  };
}

const ACTORS: AuditActor[] = [
  { id: 1, machine: "WORKSTATION-7", user: "alex", domain: "EXAMPLE", account: "EXAMPLE\\alex", os: "windows" },
  { id: 2, machine: "laptop", user: "sam", domain: null, account: "sam", os: "linux" },
];

export const AUDIT: AuditEntry[] = [
  ["session_started", "success", "connection", false, "c-web1", "web-01", "ssh deploy@203.0.113.11 via bastion", 0],
  ["secret_used", "success", "secret", false, "k-deploy", "svc-deploy", "password", 0],
  ["file_downloaded", "success", "connection", false, "c-web1", "web-01", "/var/log/nginx/access.log to /home/alex/access.log, 482113 bytes", 0],
  ["trust_rejected", "denied", "connection", true, "c-stgdb", "stg-db", "Refused to connect: the offered host key did not match the pinned one", 1],
  ["data_exported", "success", "node", true, "f-prod", "Production", "connections exported: 7 connections, 2 secrets, remoter-archive, encrypted", 0],
  ["node_updated", "success", "node", false, "c-dbp", "db-primary", null, 1],
  ["vault_unlocked", "success", "vault", false, null, null, "Slot 0 · master password", 0],
  ["data_imported", "success", "node", false, null, null, "imported from mremoteng: folders 4, connections 16, credentials 2, passwords 9", 1],
  ["session_ended", "success", "connection", false, "c-dc", "dc-01", "closed by user", 1],
  ["vault_saved", "success", "vault", false, null, null, null, 0],
].map(([event, outcome, category, warning, nodeId, nodeName, detail, actor], index) => ({
  id: 1000 - index,
  at: NOW - index * 17 * 60 * 1000,
  event: event as string,
  outcome: outcome as AuditEntry["outcome"],
  category: category as AuditEntry["category"],
  warning: warning as boolean,
  nodeId: nodeId as string | null,
  nodeName: nodeName as string | null,
  sessionId: null,
  detail: detail as string | null,
  actor: ACTORS[actor as number] ?? null,
}));

export const AUDIT_ACTORS = ACTORS.map((actor, index) => ({
  actor,
  entries: index === 0 ? 7 : 3,
  lastAt: NOW - index * 3600 * 1000,
}));

/** What the demo terminal prints, as a shell on web-01 would. */
export const TERMINAL_OUTPUT = [
  "Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-45-generic x86_64)\r\n",
  "\r\n",
  "Last login: Wed Sep 17 09:12:44 2026 from 203.0.113.5\r\n",
  "\x1b[1;32mdeploy@web-01\x1b[0m:\x1b[1;34m~\x1b[0m$ uptime\r\n",
  " 09:30:02 up 41 days,  3:17,  1 user,  load average: 0.21, 0.18, 0.15\r\n",
  "\x1b[1;32mdeploy@web-01\x1b[0m:\x1b[1;34m~\x1b[0m$ systemctl status nginx --no-pager | head -4\r\n",
  "\x1b[1;32m●\x1b[0m nginx.service - A high performance web server and a reverse proxy server\r\n",
  "     Loaded: loaded (/usr/lib/systemd/system/nginx.service; enabled; preset: enabled)\r\n",
  "     Active: \x1b[1;32mactive (running)\x1b[0m since Mon 2026-08-07 06:12:51 UTC; 1 month 10 days ago\r\n",
  "   Main PID: 1123 (nginx)\r\n",
  "\x1b[1;32mdeploy@web-01\x1b[0m:\x1b[1;34m~\x1b[0m$ df -h / /var\r\n",
  "Filesystem      Size  Used Avail Use% Mounted on\r\n",
  "/dev/sda1        79G   23G   53G  31% /\r\n",
  "/dev/sdb1       197G   71G  117G  38% /var\r\n",
  "\x1b[1;32mdeploy@web-01\x1b[0m:\x1b[1;34m~\x1b[0m$ ",
].join("");
