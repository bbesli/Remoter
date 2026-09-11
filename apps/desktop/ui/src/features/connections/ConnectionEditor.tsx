/**
 * The connection editor.
 *
 * The point of this screen is provenance. Every inheritable field says where
 * its value came from and offers the one click that changes that — inheritance
 * without a visible source is the single most common confusion in tools that
 * have this feature (docs/features/connections.md). So the resolved view from
 * the core is fetched alongside the node itself, and no field is rendered
 * before both have arrived.
 *
 * Nothing autosaves. Cancel discards, as the docs require: a half-edited
 * connection that silently persists is worse than one that is lost.
 *
 * The password is write-only. There is no command that returns one, so the
 * field can be set and cleared but never read back, and the placeholder is the
 * only thing that ever says a secret exists. On its way out it goes through a
 * ref rather than a mutation variable — TanStack retains variables in the
 * MutationCache after the call settles, and a plaintext password sitting there
 * for the life of the cache is exactly what UnlockScreen.tsx warns against.
 * The key passphrase travels the same way, for the same reason.
 *
 * The login — username, secret and method — is one thing, not three. The data
 * model puts all of it on a credential node so that one service account can be
 * shared by two hundred connections (docs/architecture/data-model.md), and the
 * core routes a username or a secret typed on a CONNECTION onto the credential
 * that connection owns, creating one where there is none. So this form sends
 * `username`, `password` and `credential` straight to the connection and lets
 * the core place them; it never writes a credential node itself, and it never
 * sends `credentialId` alongside them — the two together are refused, because
 * one says "use that shared credential" and the other says "have one of your
 * own".
 *
 * That is also why "revert to inherited" is a single instruction here
 * (`clearOverrides: ["credential"]`) rather than one per field: username and
 * secret are not the connection's to reset individually.
 *
 * The case the shape exists for: when the credential is inherited from a
 * folder, or shared with other connections, editing it in place would change
 * every connection that uses it. It is never edited in place. Typing a
 * username gives THIS connection one of its own, which overrides what it was
 * using — and the form says so, in one line, at the moment it becomes true.
 */

import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { TFunction } from "i18next";
import { open } from "@tauri-apps/plugin-dialog";
import clsx from "clsx";
import { create } from "zustand";

import { Badge } from "@/components/Badge";
import { BusyButton, BusyStatus, SkeletonRows } from "@/components/Busy";
import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Field } from "@/components/Field";
import { Icon } from "@/components/Icon";
import { TextInput } from "@/components/TextInput";
import { isolate, isolateLtr, useT } from "@/i18n";
import {
  asFailure,
  ipc,
  type CreateNode,
  type CredentialInput,
  type EffectiveConnection,
  type IpcFailure,
  type KeyFormat,
  type PrivateKeyInfo,
  type ResolvedField,
  type SecretKind,
  type TreeNode,
  type UpdateNode,
} from "@/lib/ipc";
import { invalidateAfterTreeChange, qk } from "@/lib/queryKeys";
import { useApp } from "@/stores/app";
import { useModalRegistration } from "@/hooks/useModalRegistration";

import { useFocusTrap } from "./focusTrap";
import { nodeGlyph, protocolClass } from "./NodeRow";
import s from "./ConnectionEditor.module.css";

/**
 * The editor's translator, for the helpers that are pure functions rather than
 * components. They take it as an argument because `useT` is a hook and a
 * breadcrumb is not a component.
 */
type Copy = TFunction<"connections">;

/**
 * The keys of the two messages below that are chosen by data rather than
 * written at the call site: which protocol, and which setting.
 *
 * Spelled as a union of the literals rather than as `string`, so that renaming
 * one of them is a compile error here instead of a blank line on screen. The
 * `as const` on each table is what produces it — the same shape `SessionSurface`
 * uses for its close-reason and prompt-kind tables, and for the same reason.
 */
type CopyKey =
  | (typeof PROTOCOL_LIMITS)[keyof typeof PROTOCOL_LIMITS]
  | (typeof SETTING_NOTES)[keyof typeof SETTING_NOTES];

/**
 * The protocols the shipped adapters cover. A plugin protocol widens this.
 *
 * Every one of them can now be opened. This list used to be filtered by a
 * second set naming the ones with an adapter, because `session_open` refused
 * RDP and VNC by name and choosing one produced a connection that could be
 * saved and never opened. Both adapters exist, and `session_open`'s gate now
 * admits all four — so the filter is gone rather than left as a restriction
 * nobody would think to lift.
 */
const PROTOCOLS = ["ssh", "sftp", "rdp", "vnc"] as const;

const DEFAULT_PORTS: Readonly<Record<string, string>> = {
  ssh: "22",
  sftp: "22",
  rdp: "3389",
  vnc: "5900",
};

/**
 * The protocols that can authenticate with a key or an agent. RDP and VNC
 * cannot, and offering it there would be an option that fails at connect time
 * for a reason the interface knew about all along.
 */
const KEY_AUTH_PROTOCOLS: ReadonlySet<string> = new Set(["ssh", "sftp"]);

/**
 * The file browser's filters. The named entry makes the usual key obvious;
 * "All files" is what keeps every other key reachable, because a private key
 * is identified by its content and not by its name — `key_inspect` reads the
 * container rather than the extension for exactly that reason.
 */
function keyFilters(t: Copy): { name: string; extensions: string[] }[] {
  return [
    { name: t("editor.keyFilterPrivateKey"), extensions: ["pem", "key", "ppk", "pk8"] },
    { name: t("editor.keyFilterAllFiles"), extensions: ["*"] },
  ];
}

// ------------------------------------------------------------- the store ----

export type EditorTarget =
  | { mode: "edit"; nodeId: string }
  | { mode: "create"; parentId: string | null; kind: "folder" | "connection" };

interface EditorStore {
  target: EditorTarget | null;
  open: (target: EditorTarget) => void;
  close: () => void;
}

/**
 * Which node the editor is showing, if any.
 *
 * The tree and the palette both open the editor, and only one of them is
 * guaranteed to be mounted, so the request lives outside both of them.
 */
export const useConnectionEditor = create<EditorStore>((set) => ({
  target: null,
  open: (target) => set({ target }),
  close: () => set({ target: null }),
}));

// ------------------------------------------------------------ form model ----

/** One editable field: either set on this node, or taken from an ancestor. */
interface Draft {
  own: boolean;
  value: string;
}

interface Provenance {
  /** The value that would apply if this node set nothing. */
  inheritedValue: string | null;
  /** The folder the inherited value comes from; null for a protocol default. */
  inheritedSource: string | null;
  /** False when nothing above this node supplies the field. */
  canInherit: boolean;
}

const NO_PROVENANCE: Provenance = {
  inheritedValue: null,
  inheritedSource: null,
  canInherit: false,
};

function provenanceOf(field: ResolvedField | undefined): Provenance {
  if (field === undefined) return NO_PROVENANCE;
  if (field.origin === "own") {
    return {
      inheritedValue: field.overrides,
      inheritedSource: field.sourceName,
      canInherit: field.overrides !== null,
    };
  }
  return {
    inheritedValue: field.value,
    inheritedSource: field.origin === "inherited" ? field.sourceName : null,
    canInherit: true,
  };
}

function draftOf(field: ResolvedField | undefined): Draft {
  if (field === undefined) return { own: true, value: "" };
  return { own: field.origin === "own", value: field.origin === "own" ? (field.value ?? "") : "" };
}

function findField(
  resolved: EffectiveConnection | undefined,
  name: string,
): ResolvedField | undefined {
  return resolved?.fields.find((f) => f.field === name);
}

/**
 * How the core names a protocol setting among the resolved fields.
 *
 * `node_resolve` flattens the adapter's settings map into the same list as
 * `host` and `port`, one entry per key, each carrying its own provenance. The
 * prefix is what tells the two apart.
 */
const SETTINGS_PREFIX = "settings.";

/** One protocol setting, as the core resolved it. */
interface ProtocolSetting {
  /**
   * The adapter's own key — `domain`, `rfb_version_min`, `desktop_width`. A
   * wire identifier, so it is shown as it is and never translated.
   */
  key: string;
  value: string;
  own: boolean;
  provenance: Provenance;
}

/**
 * The protocol settings this connection carries, in the core's order.
 *
 * Read out of the resolved view rather than listed here, because the list of
 * settings belongs to the adapter: RDP's schema names nine, VNC's names six,
 * and duplicating either here would mean a form that disagrees with the thing
 * that reads it the day one of them changes. What appears is what the core
 * resolved — set on this connection, inherited from a folder, or absent.
 */
function protocolSettings(resolved: EffectiveConnection | undefined): ProtocolSetting[] {
  if (resolved === undefined) return [];
  return resolved.fields
    .filter((field) => field.field.startsWith(SETTINGS_PREFIX))
    .map((field) => ({
      key: field.field.slice(SETTINGS_PREFIX.length),
      value: field.value ?? "",
      own: field.origin === "own",
      provenance: provenanceOf(field),
    }));
}

/**
 * What this build's adapter does **not** do, per protocol.
 *
 * Stated rather than left as an absence. Both framebuffer adapters report
 * `clipboard: "none"` from their own `capabilities()`, and neither carries a
 * redirection channel, so the settings for those things do not exist — and a
 * screen that simply omitted them would read as an oversight rather than as
 * the answer. The sentences are kept in step with the adapters' own
 * `capabilities()` and module documentation; that is where the truth is.
 */
const PROTOCOL_LIMITS = {
  rdp: "editor.protocolLimits.rdp",
  vnc: "editor.protocolLimits.vnc",
} as const;

function protocolLimitsKey(protocol: string): CopyKey | null {
  if (protocol === "rdp" || protocol === "vnc") return PROTOCOL_LIMITS[protocol];
  return null;
}

/**
 * The one line a particular setting's value earns, when its value has a
 * consequence the screen has to state.
 *
 * Keyed by protocol as well as by setting name: `shared` means one thing to
 * RFB (RFC 6143 §7.3.1, whether other viewers stay connected) and would mean
 * something else entirely to another adapter.
 */
const SETTING_NOTES = {
  rdpDomain: "editor.settingNote.rdpDomain",
  rdpNlaOff: "editor.settingNote.rdpNlaOff",
  vncFloor: "editor.settingNote.vncFloor",
  vncFloorLowered: "editor.settingNote.vncFloorLowered",
  vncExclusive: "editor.settingNote.vncExclusive",
  vncViewOnly: "editor.settingNote.vncViewOnly",
} as const;

/** The RFB version the floor sits at unless somebody lowered it. */
const RFB_DEFAULT_FLOOR = "3.8";

function settingNoteKey(protocol: string, key: string, value: string): CopyKey | null {
  if (protocol === "rdp") {
    if (key === "domain") return SETTING_NOTES.rdpDomain;
    // Only when it is off. On is the default and the documented position, and
    // a warning that fires on the safe setting is a warning people stop
    // reading.
    if (key === "network_level_authentication" && value === "false") {
      return SETTING_NOTES.rdpNlaOff;
    }
  }
  if (protocol === "vnc") {
    if (key === "rfb_version_min") {
      return value === RFB_DEFAULT_FLOOR ? SETTING_NOTES.vncFloor : SETTING_NOTES.vncFloorLowered;
    }
    if (key === "shared" && value === "false") return SETTING_NOTES.vncExclusive;
    if (key === "view_only" && value === "true") return SETTING_NOTES.vncViewOnly;
  }
  return null;
}

/** How this connection proves who it is, in order of increasing exposure. */
export type AuthMethod = "agent" | "privateKey" | "password";

/**
 * Where the login this entry uses comes from, before this edit.
 *
 * The distinction is the whole point of the screen: `own` may be edited in
 * place, while `inherited` and `shared` belong to other entries and are never
 * rewritten from here.
 */
export type IdentityOrigin =
  | { kind: "own" }
  | { kind: "inherited"; source: string }
  | { kind: "shared"; name: string }
  | { kind: "none" };

function identityOriginOf(
  node: TreeNode | undefined,
  resolved: EffectiveConnection | undefined,
): IdentityOrigin {
  if (node === undefined) return { kind: "none" };
  // A credential node is a login; nothing above it supplies one.
  if (node.kind === "credential") return { kind: "own" };
  // Set on this connection and belonging to it alone — the only case this
  // editor may write in place.
  if (node.attachedCredentialId !== null) return { kind: "own" };

  const field = findField(resolved, "credential");
  if (field === undefined || field.value === null || field.value === "") return { kind: "none" };
  if (field.origin === "inherited") {
    return { kind: "inherited", source: field.sourceName ?? field.value };
  }
  // Set here, but not this connection's own: a credential the user picked,
  // which other connections may point at too.
  if (field.origin === "own") return { kind: "shared", name: field.value };
  return { kind: "none" };
}

/** The login as it stood when the form was seeded. */
interface IdentityState {
  /** Whether this entry owns the credential its login lives on. */
  own: boolean;
  username: string;
  auth: AuthMethod;
  agentFilter: string;
}

interface FormState {
  name: string;
  description: string;
  tags: string;
  protocol: string;
  host: Draft;
  port: Draft;
  /**
   * Whether the login shown is this entry's own.
   *
   * False means it comes from a folder or a shared credential: the fields are
   * shown but not edited, because editing them would change what every other
   * connection using that credential logs in as.
   */
  identityOwn: boolean;
  username: string;
  /** The new secret, held only until save hands it to the core. */
  password: string;
  passwordTouched: boolean;
  auth: AuthMethod;
  /** Narrows which of the agent's identities is used. Not a secret. */
  agentFilter: string;
  /** The key file chosen in this session. Empty means "leave the stored key alone". */
  keyPath: string;
  /** Held only until save hands it to the core. Never read back, never shown. */
  keyPassphrase: string;
}

/**
 * Which method a login authenticates with.
 *
 * `secretKind` belongs to a credential; on a connection the DTO reports the
 * one attached to it, which is what lets this form show a method without the
 * user ever learning that credential nodes exist. `external` and `certificate`
 * are not editable here yet, and fall back to the password tab rather than to
 * a blank chooser.
 */
function authOf(secretKind: SecretKind | null): AuthMethod {
  if (secretKind === "agent") return "agent";
  if (secretKind === "privateKey") return "privateKey";
  return "password";
}

/** The login the form starts from, for an entry that owns one or does not. */
function seedIdentity(node: TreeNode, origin: IdentityOrigin): IdentityState {
  const own = origin.kind === "own";
  return {
    own,
    username: own ? (node.username ?? "") : "",
    auth: own ? authOf(node.secretKind) : "password",
    agentFilter: own ? (node.agentCommentFilter ?? "") : "",
  };
}

/** The file's own name; the directory is noise beside a chosen path. */
function fileName(path: string): string {
  const cut = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  return cut >= 0 ? path.slice(cut + 1) : path;
}

/**
 * The credential input the chosen method needs, or null when the method is a
 * password (which travels as `password`, never as both) or when a stored key
 * is being left alone.
 *
 * The passphrase is deliberately absent: this object becomes a mutation
 * variable, and TanStack keeps those after the call settles. It is put back in
 * the mutation function, from the ref.
 */
function credentialInputFor(form: FormState): CredentialInput | null {
  if (form.auth === "agent") {
    const filter = form.agentFilter.trim();
    return { kind: "agent", commentFilter: filter === "" ? null : filter };
  }
  if (form.auth === "privateKey" && form.keyPath !== "") {
    return { kind: "privateKey", path: form.keyPath, passphrase: null };
  }
  return null;
}

/** Puts the passphrase back, on the way to the core and nowhere else. */
function withPassphrase(
  input: CredentialInput | null | undefined,
  passphrase: string | null,
): CredentialInput | null {
  if (input === null || input === undefined) return null;
  if (input.kind !== "privateKey") return input;
  return { ...input, passphrase };
}

function parseTags(input: string): string[] {
  return input
    .split(",")
    .map((tag) => tag.trim())
    .filter((tag) => tag.length > 0);
}

// ------------------------------------------------------------- the shell ----

export function ConnectionEditor() {
  const target = useConnectionEditor((st) => st.target);
  if (target === null) return null;

  const key =
    target.mode === "edit" ? `edit:${target.nodeId}` : `create:${target.kind}:${target.parentId}`;

  return <EditorDialog key={key} target={target} />;
}

function EditorDialog({ target }: { target: EditorTarget }) {
  const t = useT("connections");
  const tCommon = useT("common");
  const close = useConnectionEditor((st) => st.close);
  const select = useApp((st) => st.select);
  const queryClient = useQueryClient();

  const dialogRef = useRef<HTMLDivElement | null>(null);
  const footerRef = useRef<HTMLElement | null>(null);

  const nodesQuery = useQuery({ queryKey: qk.nodes(), queryFn: () => ipc.listNodes() });
  const nodes = useMemo(() => nodesQuery.data ?? [], [nodesQuery.data]);

  const node: TreeNode | undefined =
    target.mode === "edit" ? nodes.find((n) => n.id === target.nodeId) : undefined;

  // Only a connection has an inheritance chain worth resolving; a folder is
  // the source of one, not a consumer.
  const resolvable = target.mode === "edit" && node?.kind === "connection";
  const resolveId = target.mode === "edit" ? target.nodeId : "";
  const resolveQuery = useQuery({
    queryKey: qk.resolve(resolveId),
    queryFn: () => ipc.resolveNode(resolveId),
    enabled: resolvable,
  });

  /*
   * Both queries gate the form, and the query client is configured with
   * `retry: false`, so a single rejection used to leave this dialog on its
   * skeleton for good: no message, no way back, only the close button. The
   * core's own failure is shown instead, with the retry it deserves.
   */
  const loadError = nodesQuery.error ?? (resolvable ? resolveQuery.error : null);
  const loadFailure = loadError === null ? null : asFailure(loadError);
  const retryLoad = () => {
    void nodesQuery.refetch();
    if (resolvable) void resolveQuery.refetch();
  };

  const resolved = resolveQuery.data;
  const origin = useMemo(() => identityOriginOf(node, resolved), [node, resolved]);

  const [form, setForm] = useState<FormState | null>(null);
  const [attempted, setAttempted] = useState(false);

  // Seed the form once, from the node and its resolved view. Re-seeding on
  // every refetch would throw away what the user is typing.
  useEffect(() => {
    if (form !== null) return;
    if (target.mode === "create") {
      const protocol = target.kind === "connection" ? "ssh" : "";
      setForm({
        name: "",
        description: "",
        tags: "",
        protocol,
        host: { own: true, value: "" },
        port: { own: true, value: "" },
        identityOwn: true,
        username: "",
        password: "",
        passwordTouched: false,
        /*
         * A password, even though the agent is the recommended method. A new
         * connection that defaulted to the agent would seal an agent choice
         * into the vault for anyone who typed a name and a host and pressed
         * Create — a login they did not ask for, holding a choice they did not
         * make. The agent is one click away and says why it is worth the click.
         */
        auth: "password",
        agentFilter: "",
        keyPath: "",
        keyPassphrase: "",
      });
      return;
    }
    if (node === undefined) return;
    if (resolvable && resolveQuery.data === undefined) return;

    const identity = seedIdentity(node, origin);
    setForm({
      name: node.name,
      description: node.description,
      tags: node.tags.join(", "),
      protocol: node.protocol ?? "",
      host: resolved ? draftOf(findField(resolved, "host")) : { own: true, value: node.host ?? "" },
      port: resolved
        ? draftOf(findField(resolved, "port"))
        : { own: true, value: node.port === null ? "" : String(node.port) },
      /*
       * An entry with nothing to inherit starts on its own empty login: the
       * common case is one server and one password, and making that person
       * press "Override here" over a login that does not exist would be a tax
       * for nothing.
       */
      identityOwn: identity.own || origin.kind === "none",
      username: identity.username,
      password: "",
      passwordTouched: false,
      auth: identity.auth,
      agentFilter: identity.agentFilter,
      keyPath: "",
      keyPassphrase: "",
    });
  }, [form, node, origin, resolvable, resolveQuery.data, resolved, target]);

  const initial = useMemo(() => {
    if (target.mode === "create" || node === undefined) return null;
    return {
      host: resolved ? draftOf(findField(resolved, "host")) : { own: true, value: node.host ?? "" },
      port: resolved
        ? draftOf(findField(resolved, "port"))
        : { own: true, value: node.port === null ? "" : String(node.port) },
      identity: seedIdentity(node, origin),
    };
  }, [node, origin, resolved, target.mode]);

  const parentId = target.mode === "create" ? target.parentId : (node?.parentId ?? null);
  const path = useMemo(() => breadcrumb(t, nodes, parentId), [nodes, parentId, t]);

  /*
   * The typed secret lives here and nowhere else on its way out.
   *
   * TanStack keeps `mutation.variables` in the MutationCache after the call
   * settles, so a password passed as a variable stays reachable in memory for
   * the life of the cache. The mutation function reads the ref, hands the value
   * straight to the command, and `onSettled` drops it — success or failure.
   */
  const passwordRef = useRef<string | null>(null);
  const passphraseRef = useRef<string | null>(null);

  // A dialog torn down mid-flight must not leave the secrets behind either.
  useEffect(
    () => () => {
      passwordRef.current = null;
      passphraseRef.current = null;
    },
    [],
  );

  /*
   * What the chosen key file is, without any of what is in it.
   *
   * This is asked before the passphrase field is drawn, so a key that needs no
   * passphrase is never asked for one — `key_inspect` reads the container out
   * of the file's content and returns a format, a flag and a size. Held in
   * state rather than read from `inspect.data` so that choosing a second file
   * cannot leave the first file's answer on screen: the core may hand back a
   * canonicalised path, which makes comparing the two an unreliable guard.
   */
  const [keyInfo, setKeyInfo] = useState<PrivateKeyInfo | null>(null);
  const [keyDialogError, setKeyDialogError] = useState<string | null>(null);
  const [keyBrowsing, setKeyBrowsing] = useState(false);

  const inspect = useMutation({
    mutationFn: (path: string) => ipc.inspectKey(path),
    onSuccess: (info) => setKeyInfo(info),
  });
  const inspectFailure = inspect.error === null ? null : asFailure(inspect.error);

  const createMutation = useMutation({
    mutationFn: async (args: {
      input: Omit<CreateNode, "password" | "credential" | "credentialId">;
      credential: CredentialInput | null;
    }) => {
      // The secrets join the request here, from the refs. A bare `password`
      // and a `credential` together are refused by the core rather than
      // guessed at, which the method chooser already guarantees.
      const credential = withPassphrase(args.credential, passphraseRef.current);
      return ipc.createNode({
        ...args.input,
        password: passwordRef.current,
        ...(credential === null ? {} : { credential }),
      });
    },
    onSuccess: async (created) => {
      await invalidateAfterTreeChange(queryClient);
      select(created.id);
      close();
    },
    onSettled: () => {
      passwordRef.current = null;
      passphraseRef.current = null;
    },
  });

  const updateMutation = useMutation({
    mutationFn: async (args: { id: string; patch: UpdateNode; setsPassword: boolean }) => {
      const patch: UpdateNode = { ...args.patch };
      const credential = withPassphrase(patch.credential, passphraseRef.current);
      if (credential !== null) patch.credential = credential;
      if (args.setsPassword && passwordRef.current !== null) {
        patch.password = passwordRef.current;
      }
      return ipc.updateNode(args.id, patch);
    },
    onSuccess: async () => {
      await invalidateAfterTreeChange(queryClient);
      close();
    },
    onSettled: () => {
      passwordRef.current = null;
      passphraseRef.current = null;
    },
  });

  const busy = createMutation.isPending || updateMutation.isPending;
  const failure =
    createMutation.error !== null
      ? asFailure(createMutation.error)
      : updateMutation.error !== null
        ? asFailure(updateMutation.error)
        : null;

  const isConnection =
    target.mode === "create" ? target.kind === "connection" : node?.kind === "connection";
  // A connection and a credential are the two kinds that carry a login. A
  // folder passes one down; it does not have one.
  const hasIdentity = isConnection === true || node?.kind === "credential";

  const plan = useMemo(() => {
    if (form === null || node === undefined || initial === null) return null;
    return buildPatch(form, node, initial, {
      isConnection: isConnection === true,
      hasIdentity,
    });
  }, [form, node, initial, isConnection, hasIdentity]);

  /*
   * The login this connection would fall back to, and where it comes from.
   * Both are read from the resolved view rather than guessed, because the
   * inherited value may be several folders up.
   */
  const credentialProvenance = provenanceOf(findField(resolved, "credential"));
  const inheritedUsername = findField(resolved, "username")?.value ?? null;

  /*
   * What handing this login back would leave in its place, or null when there
   * is nothing to hand it back to and nothing of its own to remove.
   */
  const revertLabel = useMemo(() => {
    if (target.mode !== "edit") return null;
    const fallback =
      credentialProvenance.inheritedValue ??
      (origin.kind === "inherited" ? origin.source : origin.kind === "shared" ? origin.name : null);
    if (fallback !== null) return t("editor.revertTo", { value: isolate(fallback) });
    // Nothing above supplies one. The login can still be taken away, and the
    // connection then has none — which the core allows and asks about at
    // connect time.
    return initial?.identity.own === true ? t("editor.loginRemove") : null;
  }, [credentialProvenance.inheritedValue, initial, origin, target.mode, t]);

  /*
   * The consequence, said once, at the moment it becomes true: this edit will
   * write a login, and the login it replaces belongs to something else. It is
   * not a warning — the user is doing something reasonable — but the folder's
   * credential is not being changed under them, and they deserve to know.
   */
  const consequence =
    plan?.identity !== "writes"
      ? null
      : origin.kind === "inherited"
        ? t("editor.consequenceInherited", { source: isolate(origin.source) })
        : origin.kind === "shared"
          ? t("editor.consequenceShared", { name: isolate(origin.name) })
          : null;

  const identityDirty =
    form !== null &&
    (form.username !== "" ||
      form.password !== "" ||
      form.auth !== "password" ||
      form.keyPath !== "");

  /*
   * Choosing a different method is a change even before the secret it needs
   * has been typed. Without this the form is not dirty, Save is disabled, and
   * the screen shows a method that is not the one stored — with no way to find
   * out why nothing happens.
   */
  const methodChanged =
    form !== null &&
    form.identityOwn &&
    initial?.identity.own === true &&
    form.auth !== initial.identity.auth;

  const dirty =
    target.mode === "create"
      ? form !== null && (form.name !== "" || form.host.value !== "" || identityDirty)
      : plan !== null && (Object.keys(plan.patch).length > 0 || plan.setsPassword || methodChanged);

  const keyStored = initial?.identity.own === true && initial.identity.auth === "privateKey";

  const errors =
    form === null
      ? {}
      : validate(t, form, {
          isConnection: isConnection === true,
          hasIdentity,
          mode: target.mode,
          keyInfo,
          inspecting: inspect.isPending,
          keyStored,
          initialAuth: initial?.identity.own === true ? initial.identity.auth : null,
        });
  const hasErrors = Object.keys(errors).length > 0;

  const [discardPrompt, setDiscardPrompt] = useState(false);

  const onCancel = () => {
    if (busy) return;
    // The same guard Escape applies. Without it the two most obvious ways out
    // of the dialog — the footer Cancel and the header X — discarded unsaved
    // work silently, while Escape and a backdrop click asked first.
    if (dirty) {
      setDiscardPrompt(true);
      return;
    }
    close();
  };

  /*
   * Escape obeys the two guards the rest of the dialog already obeys: a save in
   * flight owns the dialog, and unsaved work is asked about rather than thrown
   * away. It used to close unconditionally, which discarded edits that a stray
   * backdrop click was careful to protect and abandoned in-flight saves whose
   * rejection then had nowhere to appear.
   */
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      // Swallowed either way: this is a modal, and the tree behind it must not
      // act on the same press.
      e.stopPropagation();
      if (busy) return;
      if (discardPrompt) {
        setDiscardPrompt(false);
        return;
      }
      if (dirty) {
        setDiscardPrompt(true);
        return;
      }
      close();
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [busy, dirty, discardPrompt, close]);

  // The question is worthless if the answer cannot be reached from the keyboard
  // that asked it, and "Keep editing" is the first control in the footer.
  useEffect(() => {
    if (!discardPrompt) return;
    footerRef.current?.querySelector("button")?.focus();
  }, [discardPrompt]);

  // `aria-modal` promises the rest of the window is inert. Nothing enforces
  // that but this.
  useFocusTrap(true, dialogRef);
  useModalRegistration("connection-editor", true);

  const submit = () => {
    if (form === null || busy) return;
    // Errors surface on the first attempt, not while the field is being typed.
    setAttempted(true);
    if (hasErrors) return;
    if (target.mode === "create") {
      const port = form.port.value.trim();
      const writesIdentity = target.kind === "connection";
      // The secrets go into the refs, never into the variables.
      passwordRef.current =
        writesIdentity && form.auth === "password" && form.password !== "" ? form.password : null;
      passphraseRef.current =
        writesIdentity && form.auth === "privateKey" && form.keyPassphrase !== ""
          ? form.keyPassphrase
          : null;
      createMutation.mutate({
        input: {
          parentId: target.parentId,
          kind: target.kind,
          name: form.name.trim(),
          protocol: writesIdentity ? form.protocol : null,
          host: writesIdentity ? nullIfBlank(form.host.value) : null,
          port: port === "" ? null : Number(port),
          // Lands on a credential the core attaches to this connection. That
          // is the whole reason typing a username on one server just works.
          username: writesIdentity ? nullIfBlank(form.username) : null,
        },
        credential: writesIdentity ? credentialInputFor(form) : null,
      });
      return;
    }
    if (node === undefined || plan === null) return;
    passwordRef.current = plan.setsPassword ? form.password : null;
    passphraseRef.current =
      plan.patch.credential?.kind === "privateKey" && form.keyPassphrase !== ""
        ? form.keyPassphrase
        : null;
    updateMutation.mutate({ id: node.id, patch: plan.patch, setsPassword: plan.setsPassword });
  };

  /**
   * Choose a key file, then ask the core what it is.
   *
   * The dialog plugin rejects when the platform's file browser cannot start.
   * Left unhandled, the button becomes one that does nothing and the save then
   * refuses for a reason the user never saw.
   */
  async function chooseKey() {
    let picked: string | string[] | null;
    setKeyBrowsing(true);
    try {
      picked = await open({
        title: t("editor.keyDialogTitle"),
        multiple: false,
        directory: false,
        filters: keyFilters(t),
      });
    } catch {
      setKeyDialogError(t("editor.keyDialogFailed"));
      return;
    } finally {
      setKeyBrowsing(false);
    }
    setKeyDialogError(null);
    const chosen = Array.isArray(picked) ? picked[0] : picked;
    if (typeof chosen !== "string" || form === null) return;
    // The previous file's answer and passphrase go with the previous file.
    setKeyInfo(null);
    inspect.reset();
    setForm({ ...form, keyPath: chosen, keyPassphrase: "" });
    inspect.mutate(chosen);
  }

  const missing = target.mode === "edit" && nodesQuery.isSuccess && node === undefined;
  const loading = form === null && !missing && loadFailure === null;

  return (
    <div
      className={s.backdrop}
      onMouseDown={(e) => {
        // A stray backdrop click must not discard work in progress.
        if (e.target === e.currentTarget && !dirty) close();
      }}
    >
      <div
        ref={dialogRef}
        className={s.dialog}
        role="dialog"
        aria-modal="true"
        aria-label={headerLabel(t, target, node)}
        // Somewhere for focus to land while the form is still loading and the
        // dialog holds nothing but the close button.
        tabIndex={-1}
      >
        <header className={s.header}>
          <span className={headerGlyphClass(node)}>
            <Icon
              name={
                node
                  ? nodeGlyph(node)
                  : target.mode === "create" && target.kind === "folder"
                    ? "folder"
                    : "server"
              }
              size={16}
            />
          </span>
          <h2 className={s.title}>{headerLabel(t, target, node)}</h2>
          {path !== "" && (
            <span className={s.path}>{t("editor.locationPath", { path })}</span>
          )}
          <span className={s.headerSpacer} />
          <button
            type="button"
            className={s.close}
            aria-label={t("editor.close")}
            onClick={onCancel}
          >
            <Icon name="x" size={14} />
          </button>
        </header>

        {/* The dialog is already open at its full size, so an empty body would
            be a hole in the middle of the window. */}
        {loading && (
          <div className={s.loading}>
            <BusyStatus label={t("editor.loading")} size={14} />
            <div className={s.loadingFields}>
              <SkeletonRows count={4} height="var(--space-8)" widths={["100%"]} />
            </div>
          </div>
        )}

        {loadFailure !== null && (
          <div className={s.body}>
            <FailureNotice
              failure={loadFailure}
              title={t("editor.loadFailed")}
              onRetry={retryLoad}
              retryLabel={tCommon("action.retry")}
            >
              {/* A dialog that cannot load still has to be leavable without
                  hunting for the corner. */}
              <Button variant="ghost" size="sm" onClick={onCancel}>
                {t("editor.close")}
              </Button>
            </FailureNotice>
          </div>
        )}

        {missing && (
          <div className={s.body}>
            <Callout tone="warning">{t("editor.missing")}</Callout>
          </div>
        )}

        {form !== null && (
          <>
            <form
              className={s.body}
              onSubmit={(e) => {
                e.preventDefault();
                submit();
              }}
            >
              {failure !== null && (
                <FailureNotice failure={failure} title={t("editor.saveFailed")} />
              )}

              <section className={s.section}>
                <div className={s.sectionTitle}>{t("editor.sectionIdentity")}</div>

                <Field
                  label={t("editor.name")}
                  htmlFor="editor-name"
                  error={attempted ? errors.name : undefined}
                >
                  <TextInput
                    id="editor-name"
                    value={form.name}
                    onChange={(v) => setForm({ ...form, name: v })}
                    autoFocus
                    invalid={attempted && errors.name !== undefined}
                  />
                  <span className={s.provenance}>
                    <span className={s.provenanceDot} />
                    {t("editor.setHere")}
                  </span>
                </Field>

                {isConnection === true && (
                  <>
                    <Field
                      label={t("editor.protocol")}
                      htmlFor="editor-protocol"
                      help={
                        target.mode === "edit" ? t("editor.protocolFixedHelp") : undefined
                      }
                    >
                      {target.mode === "create" ? (
                        <select
                          id="editor-protocol"
                          className={s.select}
                          value={form.protocol}
                          onChange={(e) => {
                            const protocol = e.target.value;
                            // RDP and VNC cannot use a key or the agent, so a
                            // choice made under SSH does not survive the
                            // switch — it would be sent and then fail at
                            // connect time.
                            const auth = KEY_AUTH_PROTOCOLS.has(protocol) ? form.auth : "password";
                            setForm({
                              ...form,
                              protocol,
                              auth,
                              keyPassphrase: auth === "privateKey" ? form.keyPassphrase : "",
                            });
                          }}
                        >
                          {/* A protocol name is a wire identifier and is never
                              translated — docs/features/i18n.md, "What is never
                              translated". */}
                          {PROTOCOLS.map((p) => (
                            <option key={p} value={p}>
                              {p}
                            </option>
                          ))}
                        </select>
                      ) : (
                        <div className={s.readOnlyRow}>
                          <Badge tone="accent" mono>
                            {form.protocol === "" ? t("editor.protocolNone") : form.protocol}
                          </Badge>
                        </div>
                      )}
                    </Field>

                    <InheritableField
                      id="editor-host"
                      label={t("editor.host")}
                      mono
                      draft={form.host}
                      provenance={provenanceOf(findField(resolved, "host"))}
                      error={attempted ? errors.host : undefined}
                      onChange={(host) => setForm({ ...form, host })}
                    />

                    <InheritableField
                      id="editor-port"
                      label={t("editor.port")}
                      mono
                      narrow
                      placeholder={DEFAULT_PORTS[form.protocol]}
                      draft={form.port}
                      provenance={provenanceOf(findField(resolved, "port"))}
                      error={attempted ? errors.port : undefined}
                      onChange={(port) => setForm({ ...form, port })}
                    />
                  </>
                )}
              </section>

              {/* Only in edit mode: the resolved view is what these come from,
                  and a connection that does not exist yet has nothing to
                  resolve. */}
              {isConnection === true && target.mode === "edit" && (
                <ProtocolSettingsSection
                  protocol={form.protocol}
                  settings={protocolSettings(resolved)}
                />
              )}

              {hasIdentity && (
                <>
                  <div className={s.rule} />
                  <section className={s.section}>
                    <div className={s.sectionTitle}>{t("editor.sectionCredentials")}</div>

                    {form.identityOwn ? (
                      <>
                        <Field label={t("editor.username")} htmlFor="editor-username">
                          <div className={s.control}>
                            <span className={s.controlGrow}>
                              <TextInput
                                id="editor-username"
                                mono
                                value={form.username}
                                onChange={(username) => setForm({ ...form, username })}
                              />
                            </span>
                            {/* Handing the login back. One control, because
                                the username and the secret are one credential
                                and reverting half of it means nothing. */}
                            {revertLabel !== null && (
                              <Button
                                size="sm"
                                onClick={() =>
                                  setForm({
                                    ...form,
                                    identityOwn: false,
                                    username: "",
                                    password: "",
                                    passwordTouched: false,
                                    auth: "password",
                                    agentFilter: "",
                                    keyPath: "",
                                    keyPassphrase: "",
                                  })
                                }
                              >
                                {revertLabel}
                              </Button>
                            )}
                          </div>
                          {origin.kind === "own" && (
                            <span className={s.provenance}>
                              <span className={s.provenanceDot} />
                              {t("editor.setHere")}
                            </span>
                          )}
                        </Field>

                        {consequence !== null && <p className={s.consequence}>{consequence}</p>}

                        <AuthChooser
                          form={form}
                          attempted={attempted}
                          errors={errors}
                          keyCapable={
                            node?.kind === "credential" || KEY_AUTH_PROTOCOLS.has(form.protocol)
                          }
                          keyInfo={keyInfo}
                          keyStored={keyStored}
                          storedFormat={node?.keyFormat ?? null}
                          storedHasPassphrase={node?.hasPassphrase === true}
                          inspecting={inspect.isPending}
                          inspectFailure={inspectFailure}
                          dialogError={keyDialogError}
                          browsing={keyBrowsing}
                          onBrowse={() => void chooseKey()}
                          onRetryInspect={() => {
                            if (form.keyPath !== "") inspect.mutate(form.keyPath);
                          }}
                          onAuth={(auth) =>
                            setForm({
                              ...form,
                              auth,
                              // Leaving a method drops what was typed into it. A
                              // passphrase kept behind a method the user moved away
                              // from is a secret nothing on screen accounts for.
                              password: auth === "password" ? form.password : "",
                              passwordTouched: auth === "password" && form.passwordTouched,
                              keyPassphrase: auth === "privateKey" ? form.keyPassphrase : "",
                            })
                          }
                          onAgentFilter={(agentFilter) => setForm({ ...form, agentFilter })}
                          onPassphrase={(keyPassphrase) => setForm({ ...form, keyPassphrase })}
                          passwordField={
                            <PasswordField
                              hadSecret={
                                initial?.identity.own === true &&
                                initial.identity.auth === "password"
                              }
                              value={form.password}
                              error={attempted ? errors.password : undefined}
                              onChange={(password) =>
                                setForm({ ...form, password, passwordTouched: true })
                              }
                            />
                          }
                        />
                      </>
                    ) : (
                      <InheritedLogin
                        username={inheritedUsername}
                        origin={origin}
                        onOverride={() =>
                          setForm({
                            ...form,
                            identityOwn: true,
                            // Seeded with what applies today, so overriding is
                            // an edit rather than a blank slate.
                            username: inheritedUsername ?? "",
                            password: "",
                            passwordTouched: false,
                            auth: "password",
                            agentFilter: "",
                            keyPath: "",
                            keyPassphrase: "",
                          })
                        }
                      />
                    )}
                  </section>
                </>
              )}

              {target.mode === "edit" && (
                <>
                  <div className={s.rule} />
                  <section className={s.section}>
                    <div className={s.sectionTitle}>{t("editor.sectionNotes")}</div>

                    <Field label={t("editor.description")} htmlFor="editor-description">
                      <TextInput
                        id="editor-description"
                        value={form.description}
                        onChange={(v) => setForm({ ...form, description: v })}
                      />
                    </Field>

                    <Field
                      label={t("editor.tags")}
                      htmlFor="editor-tags"
                      help={t("editor.tagsHelp")}
                    >
                      <TextInput
                        id="editor-tags"
                        value={form.tags}
                        onChange={(v) => setForm({ ...form, tags: v })}
                        mono
                      />
                      <span className={s.tagList}>
                        {/* A tag is user data. It stands alone in its badge, so
                            it is isolated rather than left to take its
                            direction from the form around it. */}
                        {parseTags(form.tags).map((tag) => (
                          <Badge key={tag} mono>
                            {isolate(tag)}
                          </Badge>
                        ))}
                      </span>
                    </Field>
                  </section>
                </>
              )}
            </form>

            <footer className={s.footer} ref={footerRef}>
              {discardPrompt ? (
                <>
                  {/* Escape on a dirty form asks here rather than discarding.
                      The prompt stays inside the dialog so the focus trap keeps
                      holding, and Escape again answers "keep editing". */}
                  <span className={s.discardQuestion} role="alert">
                    {t("editor.discardTitle")}
                  </span>
                  <span className={s.footerSpacer} />
                  <Button variant="secondary" onClick={() => setDiscardPrompt(false)}>
                    {t("editor.discardKeep")}
                  </Button>
                  <Button variant="danger" onClick={close}>
                    {t("editor.discardConfirm")}
                  </Button>
                </>
              ) : (
                <>
                  <span className={s.footerNote}>{t("editor.noAutosave")}</span>
                  <span className={s.footerSpacer} />
                  <Button variant="ghost" onClick={onCancel} disabled={busy}>
                    {tCommon("action.cancel")}
                  </Button>
                  <BusyButton
                    variant="primary"
                    busy={busy}
                    busyLabel={
                      target.mode === "create" ? t("editor.creating") : t("editor.saving")
                    }
                    onClick={submit}
                    disabled={target.mode === "edit" && !dirty}
                  >
                    {target.mode === "create" ? t("editor.create") : t("editor.save")}
                  </BusyButton>
                </>
              )}
            </footer>
          </>
        )}
      </div>
    </div>
  );
}

// ------------------------------------------------------------ sub-fields ----

interface InheritableFieldProps {
  id: string;
  label: string;
  draft: Draft;
  provenance: Provenance;
  onChange: (draft: Draft) => void;
  mono?: boolean;
  narrow?: boolean;
  placeholder?: string | undefined;
  error?: string | undefined;
}

function InheritableField({
  id,
  label,
  draft,
  provenance,
  onChange,
  mono = false,
  narrow = false,
  placeholder,
  error,
}: InheritableFieldProps) {
  const t = useT("connections");
  const inherited = provenance.inheritedValue;

  return (
    <Field label={label} htmlFor={draft.own ? id : undefined} error={error}>
      <div className={s.control}>
        {draft.own ? (
          <span className={narrow ? s.controlNarrow : s.controlGrow}>
            <TextInput
              id={id}
              value={draft.value}
              onChange={(value) => onChange({ own: true, value })}
              mono={mono}
              placeholder={placeholder}
              invalid={error !== undefined}
            />
          </span>
        ) : (
          <span className={clsx(s.inheritedBox, mono && s.inheritedMono)}>
            {inherited === null || inherited === "" ? (
              <span className={s.inheritedEmpty}>{t("editor.nothingInherited")}</span>
            ) : (
              // A hostname or a port: left-to-right by specification, whatever
              // its first character happens to be, and forced so rather than
              // inferred — `db-01:22` reverses to `22:db-01` otherwise.
              isolateLtr(inherited)
            )}
          </span>
        )}

        {draft.own && provenance.canInherit && (
          <Button size="sm" onClick={() => onChange({ own: false, value: "" })}>
            {inherited === null
              ? t("editor.revertPlain")
              : t("editor.revertTo", { value: isolateLtr(inherited) })}
          </Button>
        )}
        {!draft.own && (
          <Button size="sm" onClick={() => onChange({ own: true, value: inherited ?? "" })}>
            {t("editor.overrideHere")}
          </Button>
        )}
      </div>

      <ProvenanceLine own={draft.own} provenance={provenance} />
    </Field>
  );
}

function ProvenanceLine({ own, provenance }: { own: boolean; provenance: Provenance }) {
  const t = useT("connections");

  if (own) {
    return (
      <span className={s.provenance}>
        <span className={s.provenanceDot} />
        {provenance.canInherit ? (
          <>
            {provenance.inheritedSource === null
              ? t("editor.overridesDefault")
              : t("editor.overridesSource", { source: isolate(provenance.inheritedSource) })}
            {provenance.inheritedValue !== null && (
              <>
                {` ${t("punctuation.detail")} `}
                <span className={s.mono}>{isolateLtr(provenance.inheritedValue)}</span>
              </>
            )}
          </>
        ) : (
          t("editor.setHere")
        )}
      </span>
    );
  }

  return (
    <span className={s.provenance}>
      <span className={s.provenanceGlyph}>
        <Icon name="folder" size={11} />
      </span>
      {/*
        One message rather than a phrase plus a styled name: word order around
        the source differs between languages, so the name cannot be a separate
        element without deciding for the translator where it goes.
      */}
      {provenance.inheritedSource === null
        ? t("editor.protocolDefault")
        : t("editor.inheritedFrom", { source: isolate(provenance.inheritedSource) })}
    </span>
  );
}

/**
 * The settings the connection's own protocol adapter reads, and the plain
 * statement of what this editor cannot do with them.
 *
 * **It cannot change them.** There is no command that writes a connection's
 * settings map: `node_update` carries a name, a host, a port, a login and a
 * list of overrides to clear, and nothing else. So the values are shown with
 * their provenance — which is the whole point of this screen — and the first
 * line says outright that this is a reading and not a form. An RDP or VNC
 * connection opens with what an import stored on it, what a folder above it
 * passes down, or the adapter's own defaults.
 *
 * Drawing an editable control here would have been the fifth time this product
 * shipped a control with nothing behind it. It says what it cannot do instead.
 */
function ProtocolSettingsSection({
  protocol,
  settings,
}: {
  protocol: string;
  settings: readonly ProtocolSetting[];
}) {
  const t = useT("connections");
  const limits = protocolLimitsKey(protocol);

  // Nothing resolved and nothing to say: an SSH connection with no settings of
  // its own gets no empty section.
  if (settings.length === 0 && limits === null) return null;

  return (
    <>
      <div className={s.rule} />
      <section className={s.section}>
        <div className={s.sectionTitle}>{t("editor.sectionProtocolSettings")}</div>

        <Callout tone="info">
          <p>{t("editor.protocolSettingsReadOnly")}</p>
          {limits !== null && <p>{t(limits)}</p>}
        </Callout>

        {settings.length === 0 ? (
          <p className={s.footerNote}>{t("editor.protocolSettingsNone")}</p>
        ) : (
          settings.map((setting) => {
            const note = settingNoteKey(protocol, setting.key, setting.value);
            return (
              <Field
                // The adapter's own key. A wire identifier, like a protocol
                // name: shown as it is, never translated.
                key={setting.key}
                label={setting.key}
                {...(note === null ? {} : { help: t(note) })}
              >
                <span className={clsx(s.inheritedBox, s.inheritedMono)}>
                  {setting.value === "" ? (
                    <span className={s.inheritedEmpty}>{t("editor.nothingInherited")}</span>
                  ) : (
                    // A setting value is a wire token — `true`, `3.8`, `1920`,
                    // a domain, a path. Left-to-right by specification whatever
                    // its first character is.
                    isolateLtr(setting.value)
                  )}
                </span>
                <ProvenanceLine own={setting.own} provenance={setting.provenance} />
              </Field>
            );
          })
        )}
      </section>
    </>
  );
}

/**
 * The login as it stands, when it belongs to a folder or to a shared
 * credential.
 *
 * Read-only on purpose. Editing it here would edit the credential itself, and
 * every other connection using that credential would silently start logging in
 * as somebody else. "Override here" is the way forward, and it is the same
 * phrase every other inherited field on this screen uses.
 */
function InheritedLogin({
  username,
  origin,
  onOverride,
}: {
  username: string | null;
  origin: IdentityOrigin;
  onOverride: () => void;
}) {
  const t = useT("connections");

  const source =
    origin.kind === "inherited"
      ? t("editor.loginInheritedFrom", { source: isolate(origin.source) })
      : origin.kind === "shared"
        ? t("editor.loginShared", { name: isolate(origin.name) })
        : null;

  return (
    <Field label={t("editor.username")} help={source ?? undefined}>
      <div className={s.control}>
        <span className={clsx(s.inheritedBox, s.inheritedMono)}>
          {username === null || username === "" ? (
            <span className={s.inheritedEmpty}>{t("editor.loginNoUsername")}</span>
          ) : (
            // An account name, which may be written in any script.
            isolate(username)
          )}
        </span>
        <Button size="sm" onClick={onOverride}>
          {t("editor.overrideHere")}
        </Button>
      </div>

      <span className={s.provenance}>
        <span className={s.provenanceGlyph}>
          <Icon name="folder" size={11} />
        </span>
        {origin.kind === "inherited"
          ? t("editor.inheritedFrom", { source: isolate(origin.source) })
          : origin.kind === "shared"
            ? t("editor.loginSharedCredential", { name: isolate(origin.name) })
            : t("editor.nothingInherited")}
      </span>
    </Field>
  );
}

/**
 * The container's name as a person would say it, for a key already stored.
 *
 * Format names, and format names are not translated in any language — a PKCS#8
 * file is called PKCS#8 whatever the interface is set to. docs/features/i18n.md,
 * "What is never translated".
 */
// eslint-disable-next-line remoter-i18n/no-text-constant -- format names, see above
const KEY_FORMAT_LABELS: Readonly<Record<KeyFormat, string>> = {
  openssh: "OpenSSH",
  pkcs8: "PKCS#8",
  "putty-ppk": "PuTTY PPK",
};

interface AuthChooserProps {
  form: FormState;
  attempted: boolean;
  errors: FormErrors;
  /** Whether a key or the agent can be used at all: SSH and SFTP, or a credential. */
  keyCapable: boolean;
  keyInfo: PrivateKeyInfo | null;
  /** Whether a key is already sealed into the vault for this login. */
  keyStored: boolean;
  storedFormat: KeyFormat | null;
  storedHasPassphrase: boolean;
  inspecting: boolean;
  inspectFailure: IpcFailure | null;
  dialogError: string | null;
  browsing: boolean;
  onBrowse: () => void;
  onRetryInspect: () => void;
  onAuth: (auth: AuthMethod) => void;
  onAgentFilter: (value: string) => void;
  onPassphrase: (value: string) => void;
  /** The existing password control, so its behaviour stays in one place. */
  passwordField: ReactNode;
}

/**
 * The three ways to authenticate, in order of increasing exposure.
 *
 * The order is the argument: the agent never lets the key reach this process,
 * a stored key reaches it once, and a password is a secret this application
 * holds outright. Each option says what it costs in one line, because "most
 * secure" is a claim and the sentence under it is the reason.
 *
 * Real radio inputs rather than styled buttons: arrow keys move within a radio
 * group and Tab leaves it, which is what a keyboard user expects of a choice
 * of three and is not worth reimplementing.
 */
function AuthChooser({
  form,
  attempted,
  errors,
  keyCapable,
  keyInfo,
  keyStored,
  storedFormat,
  storedHasPassphrase,
  inspecting,
  inspectFailure,
  dialogError,
  browsing,
  onBrowse,
  onRetryInspect,
  onAuth,
  onAgentFilter,
  onPassphrase,
  passwordField,
}: AuthChooserProps) {
  const t = useT("connections");
  const tCommon = useT("common");

  // A protocol that cannot use a key is not offered one. An existing key
  // credential still shows its choice, so it can be seen and changed rather
  // than silently applying from a screen that denies it exists.
  if (!keyCapable && form.auth === "password") {
    // A connection with no protocol recorded gets no sentence naming one.
    const help =
      form.protocol === ""
        ? t("editor.passwordHelp")
        : t("editor.authPasswordOnly", { protocol: form.protocol.toUpperCase() });
    return (
      <Field label={t("editor.authLabel")} help={help}>
        {passwordField}
      </Field>
    );
  }

  return (
    <Field label={t("editor.authLabel")} help={t("editor.authHelp")}>
      <div className={s.authOptions} role="radiogroup" aria-label={t("editor.authLabel")}>
        <label className={clsx(s.authOption, form.auth === "agent" && s.authOptionActive)}>
          <input
            type="radio"
            name="editor-auth"
            className={s.authRadio}
            checked={form.auth === "agent"}
            onChange={() => onAuth("agent")}
          />
          <span className={s.authText}>
            <span className={s.authTitle}>
              {t("editor.agentTitle")}
              <Badge tone="success">{t("editor.agentRecommended")}</Badge>
            </span>
            <span className={s.authBody}>{t("editor.agentBody")}</span>
          </span>
        </label>

        {form.auth === "agent" && (
          <div className={s.authDetail}>
            <Field
              label={t("editor.agentFilterLabel")}
              htmlFor="editor-agent-filter"
              help={t("editor.agentFilterHelp")}
            >
              <TextInput
                id="editor-agent-filter"
                value={form.agentFilter}
                onChange={onAgentFilter}
                mono
              />
            </Field>
          </div>
        )}

        <label className={clsx(s.authOption, form.auth === "privateKey" && s.authOptionActive)}>
          <input
            type="radio"
            name="editor-auth"
            className={s.authRadio}
            checked={form.auth === "privateKey"}
            onChange={() => onAuth("privateKey")}
          />
          <span className={s.authText}>
            <span className={s.authTitle}>{t("editor.keyTitle")}</span>
            <span className={s.authBody}>{t("editor.keyBody")}</span>
          </span>
        </label>

        {form.auth === "privateKey" && (
          <div className={s.authDetail}>
            {/* What is already sealed in, so "choose a file" is plainly a
                replacement rather than the only way to have a key at all. */}
            {keyStored && form.keyPath === "" && (
              <div className={s.keyRow}>
                <Icon name="key" size={14} />
                <span className={s.keyName}>
                  {storedFormat === null ? t("editor.keyTitle") : KEY_FORMAT_LABELS[storedFormat]}
                </span>
                <Badge tone="neutral">{t("editor.keyStored")}</Badge>
                {storedHasPassphrase && <Badge tone="neutral">{t("editor.keyEncrypted")}</Badge>}
              </div>
            )}

            {form.keyPath !== "" && (
              <div className={s.keyRow}>
                <Icon name="file" size={14} />
                {/* A file name the user chose, isolated so it cannot reorder
                    the badges beside it. The tooltip carries the full path. */}
                <span className={s.keyName} title={form.keyPath}>
                  {isolate(fileName(form.keyPath))}
                </span>
                {keyInfo !== null && (
                  <>
                    <Badge tone="accent" mono>
                      {keyInfo.formatLabel}
                    </Badge>
                    <Badge tone={keyInfo.encrypted ? "neutral" : "warning"}>
                      {keyInfo.encrypted
                        ? t("editor.keyEncrypted")
                        : t("editor.keyNotEncrypted")}
                    </Badge>
                    <span className={s.keyMeta}>
                      {t("editor.keySize", { count: keyInfo.sizeBytes })}
                    </span>
                  </>
                )}
              </div>
            )}

            {/* Reading the file is a round trip to the core, and what it
                answers decides whether a passphrase is asked for at all. */}
            {inspecting && <BusyStatus label={t("editor.keyReading")} size={13} />}

            {inspectFailure !== null && (
              <FailureNotice
                failure={inspectFailure}
                title={t("editor.keyInspectFailed")}
                onRetry={onRetryInspect}
                retryLabel={tCommon("action.retry")}
              />
            )}

            {dialogError !== null && <Callout tone="warning">{dialogError}</Callout>}

            <div className={s.control}>
              <BusyButton
                size="sm"
                busy={browsing}
                busyLabel={tCommon("action.opening")}
                onClick={onBrowse}
              >
                {form.keyPath === "" && !keyStored
                  ? t("editor.keyChoose")
                  : t("editor.keyChange")}
              </BusyButton>
              {keyStored && form.keyPath === "" && (
                <span className={s.keyMeta}>{t("editor.keyStoredHelp")}</span>
              )}
            </div>

            {attempted && errors.key !== undefined && (
              <p className={s.fieldError} role="alert">
                {errors.key}
              </p>
            )}

            {/* Only when the container says it is encrypted. Asking otherwise
                trains people to type a passphrase into a field that has no use
                for one. */}
            {keyInfo?.encrypted === true && (
              <Field
                label={t("editor.keyPassphrase")}
                htmlFor="editor-key-passphrase"
                help={t("editor.keyPassphraseHelp")}
                {...(attempted && errors.passphrase !== undefined
                  ? { error: errors.passphrase }
                  : {})}
              >
                <TextInput
                  id="editor-key-passphrase"
                  type="password"
                  value={form.keyPassphrase}
                  onChange={onPassphrase}
                  invalid={attempted && errors.passphrase !== undefined}
                />
              </Field>
            )}
          </div>
        )}

        <label className={clsx(s.authOption, form.auth === "password" && s.authOptionActive)}>
          <input
            type="radio"
            name="editor-auth"
            className={s.authRadio}
            checked={form.auth === "password"}
            onChange={() => onAuth("password")}
          />
          <span className={s.authText}>
            <span className={s.authTitle}>{t("editor.password")}</span>
            <span className={s.authBody}>{t("editor.passwordHelp")}</span>
          </span>
        </label>

        {form.auth === "password" && <div className={s.authDetail}>{passwordField}</div>}
      </div>
    </Field>
  );
}

interface PasswordFieldProps {
  /** Whether this login already authenticates with a password. */
  hadSecret: boolean;
  value: string;
  error: string | undefined;
  onChange: (value: string) => void;
}

function PasswordField({ hadSecret, value, error, onChange }: PasswordFieldProps) {
  const t = useT("connections");

  return (
    <Field
      label={t("editor.password")}
      htmlFor="editor-password"
      help={t("editor.passwordHelp")}
      {...(error === undefined ? {} : { error })}
    >
      <span className={s.controlGrow}>
        <TextInput
          id="editor-password"
          type="password"
          value={value}
          onChange={onChange}
          invalid={error !== undefined}
          placeholder={hadSecret ? t("editor.passwordUnchanged") : t("editor.passwordNotSet")}
        />
      </span>
    </Field>
  );
}

// ---------------------------------------------------------------- helpers ---

function headerGlyphClass(node: TreeNode | undefined): string {
  return clsx(s.headerGlyph, node?.kind === "connection" && protocolClass(node.protocol));
}

function headerLabel(t: Copy, target: EditorTarget, node: TreeNode | undefined): string {
  if (target.mode === "create") {
    return target.kind === "folder" ? t("editor.titleNewFolder") : t("editor.titleNewConnection");
  }
  // The entry's own name, which is user data: isolated so a right-to-left name
  // cannot reorder the heading, the breadcrumb and the close button around it.
  return node === undefined ? t("editor.titleEdit") : isolate(node.name);
}

function breadcrumb(t: Copy, nodes: readonly TreeNode[], parentId: string | null): string {
  if (parentId === null) return t("editor.locationRoot");
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const parts: string[] = [];
  let cursor: string | null = parentId;
  // A malformed parent chain must not hang the editor.
  for (let hops = 0; cursor !== null && hops < 64; hops += 1) {
    const found: TreeNode | undefined = byId.get(cursor);
    if (found === undefined) break;
    // Each folder name is user data. Isolating them one by one keeps the path
    // reading in the document's direction however the names are written.
    parts.unshift(isolate(found.name));
    cursor = found.parentId;
  }
  // The glyph is translatable; the spaces around it are layout, and a
  // catalogue message may not carry padding (src/i18n/catalogues.test.ts).
  return parts.join(` ${t("editor.breadcrumbSeparator")} `);
}

function nullIfBlank(value: string): string | null {
  const trimmed = value.trim();
  return trimmed === "" ? null : trimmed;
}

interface FormErrors {
  name?: string;
  host?: string;
  port?: string;
  key?: string;
  passphrase?: string;
  password?: string;
}

/** What the form has to know about its surroundings before it can be judged. */
interface ValidationContext {
  /** Connections are the only kind with an address of their own. */
  isConnection: boolean;
  /** Connections and credentials are the kinds that carry a login. */
  hasIdentity: boolean;
  mode: EditorTarget["mode"];
  keyInfo: PrivateKeyInfo | null;
  inspecting: boolean;
  /** Whether a key is already sealed into the vault for this login. */
  keyStored: boolean;
  /** How this entry's own login authenticated before the edit; null if it had none. */
  initialAuth: AuthMethod | null;
}

export function validate(t: Copy, form: FormState, context: ValidationContext): FormErrors {
  const errors: FormErrors = {};
  if (form.name.trim() === "") errors.name = t("editor.errorNameRequired");
  if (context.isConnection && context.mode === "create" && form.host.value.trim() === "") {
    errors.host = t("editor.errorHostRequired");
  }
  if (form.port.own) {
    const raw = form.port.value.trim();
    if (raw !== "") {
      const port = Number(raw);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        errors.port = t("editor.errorPortInvalid");
      }
    }
  }

  // The method only means anything on a login this entry is writing.
  if (!context.hasIdentity || !form.identityOwn) return errors;

  if (form.auth === "privateKey") {
    if (form.keyPath === "") {
      /*
       * A key already in the vault stays as it is when no file is chosen, and
       * `buildPatch` then writes nothing. Switching to this method without one
       * is the case that has to be refused: there is no key to authenticate
       * with and nothing on screen would have said so.
       */
      if (!context.keyStored) errors.key = t("editor.errorKeyRequired");
    } else if (context.inspecting) {
      errors.key = t("editor.errorKeyPending");
    } else if (context.keyInfo === null) {
      errors.key = t("editor.errorKeyUnreadable");
    } else if (context.keyInfo.encrypted && form.keyPassphrase === "") {
      errors.passphrase = t("editor.errorPassphraseRequired");
    }
  }

  /*
   * Moving from a key or the agent to a password without typing one would send
   * nothing at all: the stored key would stay, and the screen would claim a
   * password is in use. Asked for here rather than discovered at connect time.
   */
  if (
    form.auth === "password" &&
    context.initialAuth !== null &&
    context.initialAuth !== "password" &&
    !(form.passwordTouched && form.password !== "")
  ) {
    errors.password = t("editor.errorPasswordRequired");
  }

  return errors;
}

interface InitialDrafts {
  host: Draft;
  port: Draft;
  identity: IdentityState;
}

/** What an edit does to the login, which is what the interface has to explain. */
type IdentityWrite = "none" | "writes" | "removes";

interface PatchPlan {
  /** Everything the change consists of, except the secret. */
  patch: UpdateNode;
  /**
   * Whether a new password is part of this edit. The value itself is not here,
   * and must not be: this object is memoised across renders and, once it is a
   * mutation variable, retained by the MutationCache after the call settles.
   */
  setsPassword: boolean;
  identity: IdentityWrite;
}

/** Which kinds of field this node accepts, decided by its kind. */
interface PatchKinds {
  isConnection: boolean;
  hasIdentity: boolean;
}

/**
 * The smallest patch that expresses the edit.
 *
 * A field the user reverted becomes an entry in `clearOverrides` rather than a
 * null value, because "inherit this again" and "set this to nothing" are
 * different instructions to the core.
 */
function buildPatch(
  form: FormState,
  node: TreeNode,
  initial: InitialDrafts,
  kinds: PatchKinds,
): PatchPlan {
  const patch: UpdateNode = {};
  const clear: string[] = [];

  const name = form.name.trim();
  if (name !== node.name) patch.name = name;
  if (form.description !== node.description) patch.description = form.description;

  const tags = parseTags(form.tags);
  if (tags.join("\u001f") !== node.tags.join("\u001f")) patch.tags = tags;

  if (kinds.isConnection) {
    if (form.host.own) {
      if (!initial.host.own || form.host.value !== initial.host.value) {
        patch.host = form.host.value.trim();
      }
    }

    if (form.port.own) {
      const raw = form.port.value.trim();
      if ((!initial.port.own || form.port.value !== initial.port.value) && raw !== "") {
        patch.port = Number(raw);
      }
    } else if (initial.port.own) {
      clear.push("port");
    }
  }

  const login = kinds.hasIdentity
    ? buildLoginPatch(form, initial.identity, kinds.isConnection, patch, clear)
    : { identity: "none" as IdentityWrite, setsPassword: false };

  if (clear.length > 0) patch.clearOverrides = clear;
  return { patch, setsPassword: login.setsPassword, identity: login.identity };
}

/**
 * The login half of the patch.
 *
 * Username, secret and method live on one credential, so they are decided
 * together. Two consequences the field-by-field version got wrong:
 *
 *  - reverting is one instruction, `clearOverrides: ["credential"]`. There is
 *    no `username` or `password` override to clear — the core rejects both
 *    names, because neither is a field a connection owns;
 *  - anything written goes to the connection itself. The core puts it on the
 *    credential attached to that connection, creating one where there is none,
 *    and never touches an inherited or shared credential to do it.
 */
function buildLoginPatch(
  form: FormState,
  initial: IdentityState,
  isConnection: boolean,
  patch: UpdateNode,
  clear: string[],
): { identity: IdentityWrite; setsPassword: boolean } {
  if (!form.identityOwn) {
    // Cancelling an override that was never saved is a form-level undo, not a
    // patch: there is nothing of this connection's own to take away.
    if (!initial.own) return { identity: "none", setsPassword: false };
    // A credential node has no inheritance to fall back to, so it cannot hand
    // its own login back; only a connection reaches here.
    if (isConnection) clear.push("credential");
    return { identity: "removes", setsPassword: false };
  }

  const username = form.username.trim();
  let setsPassword = false;
  let material = false;

  if (form.auth === "password") {
    // A password only travels when the user typed a new one. An untouched
    // field means "leave the stored secret alone", never "clear it".
    setsPassword = form.passwordTouched && form.password !== "";
    material = setsPassword;
  } else if (form.auth === "agent") {
    // The agent stores nothing, so it is written only when the choice or the
    // comment filter actually changed.
    const filter = form.agentFilter.trim();
    const unchanged =
      initial.own && initial.auth === "agent" && filter === initial.agentFilter.trim();
    const input = unchanged ? null : credentialInputFor(form);
    if (input !== null) {
      patch.credential = input;
      material = true;
    }
  } else if (form.keyPath !== "") {
    /*
     * A key is written only when a file was chosen in this session. Rewriting
     * the stored one means reading a file the user never named, and it may
     * well be gone — which is the whole reason the bytes are in the vault.
     */
    const input = credentialInputFor(form);
    if (input !== null) {
      patch.credential = input;
      material = true;
    }
  }

  const changed = !initial.own || username !== initial.username;
  /*
   * The username is sent only when the user set one. Sending an empty one
   * while overriding would tell the core to name the new credential nothing,
   * throwing away the account name that was being inherited — which it
   * otherwise carries over.
   */
  if (changed && (username !== "" || initial.own || material)) patch.username = username;

  if (patch.username === undefined && !material) return { identity: "none", setsPassword: false };
  return { identity: "writes", setsPassword };
}
