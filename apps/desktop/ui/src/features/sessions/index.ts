/**
 * The session feature's public surface.
 *
 * The shell imports from here; nothing outside this directory reaches into a
 * module of it. The terminal registry in particular is deliberately not
 * exported — a component that could reach an xterm instance directly is a
 * component that could write to one from a render.
 */

export { SessionSurface, closeAllSessions } from "./SessionSurface";
export { SessionTabs } from "./SessionTabs";
export { SessionPanels } from "./SessionPanels";
export { SessionStatus } from "./SessionStatus";
export { openSession, isConnectable, closeTab, reconnect } from "./manager";
// `applyTerminalAppearance` is the one write into the registry that belongs
// outside this feature: the settings screen changes the palette and the change
// has to reach sessions that are already open. It is exported here rather than
// left to be imported from `./terminals` directly, because a caller that knows
// the module path also knows every other export in it — the registry included.
export { isTerminalFocused, applyTerminalAppearance } from "./terminals";
export { useSessions } from "./store";
export type { SessionRecord } from "./store";
