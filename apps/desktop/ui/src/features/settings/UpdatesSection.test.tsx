/**
 * The Updates screen, wired to a stubbed core.
 *
 * Three things are held here, and each one is a way this feature has gone
 * wrong before or could go wrong silently.
 *
 * The first is that nothing is contacted until somebody asks. The switch ships
 * off, and a screen that quietly made a request on open would break the
 * sentence printed next to it.
 *
 * The second is that "Check now" does not need the switch. Pressing a button
 * is the user asking directly, which is not the same thing as standing
 * permission, and tying the two together would make the feature useless to
 * anybody who never wants an automatic check.
 *
 * The third is that a failure keeps the core's own words. "Could not check"
 * covers being offline, being rate-limited and there being no release list,
 * and a user who cannot tell those apart cannot act on any of them.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { AppSettings, AppSettingsPatch, UpdateCheck } from "@/lib/ipc";

const getSettings = vi.fn<() => Promise<AppSettings>>();
const setSettings = vi.fn<(patch: AppSettingsPatch) => Promise<AppSettings>>();
const checkForUpdate = vi.fn<() => Promise<UpdateCheck>>();
const openUrl = vi.fn<(url: string) => Promise<void>>();

vi.mock("@/lib/ipc", async (importOriginal) => {
  const original = await importOriginal<typeof import("@/lib/ipc")>();
  return {
    ...original,
    ipc: {
      ...original.ipc,
      getSettings: () => getSettings(),
      setSettings: (patch: AppSettingsPatch) => setSettings(patch),
      checkForUpdate: () => checkForUpdate(),
    },
  };
});

vi.mock("@tauri-apps/plugin-opener", () => ({
  openUrl: (url: string) => openUrl(url),
}));

const { UpdatesSection } = await import("./UpdatesSection");

/**
 * Whole settings, not a cast.
 *
 * `as AppSettings` on a partial object is how a fixture stops noticing that
 * the interface reads a field it does not carry — the compiler stops checking
 * exactly where the test stops being a description of the real value.
 */
function settings(overrides: Partial<AppSettings> = {}): AppSettings {
  return {
    theme: "system",
    locale: "en",
    autoLockMinutes: 15,
    lockOnScreenLock: true,
    lockOnSuspend: true,
    sidebarWidth: 280,
    inspectorOpen: true,
    updateCheckEnabled: false,
    updateChannel: "stable",
    updateLastCheckedAt: null,
    terminalPrefix: "ctrl+alt",
    shortcuts: {},
    terminal: { palette: "auto", overrides: {}, fontFamily: "", fontSize: 13 },
    ...overrides,
  };
}

const newerRelease: UpdateCheck = {
  currentVersion: "0.1.0",
  checkedAt: 1_757_462_400,
  releases: [
    {
      tag: "v0.2.0",
      name: "Tunnels",
      notes: "Local and remote forwards.",
      url: "https://github.com/bbesli/Remoter/releases/tag/v0.2.0",
      prerelease: false,
      publishedAt: "2026-08-01T10:00:00Z",
    },
  ],
};

/**
 * One client per test, built here rather than in a `wrapper` function.
 *
 * A wrapper is a component, so React re-invokes it on every render — a client
 * constructed inside one is a new cache each time, and a `setQueryData` from a
 * mutation lands in a cache that is thrown away before it can be read.
 */
function renderSection(): void {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const node: ReactNode = <UpdatesSection />;
  render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

/**
 * The stub keeps state, because the screen depends on the core doing so.
 *
 * A `settings_set` is followed by a re-read — the check writes the timestamp
 * into the same file — and a stub that answered the second read with the
 * value from before the write would make a correct screen look broken.
 */
let stored: AppSettings;

beforeEach(() => {
  vi.clearAllMocks();
  stored = settings();
  getSettings.mockImplementation(() => Promise.resolve(stored));
  setSettings.mockImplementation((patch) => {
    // The cast is the patch type, not the fixture: a patch may carry a `null`
    // accelerator, which means "restore the shipped default" and which the
    // core resolves before it stores anything. Nothing here sends one.
    stored = { ...stored, ...patch } as AppSettings;
    return Promise.resolve(stored);
  });
  checkForUpdate.mockImplementation(() => {
    stored = { ...stored, updateLastCheckedAt: Math.floor(Date.now() / 1000) };
    return Promise.resolve(newerRelease);
  });
  openUrl.mockResolvedValue(undefined);
});

describe("UpdatesSection", () => {
  it("contacts nothing on open while the check is off", async () => {
    renderSection();

    await screen.findByRole("switch");
    expect(screen.getByRole("switch")).not.toBeChecked();
    expect(checkForUpdate).not.toHaveBeenCalled();
  });

  it("checks on open when the check is on and the last one is old", async () => {
    stored = settings({
      updateCheckEnabled: true,
      updateLastCheckedAt: Math.floor(Date.now() / 1000) - 3 * 24 * 60 * 60,
    });

    renderSection();

    await waitFor(() => expect(checkForUpdate).toHaveBeenCalledTimes(1));
  });

  it("does not check again on open when it already checked today", async () => {
    stored = settings({
      updateCheckEnabled: true,
      updateLastCheckedAt: Math.floor(Date.now() / 1000) - 60,
    });

    renderSection();

    await screen.findByRole("switch");
    expect(checkForUpdate).not.toHaveBeenCalled();
  });

  it("checks when asked, with the automatic check switched off", async () => {
    const user = userEvent.setup();
    renderSection();

    await user.click(await screen.findByRole("button", { name: /check now/i }));

    expect(checkForUpdate).toHaveBeenCalledTimes(1);
    expect(await screen.findByText(/version 0\.2\.0 is available/i)).toBeInTheDocument();
    expect(screen.getByText(/local and remote forwards/i)).toBeInTheDocument();
  });

  it("says it will not install the update, and opens the release page instead", async () => {
    const user = userEvent.setup();
    renderSection();

    await user.click(await screen.findByRole("button", { name: /check now/i }));
    await screen.findByText(/version 0\.2\.0 is available/i);

    expect(screen.getByText(/does not install updates itself/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /open the release page/i }));
    expect(openUrl).toHaveBeenCalledWith("https://github.com/bbesli/Remoter/releases/tag/v0.2.0");
  });

  it("says you are current rather than saying nothing", async () => {
    const user = userEvent.setup();
    checkForUpdate.mockResolvedValue({
      currentVersion: "0.2.0",
      checkedAt: 1_757_462_400,
      releases: newerRelease.releases,
    });

    renderSection();
    await user.click(await screen.findByRole("button", { name: /check now/i }));

    expect(await screen.findByText(/newest release/i)).toBeInTheDocument();
  });

  it("keeps the core's own words when the check fails", async () => {
    const user = userEvent.setup();
    checkForUpdate.mockRejectedValue({
      code: "update.rate-limited",
      message: "GitHub is not answering any more update checks from this network for now.",
      detail: "The limit resets at 1789075096 (Unix seconds).",
      actions: ["Try again later"],
    });

    renderSection();
    await user.click(await screen.findByRole("button", { name: /check now/i }));

    expect(await screen.findByText(/not answering any more update checks/i)).toBeInTheDocument();
    expect(screen.getByText(/the limit resets at/i)).toBeInTheDocument();
    // A way out that does not need the network Remoter just failed to use.
    expect(screen.getByRole("button", { name: /open the releases page/i })).toBeInTheDocument();
  });

  it("stores the preference when the switch is turned on", async () => {
    const user = userEvent.setup();
    renderSection();
    await user.click(await screen.findByRole("switch"));

    await waitFor(() => expect(setSettings).toHaveBeenCalledWith({ updateCheckEnabled: true }));
    await waitFor(() => expect(screen.getByRole("switch")).toBeChecked());

    // The screen showing "On" is not the same claim as the core holding it,
    // and this test's name is the second one. Turning the switch on also runs
    // a check, whose answer is re-read from the same settings entry — so a
    // switch left on screen alone would pass the assertion above.
    expect(stored.updateCheckEnabled).toBe(true);
    expect(setSettings).toHaveBeenCalledTimes(1);
  });

  it("checks straight away when permission is given, and says so beforehand", async () => {
    const user = userEvent.setup();
    renderSection();

    // The sentence beside the switch has to cover this, or the first request
    // arrives before the user expects one.
    expect(await screen.findByText(/once when you turn it on/i)).toBeInTheDocument();
    expect(checkForUpdate).not.toHaveBeenCalled();

    await user.click(screen.getByRole("switch"));

    await waitFor(() => expect(checkForUpdate).toHaveBeenCalledTimes(1));
  });

  it("checks when permission is given even though one ran an hour ago", async () => {
    const user = userEvent.setup();
    // Off, but this machine checked recently — the user pressed Check now, or
    // had the switch on earlier today. The once-a-day guard governs opening
    // this screen; it must not swallow the check the consent sentence promises
    // for the moment permission is given, or the switch does nothing visible
    // and the sentence beside it is untrue.
    stored = settings({ updateLastCheckedAt: Math.floor(Date.now() / 1000) - 60 * 60 });

    renderSection();
    await screen.findByRole("switch");
    expect(checkForUpdate).not.toHaveBeenCalled();

    await user.click(screen.getByRole("switch"));

    await waitFor(() => expect(checkForUpdate).toHaveBeenCalledTimes(1));
  });
});
