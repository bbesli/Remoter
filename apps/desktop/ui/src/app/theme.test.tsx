/**
 * The window opens in the theme the user chose, not in the default.
 *
 * The defect this pins: the stored theme was read only when the Settings screen
 * was opened, so a user who chose dark started every session in a light window
 * — while the operating system said light, which is the case every assertion
 * here is made under.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ipc")>();
  return { ...actual, ipc: { getSettings: vi.fn() } };
});

vi.mock("@tauri-apps/api/window", () => ({
  getCurrentWindow: () => ({ setBackgroundColor: () => Promise.resolve() }),
}));

import { ipc } from "@/lib/ipc";
import { useApp } from "@/stores/app";

import { applyRememberedTheme, recallTheme, useAppliedTheme } from "./theme";

const getSettings = vi.mocked(ipc.getSettings);

function Probe() {
  useAppliedTheme();
  return null;
}

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

// Node's own experimental `localStorage` global shadows jsdom's and is
// undefined without a backing file, so the test brings the plain in-memory
// storage a WebView gives the application.
class MemoryStorage {
  private items = new Map<string, string>();
  getItem(key: string): string | null {
    return this.items.get(key) ?? null;
  }
  setItem(key: string, value: string): void {
    this.items.set(key, value);
  }
  removeItem(key: string): void {
    this.items.delete(key);
  }
  clear(): void {
    this.items.clear();
  }
}
Object.defineProperty(globalThis, "localStorage", { configurable: true, value: new MemoryStorage() });

beforeEach(() => {
  // The operating system prefers light.
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    value: (query: string) => ({
      matches: query.includes("light"),
      media: query,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
    }),
  });
  localStorage.clear();
  delete document.documentElement.dataset["theme"];
  useApp.getState().setTheme("system");
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("the theme at start-up", () => {
  it("applies the stored choice without anyone opening Settings", async () => {
    getSettings.mockResolvedValue({ theme: "dark", locale: "en" } as Awaited<
      ReturnType<typeof ipc.getSettings>
    >);

    render(<Probe />, { wrapper });

    await waitFor(() => expect(document.documentElement.dataset["theme"]).toBe("dark"));
    expect(useApp.getState().theme).toBe("dark");
  });

  it("remembers what it showed, so the next start draws its first frame in it", async () => {
    getSettings.mockResolvedValue({ theme: "hc-dark", locale: "en" } as Awaited<
      ReturnType<typeof ipc.getSettings>
    >);
    render(<Probe />, { wrapper });
    await waitFor(() => expect(recallTheme()).toEqual({ choice: "hc-dark", resolved: "hc-dark" }));

    // A new start: nothing rendered yet, no settings read yet.
    delete document.documentElement.dataset["theme"];
    useApp.getState().setTheme("system");
    applyRememberedTheme();

    expect(document.documentElement.dataset["theme"]).toBe("hc-dark");
    expect(useApp.getState().theme).toBe("hc-dark");
  });

  it("lets the stored setting overrule a remembered theme that has gone stale", async () => {
    localStorage.setItem("remoter.theme.choice", "light");
    localStorage.setItem("remoter.theme.resolved", "light");
    applyRememberedTheme();
    getSettings.mockResolvedValue({ theme: "dark", locale: "en" } as Awaited<
      ReturnType<typeof ipc.getSettings>
    >);

    render(<Probe />, { wrapper });

    await waitFor(() => expect(document.documentElement.dataset["theme"]).toBe("dark"));
  });

  it("follows the operating system when the choice is system", async () => {
    getSettings.mockResolvedValue({ theme: "system", locale: "en" } as Awaited<
      ReturnType<typeof ipc.getSettings>
    >);
    render(<Probe />, { wrapper });
    await waitFor(() => expect(document.documentElement.dataset["theme"]).toBe("light"));
  });

  it("ignores a remembered value that is not a theme", () => {
    localStorage.setItem("remoter.theme.choice", "sepia");
    localStorage.setItem("remoter.theme.resolved", "sepia");
    applyRememberedTheme();
    expect(document.documentElement.dataset["theme"]).toBeUndefined();
  });
});
