/**
 * Mounts the application exactly as `main.tsx` does, then walks it to the
 * screen a screenshot is of.
 */

import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClientProvider } from "@tanstack/react-query";

import { App } from "@/app/App";
import { createQueryClient } from "@/app/queryClient";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { useConnectionEditor } from "@/features/connections/ConnectionEditor";
import { openSession } from "@/features/sessions";
import { I18nProvider } from "@/i18n";
import { useApp } from "@/stores/app";
import "@/styles/base.css";

import { NODES } from "./fixtures";

const root = document.getElementById("root");
if (!root) throw new Error("#root is missing from demo.html");

const params = new URLSearchParams(window.location.search);
const shot = params.get("shot") ?? "main";

if (shot !== "picker") {
  useApp.setState({
    screen: { name: "main" },
    expanded: new Set(["f-prod", "f-web", "f-db", "f-win"]),
    selectedNodeId: "c-web1",
    // Open on the export shot too: the status bar is then the width it is on
    // the main shot, which keeps the renderer's GPU name off the picture.
    inspectorOpen: shot === "main" || shot === "export",
  });
}

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <QueryClientProvider client={createQueryClient()}>
      <I18nProvider>
        <ErrorBoundary>
          <App />
        </ErrorBoundary>
      </I18nProvider>
    </QueryClientProvider>
  </React.StrictMode>,
);

window.setTimeout(() => {
  if (shot === "main" || shot === "export") {
    const web = NODES.find((node) => node.id === "c-web1");
    if (web !== undefined) openSession(web);
  }
  if (shot === "export") useApp.getState().openExport("f-prod");
  if (shot === "audit") useApp.getState().go({ name: "audit" });
  if (shot === "editor") useConnectionEditor.getState().open({ mode: "edit", nodeId: "c-dbp" });
}, 300);
