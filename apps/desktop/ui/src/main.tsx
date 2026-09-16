import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClientProvider } from "@tanstack/react-query";

import { App } from "./app/App";
import { installNativeFeel } from "./app/nativeFeel";
import { applyRememberedTheme } from "./app/theme";
import { createQueryClient } from "./app/queryClient";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { I18nProvider } from "./i18n";
import "./styles/base.css";

// Configured in `app/queryClient.ts`, where the vault-lock detector lives with
// it. A client built inline here is a client no test can render against.
const queryClient = createQueryClient();

// A desktop application, not a page: no reload, no print, no browser menus.
// Development builds keep them, because reload and the inspector are how the
// interface is worked on. See `app/nativeFeel.ts`.
if (import.meta.env.PROD) installNativeFeel();

// The theme the window last showed, before the first frame is drawn. The
// stored setting follows over IPC a moment later and wins. See `app/theme.ts`.
applyRememberedTheme();

const root = document.getElementById("root");
if (!root) throw new Error("#root is missing from index.html");

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      {/* Above the error boundary: the boundary's own copy is translated, and
          a language that only applied to the working case would leave the one
          screen a user reads most carefully in the wrong language. It is below
          the query provider because it reads the stored language over IPC. */}
      <I18nProvider>
        <ErrorBoundary>
          <App />
        </ErrorBoundary>
      </I18nProvider>
    </QueryClientProvider>
  </React.StrictMode>,
);
