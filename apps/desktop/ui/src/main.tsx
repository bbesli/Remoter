import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClientProvider } from "@tanstack/react-query";

import { App } from "./app/App";
import { createQueryClient } from "./app/queryClient";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { I18nProvider } from "./i18n";
import "./styles/base.css";

// Configured in `app/queryClient.ts`, where the vault-lock detector lives with
// it. A client built inline here is a client no test can render against.
const queryClient = createQueryClient();

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
