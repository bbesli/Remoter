/**
 * Bootstraps the language and keeps the document in step with it.
 *
 * Two things happen here that cannot happen anywhere else.
 *
 * **The stored language is applied at startup.** It lives in application
 * settings (`AppSettings.locale`, `crates/remoter-ipc`), which until now were
 * only read when the Settings screen was opened — so a chosen language would
 * have taken effect on the second visit to a screen nobody had a reason to
 * visit. The read happens once, here, above every screen.
 *
 * **`lang` and `dir` are written to `<html>`.** Direction is not a per-component
 * decision: the sidebar, the tab strip's edges, the inspector and every
 * directional icon mirror off that one attribute, because the stylesheets are
 * written in logical properties throughout. Setting it anywhere lower would
 * leave the chrome around it running the other way.
 *
 * The children render immediately rather than behind a spinner. English is
 * compiled in, so the worst case while the stored language loads is one frame
 * of English — which is what the user would see under a spinner anyway, minus
 * the flicker.
 */

import { useEffect, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";

import { ipc } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";
import { useApp } from "@/stores/app";

import { applyDocumentLanguage, setLanguage } from "./instance";
import { useLocale } from "./useT";

export function I18nProvider({ children }: { children: ReactNode }) {
  const setLocale = useApp((state) => state.setLocale);
  const chosen = useApp((state) => state.locale);
  const { code } = useLocale();

  // The core is the authority on what the user chose. `retry: false` and no
  // refetch: if settings cannot be read the interface still has to open, in
  // English, and the Settings screen reports the failure with its own words.
  const settings = useQuery({
    queryKey: qk.settings(),
    queryFn: ipc.getSettings,
    staleTime: Infinity,
  });

  const stored = settings.data?.locale;

  useEffect(() => {
    if (stored === undefined) return;
    setLocale(stored);
  }, [stored, setLocale]);

  // `setLanguage` refuses a locale with no catalogues and returns the one still
  // in force, so a settings file naming a half-translated language leaves the
  // interface in English rather than half-blank. The Language screen says so.
  useEffect(() => {
    void setLanguage(chosen);
  }, [chosen]);

  useEffect(() => {
    applyDocumentLanguage(code);
  }, [code]);

  return <>{children}</>;
}
