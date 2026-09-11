/**
 * The application shell.
 *
 * Routing is a discriminated union in the store rather than a URL router:
 * this is a desktop application with a fixed set of top-level screens and no
 * addressable history, so a router would be ceremony without benefit.
 *
 * The window is frameless. `MainWindow` draws its own title bar with controls;
 * the other screens draw their own bars too, so they get the window controls
 * as an overlay rather than a second stacked bar.
 */

import { useEffect } from "react";

import { WindowControls } from "@/components/WindowChrome";
import { DisconnectDialog, requestCloseWindow } from "@/features/sessions";
import { useApp } from "@/stores/app";
import { useSystemTheme } from "@/hooks/useSystemTheme";
import { VaultPicker } from "@/features/vault/VaultPicker";
import { CreateVaultWizard } from "@/features/vault/CreateVaultWizard";
import { RecoveryKeyScreen } from "@/features/vault/RecoveryKeyScreen";
import { UnlockScreen } from "@/features/vault/UnlockScreen";
import { MainWindow } from "@/features/shell/MainWindow";
import { AppSettings } from "@/features/settings/AppSettings";
import { VaultSettings } from "@/features/vaultsettings/VaultSettings";
import { AuditViewer } from "@/features/audit/AuditViewer";
import { ImportWizard } from "@/features/import/ImportWizard";

export function App() {
  const screen = useApp((state) => state.screen);
  const theme = useApp((state) => state.theme);
  const systemTheme = useSystemTheme();

  useEffect(() => {
    const resolved = theme === "system" ? systemTheme : theme;
    document.documentElement.dataset["theme"] = resolved;
  }, [theme, systemTheme]);

  /*
   * The disconnect confirmation is mounted here, on both branches, for two
   * reasons. It is asked from places that are not inside the session area —
   * the window's close control, and the `tab.close` shortcut — and the session
   * area is swept by a layout test that fails on anything positioned out of
   * flow inside it, because chrome over a remote desktop covered the Start
   * button once already. At the shell it is neither.
   */
  if (screen.name === "main") {
    return (
      <>
        <MainWindow />
        <DisconnectDialog />
      </>
    );
  }

  return (
    <>
      {/* These four screens are reachable with sessions still open, and this
          overlay's close button ends them all. It asks the same question the
          main window's title bar asks. */}
      <WindowControls beforeClose={requestCloseWindow} />
      {screen.name === "picker" && <VaultPicker />}
      {screen.name === "create" && <CreateVaultWizard />}
      {screen.name === "recovery" && <RecoveryKeyScreen result={screen.result} />}
      {screen.name === "unlock" && <UnlockScreen path={screen.path} relock={screen.relock} />}
      {screen.name === "settings" && <AppSettings />}
      {/* Each of these three draws its own header and leaves through
          `goBack()`, so they get the window controls as an overlay exactly as
          the settings screen does. Their headers reserve
          `--window-controls-w` at the inline end; the overlay sits above them
          and a control underneath it closes the application. */}
      {screen.name === "vault-settings" && <VaultSettings />}
      {screen.name === "audit" && <AuditViewer />}
      {screen.name === "import" && <ImportWizard />}
      <DisconnectDialog />
    </>
  );
}
