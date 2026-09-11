/**
 * About.
 *
 * The version comes from the running binary rather than a constant compiled
 * into this file: a number typed here would be right on the day it was written
 * and wrong on the day someone needed it for a bug report.
 *
 * The licence line names the plugin exception because that is the question a
 * plugin author arrives with, and the answer — "any licence you like, through
 * the published ABI" — is otherwise buried three documents deep.
 *
 * That line used to read as though this build loaded plugins. It does not:
 * there is no plugin host in the workspace, only the ABI and SDK crates a
 * future one will use. So the row now says that first and the licence position
 * second. A screen that describes a capability the binary does not have is the
 * same defect as a button that does nothing — the reader cannot tell which
 * parts of the rest to believe.
 *
 * Links open in the system browser through the opener plugin. The URL is shown
 * beside the button and is selectable, so a user who cannot open a browser from
 * here can still copy it.
 */

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getVersion } from "@tauri-apps/api/app";
import { openUrl } from "@tauri-apps/plugin-opener";

import { Button } from "@/components/Button";
import { FailureNotice } from "@/components/FailureNotice";
import { useT } from "@/i18n";
import { asFailure, type IpcFailure } from "@/lib/ipc";

import { SettingsSection } from "./SettingsSection";
import s from "./AboutSection.module.css";

const REPOSITORY_URL = "https://github.com/bbesli/Remoter";

export function AboutSection() {
  const t = useT("settings");
  const [openFailure, setOpenFailure] = useState<IpcFailure | null>(null);

  const version = useQuery({
    // The one key in the frontend that is not built in lib/queryKeys.ts, and
    // deliberately so: this is the Tauri binary's own version, not vault or
    // settings data, so nothing else reads it and nothing invalidates it.
    // Add a builder there the moment a second reader appears.
    queryKey: ["appVersion"],
    queryFn: () => getVersion(),
    staleTime: Infinity,
  });

  async function open() {
    setOpenFailure(null);
    try {
      await openUrl(REPOSITORY_URL);
    } catch (e) {
      setOpenFailure(asFailure(e));
    }
  }

  const versionText = version.isPending
    ? t("about.versionReading")
    : version.isError
      ? t("about.versionUnavailable")
      : version.data;

  return (
    <SettingsSection title={t("about.title")} description={t("about.description")}>
      <dl className={s.facts}>
        <dt className={s.term}>{t("about.versionLabel")}</dt>
        <dd className={[s.value, s.mono].join(" ")}>{versionText}</dd>

        <dt className={s.term}>{t("about.licenceLabel")}</dt>
        <dd className={s.value}>{t("about.licenceValue")}</dd>

        <dt className={s.term}>{t("about.exceptionLabel")}</dt>
        <dd className={s.value}>{t("about.exceptionValue")}</dd>

        <dt className={s.term}>{t("about.updatesLabel")}</dt>
        <dd className={s.value}>{t("about.updatesValue")}</dd>

        <dt className={s.term}>{t("about.repositoryLabel")}</dt>
        <dd className={s.value}>
          <div className={s.repository}>
            <code className={["selectable", s.url].join(" ")}>{REPOSITORY_URL}</code>
            <Button size="sm" onClick={() => void open()}>
              {t("about.repositoryOpen")}
            </Button>
          </div>
        </dd>
      </dl>

      {openFailure !== null && (
        <FailureNotice
          failure={openFailure}
          title={t("about.repositoryFailed")}
          onRetry={() => void open()}
        />
      )}
    </SettingsSection>
  );
}
