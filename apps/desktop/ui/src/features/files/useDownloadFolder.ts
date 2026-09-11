/**
 * Where a download lands, and how the local pane comes to already know.
 *
 * # The defect this replaces
 *
 * The local pane started with nothing and remembered nothing. Every file pane
 * opened with no destination, so every download began by opening a folder
 * picker — including the second download into the folder the first one went to,
 * and including the one after a restart. Two panes open on two hosts each had
 * to be told separately. That is not a missing convenience; it is a control
 * that makes the user do the same work every time it is used.
 *
 * # Two sources, in order
 *
 * 1. **What was chosen last**, from `settings.fileDownloadFolder`. It lives in
 *    the app settings file rather than in a store, so it survives a restart and
 *    is shared by every pane in the window — which is the point: "the folder I
 *    download into" is a property of the person, not of one tab.
 * 2. **The platform's own downloads folder**, from Tauri's `downloadDir()`,
 *    when nothing has been chosen yet. A first-run pane that already points
 *    somewhere sensible is the difference between one click and three.
 *
 * The default is offered, not written: it becomes the stored preference only
 * once a transfer actually uses it, so "Remoter has never been told where to
 * put things" and "the user chose their Downloads folder" stay distinguishable.
 *
 * # Why this is a query and a mutation
 *
 * The settings are the core's, so they are server state in TanStack Query's
 * sense (CLAUDE.md §6) and reach the interface through `qk.settings()` like
 * every other read of them. Writing goes through the same command the settings
 * screen uses, so a folder chosen here is visible there and vice versa.
 */

import { useCallback, useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { downloadDir } from "@tauri-apps/api/path";

import { ipc, type AppSettings } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";

export interface DownloadFolder {
  /** Where a download would go, or `null` if nothing is known yet. */
  folder: string | null;
  /**
   * True when {@link folder} is the platform's default rather than a folder
   * anybody chose. The pane says which, because "we picked this for you" and
   * "you picked this" are different promises.
   */
  isDefault: boolean;
  /** True while either source is still being read. */
  loading: boolean;
  /** Chooses a folder and remembers it for every pane and every restart. */
  remember: (folder: string) => void;
}

export function useDownloadFolder(): DownloadFolder {
  const queryClient = useQueryClient();
  const settings = useQuery({ queryKey: qk.settings(), queryFn: ipc.getSettings });

  // The platform's own downloads folder. Not a query: it is a constant for the
  // life of the process, it has no key anything else would share, and it is
  // read once. `null` also covers the case where the platform has no such
  // folder, which is not an error and must not be reported as one.
  const [platformDefault, setPlatformDefault] = useState<string | null>(null);
  const [askedPlatform, setAskedPlatform] = useState(false);

  useEffect(() => {
    let live = true;
    void downloadDir()
      .then((path) => {
        if (live) setPlatformDefault(path);
      })
      .catch(() => {
        // A platform with no downloads folder, or a permission this build was
        // not granted. The pane then starts with nothing, which is exactly
        // where it started before — not a failure worth a notice.
      })
      .finally(() => {
        if (live) setAskedPlatform(true);
      });
    return () => {
      live = false;
    };
  }, []);

  const remembered = settings.data?.fileDownloadFolder ?? null;

  const save = useMutation({
    mutationFn: (folder: string) => ipc.setSettings({ fileDownloadFolder: folder }),
    onSuccess: (next: AppSettings) => {
      // The command returns the whole settings object, so the cache is set
      // rather than invalidated: a refetch would ask for what is already here.
      queryClient.setQueryData(qk.settings(), next);
    },
    // A folder that could not be remembered is still a folder that can be used.
    // The transfer is the thing the user asked for; the memory is a courtesy,
    // and failing it loudly would put an error over a download that works.
  });

  const remember = useCallback(
    (folder: string) => {
      save.mutate(folder);
    },
    [save],
  );

  return {
    folder: remembered ?? platformDefault,
    isDefault: remembered === null && platformDefault !== null,
    loading: settings.isPending || !askedPlatform,
    remember,
  };
}
