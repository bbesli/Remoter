/**
 * Whether the user arrived by pressing "bring across what I have".
 *
 * The first-run screen offers two doors and only one of them can be honoured
 * immediately. Importing needs an open vault — `import_parse` refuses to hold a
 * preview full of recovered passwords with nothing to seal them into — so the
 * import door has to run the create-vault wizard first and open the importer
 * afterwards. Something has to carry that "afterwards" across three screens.
 *
 * It is not in `stores/app.ts` with the rest of the routing because it is not
 * routing: it is one question the launch screen asked, answered once, consumed
 * once, and meaningless outside the first run. Keeping it beside the screens
 * that set and read it means the whole flow is legible from this directory.
 *
 * It holds no secret and survives nothing: a reload clears it, which is the
 * right behaviour — a user who restarts mid-creation is no longer mid-anything.
 */

import { create } from "zustand";

interface ImportIntentStore {
  /** True between the import door being pressed and the importer opening. */
  wanted: boolean;
  setWanted: (wanted: boolean) => void;
}

export const useImportIntent = create<ImportIntentStore>((set) => ({
  wanted: false,
  setWanted: (wanted) => set({ wanted }),
}));
