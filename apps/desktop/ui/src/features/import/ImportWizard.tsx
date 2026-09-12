/**
 * The import wizard.
 *
 * One rule governs the whole screen: **nothing touches the vault until the
 * commit**. Detection reads a header, the parse builds a tree in the core's own
 * memory, and the preview draws it. The first and only write is step 7, in one
 * transaction.
 *
 * The steps, and which of them are work rather than input:
 *
 *   1 Source        the file, and what the core detects it to be
 *   2 Secrets       the document password, and what the file's protection was
 *   3 Parse         work — the core reads the file
 *   4 Preview       the tree as it would be created, node by node
 *   5 Report        findings by severity
 *   6 Destination   the folder to import into
 *   7 Commit        work — one transaction
 *   8 Result        what was written, and what to do about it
 *
 * Two things the core reports that this interface refuses to bury: a file
 * encrypted with mRemoteNG's published default password is called out at step
 * 2, as soon as detection knows, rather than in the report after the fact; and
 * a `ProxyJump` that became a real gateway chain is shown on the node in the
 * preview, because it is the most valuable thing the importer does and it is
 * otherwise invisible.
 *
 * Two things the core does not do, which are therefore not drawn: it does not
 * compare an import against what is already in the vault, and it cannot undo a
 * commit. The preview says so and says what to do instead — untick it now.
 *
 * Secrets: the document password lives in this component's state only until
 * `import_parse` has taken it, and is cleared on success. The preview handle
 * that comes back names a parse held in the core with recovered passwords in
 * it, so leaving cancels it — through the confirmation when the user leaves
 * deliberately, and unconditionally on unmount, which is what covers the vault
 * locking underneath the wizard.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { BusyStatus, SkeletonRows } from "@/components/Busy";
import { Button } from "@/components/Button";
import { Icon } from "@/components/Icon";
import { useAnyModalOpen } from "@/hooks/useModalRegistration";
import { useStagedSecret } from "@/hooks/useStagedSecret";
import { useLocale, useT } from "@/i18n";
import { asFailure, ipc } from "@/lib/ipc";
import type {
  ImportDetection,
  ImportPreview,
  ImportReport,
  ImportResult,
  ImportSource,
} from "@/lib/ipc";
import { invalidateAfterTreeChange, qk } from "@/lib/queryKeys";
import { useApp } from "@/stores/app";

import { CommitStep } from "./CommitStep";
import { DestinationStep, folderPaths } from "./DestinationStep";
import { DiscardDialog } from "./DiscardDialog";
import { PreviewStep } from "./PreviewStep";
import { ReportStep } from "./ReportStep";
import { ResultStep } from "./ResultStep";
import { SecretsStep } from "./SecretsStep";
import { SourceStep } from "./SourceStep";
import {
  excludedRoots,
  includedCounts,
  indexNodes,
  matchingIds,
  toggleNode,
  type ImportTreeIndex,
} from "./selection";
import {
  canGoTo,
  forwardBlock,
  jumpBlock,
  STEPS,
  wantsDocumentPassword,
  type StepNumber,
  type WizardFacts,
} from "./steps";
import s from "./ImportWizard.module.css";

/**
 * The forward control's label, per step, as a catalogue key.
 *
 * Step 1 is the exception and is handled at the call site: before the file has
 * been looked at, the same button reads the file rather than moving on.
 */
const FORWARD_LABEL = {
  1: "nav.continue",
  2: "nav.parse",
  3: "nav.continue",
  4: "nav.continue",
  5: "nav.toDestination",
  6: "nav.toCommit",
  7: "nav.continue",
  8: "nav.done",
} as const satisfies Record<StepNumber, string>;

/**
 * Which standing note the footer carries, as a catalogue key.
 *
 * Every step but the last two is a step where nothing has been written.
 */
function footerNote(step: StepNumber): {
  key: "footer.written" | "footer.willWrite" | "footer.nothingWritten";
  tone: "muted" | "warning";
} {
  if (step === 8) return { key: "footer.written", tone: "muted" };
  if (step === 7) return { key: "footer.willWrite", tone: "warning" };
  return { key: "footer.nothingWritten", tone: "muted" };
}

export function ImportWizard() {
  const t = useT("import");
  const { code: locale } = useLocale();
  const goBack = useApp((state) => state.goBack);
  const queryClient = useQueryClient();
  const modalOpen = useAnyModalOpen();

  const [step, setStep] = useState<StepNumber>(1);
  const [path, setPath] = useState("");
  const [detection, setDetection] = useState<ImportDetection | null>(null);
  /** The path the detection describes, so a typed edit invalidates it. */
  const [detectedFor, setDetectedFor] = useState<string | null>(null);
  const [sourceOverride, setSourceOverride] = useState<ImportSource | null>(null);

  const [password, setPassword] = useState("");
  const [reveal, setReveal] = useState(false);

  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [excluded, setExcluded] = useState<ReadonlySet<string>>(new Set());
  const [collapsed, setCollapsed] = useState<ReadonlySet<string>>(new Set());
  const [filter, setFilter] = useState("");

  const [destinationId, setDestinationId] = useState<string | null>(null);
  const [result, setResult] = useState<ImportResult | null>(null);
  /** Kept past the commit: the result page explains itself from the findings. */
  const [committedReport, setCommittedReport] = useState<ImportReport | null>(null);

  const [discarding, setDiscarding] = useState(false);

  /**
   * The preview the core is holding for us, read by the unmount cleanup.
   *
   * A ref rather than the state value because the cleanup runs once, with
   * whatever it closed over — and the one thing it must not do is fail to
   * cancel a live preview full of recovered passwords.
   */
  const liveImportId = useRef<string | null>(null);

  const nodes = useQuery({ queryKey: qk.nodes(), queryFn: ipc.listNodes });

  const detect = useMutation({
    mutationFn: (target: string) => ipc.detectImport(target),
    onSuccess: (data, target) => {
      setDetection(data);
      setDetectedFor(target);
      // Detection is the authority until the user overrules it; a new file
      // clears an override made for the previous one.
      setSourceOverride(null);
    },
  });

  // The document password is staged in a ref rather than passed as a mutation
  // variable: TanStack retains variables in its cache after the call settles,
  // so a password passed that way outlives the parse it was for. See
  // useStagedSecret.
  const stagedParse = useStagedSecret<{
    path: string;
    password: string | null;
    source: ImportSource | null;
  }>();

  const parse = useMutation({
    mutationFn: () => {
      const vars = stagedParse.read();
      if (vars === null) return Promise.reject(new Error("nothing staged"));
      return ipc.parseImport(vars.path, vars.password, vars.source);
    },
    onSuccess: (data) => {
      stagedParse.clear();
      liveImportId.current = data.importId;
      setPreview(data);
      setExcluded(new Set());
      setCollapsed(new Set());
      setFilter("");
      // The password has been taken by the core and is not needed again. It is
      // dropped here rather than held for the life of the screen.
      setPassword("");
      setReveal(false);
      setStep(4);
    },
    onError: () => {
      // Back to the field that most often explains it.
      setStep(2);
    },
  });

  const commit = useMutation({
    mutationFn: (vars: { importId: string; destinationId: string | null; excludedIds: string[] }) =>
      ipc.commitImport({
        importId: vars.importId,
        destinationId: vars.destinationId,
        excludedIds: vars.excludedIds,
      }),
    onSuccess: async (data) => {
      // The handle is spent: the core dropped the preview when it committed it.
      liveImportId.current = null;
      setCommittedReport(preview?.report ?? null);
      setResult(data);
      setStep(8);
      await invalidateAfterTreeChange(queryClient);
    },
  });

  const cancel = useMutation({
    mutationFn: (importId: string) => ipc.cancelImport(importId),
    onSuccess: () => {
      liveImportId.current = null;
    },
  });

  // Whatever happens to this screen — the route changes, the vault locks and
  // the shell replaces it — the parse must not be left resident in the core.
  useEffect(() => {
    return () => {
      const id = liveImportId.current;
      if (id === null) return;
      liveImportId.current = null;
      void ipc.cancelImport(id).catch(() => {
        // Cancelling a preview the core has already dropped is not a failure,
        // and there is no screen left to report one to.
      });
    };
  }, []);

  const index: ImportTreeIndex = useMemo(
    // The locale orders siblings, so a language change re-sorts the preview.
    () => indexNodes(preview?.nodes ?? [], locale),
    [preview, locale],
  );
  const counts = useMemo(() => includedCounts(index, excluded), [index, excluded]);
  // The filter folds under the reader's casing rules, so the language has to
  // reach it. See `matchingIds`.
  const visible = useMemo(() => matchingIds(index, filter, locale), [index, filter, locale]);

  const source: ImportSource | null = sourceOverride ?? detection?.format ?? null;
  /**
   * Whether the forward control on step 1 reads the file rather than moving on.
   *
   * An explicit choice of format ends it: a file the sniffer refuses — or
   * cannot reach — would otherwise leave the user pressing "Read this file"
   * against the same failure forever, with the format they picked ignored.
   */
  const needsDetect = path !== "" && detectedFor !== path && sourceOverride === null;
  const busy = detect.isPending || parse.isPending || commit.isPending || cancel.isPending;

  const parseFailure = parse.isError ? asFailure(parse.error) : null;

  const facts: WizardFacts = {
    hasFile: path !== "",
    format: source,
    detected: detection !== null && !needsDetect,
    // Either voice: the file's own header, or the parse coming back to say the
    // document password is what is missing. Detection cannot always know —
    // a format the sniffer would not commit to has no header read at all.
    passwordRequired:
      (detection?.passwordRequired ?? false) || wantsDocumentPassword(parseFailure),
    hasPassword: password !== "",
    hasPreview: preview !== null,
    includedCount: counts.total,
    committed: result !== null,
    busy,
  };

  const folders = nodes.isSuccess ? folderPaths(nodes.data, locale) : null;
  const destinationLabel =
    destinationId === null ? null : (folders?.find((f) => f.id === destinationId)?.path ?? null);

  const onPath = useCallback((next: string) => {
    setPath(next);
    setDetection(null);
    setDetectedFor(null);
    setSourceOverride(null);
  }, []);

  const runDetect = useCallback(() => {
    if (path === "") return;
    detect.mutate(path);
  }, [detect, path]);

  const runParse = useCallback(() => {
    if (path === "") return;
    setStep(3);
    stagedParse.stage({
      path,
      password: password === "" ? null : password,
      // Sent only when the user overruled detection: the core detects for
      // itself otherwise, and passing back its own answer would hide a
      // disagreement rather than surface it.
      source: sourceOverride,
    });
    parse.mutate();
  }, [parse, stagedParse, password, path, sourceOverride]);

  const runCommit = useCallback(() => {
    if (preview === null) return;
    commit.mutate({
      importId: preview.importId,
      destinationId,
      excludedIds: excludedRoots(index, excluded),
    });
  }, [commit, destinationId, excluded, index, preview]);

  const reset = useCallback(() => {
    setStep(1);
    setPath("");
    setDetection(null);
    setDetectedFor(null);
    setSourceOverride(null);
    setPassword("");
    setReveal(false);
    setPreview(null);
    setExcluded(new Set());
    setCollapsed(new Set());
    setFilter("");
    setDestinationId(null);
    setResult(null);
    setCommittedReport(null);
    detect.reset();
    parse.reset();
    stagedParse.clear();
    commit.reset();
    cancel.reset();
  }, [cancel, commit, detect, parse]);

  const leave = useCallback(() => {
    // A preview still held in the core is worth a question; anything else
    // leaves at once.
    if (liveImportId.current === null) {
      goBack();
      return;
    }
    setDiscarding(true);
  }, [goBack]);

  const confirmDiscard = useCallback(() => {
    const id = liveImportId.current;
    if (id === null) {
      goBack();
      return;
    }
    cancel.mutate(id, { onSuccess: () => goBack() });
  }, [cancel, goBack]);

  // Escape leaves, unless a modal of our own is up — that one answers Escape
  // itself, and both firing would close the dialog and the wizard together.
  useEffect(() => {
    if (modalOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      e.preventDefault();
      leave();
    };
    document.addEventListener("keydown", onKeyDown, true);
    return () => document.removeEventListener("keydown", onKeyDown, true);
  }, [leave, modalOpen]);

  const onToggleNode = useCallback(
    (id: string) => setExcluded((current) => toggleNode(current, index, id)),
    [index],
  );
  const onToggleCollapsed = useCallback((id: string) => {
    setCollapsed((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);
  const includeAll = useCallback(() => setExcluded(new Set()), []);
  const excludeAll = useCallback(
    () => setExcluded(new Set(preview?.nodes.map((node) => node.id) ?? [])),
    [preview],
  );

  const block = forwardBlock(step, facts);
  const nextLabel = step === 1 && needsDetect ? t("nav.detect") : t(FORWARD_LABEL[step]);
  const onNext = () => {
    switch (step) {
      case 1:
        if (needsDetect) runDetect();
        else setStep(2);
        return;
      case 2:
        runParse();
        return;
      case 4:
        setStep(5);
        return;
      case 5:
        setStep(6);
        return;
      case 6:
        setStep(7);
        return;
      case 8:
        goBack();
        return;
      default:
        return;
    }
  };

  const note = footerNote(step);
  const showNext = step !== 3 && step !== 7;
  const showBack = step > 1 && step !== 8 && !busy;

  return (
    <div className={s.screen}>
      <header className={s.header}>
        <span className={s.headerIcon} aria-hidden="true">
          <Icon name="download" size={15} />
        </span>
        <h1 className={s.headerTitle}>{t("wizard.title")}</h1>
        <div className={s.spacer} />
        <button
          type="button"
          className={s.closeButton}
          onClick={leave}
          title={t("wizard.closeHint")}
          aria-label={t("wizard.close")}
        >
          <Icon name="x" size={14} />
        </button>
      </header>

      <nav className={s.rail} aria-label={t("rail.label")}>
        {STEPS.map((definition, i) => {
          const reachable = definition.n !== step && canGoTo(definition.n, facts);
          const state =
            definition.n === step ? "current" : definition.n < step ? "done" : "ahead";
          const refusal = jumpBlock(definition.n, facts);
          return (
            <span key={definition.n} className={s.railStepWrap}>
              <button
                type="button"
                className={s.railStep}
                data-state={state}
                aria-current={definition.n === step ? "step" : undefined}
                disabled={!reachable}
                title={refusal === null ? t(definition.labelKey) : t(refusal)}
                onClick={() => setStep(definition.n)}
              >
                <span className={s.railNumber}>{definition.n}</span>
                {t(definition.labelKey)}
              </button>
              {i < STEPS.length - 1 && <span className={s.railConnector} />}
            </span>
          );
        })}
      </nav>

      <div className={s.body}>
        {step === 1 && (
          <SourceStep
            path={path}
            onPath={onPath}
            detection={detection}
            detecting={detect.isPending}
            failure={detect.isError ? asFailure(detect.error) : null}
            onRetry={runDetect}
            source={source}
            onSource={setSourceOverride}
            overridden={sourceOverride !== null}
          />
        )}

        {step === 2 && (
          <SecretsStep
            detection={detection}
            path={path}
            password={password}
            onPassword={setPassword}
            reveal={reveal}
            onReveal={setReveal}
            failure={parseFailure}
            onRetry={runParse}
          />
        )}

        {step === 3 && (
          <div className={`${s.step} ${s.narrow}`}>
            <BusyStatus label={t("parse.busy")} note={t("parse.busyNote")} size={16} />
            <SkeletonRows count={6} />
          </div>
        )}

        {step === 4 && preview !== null && (
          <PreviewStep
            preview={preview}
            index={index}
            excluded={excluded}
            onToggle={onToggleNode}
            onIncludeAll={includeAll}
            onExcludeAll={excludeAll}
            collapsed={collapsed}
            onToggleCollapsed={onToggleCollapsed}
            filter={filter}
            onFilter={setFilter}
            visible={visible}
          />
        )}

        {step === 5 && preview !== null && <ReportStep report={preview.report} />}

        {step === 6 && (
          <DestinationStep
            destinationId={destinationId}
            onDestination={setDestinationId}
            folders={folders}
            pending={nodes.isPending}
            failure={nodes.isError ? asFailure(nodes.error) : null}
            onRetry={() => void nodes.refetch()}
          />
        )}

        {step === 7 && (
          <CommitStep
            counts={counts}
            excludedCount={(preview?.nodes.length ?? 0) - counts.total}
            destinationLabel={destinationLabel}
            committing={commit.isPending}
            failure={commit.isError ? asFailure(commit.error) : null}
            onCommit={runCommit}
          />
        )}

        {step === 8 && result !== null && (
          <ResultStep
            result={result}
            report={committedReport}
            destinationLabel={destinationLabel}
            onDone={goBack}
            onAnother={reset}
          />
        )}
      </div>

      <footer className={s.footer}>
        <span className={s.footerNote} data-tone={note.tone}>
          <Icon name={note.tone === "warning" ? "alert" : "lock"} size={13} />
          {t(note.key)}
        </span>
        <div className={s.spacer} />
        <div className={s.footerButtons}>
          {showBack && <Button onClick={() => setStep(backStep(step))}>{t("nav.back")}</Button>}
          {showNext && (
            <Button
              variant="primary"
              onClick={onNext}
              disabled={block !== null}
              {...(block === null ? {} : { title: t(block) })}
            >
              {nextLabel}
            </Button>
          )}
        </div>
      </footer>

      {discarding && (
        <DiscardDialog
          busy={cancel.isPending}
          failure={cancel.isError ? asFailure(cancel.error) : null}
          onConfirm={confirmDiscard}
          onCancel={() => setDiscarding(false)}
          onLeaveAnyway={goBack}
        />
      )}
    </div>
  );
}

/** Back skips the two work steps: there is nothing to go back to inside them. */
function backStep(step: StepNumber): StepNumber {
  if (step === 4) return 2;
  if (step === 1) return 1;
  return (step - 1) as StepNumber;
}
