/**
 * Catches a render throw so one broken component does not unmount the
 * application.
 *
 * There was none, and the consequence was specific rather than theoretical: a
 * throw anywhere in the tree takes down a recovery-key dialog the user has not
 * yet transcribed, and that key cannot be produced again by anything. The
 * boundary keeps the window alive and says what happened.
 *
 * It deliberately does NOT show the error's message in the main body. A render
 * error can carry interpolated values, and this application renders
 * credentials' surroundings — the message goes to a copyable details block the
 * user opens on purpose, not into the page.
 */

import { Component, type ErrorInfo, type ReactNode } from "react";

import { useT } from "@/i18n";

import { Button } from "./Button";
import s from "./ErrorBoundary.module.css";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
  where: string | null;
  copied: boolean;
}

interface FallbackProps {
  error: Error;
  where: string | null;
  copied: boolean;
  onCopy: () => void;
  onRetry: () => void;
}

/**
 * The screen itself, as a function component.
 *
 * Split out of the class for one reason: `useT` is a hook and a class cannot
 * call one. Rendering the copy through the hook rather than through the
 * instance directly is what makes this screen follow a language change like
 * every other — and `main.tsx` deliberately mounts the boundary *inside* the
 * i18n provider so that the one screen a user reads most carefully is not the
 * one screen left in English.
 */
function ErrorScreen({ error, where, copied, onCopy, onRetry }: FallbackProps) {
  const t = useT("common");

  return (
    <div className={s.wrap} role="alert">
      <div className={s.card}>
        <h1 className={s.title}>{t("crash.title")}</h1>
        <p className={s.lead}>{t("crash.lead")}</p>
        <details className={s.details}>
          <summary className={s.summary}>{t("crash.details")}</summary>
          {/* The diagnostic itself: an error name, its message and a component
              stack. Never translated — it is what gets pasted into a bug
              report, and a translated stack helps nobody read it. */}
          <pre className={`${s.stack} selectable`}>
            {error.name}: {error.message}
            {where === null ? null : `\n${where}`}
          </pre>
        </details>
        <div className={s.actions}>
          <Button variant="secondary" size="md" onClick={onCopy}>
            {copied ? t("crash.copied") : t("crash.copy")}
          </Button>
          <Button variant="primary" size="md" onClick={onRetry}>
            {t("crash.retry")}
          </Button>
        </div>
      </div>
    </div>
  );
}

export class ErrorBoundary extends Component<Props, State> {
  override state: State = { error: null, where: null, copied: false };

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error };
  }

  override componentDidCatch(_error: Error, info: ErrorInfo): void {
    // The component stack, not the props: props can carry anything.
    this.setState({ where: info.componentStack ?? null });
  }

  private readonly retry = (): void => {
    this.setState({ error: null, where: null, copied: false });
  };

  private readonly copy = (): void => {
    const { error, where } = this.state;
    const text = [error?.name, error?.message, error?.stack, where]
      .filter((part) => typeof part === "string" && part.length > 0)
      .join("\n\n");
    void navigator.clipboard
      .writeText(text)
      .then(() => this.setState({ copied: true }))
      .catch(() => {
        /* A clipboard that refuses is not worth a second error. */
      });
  };

  override render(): ReactNode {
    const { error, where, copied } = this.state;
    if (error === null) return this.props.children;

    return (
      <ErrorScreen
        error={error}
        where={where}
        copied={copied}
        onCopy={this.copy}
        onRetry={this.retry}
      />
    );
  }
}
