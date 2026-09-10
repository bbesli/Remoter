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

import { Button } from "./Button";
import s from "./ErrorBoundary.module.css";

const TEXT = {
  title: "Something in the interface stopped working",
  lead: "The rest of Remoter is still running and your vault has not been touched. If you were part-way through something that cannot be repeated — a recovery key you had not yet written down — do not close this window; copy the details and ask for help first.",
  retry: "Try rendering again",
  details: "Technical details",
  copy: "Copy details",
  copied: "Copied",
} as const;

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
  where: string | null;
  copied: boolean;
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
      <div className={s.wrap} role="alert">
        <div className={s.card}>
          <h1 className={s.title}>{TEXT.title}</h1>
          <p className={s.lead}>{TEXT.lead}</p>
          <details className={s.details}>
            <summary className={s.summary}>{TEXT.details}</summary>
            <pre className={`${s.stack} selectable`}>
              {error.name}: {error.message}
              {where === null ? null : `\n${where}`}
            </pre>
          </details>
          <div className={s.actions}>
            <Button variant="secondary" size="md" onClick={this.copy}>
              {copied ? TEXT.copied : TEXT.copy}
            </Button>
            <Button variant="primary" size="md" onClick={this.retry}>
              {TEXT.retry}
            </Button>
          </div>
        </div>
      </div>
    );
  }
}
