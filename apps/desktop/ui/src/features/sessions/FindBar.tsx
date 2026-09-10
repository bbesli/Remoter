/**
 * Find in the scrollback.
 *
 * Opened with Ctrl/Cmd+Shift+F while a terminal has focus — Shift because
 * `Ctrl+F` is "forward one character" in every readline binding and in vi, and
 * an application that swallowed it would be one people stop using for real
 * work (`docs/ui/information-architecture.md`).
 *
 * It is deliberately *not* a modal. Nothing behind it is inert: the session
 * keeps producing output while the bar is open, and a focus trap over a live
 * terminal would be a promise the application has no reason to make.
 */

import { useEffect, useRef, useState } from "react";

import { Icon } from "@/components/Icon";
import { TextInput } from "@/components/TextInput";
import { clearSearch, focusTerminal, searchTerminal } from "./terminals";

import s from "./FindBar.module.css";

const TEXT = {
  label: "Find in the scrollback",
  placeholder: "Find…",
  previous: "Previous match",
  next: "Next match",
  close: "Close the find bar",
  noMatch: "no match",
} as const;

export function FindBar({ tabId, onClose }: { tabId: string; onClose: () => void }) {
  const [needle, setNeedle] = useState("");
  const [missed, setMissed] = useState(false);
  const inputRef = useRef<HTMLDivElement>(null);

  // The bar takes focus on open and hands it back on close, so Escape puts the
  // caret straight back in the shell rather than nowhere.
  useEffect(() => {
    return () => {
      clearSearch(tabId);
      focusTerminal(tabId);
    };
  }, [tabId]);

  const find = (back: boolean) => {
    if (needle === "") return;
    setMissed(!searchTerminal(tabId, needle, back));
  };

  return (
    <div className={s.bar} ref={inputRef} role="search" aria-label={TEXT.label}>
      <span className={s.glyph} aria-hidden="true">
        <Icon name="search" size={13} />
      </span>
      <span className={s.field}>
        <TextInput
          value={needle}
          onChange={(value) => {
            setNeedle(value);
            setMissed(false);
          }}
          placeholder={TEXT.placeholder}
          ariaLabel={TEXT.label}
          mono
          autoFocus
          invalid={missed}
          onKeyDown={(event) => {
            if (event.key === "Escape") {
              event.preventDefault();
              event.stopPropagation();
              onClose();
              return;
            }
            if (event.key !== "Enter") return;
            event.preventDefault();
            find(event.shiftKey);
          }}
        />
      </span>
      {missed && <span className={s.miss}>{TEXT.noMatch}</span>}
      <button
        type="button"
        className={s.control}
        onClick={() => find(true)}
        title={TEXT.previous}
        aria-label={TEXT.previous}
      >
        <Icon name="chevron-right" size={13} />
      </button>
      <button
        type="button"
        className={s.control}
        onClick={() => find(false)}
        title={TEXT.next}
        aria-label={TEXT.next}
      >
        <Icon name="chevron-down" size={13} />
      </button>
      <button
        type="button"
        className={s.control}
        onClick={onClose}
        title={TEXT.close}
        aria-label={TEXT.close}
      >
        <Icon name="x" size={13} />
      </button>
    </div>
  );
}
