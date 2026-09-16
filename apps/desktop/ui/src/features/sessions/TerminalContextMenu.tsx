/**
 * A terminal's own menu, drawn where the right button was pressed.
 *
 * It replaces the WebView's text-field menu — Cut, Paste, Insert Emoji, Insert
 * Unicode Control Character — which is a browser's menu and was the most
 * visible reason a session here read as a web page. The items are the ones
 * GNOME Terminal and Terminal.app offer, and each carries its shortcut written
 * the way that platform's own menus write it, because that is where people
 * learn the shortcuts.
 *
 * Windows has no menu here by default: its terminals copy or paste on the right
 * button, and `terminals.ts` does that without asking React. Shift+right-click
 * reaches this menu on every platform.
 */

import { useEffect, useRef } from "react";

import { Icon } from "@/components/Icon";
import { documentDirection, inlineStartOffset, useT } from "@/i18n";
import { currentPlatform } from "@/lib/platform";

import { menuShortcut } from "./terminalInput";
import { focusTerminal, runTerminalAction } from "./terminals";

import s from "./TerminalContextMenu.module.css";

/** How far from the window's edges the menu is kept, so it never opens clipped. */
const EDGE = 8;
/** The menu's size, for keeping it inside the window before it has been measured. */
const WIDTH = 240;
const HEIGHT = 200;

interface TerminalContextMenuProps {
  tabId: string;
  x: number;
  y: number;
  hasSelection: boolean;
  onFind: () => void;
  onClose: () => void;
}

export function TerminalContextMenu({
  tabId,
  x,
  y,
  hasSelection,
  onFind,
  onClose,
}: TerminalContextMenuProps) {
  const t = useT("sessions");
  const platform = currentPlatform();
  const ref = useRef<HTMLDivElement | null>(null);

  // Keyboard first: the menu takes focus on its first usable item, so it can
  // be driven with the arrows and Escape like any native menu.
  useEffect(() => {
    const first = ref.current?.querySelector<HTMLButtonElement>("button:not(:disabled)");
    first?.focus();
  }, []);

  useEffect(() => {
    const close = () => onClose();
    const onPointer = (event: PointerEvent) => {
      if (ref.current !== null && event.target instanceof Node && ref.current.contains(event.target)) {
        return;
      }
      onClose();
    };
    window.addEventListener("pointerdown", onPointer, true);
    window.addEventListener("resize", close);
    window.addEventListener("blur", close);
    return () => {
      window.removeEventListener("pointerdown", onPointer, true);
      window.removeEventListener("resize", close);
      window.removeEventListener("blur", close);
    };
  }, [onClose]);

  const act = (run: () => void) => {
    onClose();
    run();
  };

  const onKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    const items = [
      ...(ref.current?.querySelectorAll<HTMLButtonElement>("button:not(:disabled)") ?? []),
    ];
    const index = items.indexOf(document.activeElement as HTMLButtonElement);
    if (event.key === "Escape") {
      event.preventDefault();
      onClose();
      focusTerminal(tabId);
    } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      if (items.length === 0) return;
      const step = event.key === "ArrowDown" ? 1 : -1;
      items[(index + step + items.length) % items.length]?.focus();
    } else if (event.key === "Tab") {
      // A menu is not a tab stop sequence; Tab leaving it closes it, as native
      // menus do, instead of walking focus into the page behind.
      event.preventDefault();
      onClose();
      focusTerminal(tabId);
    }
  };

  const left = Math.min(Math.max(x, EDGE), window.innerWidth - WIDTH - EDGE);
  const top = Math.min(Math.max(y, EDGE), window.innerHeight - HEIGHT - EDGE);

  return (
    <div
      ref={ref}
      className={s.menu}
      role="menu"
      aria-label={t("terminalMenu.label")}
      onKeyDown={onKeyDown}
      onContextMenu={(event) => event.preventDefault()}
      style={{
        // Physical coordinates from the click, placed logically so an RTL
        // interface mirrors the menu the same way it mirrors everything else.
        insetInlineStart: `${inlineStartOffset(left, window.innerWidth, documentDirection())}px`,
        top: `${top}px`,
      }}
    >
      <Item
        icon="copy"
        label={t("terminalMenu.copy")}
        shortcut={menuShortcut(platform, "copy")}
        disabled={!hasSelection}
        onClick={() => act(() => void runTerminalAction(tabId, "copy"))}
      />
      <Item
        label={t("terminalMenu.paste")}
        shortcut={menuShortcut(platform, "paste")}
        onClick={() => act(() => void runTerminalAction(tabId, "paste"))}
      />
      <Item
        label={t("terminalMenu.selectAll")}
        shortcut={menuShortcut(platform, "selectAll")}
        onClick={() => act(() => void runTerminalAction(tabId, "selectAll"))}
      />
      <div className={s.separator} role="separator" />
      <Item
        icon="search"
        label={t("terminalMenu.find")}
        shortcut={menuShortcut(platform, "find")}
        onClick={() => act(onFind)}
      />
      <Item
        label={t("terminalMenu.clearScrollback")}
        shortcut={menuShortcut(platform, "clearScrollback")}
        onClick={() =>
          act(() => {
            void runTerminalAction(tabId, "clearScrollback");
            focusTerminal(tabId);
          })
        }
      />
    </div>
  );
}

interface ItemProps {
  icon?: "copy" | "search";
  label: string;
  shortcut: string | null;
  disabled?: boolean;
  onClick: () => void;
}

function Item({ icon, label, shortcut, disabled = false, onClick }: ItemProps) {
  return (
    <button type="button" role="menuitem" className={s.item} disabled={disabled} onClick={onClick}>
      <span className={s.icon} aria-hidden="true">
        {icon !== undefined && <Icon name={icon} size={13} />}
      </span>
      <span className={s.label}>{label}</span>
      {shortcut !== null && (
        // Key names are never translated, and a shortcut reads left to right
        // whatever the interface language.
        <kbd className={s.shortcut} dir="ltr">
          {shortcut}
        </kbd>
      )}
    </button>
  );
}
