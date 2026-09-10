/**
 * The application's icon vocabulary.
 *
 * Naming the icons here rather than importing Lucide at each call site keeps
 * the set closed: a contributor adds a name to this union deliberately, which
 * is what stops a second icon language creeping in. Icons inherit
 * `currentColor`, so tone is the caller's business.
 */

import {
  ArrowLeft,
  ArrowRight,
  Check,
  ChevronDown,
  ChevronRight,
  Copy,
  Download,
  File,
  Folder,
  Key,
  Lock,
  LockOpen,
  Plus,
  Printer,
  Search,
  Server,
  Settings,
  Shield,
  Star,
  Trash2,
  TriangleAlert,
  Usb,
  X,
  type LucideIcon,
} from "lucide-react";

export type IconName =
  | "folder"
  | "server"
  | "key"
  | "lock"
  | "unlock"
  | "search"
  | "plus"
  | "chevron-right"
  | "chevron-down"
  | "x"
  | "check"
  | "alert"
  | "file"
  | "usb"
  | "shield"
  | "copy"
  | "download"
  | "printer"
  | "arrow-left"
  | "arrow-right"
  | "settings"
  | "trash"
  | "star";

const ICONS: Record<IconName, LucideIcon> = {
  folder: Folder,
  server: Server,
  key: Key,
  lock: Lock,
  unlock: LockOpen,
  search: Search,
  plus: Plus,
  "chevron-right": ChevronRight,
  "chevron-down": ChevronDown,
  x: X,
  check: Check,
  alert: TriangleAlert,
  file: File,
  usb: Usb,
  shield: Shield,
  copy: Copy,
  download: Download,
  printer: Printer,
  "arrow-left": ArrowLeft,
  "arrow-right": ArrowRight,
  settings: Settings,
  trash: Trash2,
  star: Star,
};

/** Directional icons mirror under RTL; object icons do not. */
const MIRRORS_IN_RTL: ReadonlySet<IconName> = new Set<IconName>([
  "chevron-right",
  "arrow-left",
  "arrow-right",
]);

interface IconProps {
  name: IconName;
  size?: number | undefined;
  /** Only set this when the icon is the sole carrier of meaning. */
  title?: string | undefined;
}

export function Icon({ name, size = 16, title }: IconProps) {
  const Glyph = ICONS[name];
  const labelled = title !== undefined && title !== "";

  return (
    <Glyph
      size={size}
      strokeWidth={1.9}
      absoluteStrokeWidth
      className={MIRRORS_IN_RTL.has(name) ? "mirror-in-rtl" : undefined}
      aria-hidden={labelled ? undefined : true}
      {...(labelled ? { role: "img", "aria-label": title } : {})}
      focusable="false"
    />
  );
}
