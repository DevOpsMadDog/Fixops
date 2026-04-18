/**
 * User preferences — persisted to localStorage with in-memory fallback.
 *
 * This module owns the canonical type, defaults, storage key, and low-level
 * read/write helpers. The `usePreferences` hook (src/hooks/use-preferences.ts)
 * is the React-friendly wrapper for component use.
 */

export interface UserPreferences {
  theme: "dark" | "light" | "system";
  defaultOrgId: string;
  dashboardLayout: "grid" | "list";
  itemsPerPage: number;
  sidebarCollapsed: boolean;
  favoritePages: string[];
}

export const PREFERENCES_STORAGE_KEY = "aldeci-user-prefs";

export const PREFERENCES_DEFAULTS: UserPreferences = {
  theme: "dark",
  defaultOrgId: "default",
  dashboardLayout: "grid",
  itemsPerPage: 25,
  sidebarCollapsed: false,
  favoritePages: [],
};

// ── Storage helpers ──────────────────────────────────────────────────────────

function canUseBrowserStorage(): boolean {
  try {
    return typeof window !== "undefined" && typeof window.localStorage !== "undefined";
  } catch {
    return false;
  }
}

/**
 * Load preferences from localStorage, merging with defaults so that any new
 * fields added in the future are always present.
 */
export function loadPreferences(): UserPreferences {
  if (!canUseBrowserStorage()) return { ...PREFERENCES_DEFAULTS };
  try {
    const raw = window.localStorage.getItem(PREFERENCES_STORAGE_KEY);
    if (!raw) return { ...PREFERENCES_DEFAULTS };
    const parsed = JSON.parse(raw) as Partial<UserPreferences>;
    // Merge parsed over defaults so new keys are always populated
    return { ...PREFERENCES_DEFAULTS, ...parsed };
  } catch {
    return { ...PREFERENCES_DEFAULTS };
  }
}

/**
 * Persist the full preferences object to localStorage. Silently no-ops on
 * quota/security errors.
 */
export function savePreferences(prefs: UserPreferences): void {
  if (!canUseBrowserStorage()) return;
  try {
    window.localStorage.setItem(PREFERENCES_STORAGE_KEY, JSON.stringify(prefs));
  } catch {
    // quota exceeded or private-browsing restriction — ignore
  }
}

/**
 * Apply the `theme` preference to the document root so Tailwind's `dark` class
 * strategy works correctly.
 */
export function applyTheme(theme: UserPreferences["theme"]): void {
  if (typeof document === "undefined") return;
  const prefersDark = window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? true;
  const isDark = theme === "dark" || (theme === "system" && prefersDark);
  document.documentElement.classList.toggle("dark", isDark);
}
