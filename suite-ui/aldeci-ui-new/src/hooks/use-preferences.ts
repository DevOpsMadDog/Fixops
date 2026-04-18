/**
 * usePreferences — React hook for reading and updating user preferences.
 *
 * Backed by the Zustand app store so all components share one reactive source
 * of truth. Preferences are persisted to localStorage automatically.
 */
import { useCallback } from "react";
import { useAppStore } from "@/stores";
import type { UserPreferences } from "@/lib/preferences";
import { applyTheme } from "@/lib/preferences";
import { setStoredOrgId } from "@/lib/api";

export interface UsePreferencesReturn {
  preferences: UserPreferences;
  /** Merge a partial update into preferences and persist. */
  setPreference: <K extends keyof UserPreferences>(key: K, value: UserPreferences[K]) => void;
  /** Replace preferences wholesale and persist. */
  setPreferences: (patch: Partial<UserPreferences>) => void;
  /** Toggle sidebarCollapsed. */
  toggleSidebar: () => void;
  /** Cycle through "dark" → "light" → "system". */
  cycleTheme: () => void;
  /** Add a page path to favoritePages (idempotent). */
  addFavorite: (path: string) => void;
  /** Remove a page path from favoritePages. */
  removeFavorite: (path: string) => void;
  /** True if the given path is in favoritePages. */
  isFavorite: (path: string) => boolean;
}

export function usePreferences(): UsePreferencesReturn {
  const { preferences, setPreferences: storeSet, toggleSidebar } = useAppStore();

  const setPreference = useCallback(
    <K extends keyof UserPreferences>(key: K, value: UserPreferences[K]) => {
      storeSet({ [key]: value } as Partial<UserPreferences>);

      // Side-effects for specific fields
      if (key === "theme") {
        applyTheme(value as UserPreferences["theme"]);
      }
      if (key === "defaultOrgId") {
        setStoredOrgId(value as string);
      }
    },
    [storeSet]
  );

  const setPreferences = useCallback(
    (patch: Partial<UserPreferences>) => {
      storeSet(patch);
      if (patch.theme !== undefined) applyTheme(patch.theme);
      if (patch.defaultOrgId !== undefined) setStoredOrgId(patch.defaultOrgId);
    },
    [storeSet]
  );

  const cycleTheme = useCallback(() => {
    const order: UserPreferences["theme"][] = ["dark", "light", "system"];
    const current = preferences.theme as UserPreferences["theme"];
    const next = order[(order.indexOf(current) + 1) % order.length];
    setPreference("theme", next);
  }, [preferences.theme, setPreference]);

  const addFavorite = useCallback(
    (path: string) => {
      if (!preferences.favoritePages.includes(path)) {
        setPreference("favoritePages", [...preferences.favoritePages, path]);
      }
    },
    [preferences.favoritePages, setPreference]
  );

  const removeFavorite = useCallback(
    (path: string) => {
      setPreference(
        "favoritePages",
        preferences.favoritePages.filter((p) => p !== path)
      );
    },
    [preferences.favoritePages, setPreference]
  );

  const isFavorite = useCallback(
    (path: string) => preferences.favoritePages.includes(path),
    [preferences.favoritePages]
  );

  return {
    preferences: preferences as UserPreferences,
    setPreference,
    setPreferences,
    toggleSidebar,
    cycleTheme,
    addFavorite,
    removeFavorite,
    isFavorite,
  };
}
