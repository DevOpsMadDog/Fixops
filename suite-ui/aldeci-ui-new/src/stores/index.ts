import { create } from "zustand";
import {
  loadPreferences,
  savePreferences,
  applyTheme,
  PREFERENCES_DEFAULTS,
} from "@/lib/preferences";
import type { UserPreferences as ExtendedPreferences } from "@/lib/preferences";

// Internal store preferences: superset of ExtendedPreferences + legacy fields
interface UserPreferences extends ExtendedPreferences {
  role: string;
  homeSpace: string;
  copilotOpen: boolean;
  onboardingComplete: boolean;
}

interface AppState {
  preferences: UserPreferences;
  setPreferences: (p: Partial<UserPreferences>) => void;
  toggleCopilot: () => void;
  toggleSidebar: () => void;
  toggleTheme: () => void;
  completeOnboarding: () => void;
}

// Storage adapter — localStorage with in-memory fallback
const STORAGE_KEY = "aldeci-prefs";

function safePersist(key: string, state: unknown) {
  try {
    if (typeof window !== "undefined" && window.localStorage) {
      window.localStorage.setItem(key, JSON.stringify(state));
      return;
    }
  } catch { /* quota or security error — fall through */ }
}

function safeHydrate<T>(key: string, fallback: T): T {
  try {
    if (typeof window !== "undefined" && window.localStorage) {
      const raw = window.localStorage.getItem(key);
      if (raw) return JSON.parse(raw) as T;
    }
  } catch { /* */ }
  return fallback;
}

const DEFAULTS: UserPreferences = {
  // Legacy fields
  role: "",
  homeSpace: "/mission-control",
  copilotOpen: false,
  onboardingComplete: false,
  // Extended preference fields (merged from preferences lib)
  ...PREFERENCES_DEFAULTS,
};

// Hydrate: merge legacy aldeci-prefs store + new aldeci-user-prefs store
function hydratePreferences(): UserPreferences {
  const legacyStored = safeHydrate<Partial<UserPreferences>>(STORAGE_KEY, {});
  const extendedStored = loadPreferences(); // from aldeci-user-prefs key
  return { ...DEFAULTS, ...legacyStored, ...extendedStored };
}

// Apply theme on initial load
const initialPrefs = hydratePreferences();
applyTheme(initialPrefs.theme);

export const useAppStore = create<AppState>()((set, get) => ({
  preferences: initialPrefs,
  setPreferences: (p) => {
    set((s) => {
      const next = { ...s.preferences, ...p };
      safePersist(STORAGE_KEY, next);
      // Also persist extended preferences to the dedicated key
      savePreferences({
        theme: next.theme,
        defaultOrgId: next.defaultOrgId,
        dashboardLayout: next.dashboardLayout,
        itemsPerPage: next.itemsPerPage,
        sidebarCollapsed: next.sidebarCollapsed,
        favoritePages: next.favoritePages,
      });
      return { preferences: next };
    });
  },
  toggleCopilot: () => {
    const next = { ...get().preferences, copilotOpen: !get().preferences.copilotOpen };
    set({ preferences: next }); safePersist(STORAGE_KEY, next);
  },
  toggleSidebar: () => {
    const next = { ...get().preferences, sidebarCollapsed: !get().preferences.sidebarCollapsed };
    set({ preferences: next });
    safePersist(STORAGE_KEY, next);
    savePreferences({
      theme: next.theme,
      defaultOrgId: next.defaultOrgId,
      dashboardLayout: next.dashboardLayout,
      itemsPerPage: next.itemsPerPage,
      sidebarCollapsed: next.sidebarCollapsed,
      favoritePages: next.favoritePages,
    });
  },
  toggleTheme: () => {
    const current = get().preferences.theme;
    // Legacy toggle: dark ↔ light (system handled via cycleTheme in usePreferences)
    const next = { ...get().preferences, theme: current === "dark" ? "light" as const : "dark" as const };
    applyTheme(next.theme);
    set({ preferences: next });
    safePersist(STORAGE_KEY, next);
    savePreferences({
      theme: next.theme,
      defaultOrgId: next.defaultOrgId,
      dashboardLayout: next.dashboardLayout,
      itemsPerPage: next.itemsPerPage,
      sidebarCollapsed: next.sidebarCollapsed,
      favoritePages: next.favoritePages,
    });
  },
  completeOnboarding: () => {
    const next = { ...get().preferences, onboardingComplete: true };
    set({ preferences: next }); safePersist(STORAGE_KEY, next);
  },
}));
