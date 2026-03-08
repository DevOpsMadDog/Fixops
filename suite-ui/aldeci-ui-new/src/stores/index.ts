import { create } from "zustand";

interface UserPreferences {
  role: string;
  homeSpace: string;
  theme: "dark" | "light";
  copilotOpen: boolean;
  sidebarCollapsed: boolean;
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

// Storage adapter — in-memory only (safe for all environments)
const _mem = new Map<string, string>();
function safePersist(key: string, state: unknown) {
  _mem.set(key, JSON.stringify(state));
}
function safeHydrate<T>(key: string, fallback: T): T {
  const raw = _mem.get(key);
  if (raw) { try { return JSON.parse(raw) as T; } catch { /* */ } }
  return fallback;
}

const DEFAULTS: UserPreferences = {
  role: "",
  homeSpace: "/mission-control",
  theme: "dark",
  copilotOpen: false,
  sidebarCollapsed: false,
  onboardingComplete: false,
};

export const useAppStore = create<AppState>()((set, get) => ({
  preferences: safeHydrate<UserPreferences>("aldeci-prefs", DEFAULTS),
  setPreferences: (p) => {
    set((s) => {
      const next = { ...s.preferences, ...p };
      safePersist("aldeci-prefs", next);
      return { preferences: next };
    });
  },
  toggleCopilot: () => {
    const next = { ...get().preferences, copilotOpen: !get().preferences.copilotOpen };
    set({ preferences: next }); safePersist("aldeci-prefs", next);
  },
  toggleSidebar: () => {
    const next = { ...get().preferences, sidebarCollapsed: !get().preferences.sidebarCollapsed };
    set({ preferences: next }); safePersist("aldeci-prefs", next);
  },
  toggleTheme: () => {
    const next = { ...get().preferences, theme: get().preferences.theme === "dark" ? "light" as const : "dark" as const };
    set({ preferences: next }); safePersist("aldeci-prefs", next);
  },
  completeOnboarding: () => {
    const next = { ...get().preferences, onboardingComplete: true };
    set({ preferences: next }); safePersist("aldeci-prefs", next);
  },
}));
