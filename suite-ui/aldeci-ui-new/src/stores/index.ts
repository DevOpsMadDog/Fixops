import { create } from "zustand";
import { persist } from "zustand/middleware";

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

export const useAppStore = create<AppState>()(
  persist(
    (set) => ({
      preferences: {
        role: "",
        homeSpace: "/mission-control",
        theme: "dark",
        copilotOpen: false,
        sidebarCollapsed: false,
        onboardingComplete: false,
      },
      setPreferences: (p) =>
        set((s) => ({ preferences: { ...s.preferences, ...p } })),
      toggleCopilot: () =>
        set((s) => ({
          preferences: { ...s.preferences, copilotOpen: !s.preferences.copilotOpen },
        })),
      toggleSidebar: () =>
        set((s) => ({
          preferences: { ...s.preferences, sidebarCollapsed: !s.preferences.sidebarCollapsed },
        })),
      toggleTheme: () =>
        set((s) => ({
          preferences: {
            ...s.preferences,
            theme: s.preferences.theme === "dark" ? "light" : "dark",
          },
        })),
      completeOnboarding: () =>
        set((s) => ({
          preferences: { ...s.preferences, onboardingComplete: true },
        })),
    }),
    { name: "aldeci-preferences" }
  )
);
