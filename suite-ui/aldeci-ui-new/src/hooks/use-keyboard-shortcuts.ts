/**
 * useKeyboardShortcuts — registers global keyboard shortcuts for power users.
 *
 * Note: Cmd+K / Ctrl+K is handled by GlobalSearch directly.
 *
 * Shortcuts registered here:
 *   Cmd+/   → show keyboard shortcut help modal
 *   N       → navigate to /notifications
 *   D       → navigate to /mission-control (dashboard)
 *   S       → navigate to /settings
 */
import { useEffect } from "react";
import { useNavigate } from "react-router-dom";

interface UseKeyboardShortcutsOptions {
  onShowHelp: () => void;
}

export function useKeyboardShortcuts({ onShowHelp }: UseKeyboardShortcutsOptions) {
  const navigate = useNavigate();

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      const target = e.target as HTMLElement;
      const isEditable =
        target.tagName === "INPUT" ||
        target.tagName === "TEXTAREA" ||
        target.isContentEditable;

      const isMeta = e.metaKey || e.ctrlKey;

      // Cmd+/ → show shortcut help modal
      if (isMeta && e.key === "/") {
        e.preventDefault();
        onShowHelp();
        return;
      }

      // Single-key shortcuts — only fire when not typing in an input
      if (isEditable) return;

      switch (e.key) {
        case "n":
        case "N":
          navigate("/notifications");
          break;
        case "d":
        case "D":
          navigate("/mission-control");
          break;
        case "s":
        case "S":
          navigate("/settings");
          break;
        default:
          break;
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [navigate, onShowHelp]);
}
