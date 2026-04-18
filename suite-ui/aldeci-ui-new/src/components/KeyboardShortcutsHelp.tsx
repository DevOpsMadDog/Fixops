import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";

interface ShortcutRow {
  keys: string[];
  description: string;
}

const SHORTCUTS: { section: string; rows: ShortcutRow[] }[] = [
  {
    section: "Global",
    rows: [
      { keys: ["⌘", "K"], description: "Open global search" },
      { keys: ["⌘", "/"], description: "Show keyboard shortcuts" },
      { keys: ["Esc"], description: "Close modal / dismiss dropdown" },
    ],
  },
  {
    section: "Navigation",
    rows: [
      { keys: ["D"], description: "Go to Dashboard (Mission Control)" },
      { keys: ["S"], description: "Go to Settings" },
      { keys: ["N"], description: "Go to Notifications" },
    ],
  },
];

interface KeyboardShortcutsHelpProps {
  open: boolean;
  onClose: () => void;
}

function Kbd({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="inline-flex items-center justify-center rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-[11px] font-medium text-muted-foreground shadow-sm">
      {children}
    </kbd>
  );
}

export function KeyboardShortcutsHelp({ open, onClose }: KeyboardShortcutsHelpProps) {
  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Keyboard Shortcuts</DialogTitle>
          <DialogDescription>
            Power-user shortcuts available throughout ALDECI.
          </DialogDescription>
        </DialogHeader>

        <div className="mt-2 space-y-5">
          {SHORTCUTS.map((group) => (
            <div key={group.section}>
              <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                {group.section}
              </p>
              <div className="space-y-2">
                {group.rows.map((row) => (
                  <div key={row.description} className="flex items-center justify-between gap-4">
                    <span className="text-sm text-foreground">{row.description}</span>
                    <div className="flex items-center gap-1">
                      {row.keys.map((k, i) => (
                        <span key={i} className="flex items-center gap-1">
                          <Kbd>{k}</Kbd>
                          {i < row.keys.length - 1 && (
                            <span className="text-[10px] text-muted-foreground">+</span>
                          )}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </DialogContent>
    </Dialog>
  );
}
