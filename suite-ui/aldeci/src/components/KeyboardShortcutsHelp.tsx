/**
 * KeyboardShortcutsHelp — Shows keyboard shortcuts overlay (press ? to open)
 *
 * UX Polish component: Helps users discover keyboard shortcuts across the app.
 * Renders a modal overlay with grouped shortcuts and their key bindings.
 */
import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Keyboard,
  X,
  Search,
  Command,
  ArrowUp,
  ArrowDown,
  CornerDownLeft,
} from 'lucide-react';

interface Shortcut {
  keys: string[];
  description: string;
}

interface ShortcutGroup {
  title: string;
  shortcuts: Shortcut[];
}

const SHORTCUT_GROUPS: ShortcutGroup[] = [
  {
    title: 'Navigation',
    shortcuts: [
      { keys: ['⌘', 'K'], description: 'Open Command Palette' },
      { keys: ['Esc'], description: 'Close dialog / dismiss overlay' },
      { keys: ['?'], description: 'Show keyboard shortcuts' },
      { keys: ['G', 'D'], description: 'Go to Dashboard' },
      { keys: ['G', 'S'], description: 'Go to Settings' },
    ],
  },
  {
    title: 'Command Palette',
    shortcuts: [
      { keys: ['↑', '↓'], description: 'Navigate results' },
      { keys: ['↵'], description: 'Select / navigate to result' },
      { keys: ['Esc'], description: 'Close palette' },
    ],
  },
  {
    title: 'Tables & Lists',
    shortcuts: [
      { keys: ['J'], description: 'Next item' },
      { keys: ['K'], description: 'Previous item' },
      { keys: ['↵'], description: 'Open selected item' },
      { keys: ['/'], description: 'Focus search / filter' },
    ],
  },
  {
    title: 'Actions',
    shortcuts: [
      { keys: ['R'], description: 'Refresh current view' },
      { keys: ['⌘', 'S'], description: 'Save current form' },
      { keys: ['⌘', 'Z'], description: 'Undo last action' },
    ],
  },
];

function KeyCombo({ keys }: { keys: string[] }) {
  return (
    <span className="flex items-center gap-1">
      {keys.map((key, i) => (
        <span key={i} className="flex items-center gap-0.5">
          {i > 0 && <span className="text-gray-600 text-[10px] mx-0.5">+</span>}
          <kbd className="inline-flex items-center justify-center min-w-[24px] h-6 px-1.5 rounded bg-gray-800 border border-gray-600/40 text-[11px] font-mono text-gray-300 shadow-sm">
            {key === '⌘' ? <Command className="w-3 h-3" /> :
             key === '↑' ? <ArrowUp className="w-3 h-3" /> :
             key === '↓' ? <ArrowDown className="w-3 h-3" /> :
             key === '↵' ? <CornerDownLeft className="w-3 h-3" /> :
             key}
          </kbd>
        </span>
      ))}
    </span>
  );
}

export default function KeyboardShortcutsHelp() {
  const [open, setOpen] = useState(false);

  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    // Don't trigger when typing in inputs
    const target = e.target as HTMLElement;
    if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable) {
      return;
    }

    // ? key (shift + /)
    if (e.key === '?' && !e.metaKey && !e.ctrlKey) {
      e.preventDefault();
      setOpen(prev => !prev);
    }

    // Escape to close
    if (e.key === 'Escape' && open) {
      setOpen(false);
    }

    // G+D for dashboard, G+S for settings (chord shortcuts)
    // These are handled by the CommandPalette, listed here for reference
  }, [open]);

  useEffect(() => {
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);

  return (
    <AnimatePresence>
      {open && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50"
            onClick={() => setOpen(false)}
          />

          {/* Modal */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4 pointer-events-none"
          >
            <div
              className="w-full max-w-2xl max-h-[80vh] overflow-y-auto rounded-xl border border-gray-700/30 bg-gray-900/95 backdrop-blur-xl shadow-2xl pointer-events-auto"
              role="dialog"
              aria-label="Keyboard Shortcuts"
            >
              {/* Header */}
              <div className="flex items-center justify-between p-5 border-b border-gray-700/30">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center">
                    <Keyboard className="w-5 h-5 text-primary" />
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold text-gray-100">Keyboard Shortcuts</h2>
                    <p className="text-xs text-gray-500">Press <kbd className="px-1 py-0.5 bg-gray-800 rounded text-[10px] border border-gray-700/40">?</kbd> to toggle</p>
                  </div>
                </div>
                <button
                  onClick={() => setOpen(false)}
                  className="p-2 rounded-lg hover:bg-gray-800 transition-colors text-gray-400 hover:text-gray-200"
                  aria-label="Close keyboard shortcuts"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Shortcut Groups */}
              <div className="p-5 grid grid-cols-1 md:grid-cols-2 gap-6">
                {SHORTCUT_GROUPS.map((group) => (
                  <div key={group.title}>
                    <h3 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-3">
                      {group.title}
                    </h3>
                    <div className="space-y-2">
                      {group.shortcuts.map((shortcut, i) => (
                        <div
                          key={i}
                          className="flex items-center justify-between py-1.5 group"
                        >
                          <span className="text-sm text-gray-300 group-hover:text-gray-100 transition-colors">
                            {shortcut.description}
                          </span>
                          <KeyCombo keys={shortcut.keys} />
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>

              {/* Footer */}
              <div className="p-4 border-t border-gray-700/30 text-center">
                <p className="text-xs text-gray-600">
                  <Search className="w-3 h-3 inline mr-1" />
                  Tip: Use <KeyCombo keys={['⌘', 'K']} /> to quickly navigate anywhere
                </p>
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
