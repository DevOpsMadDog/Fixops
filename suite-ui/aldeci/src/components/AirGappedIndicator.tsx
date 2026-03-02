import { useEffect, useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Server, ShieldOff, ChevronDown, ChevronUp } from 'lucide-react';
import { Badge } from './ui/badge';
import { api } from '../lib/api';

// ─── Types ───────────────────────────────────────────────────────────────────

type DeploymentMode = 'cloud' | 'on-prem' | 'air-gapped';
type ScannerKey = 'sast' | 'dast' | 'secrets' | 'container' | 'cspm';

interface ScannerStatus { key: ScannerKey; label: string; active: boolean }
interface Integration { id: string; type?: string; is_cloud?: boolean; connected?: boolean }

interface IndicatorState {
  mode: DeploymentMode;
  scanners: ScannerStatus[];
  activeCount: number;
  loading: boolean;
  error: string | null;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const SCANNER_KEYS: ScannerKey[] = ['sast', 'dast', 'secrets', 'container', 'cspm'];
const SCANNER_LABELS: Record<ScannerKey, string> = {
  sast: 'SAST', dast: 'DAST', secrets: 'Secrets', container: 'Container', cspm: 'CSPM',
};
const CLOUD_TYPES = new Set([
  'snyk', 'sonarqube', 'github', 'gitlab', 'azure_devops', 'aws_security_hub',
  'azure_defender', 'wiz', 'prisma_cloud', 'orca', 'lacework', 'threatmapper', 'dependabot',
]);

const MODE_CFG = {
  cloud: { label: 'Cloud', Icon: Shield, badge: 'bg-blue-500/15 text-blue-300 border-blue-500/30', pulse: false },
  'on-prem': { label: 'On-Prem', Icon: Server, badge: 'bg-purple-500/15 text-purple-300 border-purple-500/30', pulse: false },
  'air-gapped': { label: 'Air-Gapped', Icon: ShieldOff, badge: 'bg-amber-500/15 text-amber-300 border-amber-500/30', pulse: true },
} as const;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function detectMode(integrations: Integration[]): DeploymentMode {
  const live = integrations.filter((i) => i.connected !== false);
  if (!live.length) return 'air-gapped';
  return live.some((i) => i.is_cloud || CLOUD_TYPES.has((i.type ?? '').toLowerCase()))
    ? 'cloud' : 'on-prem';
}

// ─── Component ────────────────────────────────────────────────────────────────

function AirGappedIndicator() {
  const [state, setState] = useState<IndicatorState>({
    mode: 'air-gapped', scanners: [], activeCount: 0, loading: true, error: null,
  });
  const [open, setOpen] = useState(false);

  const fetchStatus = useCallback(async () => {
    setState((p) => ({ ...p, loading: true, error: null }));
    try {
      const [intResp, ...scanResps] = await Promise.allSettled([
        api.get<Integration[]>('/api/v1/integrations'),
        ...SCANNER_KEYS.map((k) =>
          api.get<{ active?: boolean; enabled?: boolean; status?: string }>(`/api/v1/${k}/status`),
        ),
      ]);

      const integrations: Integration[] =
        intResp.status === 'fulfilled' ? (intResp.value.data ?? []) : [];

      const scanners: ScannerStatus[] = SCANNER_KEYS.map((key, i) => {
        const r = scanResps[i];
        let active = false;
        if (r.status === 'fulfilled') {
          const d = r.value.data;
          active = !!(d?.active || d?.enabled || d?.status === 'active' || d?.status === 'running');
        }
        return { key, label: SCANNER_LABELS[key], active };
      });

      setState({
        mode: detectMode(integrations),
        scanners,
        activeCount: scanners.filter((s) => s.active).length,
        loading: false,
        error: null,
      });
    } catch (err) {
      setState((p) => ({
        ...p, loading: false,
        error: err instanceof Error ? err.message : 'Failed to load status',
      }));
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    const timer = setInterval(fetchStatus, 60_000);
    return () => clearInterval(timer);
  }, [fetchStatus]);

  const { mode, scanners, activeCount, loading } = state;
  const cfg = MODE_CFG[mode];
  const { Icon } = cfg;
  const total = SCANNER_KEYS.length;

  const healthDot =
    activeCount === total ? 'bg-emerald-400' :
    activeCount === 0 ? 'bg-red-400' : 'bg-amber-400';

  const ModeLabel = () => (
    <span className="flex items-center gap-1">
      <Icon className="w-3 h-3 flex-shrink-0" />
      <span className={`${cfg.badge} px-1 py-0 rounded text-[10px] border`}>{cfg.label}</span>
    </span>
  );

  return (
    <div className="relative inline-block" style={{ maxWidth: 200 }}>
      <button
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-label={`${cfg.label} mode. ${activeCount}/${total} scanners active.`}
        className={`flex items-center gap-1.5 px-2 py-1 rounded-md border text-xs font-medium
          bg-gray-800/60 border-gray-700/30 hover:border-gray-600/50
          transition-colors duration-150 cursor-pointer w-full ${loading ? 'opacity-60' : ''}`}
      >
        {/* Health dot */}
        <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${healthDot} ${cfg.pulse ? 'animate-pulse' : ''}`} />

        {/* Mode icon + label — animated pulse for air-gapped */}
        {mode === 'air-gapped' ? (
          <motion.span
            animate={{ opacity: [1, 0.55, 1] }}
            transition={{ repeat: Infinity, duration: 2, ease: 'easeInOut' }}
          >
            <ModeLabel />
          </motion.span>
        ) : (
          <ModeLabel />
        )}

        {/* Scanner count */}
        <span className="text-gray-400 ml-auto text-[10px] flex-shrink-0">
          {loading ? '…' : `${activeCount}/${total}`}
        </span>

        {open
          ? <ChevronUp className="w-3 h-3 text-gray-500 flex-shrink-0" />
          : <ChevronDown className="w-3 h-3 text-gray-500 flex-shrink-0" />}
      </button>

      {/* Expanded scanner popover */}
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -4, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -4, scale: 0.97 }}
            transition={{ duration: 0.13 }}
            className="absolute left-0 top-full mt-1 z-50 w-48
              bg-gray-900 border border-gray-700/50 rounded-lg shadow-xl p-2 space-y-1"
          >
            <p className="text-[10px] text-gray-500 uppercase tracking-wider px-1 pb-1 border-b border-gray-700/40">
              Native Scanner Coverage
            </p>
            {scanners.map((s) => (
              <div key={s.key} className="flex items-center justify-between px-1 py-0.5">
                <span className="text-xs text-gray-300">{s.label}</span>
                <Badge variant={s.active ? 'success' : 'info'} className="text-[10px] px-1.5 py-0 h-4">
                  {s.active ? 'Active' : 'Off'}
                </Badge>
              </div>
            ))}
            <p className="text-[10px] text-gray-600 px-1 pt-1 border-t border-gray-700/40">
              Mode: <span className="text-gray-400">{cfg.label}</span>
            </p>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export { AirGappedIndicator };
export default AirGappedIndicator;
