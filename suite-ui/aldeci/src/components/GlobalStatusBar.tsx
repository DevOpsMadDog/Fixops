import { useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Activity, Wifi, WifiOff, Key, Settings2, Server, RefreshCw,
} from 'lucide-react';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { useRuntimeConfigStore } from '../stores';
import { useNavigate } from 'react-router-dom';
import { getActiveApiKey } from '../lib/api';

export default function GlobalStatusBar() {
  const navigate = useNavigate();
  const {
    apiVersion, apiKeyHint, authMode, mode, serviceHealth,
    loaded, loading, error, fetchConfig, checkServiceHealth,
  } = useRuntimeConfigStore();

  // Fetch config on mount and poll health every 30s
  useEffect(() => {
    fetchConfig();
    const interval = setInterval(checkServiceHealth, 30000);
    return () => clearInterval(interval);
  }, [fetchConfig, checkServiceHealth]);

  const healthyCount = serviceHealth.filter((s) => s.status === 'healthy').length;
  const totalCount = serviceHealth.length;
  const allHealthy = healthyCount === totalCount && totalCount > 0;
  const anyUnhealthy = serviceHealth.some((s) => s.status === 'unhealthy');

  // Mask API key for display
  const activeKey = getActiveApiKey();
  const maskedKey = activeKey
    ? `${activeKey.slice(0, 4)}${'•'.repeat(Math.max(0, activeKey.length - 4))}`
    : '(not set)';

  return (
    <motion.div
      initial={{ opacity: 0, y: -10 }}
      animate={{ opacity: 1, y: 0 }}
      className="flex items-center gap-3 px-4 py-1.5 border-b border-border bg-card/40 backdrop-blur text-xs"
    >
      {/* API Connection Status */}
      <div className="flex items-center gap-1.5">
        {allHealthy ? (
          <Wifi className="w-3.5 h-3.5 text-emerald-400" />
        ) : anyUnhealthy ? (
          <WifiOff className="w-3.5 h-3.5 text-red-400" />
        ) : (
          <Activity className="w-3.5 h-3.5 text-yellow-400 animate-pulse" />
        )}
        <Badge
          variant={allHealthy ? 'default' : anyUnhealthy ? 'destructive' : 'secondary'}
          className="text-[10px] px-1.5 py-0 h-4"
        >
          {loading ? 'connecting…' : error ? 'offline' : allHealthy ? 'API Connected' : anyUnhealthy ? 'Degraded' : 'checking…'}
        </Badge>
      </div>

      {/* Services Health */}
      {loaded && (
        <div className="flex items-center gap-1.5">
          <Server className="w-3 h-3 text-muted-foreground" />
          <span className="text-muted-foreground">
            Services: <span className={allHealthy ? 'text-emerald-400' : 'text-yellow-400'}>{healthyCount}/{totalCount}</span>
          </span>
          {/* Individual service dots */}
          <div className="flex items-center gap-0.5 ml-1">
            {serviceHealth.map((svc) => (
              <div
                key={svc.key}
                title={`${svc.label}: ${svc.status}`}
                className={`w-1.5 h-1.5 rounded-full ${
                  svc.status === 'healthy' ? 'bg-emerald-400' :
                  svc.status === 'unhealthy' ? 'bg-red-400' :
                  'bg-yellow-400 animate-pulse'
                }`}
              />
            ))}
          </div>
        </div>
      )}

      {/* Version */}
      {apiVersion && (
        <span className="text-muted-foreground">v{apiVersion}</span>
      )}

      {/* Mode */}
      {mode && (
        <Badge variant="outline" className="text-[10px] px-1.5 py-0 h-4">
          {mode}
        </Badge>
      )}

      {/* Spacer */}
      <div className="flex-1" />

      {/* API Key (masked) */}
      <button
        onClick={() => navigate('/settings')}
        className="flex items-center gap-1 text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
        title="Click to manage API key in Settings"
      >
        <Key className="w-3 h-3" />
        <span className="font-mono">{apiKeyHint || maskedKey}</span>
      </button>

      {/* Auth mode */}
      <span className="text-muted-foreground">{authMode}</span>

      {/* Overlay Config */}
      <Button
        variant="ghost"
        size="icon"
        className="h-5 w-5"
        onClick={() => navigate('/settings/overlay')}
        title="Edit Overlay Configuration"
      >
        <Settings2 className="w-3 h-3" />
      </Button>

      {/* Refresh */}
      <Button
        variant="ghost"
        size="icon"
        className="h-5 w-5"
        onClick={() => { fetchConfig(); checkServiceHealth(); }}
        title="Refresh status"
      >
        <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
      </Button>
    </motion.div>
  );
}

