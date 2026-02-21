import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Settings, Shield, Brain, Zap, ToggleLeft, ToggleRight, Save,
  RefreshCw, AlertTriangle, CheckCircle2, Loader2,
  Layers, Lock,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Input } from '../../components/ui/input';
import { nerveCenterApi } from '../../lib/api';
import { toast } from 'sonner';

const MATURITY_LEVELS = [
  { value: 'foundational', label: 'Foundational', description: 'Fail on critical, warn on high', color: 'text-blue-400' },
  { value: 'scaling', label: 'Scaling', description: 'Fail on high, warn on medium', color: 'text-yellow-400' },
  { value: 'advanced', label: 'Advanced', description: 'Fail on medium, warn on medium', color: 'text-green-400' },
];

export default function OverlayConfig() {
  const queryClient = useQueryClient();
  const [localConfig, setLocalConfig] = useState<any>(null);
  const [hasChanges, setHasChanges] = useState(false);

  // Fetch overlay config
  const { data: overlayConfig, isLoading } = useQuery({
    queryKey: ['overlay-config'],
    queryFn: nerveCenterApi.getOverlayConfig,
  });

  // Sync fetched config to local state
  useEffect(() => {
    if (overlayConfig && !localConfig) {
      setLocalConfig(JSON.parse(JSON.stringify(overlayConfig)));
    }
  }, [overlayConfig, localConfig]);

  // Save mutation
  const saveMutation = useMutation({
    mutationFn: () => nerveCenterApi.updateOverlayConfig(localConfig),
    onSuccess: () => {
      toast.success('Overlay configuration saved successfully');
      setHasChanges(false);
      queryClient.invalidateQueries({ queryKey: ['overlay-config'] });
    },
    onError: () => toast.error('Failed to save configuration'),
  });

  // Toggle a module
  const toggleModule = (key: string) => {
    if (!localConfig) return;
    const updated = { ...localConfig };
    updated.modules = { ...updated.modules };
    updated.modules[key] = { ...updated.modules[key], enabled: !updated.modules[key].enabled };
    setLocalConfig(updated);
    setHasChanges(true);
  };

  // Update risk model
  const setDefaultModel = (model: string) => {
    if (!localConfig) return;
    const updated = { ...localConfig };
    updated.risk_models = { ...updated.risk_models, default_model: model };
    setLocalConfig(updated);
    setHasChanges(true);
  };

  // Update maturity level
  const setMaturity = (level: string) => {
    if (!localConfig) return;
    const updated = { ...localConfig };
    updated.guardrails = { ...updated.guardrails, maturity: level };
    setLocalConfig(updated);
    setHasChanges(true);
  };

  // Update exploit signal threshold
  const updateSignalThreshold = (signal: string, field: string, value: any) => {
    if (!localConfig) return;
    const updated = { ...localConfig };
    updated.exploit_signals = { ...updated.exploit_signals };
    updated.exploit_signals[signal] = { ...updated.exploit_signals[signal], [field]: value };
    setLocalConfig(updated);
    setHasChanges(true);
  };

  // Reset to server state
  const resetConfig = () => {
    if (overlayConfig) {
      setLocalConfig(JSON.parse(JSON.stringify(overlayConfig)));
      setHasChanges(false);
      toast.info('Configuration reset to last saved state');
    }
  };

  if (isLoading || !localConfig) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 className="w-12 h-12 animate-spin text-primary" />
      </div>
    );
  }

  const modules = localConfig.modules || {};
  const riskModels = localConfig.risk_models || {};
  const signals = localConfig.exploit_signals || {};
  const guardrails = localConfig.guardrails || {};
  const frameworks = localConfig.compliance_frameworks || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Layers className="w-8 h-8 text-primary" /> Overlay Configuration
          </h1>
          <p className="text-muted-foreground mt-1">Configure risk models, modules, exploit signals, and guardrails</p>
        </div>
        <div className="flex gap-2">
          {hasChanges && <Badge variant="outline" className="text-yellow-400 border-yellow-400/50 animate-pulse">Unsaved changes</Badge>}
          <Button variant="outline" size="sm" onClick={resetConfig} disabled={!hasChanges}><RefreshCw className="w-4 h-4 mr-1" /> Reset</Button>
          <Button size="sm" onClick={() => saveMutation.mutate()} disabled={!hasChanges || saveMutation.isPending}>
            {saveMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-1" /> : <Save className="w-4 h-4 mr-1" />} Save Configuration
          </Button>
        </div>
      </div>

      {/* Risk Models */}
      <Card className="glass-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Brain className="w-5 h-5 text-purple-400" /> Risk Models</CardTitle>
          <CardDescription>Select the default risk scoring model and fallback chain</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-3 gap-3">
            {Object.entries(riskModels.models || {}).map(([key, model]: [string, any]) => (
              <button key={key} onClick={() => setDefaultModel(key)}
                className={`p-4 rounded-lg border text-left transition-all ${riskModels.default_model === key ? 'border-primary bg-primary/10 ring-1 ring-primary/30' : 'border-border/50 hover:border-primary/30'}`}>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium text-sm">{key.replace(/_/g, ' ')}</span>
                  {riskModels.default_model === key && <Badge className="text-[9px] bg-primary">DEFAULT</Badge>}
                </div>
                <p className="text-xs text-muted-foreground">{model.description}</p>
                <div className="flex items-center gap-2 mt-2 text-xs">
                  <span className="text-muted-foreground">Priority:</span>
                  <span className="font-mono">{model.priority}</span>
                </div>
              </button>
            ))}
          </div>
          <div className="mt-3 p-2 rounded border border-border/50 bg-card/30">
            <p className="text-xs text-muted-foreground">Fallback chain: {riskModels.fallback_chain?.map((m: string) => m.replace(/_/g, ' ')).join(' → ')}</p>
          </div>
        </CardContent>
      </Card>

      {/* Modules */}
      <Card className="glass-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Settings className="w-5 h-5 text-blue-400" /> Modules</CardTitle>
          <CardDescription>Enable or disable platform capabilities</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-3">
            {Object.entries(modules).map(([key, mod]: [string, any]) => (
              <button key={key} onClick={() => toggleModule(key)}
                className={`flex items-center justify-between p-3 rounded-lg border transition-all ${mod.enabled ? 'border-green-500/30 bg-green-500/5' : 'border-border/50 opacity-60'}`}>
                <div className="flex items-center gap-3">
                  {mod.enabled ? <ToggleRight className="w-5 h-5 text-green-400" /> : <ToggleLeft className="w-5 h-5 text-muted-foreground" />}
                  <div className="text-left">
                    <p className="text-sm font-medium">{key.replace(/_/g, ' ')}</p>
                    <p className="text-xs text-muted-foreground">{mod.description}</p>
                  </div>
                </div>
                <Badge variant="outline" className={`text-[9px] ${mod.enabled ? 'text-green-400 border-green-400/50' : 'text-muted-foreground'}`}>
                  {mod.enabled ? 'ON' : 'OFF'}
                </Badge>
              </button>
            ))}
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-2 gap-4">
        {/* Exploit Signals */}
        <Card className="glass-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><AlertTriangle className="w-5 h-5 text-orange-400" /> Exploit Signals</CardTitle>
            <CardDescription>Configure threat signal detection and escalation</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {Object.entries(signals).map(([key, sig]: [string, any]) => (
              <div key={key} className="p-3 rounded-lg border border-border/50 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Zap className="w-4 h-4 text-orange-400" />
                    <span className="text-sm font-medium">{key.replace(/_/g, ' ')}</span>
                  </div>
                  <Badge variant="outline" className="text-[9px]">{sig.mode}</Badge>
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  {sig.threshold !== undefined && (
                    <div className="flex items-center gap-2">
                      <span className="text-muted-foreground">Threshold:</span>
                      <Input type="number" step="0.05" min="0" max="1" value={sig.threshold}
                        onChange={(e) => updateSignalThreshold(key, 'threshold', parseFloat(e.target.value))}
                        className="h-6 w-20 text-xs" />
                    </div>
                  )}
                  {sig.escalate_to && (
                    <div className="flex items-center gap-2">
                      <span className="text-muted-foreground">Escalate to:</span>
                      <Badge variant="destructive" className="text-[9px]">{sig.escalate_to}</Badge>
                    </div>
                  )}
                  {sig.severity_floor && (
                    <div className="flex items-center gap-2">
                      <span className="text-muted-foreground">Floor:</span>
                      <Badge variant="outline" className="text-[9px]">{sig.severity_floor}</Badge>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Guardrails & Compliance */}
        <div className="space-y-4">
          {/* Guardrails Maturity */}
          <Card className="glass-card">
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2"><Shield className="w-5 h-5 text-green-400" /> Guardrails Maturity</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {MATURITY_LEVELS.map((level) => (
                  <button key={level.value} onClick={() => setMaturity(level.value)}
                    className={`w-full flex items-center justify-between p-3 rounded-lg border transition-all text-left ${guardrails.maturity === level.value ? 'border-primary bg-primary/10' : 'border-border/50 hover:border-primary/30'}`}>
                    <div>
                      <p className={`text-sm font-medium ${level.color}`}>{level.label}</p>
                      <p className="text-xs text-muted-foreground">{level.description}</p>
                    </div>
                    {guardrails.maturity === level.value && <CheckCircle2 className="w-5 h-5 text-primary" />}
                  </button>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Compliance Frameworks */}
          <Card className="glass-card">
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2"><Lock className="w-5 h-5 text-cyan-400" /> Compliance Frameworks</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                {frameworks.map((f: string) => (
                  <Badge key={f} variant="outline" className="text-xs cursor-pointer hover:bg-primary/20 transition-colors px-3 py-1">{f}</Badge>
                ))}
              </div>
              <p className="text-xs text-muted-foreground mt-2">{frameworks.length} frameworks tracked</p>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

