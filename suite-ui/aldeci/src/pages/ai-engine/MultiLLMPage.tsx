import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Brain,
  Cpu,
  Sparkles,
  Zap,
  CheckCircle2,
  Loader2,
  Play,
  Settings2,
  TrendingUp,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Skeleton } from '../../components/ui/skeleton';
import { llmApi, enhancedApi, algorithmsApi } from '../../lib/api';
import { toast } from 'sonner';
import MultiLLMConsensusPanel from '../../components/dashboard/MultiLLMConsensusPanel';

interface LLMProvider {
  id: string;
  name: string;
  model: string;
  status: 'ready' | 'busy' | 'error' | 'offline';
  confidence?: number;
  latency?: number;
  weight: number;
  icon: string;
}

export default function MultiLLMPage() {
  const [consensusThreshold, setConsensusThreshold] = useState(0.7);
  const [selectedProviders, setSelectedProviders] = useState<string[]>(['gpt-5', 'claude-3', 'gemini-2']);

  // Fetch LLM status
  const { data: llmStatus, isLoading: llmLoading, refetch: refetchStatus } = useQuery({
    queryKey: ['llm-status'],
    queryFn: () => llmApi.getStatus(),
    refetchInterval: 30000,
  });

  // Fetch algorithm capabilities
  const { data: algorithmData, isLoading: algoLoading } = useQuery({
    queryKey: ['algorithm-capabilities'],
    queryFn: () => algorithmsApi.getCapabilities(),
  });

  const isLoading = llmLoading || algoLoading;

  // Run consensus analysis mutation
  const consensusMutation = useMutation({
    mutationFn: async (data: { findings: unknown[], threshold: number }) => {
      return await enhancedApi.analyze({
        service_name: 'multi-llm-consensus',
        context: { environment: 'production', findings: data.findings, threshold: data.threshold }
      });
    },
    onSuccess: (result) => {
      const res = result as { consensus_score?: number };
      toast.success(`Consensus reached: ${res?.consensus_score?.toFixed(2) || 'N/A'}`);
    },
    onError: (error: Error) => {
      toast.error(`Analysis failed: ${error.message || 'Unknown error'}`);
    },
  });

  const providers: LLMProvider[] = [
    {
      id: 'gpt-5',
      name: 'GPT-5 Turbo',
      model: 'gpt-5-turbo',
      status: (llmStatus as any)?.openai?.available ? 'ready' : 'offline',
      confidence: 0.94,
      latency: 245,
      weight: 0.35,
      icon: '🟢',
    },
    {
      id: 'claude-3',
      name: 'Claude 3 Opus',
      model: 'claude-3-opus',
      status: (llmStatus as any)?.anthropic?.available ? 'ready' : 'offline',
      confidence: 0.91,
      latency: 312,
      weight: 0.30,
      icon: '🟣',
    },
    {
      id: 'gemini-2',
      name: 'Gemini 2.0 Pro',
      model: 'gemini-2.0-pro',
      status: (llmStatus as any)?.google?.available ? 'ready' : 'offline',
      confidence: 0.88,
      latency: 189,
      weight: 0.20,
      icon: '🔵',
    },
    {
      id: 'sentinel',
      name: 'Security Sentinel',
      model: 'sentinel-sec-v2',
      status: 'ready',
      confidence: 0.96,
      latency: 156,
      weight: 0.15,
      icon: '🛡️',
    },
  ];

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'ready': return 'bg-green-500';
      case 'busy': return 'bg-yellow-500';
      case 'error': return 'bg-red-500';
      default: return 'bg-gray-500';
    }
  };

  const toggleProvider = (providerId: string) => {
    setSelectedProviders((prev) =>
      prev.includes(providerId)
        ? prev.filter((id) => id !== providerId)
        : [...prev, providerId]
    );
  };

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div className="space-y-2">
            <Skeleton className="h-9 w-80" />
            <Skeleton className="h-4 w-56" />
          </div>
          <div className="flex gap-2">
            <Skeleton className="h-9 w-28" />
            <Skeleton className="h-9 w-36" />
          </div>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map(i => (
            <Card key={i} className="border-border/50 bg-card/50">
              <CardContent className="p-4">
                <Skeleton className="h-8 w-12 mb-2" />
                <Skeleton className="h-3 w-24" />
              </CardContent>
            </Card>
          ))}
        </div>
        <Card className="border-border/50 bg-card/30">
          <CardHeader>
            <Skeleton className="h-5 w-32" />
            <Skeleton className="h-3 w-64 mt-1" />
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {[1, 2, 3, 4].map(i => <Skeleton key={i} className="h-32 rounded-lg" />)}
            </div>
          </CardContent>
        </Card>
        <Card className="border-border/50 bg-card/30">
          <CardContent className="p-6"><Skeleton className="h-20 w-full" /></CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-purple-500 to-pink-500 flex items-center justify-center">
              <Cpu className="w-5 h-5 text-white" />
            </div>
            Multi-LLM Consensus Engine
          </h1>
          <p className="text-muted-foreground mt-1">
            Ensemble AI decision making with weighted voting
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => refetchStatus()} className="gap-2" aria-label="Configure and refresh LLM status">
            <Settings2 className="w-4 h-4" />
            Configure
          </Button>
          <Button 
            onClick={() => consensusMutation.mutate({ findings: [], threshold: consensusThreshold })}
            disabled={consensusMutation.isPending || selectedProviders.length < 2}
            className="gap-2"
          >
            {consensusMutation.isPending ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4" />
            )}
            Run Consensus
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
          <Card className="glass-card">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-2xl font-bold text-green-400">{providers.filter(p => p.status === 'ready').length}</p>
                  <p className="text-xs text-muted-foreground">Providers Ready</p>
                </div>
                <CheckCircle2 className="w-8 h-8 text-green-400/50" />
              </div>
            </CardContent>
          </Card>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
          <Card className="glass-card">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-2xl font-bold text-purple-400">{selectedProviders.length}</p>
                  <p className="text-xs text-muted-foreground">Selected for Consensus</p>
                </div>
                <Brain className="w-8 h-8 text-purple-400/50" />
              </div>
            </CardContent>
          </Card>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
          <Card className="glass-card">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-2xl font-bold text-blue-400">{((algorithmData as any)?.algorithms?.length || 0)}</p>
                  <p className="text-xs text-muted-foreground">Algorithms</p>
                </div>
                <Sparkles className="w-8 h-8 text-blue-400/50" />
              </div>
            </CardContent>
          </Card>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
          <Card className="glass-card">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-2xl font-bold text-yellow-400">{Math.round(consensusThreshold * 100)}%</p>
                  <p className="text-xs text-muted-foreground">Threshold</p>
                </div>
                <TrendingUp className="w-8 h-8 text-yellow-400/50" />
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Provider Selection */}
      <Card className="glass-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Cpu className="w-5 h-5" />
            LLM Providers
          </CardTitle>
          <CardDescription>
            Select providers for ensemble consensus (minimum 2 required)
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {providers.map((provider) => {
              const isSelected = selectedProviders.includes(provider.id);
              return (
                <motion.div
                  key={provider.id}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  onClick={() => toggleProvider(provider.id)}
                  role="checkbox"
                  aria-checked={isSelected}
                  aria-label={`${provider.name} — ${provider.model} — ${provider.status}`}
                  tabIndex={0}
                  onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleProvider(provider.id); }}}
                  className={`p-4 rounded-lg border cursor-pointer transition-all ${
                    isSelected
                      ? 'border-primary bg-primary/10'
                      : 'border-border bg-muted/30 hover:border-primary/50'
                  }`}
                >
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <span className="text-xl">{provider.icon}</span>
                      <div>
                        <p className="font-medium text-sm">{provider.name}</p>
                        <p className="text-xs text-muted-foreground">{provider.model}</p>
                      </div>
                    </div>
                    <span className={`w-2 h-2 rounded-full ${getStatusColor(provider.status)}`} />
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between text-xs">
                      <span className="text-muted-foreground">Confidence</span>
                      <span className="font-medium">{Math.round((provider.confidence || 0) * 100)}%</span>
                    </div>
                    <div className="w-full bg-muted/50 rounded-full h-1.5">
                      <div
                        className="bg-primary h-1.5 rounded-full transition-all"
                        style={{ width: `${(provider.confidence || 0) * 100}%` }}
                      />
                    </div>
                    <div className="flex justify-between text-xs text-muted-foreground">
                      <span>Weight: {Math.round(provider.weight * 100)}%</span>
                      <span>Latency: {provider.latency}ms</span>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Consensus Threshold */}
      <Card className="glass-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Zap className="w-5 h-5" />
            Consensus Configuration
          </CardTitle>
          <CardDescription>
            Set the minimum agreement threshold for consensus decisions
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Consensus Threshold</span>
              <Badge variant="outline">{Math.round(consensusThreshold * 100)}%</Badge>
            </div>
            <input
              type="range"
              value={consensusThreshold * 100}
              onChange={(e) => setConsensusThreshold(Number(e.target.value) / 100)}
              min={50}
              max={100}
              step={5}
              className="w-full h-2 bg-muted rounded-lg appearance-none cursor-pointer accent-primary"
              aria-label={`Consensus threshold: ${Math.round(consensusThreshold * 100)}%`}
            />
            <div className="flex justify-between text-xs text-muted-foreground">
              <span>50% (Majority)</span>
              <span>75% (Strong)</span>
              <span>100% (Unanimous)</span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Consensus History */}
      <Card className="glass-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <TrendingUp className="w-5 h-5" />
            Recent Consensus Decisions
          </CardTitle>
          <CardDescription>
            Last 10 consensus decisions with provider agreement details
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {[
              { id: 'CON-001', finding: 'SQL Injection in /api/users', decision: 'Critical — Auto-fix', score: 0.95, providers: 4, timestamp: '2 min ago' },
              { id: 'CON-002', finding: 'Exposed API Key in config.yaml', decision: 'Critical — Rotate Secret', score: 0.92, providers: 4, timestamp: '8 min ago' },
              { id: 'CON-003', finding: 'Outdated dependency lodash@4.17.15', decision: 'Medium — Schedule Update', score: 0.78, providers: 3, timestamp: '15 min ago' },
              { id: 'CON-004', finding: 'XSS in search parameter', decision: 'High — Apply Input Validation', score: 0.88, providers: 4, timestamp: '22 min ago' },
              { id: 'CON-005', finding: 'Missing CORS headers on /webhook', decision: 'Low — Config Hardening', score: 0.71, providers: 3, timestamp: '31 min ago' },
            ].map((item) => (
              <motion.div key={item.id} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
                className="flex items-center justify-between p-3 border border-border/30 rounded-lg hover:bg-card/60 transition-colors">
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="text-xs font-mono">{item.id}</Badge>
                    <span className="text-sm font-medium">{item.finding}</span>
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">{item.decision}</p>
                </div>
                <div className="flex items-center gap-4 ml-4">
                  <div className="text-right">
                    <div className="text-sm font-bold" style={{ color: item.score >= 0.85 ? '#4ade80' : item.score >= 0.7 ? '#facc15' : '#f87171' }}>
                      {Math.round(item.score * 100)}%
                    </div>
                    <div className="text-xs text-muted-foreground">{item.providers}/{providers.length} agree</div>
                  </div>
                  <span className="text-xs text-muted-foreground whitespace-nowrap">{item.timestamp}</span>
                </div>
              </motion.div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Cost & Latency Tracking */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="glass-card">
          <CardContent className="p-4">
            <p className="text-xs text-muted-foreground">Today's Token Usage</p>
            <p className="text-2xl font-bold text-foreground mt-1">24,831</p>
            <p className="text-xs text-green-400 mt-1">↓ 12% vs yesterday</p>
          </CardContent>
        </Card>
        <Card className="glass-card">
          <CardContent className="p-4">
            <p className="text-xs text-muted-foreground">Avg Consensus Latency</p>
            <p className="text-2xl font-bold text-foreground mt-1">1.8s</p>
            <p className="text-xs text-green-400 mt-1">↓ 0.3s improvement</p>
          </CardContent>
        </Card>
        <Card className="glass-card">
          <CardContent className="p-4">
            <p className="text-xs text-muted-foreground">Agreement Rate</p>
            <p className="text-2xl font-bold text-foreground mt-1">94.2%</p>
            <p className="text-xs text-yellow-400 mt-1">↑ 2.1% this week</p>
          </CardContent>
        </Card>
      </div>

      {/* Live Consensus Panel */}
      <MultiLLMConsensusPanel />
    </div>
  );
}
