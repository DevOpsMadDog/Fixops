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
  const { data: llmStatus, refetch: refetchStatus } = useQuery({
    queryKey: ['llm-status'],
    queryFn: () => llmApi.getStatus(),
    refetchInterval: 30000,
  });

  // Fetch algorithm capabilities
  const { data: algorithmData } = useQuery({
    queryKey: ['algorithm-capabilities'],
    queryFn: () => algorithmsApi.getCapabilities(),
  });

  // Run consensus analysis mutation
  const consensusMutation = useMutation({
    mutationFn: async (data: { findings: unknown[], threshold: number }) => {
      return await enhancedApi.analyze({
        service: 'multi-llm-consensus',
        context: { environment: 'production', findings: data.findings, threshold: data.threshold }
      });
    },
    onSuccess: (result) => {
      toast.success(`Consensus reached: ${(result as any)?.consensus_score?.toFixed(2) || 'N/A'}`);
    },
    onError: (error: any) => {
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
          <Button variant="outline" size="sm" onClick={() => refetchStatus()} className="gap-2">
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
            />
            <div className="flex justify-between text-xs text-muted-foreground">
              <span>50% (Majority)</span>
              <span>75% (Strong)</span>
              <span>100% (Unanimous)</span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Live Consensus Panel */}
      <MultiLLMConsensusPanel />
    </div>
  );
}
