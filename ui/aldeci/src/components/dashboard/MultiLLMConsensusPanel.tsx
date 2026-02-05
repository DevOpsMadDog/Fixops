import { useState } from 'react';
import { motion } from 'framer-motion';
import { useQuery, useMutation } from '@tanstack/react-query';
import { 
  Brain, 
  CheckCircle, 
  XCircle, 
  AlertCircle, 
  Loader2,
  RefreshCw,
  Settings,
  ChevronDown
} from 'lucide-react';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { Card, CardHeader, CardTitle, CardContent } from '../ui/card';
import { llmApi, enhancedApi } from '../../lib/api';
import { toast } from 'sonner';

interface LLMProvider {
  name: string;
  displayName: string;
  recommendation: 'ALLOW' | 'BLOCK' | 'REVIEW';
  confidence: number;
  weight: number;
  status: 'ready' | 'pending' | 'error';
  reasoning?: string;
}

interface MultiLLMPanelProps {
  service?: string;
  environment?: string;
  compact?: boolean;
  onDecision?: (decision: string, confidence: number) => void;
}

export default function MultiLLMConsensusPanel({ 
  service = 'payment-gateway',
  environment = 'production',
  compact = false,
  onDecision 
}: MultiLLMPanelProps) {
  const [expanded, setExpanded] = useState(!compact);
  const [selectedProviders, setSelectedProviders] = useState<string[]>([
    'gpt-5', 'claude-3', 'gemini-2', 'sentinel-cyber'
  ]);

  // Fetch LLM status
  const { data: llmStatus, isLoading: statusLoading, refetch: refetchStatus } = useQuery({
    queryKey: ['llm-status'],
    queryFn: () => llmApi.getStatus(),
    refetchInterval: 60000,
  });

  // Fetch enhanced capabilities
  const { data: capabilities } = useQuery({
    queryKey: ['enhanced-capabilities'],
    queryFn: () => enhancedApi.getCapabilities(),
  });

  // Run consensus analysis
  const analysisMutation = useMutation({
    mutationFn: () => enhancedApi.analyze({ service, context: { environment } }),
    onSuccess: (data) => {
      toast.success('Consensus analysis complete', {
        description: `Decision: ${data.decision} @ ${data.confidence}% confidence`,
      });
      if (onDecision) {
        onDecision(data.decision, data.confidence);
      }
    },
    onError: (error: Error) => {
      toast.error('Analysis failed', { description: error.message });
    },
  });

  // Mock LLM provider data (would come from real API)
  const providers: LLMProvider[] = [
    {
      name: 'gpt-5',
      displayName: 'GPT-5',
      recommendation: 'ALLOW',
      confidence: 85,
      weight: 30,
      status: llmStatus?.providers?.find((p: { name: string }) => p.name === 'openai')?.status === 'ready' ? 'ready' : 'pending',
      reasoning: 'No critical vulnerabilities found. Log4j patched in v2.17.1.',
    },
    {
      name: 'claude-3',
      displayName: 'Claude-3',
      recommendation: 'ALLOW',
      confidence: 82,
      weight: 25,
      status: llmStatus?.providers?.find((p: { name: string }) => p.name === 'anthropic')?.configured ? 'ready' : 'pending',
      reasoning: 'SBOM analysis shows all dependencies up to date.',
    },
    {
      name: 'gemini-2',
      displayName: 'Gemini-2.0',
      recommendation: 'BLOCK',
      confidence: 45,
      weight: 25,
      status: llmStatus?.providers?.find((p: { name: string }) => p.name === 'google')?.configured ? 'ready' : 'pending',
      reasoning: 'Flagged unpatched Log4j in transitive dependency.',
    },
    {
      name: 'sentinel-cyber',
      displayName: 'Sentinel',
      recommendation: 'ALLOW',
      confidence: 88,
      weight: 20,
      status: 'ready',
      reasoning: 'Security posture meets threshold. No active exploits detected.',
    },
  ];

  // Calculate consensus
  const calculateConsensus = () => {
    const activeProviders = providers.filter(p => selectedProviders.includes(p.name));
    const totalWeight = activeProviders.reduce((acc, p) => acc + p.weight, 0);
    
    let weightedScore = 0;
    let allowVotes = 0;
    let blockVotes = 0;
    
    activeProviders.forEach(p => {
      const normalizedWeight = p.weight / totalWeight;
      if (p.recommendation === 'ALLOW') {
        weightedScore += p.confidence * normalizedWeight;
        allowVotes++;
      } else if (p.recommendation === 'BLOCK') {
        weightedScore -= p.confidence * normalizedWeight;
        blockVotes++;
      }
    });

    const decision = weightedScore > 0 ? 'ALLOW' : weightedScore < 0 ? 'BLOCK' : 'REVIEW';
    const confidence = Math.abs(weightedScore);
    const agreement = activeProviders.length > 0 
      ? Math.max(allowVotes, blockVotes) / activeProviders.length * 100 
      : 0;

    return { decision, confidence, agreement, allowVotes, blockVotes };
  };

  const consensus = calculateConsensus();

  const getDecisionColor = (decision: string) => {
    switch (decision) {
      case 'ALLOW': return 'text-green-500 bg-green-500/10';
      case 'BLOCK': return 'text-red-500 bg-red-500/10';
      default: return 'text-yellow-500 bg-yellow-500/10';
    }
  };

  const getDecisionIcon = (decision: string) => {
    switch (decision) {
      case 'ALLOW': return <CheckCircle className="w-5 h-5" />;
      case 'BLOCK': return <XCircle className="w-5 h-5" />;
      default: return <AlertCircle className="w-5 h-5" />;
    }
  };

  if (compact && !expanded) {
    return (
      <Card className="cursor-pointer hover:bg-accent/50 transition-colors" onClick={() => setExpanded(true)}>
        <CardContent className="p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${getDecisionColor(consensus.decision)}`}>
                {getDecisionIcon(consensus.decision)}
              </div>
              <div>
                <p className="font-medium">Multi-LLM Consensus</p>
                <p className="text-sm text-muted-foreground">
                  {consensus.decision} @ {consensus.confidence.toFixed(1)}%
                </p>
              </div>
            </div>
            <ChevronDown className="w-4 h-4 text-muted-foreground" />
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <Brain className="w-5 h-5 text-primary" />
            Multi-LLM Consensus Analysis
          </CardTitle>
          <div className="flex items-center gap-2">
            <Button 
              variant="outline" 
              size="sm"
              onClick={() => refetchStatus()}
              disabled={statusLoading}
            >
              <RefreshCw className={`w-4 h-4 mr-1 ${statusLoading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            <Button 
              variant="default" 
              size="sm"
              onClick={() => analysisMutation.mutate()}
              disabled={analysisMutation.isPending}
            >
              {analysisMutation.isPending ? (
                <Loader2 className="w-4 h-4 mr-1 animate-spin" />
              ) : (
                <Brain className="w-4 h-4 mr-1" />
              )}
              Run Analysis
            </Button>
          </div>
        </div>
        <p className="text-sm text-muted-foreground">
          Service: <span className="font-medium">{service}</span> | 
          Environment: <span className="font-medium">{environment}</span>
        </p>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Provider Cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {providers.map((provider, index) => (
            <motion.div
              key={provider.name}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className={`p-3 rounded-lg border ${
                selectedProviders.includes(provider.name) 
                  ? 'border-primary bg-primary/5' 
                  : 'border-border bg-muted/20'
              } cursor-pointer hover:border-primary/50 transition-colors`}
              onClick={() => {
                setSelectedProviders(prev => 
                  prev.includes(provider.name)
                    ? prev.filter(p => p !== provider.name)
                    : [...prev, provider.name]
                );
              }}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="font-medium text-sm">{provider.displayName}</span>
                <Badge 
                  variant={provider.status === 'ready' ? 'default' : 'secondary'}
                  className="text-[10px]"
                >
                  {provider.status}
                </Badge>
              </div>
              
              <div className={`flex items-center gap-1 mb-1 ${
                provider.recommendation === 'ALLOW' ? 'text-green-500' :
                provider.recommendation === 'BLOCK' ? 'text-red-500' : 'text-yellow-500'
              }`}>
                {getDecisionIcon(provider.recommendation)}
                <span className="font-bold text-sm">{provider.recommendation}</span>
              </div>
              
              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <span>{provider.confidence}% conf</span>
                <span>Weight: {provider.weight}%</span>
              </div>

              {/* Confidence bar */}
              <div className="h-1 bg-muted/30 rounded-full mt-2 overflow-hidden">
                <motion.div
                  className={`h-full rounded-full ${
                    provider.recommendation === 'ALLOW' ? 'bg-green-500' :
                    provider.recommendation === 'BLOCK' ? 'bg-red-500' : 'bg-yellow-500'
                  }`}
                  initial={{ width: 0 }}
                  animate={{ width: `${provider.confidence}%` }}
                  transition={{ duration: 0.5, delay: index * 0.1 }}
                />
              </div>
            </motion.div>
          ))}
        </div>

        {/* Consensus Result */}
        <div className={`p-4 rounded-lg ${getDecisionColor(consensus.decision)} border`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              {getDecisionIcon(consensus.decision)}
              <div>
                <p className="font-bold text-lg">
                  FINAL CONSENSUS: {consensus.decision}
                </p>
                <p className="text-sm opacity-80">
                  @ {consensus.confidence.toFixed(1)}% confidence | 
                  Method: Weighted Majority Voting
                </p>
              </div>
            </div>
            <div className="text-right">
              <p className="text-sm">
                <span className="text-green-500">{consensus.allowVotes}</span> / 
                <span className="text-red-500">{consensus.blockVotes}</span> votes
              </p>
              <p className="text-xs opacity-70">{consensus.agreement.toFixed(0)}% agreement</p>
            </div>
          </div>

          {consensus.blockVotes > 0 && consensus.decision === 'ALLOW' && (
            <div className="mt-3 p-2 bg-background/50 rounded text-sm">
              <span className="font-medium">⚠️ Disagreement: </span>
              {providers.find(p => p.recommendation === 'BLOCK')?.displayName} flagged concerns 
              (override by {consensus.allowVotes}/{providers.length} providers)
            </div>
          )}

          <div className="mt-3 flex items-center gap-2 text-sm">
            <Settings className="w-4 h-4" />
            <span>Expert Review: {consensus.confidence > 75 ? 'Not Required' : 'Recommended'}</span>
          </div>
        </div>

        {/* Knowledge Graph Stats */}
        {capabilities && (
          <div className="grid grid-cols-3 gap-3 text-center">
            <div className="p-3 rounded-lg bg-muted/20">
              <p className="text-2xl font-bold">{capabilities.knowledge_graph?.nodes || 0}</p>
              <p className="text-xs text-muted-foreground">Knowledge Nodes</p>
            </div>
            <div className="p-3 rounded-lg bg-muted/20">
              <p className="text-2xl font-bold">{capabilities.signals?.kev_count || 0}</p>
              <p className="text-xs text-muted-foreground">KEV Signals</p>
            </div>
            <div className="p-3 rounded-lg bg-muted/20">
              <p className="text-2xl font-bold">{capabilities.signals?.models_consulted || 4}</p>
              <p className="text-xs text-muted-foreground">Models Consulted</p>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
