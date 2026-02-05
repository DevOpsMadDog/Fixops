import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  GitBranch,
  Brain,
  Settings,
  Play,
  CheckCircle2,
  Shield,
  Zap,
  RefreshCw,
  Loader2,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { Progress } from '../components/ui/progress';
import { algorithmsApi } from '../lib/api';
import { toast } from 'sonner';

interface AlgorithmCardProps {
  name: string;
  description?: string;
  type?: string;
  enabled?: boolean;
  onToggle?: () => void;
}

function AlgorithmCard({ name, description, type, enabled, onToggle }: AlgorithmCardProps) {
  return (
    <Card className={`glass-card ${enabled ? 'border-primary/30' : ''}`}>
      <CardContent className="pt-6">
        <div className="flex items-start justify-between">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Brain className="w-5 h-5 text-primary" />
              <h4 className="font-semibold">{name}</h4>
            </div>
            {description && (
              <p className="text-sm text-muted-foreground">{description}</p>
            )}
            {type && (
              <Badge variant="outline">{type}</Badge>
            )}
          </div>
          <Button
            variant={enabled ? 'default' : 'outline'}
            size="sm"
            onClick={onToggle}
          >
            {enabled ? 'Enabled' : 'Enable'}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

export default function DecisionEngine() {
  const [enabledAlgorithms, setEnabledAlgorithms] = useState<Set<string>>(
    new Set(['CVSS', 'EPSS', 'KEV'])
  );

  // Fetch real algorithm capabilities
  const { data: capabilitiesData, isLoading: capabilitiesLoading, refetch } = useQuery({
    queryKey: ['decision-capabilities'],
    queryFn: algorithmsApi.getCapabilities,
  });

  // Prioritization mutation
  const prioritizeMutation = useMutation({
    mutationFn: async () => {
      // Call prioritization API
      const response = await algorithmsApi.prioritize({
        algorithms: Array.from(enabledAlgorithms),
        context: {
          asset_criticality: 'high',
          data_sensitivity: 'confidential',
        },
      });
      return response;
    },
    onSuccess: (data) => {
      toast.success('Prioritization complete', {
        description: `Processed ${data.findings_count || 'N/A'} findings`,
      });
    },
    onError: (error: any) => {
      toast.error('Prioritization failed', {
        description: error.response?.data?.detail || error.message,
      });
    },
  });

  const toggleAlgorithm = (name: string) => {
    setEnabledAlgorithms((prev) => {
      const next = new Set(prev);
      if (next.has(name)) {
        next.delete(name);
      } else {
        next.add(name);
      }
      return next;
    });
  };

  const handleRunPrioritization = () => {
    if (enabledAlgorithms.size === 0) {
      toast.error('Select at least one algorithm');
      return;
    }
    prioritizeMutation.mutate();
  };

  // Algorithm descriptions
  const algorithmInfo: Record<string, { description: string; type: string }> = {
    CVSS: {
      description: 'Common Vulnerability Scoring System - Industry standard severity scoring',
      type: 'Severity',
    },
    EPSS: {
      description: 'Exploit Prediction Scoring System - ML-based exploitation probability',
      type: 'Probability',
    },
    SSVC: {
      description: 'Stakeholder-Specific Vulnerability Categorization - Context-aware decisions',
      type: 'Decision',
    },
    KEV: {
      description: 'Known Exploited Vulnerabilities - CISA active exploitation tracking',
      type: 'Threat Intel',
    },
  };

  const algorithms = capabilitiesData?.algorithms || Object.keys(algorithmInfo);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <GitBranch className="w-8 h-8 text-primary" />
            Decision Engine
          </h1>
          <p className="text-muted-foreground mt-1">
            Risk prioritization and decision framework
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => refetch()} className="gap-2">
            <RefreshCw className="w-4 h-4" />
            Refresh
          </Button>
          <Button onClick={handleRunPrioritization} disabled={prioritizeMutation.isPending} className="gap-2">
            {prioritizeMutation.isPending ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4" />
            )}
            Run Prioritization
          </Button>
        </div>
      </div>

      {/* Algorithm Status */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="glass-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between mb-2">
              <Brain className="w-6 h-6 text-primary" />
              <Badge variant="default">Active</Badge>
            </div>
            <h3 className="text-2xl font-bold">{algorithms.length}</h3>
            <p className="text-sm text-muted-foreground">Available Algorithms</p>
          </CardContent>
        </Card>

        <Card className="glass-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between mb-2">
              <CheckCircle2 className="w-6 h-6 text-green-500" />
              <Badge variant="default">{enabledAlgorithms.size}</Badge>
            </div>
            <h3 className="text-2xl font-bold">{enabledAlgorithms.size}</h3>
            <p className="text-sm text-muted-foreground">Enabled Algorithms</p>
          </CardContent>
        </Card>

        <Card className="glass-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between mb-2">
              <Zap className="w-6 h-6 text-yellow-500" />
            </div>
            <h3 className="text-2xl font-bold">Real-time</h3>
            <p className="text-sm text-muted-foreground">Decision Speed</p>
          </CardContent>
        </Card>

        <Card className="glass-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between mb-2">
              <Shield className="w-6 h-6 text-blue-500" />
            </div>
            <h3 className="text-2xl font-bold">Context-Aware</h3>
            <p className="text-sm text-muted-foreground">Decision Type</p>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="algorithms" className="space-y-6">
        <TabsList>
          <TabsTrigger value="algorithms">Algorithms</TabsTrigger>
          <TabsTrigger value="ssvc">SSVC Framework</TabsTrigger>
          <TabsTrigger value="configuration">Configuration</TabsTrigger>
        </TabsList>

        {/* Algorithms Tab */}
        <TabsContent value="algorithms" className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle>Prioritization Algorithms</CardTitle>
              <CardDescription>
                Select which algorithms to use for vulnerability prioritization
              </CardDescription>
            </CardHeader>
            <CardContent>
              {capabilitiesLoading ? (
                <div className="space-y-4">
                  {[1, 2, 3, 4].map((i) => (
                    <div key={i} className="h-24 skeleton rounded-lg" />
                  ))}
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {algorithms.map((algo: any, index: number) => {
                    const name = typeof algo === 'string' ? algo : algo.name;
                    const info = algorithmInfo[name] || {
                      description: algo.description || 'Prioritization algorithm',
                      type: algo.type || 'Algorithm',
                    };
                    
                    return (
                      <motion.div
                        key={name}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: index * 0.1 }}
                      >
                        <AlgorithmCard
                          name={name}
                          description={info.description}
                          type={info.type}
                          enabled={enabledAlgorithms.has(name)}
                          onToggle={() => toggleAlgorithm(name)}
                        />
                      </motion.div>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Differentiators */}
          {capabilitiesData?.differentiators && (
            <Card className="glass-card">
              <CardHeader>
                <CardTitle>Key Differentiators</CardTitle>
                <CardDescription>
                  What makes ALdeci's decision engine unique
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {capabilitiesData.differentiators.map((diff: string, index: number) => (
                    <motion.div
                      key={index}
                      initial={{ opacity: 0, scale: 0.95 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ delay: index * 0.05 }}
                      className="p-4 rounded-lg bg-primary/5 border border-primary/20"
                    >
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="w-4 h-4 text-primary" />
                        <span className="text-sm font-medium">{diff}</span>
                      </div>
                    </motion.div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* SSVC Tab */}
        <TabsContent value="ssvc" className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle>SSVC Decision Framework</CardTitle>
              <CardDescription>
                Stakeholder-Specific Vulnerability Categorization
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Decision Factors */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <h4 className="font-medium">Exploitation Status</h4>
                  <div className="space-y-2">
                    {['None', 'PoC', 'Active'].map((status) => (
                      <div key={status} className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
                        <span>{status}</span>
                        <Badge variant={status === 'Active' ? 'critical' : status === 'PoC' ? 'high' : 'secondary'}>
                          {status}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="space-y-4">
                  <h4 className="font-medium">Automatable</h4>
                  <div className="space-y-2">
                    {['Yes', 'No'].map((auto) => (
                      <div key={auto} className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
                        <span>{auto}</span>
                        <Badge variant={auto === 'Yes' ? 'high' : 'low'}>
                          {auto === 'Yes' ? 'High Risk' : 'Lower Risk'}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="space-y-4">
                  <h4 className="font-medium">Technical Impact</h4>
                  <div className="space-y-2">
                    {['Total', 'Partial'].map((impact) => (
                      <div key={impact} className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
                        <span>{impact}</span>
                        <Badge variant={impact === 'Total' ? 'critical' : 'medium'}>
                          {impact}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="space-y-4">
                  <h4 className="font-medium">Mission Prevalence</h4>
                  <div className="space-y-2">
                    {['Essential', 'Important', 'Limited'].map((mission) => (
                      <div key={mission} className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
                        <span>{mission}</span>
                        <Badge variant={mission === 'Essential' ? 'critical' : mission === 'Important' ? 'high' : 'low'}>
                          {mission}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Decision Outcomes */}
              <div className="pt-6 border-t border-border">
                <h4 className="font-medium mb-4">Decision Outcomes</h4>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  {[
                    { decision: 'Act', color: 'bg-red-500', description: 'Immediate action required' },
                    { decision: 'Attend', color: 'bg-orange-500', description: 'High priority remediation' },
                    { decision: 'Track*', color: 'bg-yellow-500', description: 'Close monitoring needed' },
                    { decision: 'Track', color: 'bg-green-500', description: 'Standard tracking' },
                  ].map((outcome) => (
                    <Card key={outcome.decision} className="glass-card">
                      <CardContent className="pt-6 text-center">
                        <div className={`w-12 h-12 rounded-full ${outcome.color} mx-auto mb-3 flex items-center justify-center`}>
                          <span className="text-white font-bold">{outcome.decision[0]}</span>
                        </div>
                        <h5 className="font-semibold">{outcome.decision}</h5>
                        <p className="text-xs text-muted-foreground mt-1">{outcome.description}</p>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Configuration Tab */}
        <TabsContent value="configuration" className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Settings className="w-5 h-5" />
                Decision Configuration
              </CardTitle>
              <CardDescription>
                Configure how the decision engine prioritizes vulnerabilities
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <div>
                  <label className="text-sm font-medium">EPSS Threshold</label>
                  <p className="text-xs text-muted-foreground mb-2">
                    Minimum EPSS score to trigger high priority
                  </p>
                  <div className="flex items-center gap-4">
                    <Progress value={30} className="flex-1" />
                    <span className="text-sm font-medium">30%</span>
                  </div>
                </div>

                <div>
                  <label className="text-sm font-medium">CVSS Base Score Threshold</label>
                  <p className="text-xs text-muted-foreground mb-2">
                    Minimum CVSS score for critical classification
                  </p>
                  <div className="flex items-center gap-4">
                    <Progress value={70} className="flex-1" />
                    <span className="text-sm font-medium">7.0</span>
                  </div>
                </div>

                <div>
                  <label className="text-sm font-medium">KEV Priority Boost</label>
                  <p className="text-xs text-muted-foreground mb-2">
                    Automatically elevate KEV-listed vulnerabilities
                  </p>
                  <Badge variant="default">Enabled</Badge>
                </div>

                <div>
                  <label className="text-sm font-medium">Asset Context Weight</label>
                  <p className="text-xs text-muted-foreground mb-2">
                    Factor asset criticality into prioritization
                  </p>
                  <div className="flex items-center gap-4">
                    <Progress value={50} className="flex-1" />
                    <span className="text-sm font-medium">50%</span>
                  </div>
                </div>
              </div>

              <div className="pt-6 border-t border-border flex justify-end gap-2">
                <Button variant="outline">Reset to Defaults</Button>
                <Button>Save Configuration</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
