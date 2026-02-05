import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  FileSignature,
  Download,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Shield,
  FileText,
  RefreshCw,
  Loader2,
  ExternalLink,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { complianceApi, reportsApi, auditApi } from '../../lib/api';
import { toast } from 'sonner';

interface ComplianceFramework {
  id: string;
  name: string;
  description: string;
  controls_total: number;
  controls_passing: number;
  controls_failing: number;
  last_assessed: string;
  status: 'compliant' | 'non-compliant' | 'partial' | 'pending';
}

export default function ComplianceReports() {
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null);

  // Fetch compliance status
  const { isLoading: complianceLoading, refetch: refetchCompliance } = useQuery({
    queryKey: ['compliance-status'],
    queryFn: () => complianceApi.getStatus(),
    retry: false,
  });

  // Fetch available reports
  useQuery({
    queryKey: ['compliance-reports'],
    queryFn: () => reportsApi.getTemplates(),
    retry: false,
  });

  // Fetch audit trail
  const { data: auditData } = useQuery({
    queryKey: ['audit-trail'],
    queryFn: () => auditApi.getLogs({ limit: 10 }),
    retry: false,
  });

  // Generate report mutation
  const generateReportMutation = useMutation({
    mutationFn: async (frameworkId: string) => {
      return await reportsApi.create({
        framework: frameworkId,
        format: 'pdf'
      });
    },
    onSuccess: () => {
      toast.success('Report generation started');
    },
    onError: (error: Error) => {
      toast.error(`Failed to generate report: ${error.message}`);
    },
  });

  // Mock frameworks (would come from API)
  const frameworks: ComplianceFramework[] = [
    {
      id: 'pci-dss',
      name: 'PCI DSS 4.0',
      description: 'Payment Card Industry Data Security Standard',
      controls_total: 280,
      controls_passing: 256,
      controls_failing: 12,
      last_assessed: '2024-01-15',
      status: 'partial',
    },
    {
      id: 'soc2',
      name: 'SOC 2 Type II',
      description: 'Service Organization Control 2',
      controls_total: 85,
      controls_passing: 85,
      controls_failing: 0,
      last_assessed: '2024-01-10',
      status: 'compliant',
    },
    {
      id: 'iso27001',
      name: 'ISO 27001:2022',
      description: 'Information Security Management System',
      controls_total: 114,
      controls_passing: 108,
      controls_failing: 6,
      last_assessed: '2024-01-08',
      status: 'partial',
    },
    {
      id: 'nist',
      name: 'NIST CSF 2.0',
      description: 'Cybersecurity Framework',
      controls_total: 106,
      controls_passing: 98,
      controls_failing: 8,
      last_assessed: '2024-01-05',
      status: 'partial',
    },
    {
      id: 'slsa',
      name: 'SLSA Level 3',
      description: 'Supply-chain Levels for Software Artifacts',
      controls_total: 15,
      controls_passing: 15,
      controls_failing: 0,
      last_assessed: '2024-01-14',
      status: 'compliant',
    },
  ];

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'compliant':
        return <Badge className="bg-green-500/20 text-green-400 border-green-500/30">Compliant</Badge>;
      case 'non-compliant':
        return <Badge className="bg-red-500/20 text-red-400 border-red-500/30">Non-Compliant</Badge>;
      case 'partial':
        return <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30">Partial</Badge>;
      default:
        return <Badge className="bg-gray-500/20 text-gray-400 border-gray-500/30">Pending</Badge>;
    }
  };

  const getCompliancePercentage = (framework: ComplianceFramework) => {
    return Math.round((framework.controls_passing / framework.controls_total) * 100);
  };

  // Calculate overall stats
  const totalControls = frameworks.reduce((acc, f) => acc + f.controls_total, 0);
  const passingControls = frameworks.reduce((acc, f) => acc + f.controls_passing, 0);
  const failingControls = frameworks.reduce((acc, f) => acc + f.controls_failing, 0);
  const overallCompliance = Math.round((passingControls / totalControls) * 100);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-emerald-500 to-teal-500 flex items-center justify-center">
              <FileSignature className="w-5 h-5 text-white" />
            </div>
            Compliance Reports
          </h1>
          <p className="text-muted-foreground mt-1">
            Regulatory compliance tracking and evidence generation
          </p>
        </div>
        <Button variant="outline" onClick={() => refetchCompliance()} className="gap-2">
          <RefreshCw className="w-4 h-4" />
          Refresh
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
          <Card className="glass-card">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-2xl font-bold text-emerald-400">{overallCompliance}%</p>
                  <p className="text-xs text-muted-foreground">Overall Compliance</p>
                </div>
                <Shield className="w-8 h-8 text-emerald-400/50" />
              </div>
            </CardContent>
          </Card>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
          <Card className="glass-card">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-2xl font-bold text-green-400">{passingControls}</p>
                  <p className="text-xs text-muted-foreground">Controls Passing</p>
                </div>
                <CheckCircle2 className="w-8 h-8 text-green-400/50" />
              </div>
            </CardContent>
          </Card>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
          <Card className="glass-card">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-2xl font-bold text-red-400">{failingControls}</p>
                  <p className="text-xs text-muted-foreground">Controls Failing</p>
                </div>
                <AlertTriangle className="w-8 h-8 text-red-400/50" />
              </div>
            </CardContent>
          </Card>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
          <Card className="glass-card">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-2xl font-bold text-blue-400">{frameworks.length}</p>
                  <p className="text-xs text-muted-foreground">Frameworks</p>
                </div>
                <FileText className="w-8 h-8 text-blue-400/50" />
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Frameworks */}
      <Card className="glass-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="w-5 h-5" />
            Compliance Frameworks
          </CardTitle>
          <CardDescription>
            {complianceLoading ? 'Loading...' : `${frameworks.length} frameworks tracked`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {frameworks.map((framework, index) => {
              const percentage = getCompliancePercentage(framework);
              const isSelected = selectedFramework === framework.id;
              
              return (
                <motion.div
                  key={framework.id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.1 }}
                  onClick={() => setSelectedFramework(isSelected ? null : framework.id)}
                  className={`p-4 rounded-lg border cursor-pointer transition-all ${
                    isSelected 
                      ? 'border-primary bg-primary/5' 
                      : 'border-border bg-muted/30 hover:border-primary/50'
                  }`}
                >
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-muted flex items-center justify-center">
                        <FileSignature className="w-5 h-5 text-primary" />
                      </div>
                      <div>
                        <h3 className="font-semibold">{framework.name}</h3>
                        <p className="text-sm text-muted-foreground">{framework.description}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      {getStatusBadge(framework.status)}
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={(e) => {
                          e.stopPropagation();
                          generateReportMutation.mutate(framework.id);
                        }}
                        disabled={generateReportMutation.isPending}
                      >
                        {generateReportMutation.isPending ? (
                          <Loader2 className="w-4 h-4 animate-spin" />
                        ) : (
                          <Download className="w-4 h-4" />
                        )}
                      </Button>
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">
                        {framework.controls_passing} / {framework.controls_total} controls
                      </span>
                      <span className="font-medium">{percentage}%</span>
                    </div>
                    <div className="w-full bg-muted/50 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full transition-all ${
                          percentage === 100 
                            ? 'bg-green-500' 
                            : percentage >= 80 
                            ? 'bg-yellow-500' 
                            : 'bg-red-500'
                        }`}
                        style={{ width: `${percentage}%` }}
                      />
                    </div>
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                      <Clock className="w-3 h-3" />
                      Last assessed: {new Date(framework.last_assessed).toLocaleDateString()}
                    </div>
                  </div>

                  {isSelected && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      className="mt-4 pt-4 border-t border-border"
                    >
                      <div className="grid grid-cols-3 gap-4">
                        <div className="text-center p-3 rounded-lg bg-green-500/10">
                          <p className="text-lg font-bold text-green-400">{framework.controls_passing}</p>
                          <p className="text-xs text-muted-foreground">Passing</p>
                        </div>
                        <div className="text-center p-3 rounded-lg bg-red-500/10">
                          <p className="text-lg font-bold text-red-400">{framework.controls_failing}</p>
                          <p className="text-xs text-muted-foreground">Failing</p>
                        </div>
                        <div className="text-center p-3 rounded-lg bg-gray-500/10">
                          <p className="text-lg font-bold text-gray-400">
                            {framework.controls_total - framework.controls_passing - framework.controls_failing}
                          </p>
                          <p className="text-xs text-muted-foreground">N/A</p>
                        </div>
                      </div>
                      <div className="flex gap-2 mt-4">
                        <Button size="sm" className="gap-2 flex-1">
                          <ExternalLink className="w-4 h-4" />
                          View Details
                        </Button>
                        <Button 
                          size="sm" 
                          variant="outline" 
                          className="gap-2 flex-1"
                          onClick={(e) => {
                            e.stopPropagation();
                            generateReportMutation.mutate(framework.id);
                          }}
                        >
                          <Download className="w-4 h-4" />
                          Download Report
                        </Button>
                      </div>
                    </motion.div>
                  )}
                </motion.div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Recent Activity */}
      <Card className="glass-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Clock className="w-5 h-5" />
            Recent Compliance Activity
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {((auditData as any)?.logs || []).slice(0, 5).map((log: any, index: number) => (
              <motion.div
                key={log.id || index}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: index * 0.1 }}
                className="flex items-center gap-3 p-3 rounded-lg bg-muted/30"
              >
                <CheckCircle2 className="w-4 h-4 text-green-400" />
                <div className="flex-1">
                  <p className="text-sm">{log.action || log.message || 'Compliance check completed'}</p>
                  <p className="text-xs text-muted-foreground">
                    {log.timestamp ? new Date(log.timestamp).toLocaleString() : 'Just now'}
                  </p>
                </div>
              </motion.div>
            ))}
            {(!auditData || (auditData as any)?.logs?.length === 0) && (
              <div className="text-center py-8 text-muted-foreground">
                <Clock className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p>No recent activity</p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
