import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  FileCheck,
  Download,
  Shield,
  CheckCircle2,
  Clock,
  FileText,
  FolderOpen,
  RefreshCw,
  Loader2,
  Calendar,
  Building2,
  Lock,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { ScrollArea } from '../components/ui/scroll-area';
import { Progress } from '../components/ui/progress';
import { complianceApi } from '../lib/api';
import { toast } from 'sonner';

interface ComplianceFramework {
  id: string;
  name: string;
  version: string;
  controlsTotal: number;
  controlsMet: number;
  icon: React.ReactNode;
}

interface EvidenceItem {
  id: string;
  name: string;
  framework: string;
  control: string;
  status: 'collected' | 'pending' | 'missing';
  collectedAt?: string;
}

export default function EvidenceVault() {
  const [selectedFramework, setSelectedFramework] = useState<string>('pci-dss');
  const [evidenceItems, setEvidenceItems] = useState<EvidenceItem[]>([
    { id: '1', name: 'Vulnerability Scan Report', framework: 'PCI DSS', control: '11.3.2', status: 'collected', collectedAt: '2024-01-15' },
    { id: '2', name: 'Penetration Test Results', framework: 'PCI DSS', control: '11.4', status: 'collected', collectedAt: '2024-01-10' },
    { id: '3', name: 'Access Control Policy', framework: 'SOC 2', control: 'CC6.1', status: 'pending' },
    { id: '4', name: 'Encryption Standards', framework: 'PCI DSS', control: '3.4', status: 'missing' },
  ]);

  // Fetch compliance status
  const { data: _complianceData, isLoading: _complianceLoading, refetch } = useQuery({
    queryKey: ['compliance-status'],
    queryFn: complianceApi.getStatus,
    retry: false,
  });

  // Generate report mutation
  const reportMutation = useMutation({
    mutationFn: async (framework: string) => {
      return complianceApi.generateReport(framework);
    },
    onSuccess: (_data) => {
      toast.success('Report generated', {
        description: 'Compliance report is ready for download',
      });
    },
    onError: (error: any) => {
      toast.error('Failed to generate report', {
        description: error.response?.data?.detail || error.message,
      });
    },
  });

  // Collect evidence mutation
  const collectMutation = useMutation({
    mutationFn: async (evidenceId: string) => {
      return complianceApi.collectEvidence(evidenceId);
    },
    onSuccess: (_data, evidenceId) => {
      setEvidenceItems((prev) =>
        prev.map((e) =>
          e.id === evidenceId
            ? { ...e, status: 'collected', collectedAt: new Date().toISOString().split('T')[0] }
            : e
        )
      );
      toast.success('Evidence collected');
    },
    onError: (error: any) => {
      toast.error('Failed to collect evidence', {
        description: error.response?.data?.detail || error.message,
      });
    },
  });

  const frameworks: ComplianceFramework[] = [
    {
      id: 'pci-dss',
      name: 'PCI DSS',
      version: '4.0',
      controlsTotal: 264,
      controlsMet: 189,
      icon: <Lock className="w-6 h-6" />,
    },
    {
      id: 'soc2',
      name: 'SOC 2',
      version: 'Type II',
      controlsTotal: 64,
      controlsMet: 52,
      icon: <Shield className="w-6 h-6" />,
    },
    {
      id: 'nist',
      name: 'NIST CSF',
      version: '2.0',
      controlsTotal: 108,
      controlsMet: 78,
      icon: <Building2 className="w-6 h-6" />,
    },
    {
      id: 'iso27001',
      name: 'ISO 27001',
      version: '2022',
      controlsTotal: 93,
      controlsMet: 67,
      icon: <FileCheck className="w-6 h-6" />,
    },
  ];

  const getCompliancePercentage = (framework: ComplianceFramework) => {
    return Math.round((framework.controlsMet / framework.controlsTotal) * 100);
  };

  const getStatusIcon = (status: EvidenceItem['status']) => {
    switch (status) {
      case 'collected':
        return <CheckCircle2 className="w-4 h-4 text-green-500" />;
      case 'pending':
        return <Clock className="w-4 h-4 text-yellow-500" />;
      default:
        return <FileText className="w-4 h-4 text-red-500" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <FileCheck className="w-8 h-8 text-primary" />
            Evidence Vault
          </h1>
          <p className="text-muted-foreground mt-1">
            Compliance evidence collection and reporting
          </p>
        </div>
        <Button variant="outline" onClick={() => refetch()} className="gap-2">
          <RefreshCw className="w-4 h-4" />
          Refresh
        </Button>
      </div>

      {/* Framework Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {frameworks.map((framework, index) => {
          const percentage = getCompliancePercentage(framework);
          const isSelected = selectedFramework === framework.id;
          
          return (
            <motion.div
              key={framework.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
            >
              <Card
                className={`glass-card cursor-pointer transition-all ${
                  isSelected ? 'border-primary ring-1 ring-primary' : 'hover:border-primary/50'
                }`}
                onClick={() => setSelectedFramework(framework.id)}
              >
                <CardContent className="pt-6">
                  <div className="flex items-start justify-between mb-4">
                    <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center text-primary">
                      {framework.icon}
                    </div>
                    <Badge variant={percentage >= 80 ? 'default' : percentage >= 50 ? 'medium' : 'high'}>
                      {percentage}%
                    </Badge>
                  </div>
                  <h3 className="font-semibold">{framework.name}</h3>
                  <p className="text-sm text-muted-foreground">v{framework.version}</p>
                  <div className="mt-4 space-y-2">
                    <Progress value={percentage} />
                    <p className="text-xs text-muted-foreground">
                      {framework.controlsMet} of {framework.controlsTotal} controls met
                    </p>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          );
        })}
      </div>

      <Tabs defaultValue="evidence" className="space-y-6">
        <TabsList>
          <TabsTrigger value="evidence">Evidence Collection</TabsTrigger>
          <TabsTrigger value="reports">Reports</TabsTrigger>
          <TabsTrigger value="gaps">Gap Analysis</TabsTrigger>
        </TabsList>

        {/* Evidence Tab */}
        <TabsContent value="evidence" className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Evidence Items</CardTitle>
                  <CardDescription>
                    Collected artifacts for compliance validation
                  </CardDescription>
                </div>
                <Button variant="outline" className="gap-2">
                  <FolderOpen className="w-4 h-4" />
                  Import Evidence
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[400px]">
                <div className="space-y-3">
                  {evidenceItems.map((item, index) => (
                    <motion.div
                      key={item.id}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.05 }}
                      className="flex items-center justify-between p-4 rounded-lg border border-border bg-muted/30"
                    >
                      <div className="flex items-center gap-4">
                        {getStatusIcon(item.status)}
                        <div>
                          <p className="font-medium">{item.name}</p>
                          <div className="flex items-center gap-2 mt-1">
                            <Badge variant="outline">{item.framework}</Badge>
                            <span className="text-xs text-muted-foreground">
                              Control: {item.control}
                            </span>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        {item.collectedAt && (
                          <span className="text-xs text-muted-foreground flex items-center gap-1">
                            <Calendar className="w-3 h-3" />
                            {item.collectedAt}
                          </span>
                        )}
                        {item.status !== 'collected' && (
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => collectMutation.mutate(item.id)}
                            disabled={collectMutation.isPending}
                          >
                            {collectMutation.isPending ? (
                              <Loader2 className="w-3 h-3 animate-spin" />
                            ) : (
                              'Collect'
                            )}
                          </Button>
                        )}
                        {item.status === 'collected' && (
                          <Button size="sm" variant="ghost">
                            <Download className="w-3 h-3" />
                          </Button>
                        )}
                      </div>
                    </motion.div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Reports Tab */}
        <TabsContent value="reports" className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle>Generate Compliance Report</CardTitle>
              <CardDescription>
                Create comprehensive compliance reports for auditors
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {frameworks.map((framework, index) => (
                  <motion.div
                    key={framework.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1 }}
                  >
                    <Card className="glass-card">
                      <CardContent className="pt-6">
                        <div className="flex items-start justify-between">
                          <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center text-primary">
                              {framework.icon}
                            </div>
                            <div>
                              <h4 className="font-semibold">{framework.name} Report</h4>
                              <p className="text-sm text-muted-foreground">
                                Version {framework.version}
                              </p>
                            </div>
                          </div>
                          <Button
                            size="sm"
                            onClick={() => reportMutation.mutate(framework.id)}
                            disabled={reportMutation.isPending}
                            className="gap-1"
                          >
                            {reportMutation.isPending ? (
                              <Loader2 className="w-3 h-3 animate-spin" />
                            ) : (
                              <Download className="w-3 h-3" />
                            )}
                            Generate
                          </Button>
                        </div>
                        <div className="mt-4 pt-4 border-t border-border">
                          <div className="flex justify-between text-sm">
                            <span className="text-muted-foreground">Compliance Score</span>
                            <span className="font-medium">{getCompliancePercentage(framework)}%</span>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </motion.div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Report History */}
          <Card className="glass-card">
            <CardHeader>
              <CardTitle>Report History</CardTitle>
              <CardDescription>Previously generated reports</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {[
                  { name: 'PCI DSS Q4 2024 Report', date: '2024-01-15', format: 'PDF' },
                  { name: 'SOC 2 Annual Review', date: '2024-01-10', format: 'PDF' },
                  { name: 'NIST CSF Gap Analysis', date: '2024-01-05', format: 'XLSX' },
                ].map((report, index) => (
                  <motion.div
                    key={index}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: index * 0.1 }}
                    className="flex items-center justify-between p-3 rounded-lg bg-muted/50"
                  >
                    <div className="flex items-center gap-3">
                      <FileText className="w-5 h-5 text-muted-foreground" />
                      <div>
                        <p className="font-medium text-sm">{report.name}</p>
                        <p className="text-xs text-muted-foreground">{report.date}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">{report.format}</Badge>
                      <Button size="sm" variant="ghost">
                        <Download className="w-4 h-4" />
                      </Button>
                    </div>
                  </motion.div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Gaps Tab */}
        <TabsContent value="gaps" className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle>Compliance Gaps</CardTitle>
              <CardDescription>
                Identified gaps requiring remediation
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {[
                  { control: '3.4', framework: 'PCI DSS', title: 'Encryption at Rest', severity: 'high', description: 'Cardholder data not encrypted with strong cryptography' },
                  { control: '11.5', framework: 'PCI DSS', title: 'File Integrity Monitoring', severity: 'medium', description: 'FIM not deployed on all critical systems' },
                  { control: 'CC7.2', framework: 'SOC 2', title: 'Incident Response', severity: 'low', description: 'Incident response testing documentation incomplete' },
                ].map((gap, index) => (
                  <motion.div
                    key={index}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1 }}
                    className="p-4 rounded-lg border border-border bg-muted/30"
                  >
                    <div className="flex items-start justify-between">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <Badge variant={gap.severity === 'high' ? 'critical' : gap.severity === 'medium' ? 'medium' : 'low'}>
                            {gap.severity}
                          </Badge>
                          <Badge variant="outline">{gap.framework}</Badge>
                          <span className="text-sm text-muted-foreground">
                            Control {gap.control}
                          </span>
                        </div>
                        <h4 className="font-semibold">{gap.title}</h4>
                        <p className="text-sm text-muted-foreground">{gap.description}</p>
                      </div>
                      <Button size="sm" variant="outline">
                        Remediate
                      </Button>
                    </div>
                  </motion.div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
