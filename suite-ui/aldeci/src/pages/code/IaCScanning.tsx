import { useState, useMemo } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Cloud, Play, CheckCircle2, AlertTriangle, Shield,
  Loader2, FileCode, Search, BarChart3,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { cspmScanApi } from '../../lib/api';
import { toast } from 'sonner';

// ============================================================================
// Types
// ============================================================================

interface IaCFinding {
  id: string;
  rule_id: string;
  title: string;
  severity: string;
  resource_type: string;
  resource_name?: string;
  file_path?: string;
  line_number?: number;
  description?: string;
  remediation?: string;
}

interface ScanResult {
  scan_id: string;
  findings: IaCFinding[];
  summary?: Record<string, number>;
  scan_type: string;
  timestamp: string;
}

// ============================================================================
// Constants
// ============================================================================

const severityColors: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  info: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

const EXAMPLE_TERRAFORM = `resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  # Missing: server-side encryption
  # Missing: versioning
  # Missing: access logging
}

resource "aws_security_group" "web" {
  name = "web-sg"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Overly permissive
  }
}`;

const EXAMPLE_CLOUDFORMATION = `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-insecure-bucket
      # No encryption configured
      # No versioning
      # No public access block`;

const containerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.05 } },
};

const itemVariants = {
  hidden: { opacity: 0, y: 12 },
  visible: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 200, damping: 22 } },
};

// ============================================================================
// Main IaC Scanning Page [V3]
// ============================================================================

export default function IaCScanning() {
  const [codeInput, setCodeInput] = useState(EXAMPLE_TERRAFORM);
  const [scanType, setScanType] = useState<'terraform' | 'cloudformation'>('terraform');
  const [results, setResults] = useState<ScanResult | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  // Fetch rules from real API
  const { data: rules = [], isLoading: rulesLoading } = useQuery({
    queryKey: ['cspm-rules'],
    queryFn: () => cspmScanApi.getRules(),
    retry: false,
  });

  // Scan mutation
  const scanMutation = useMutation({
    mutationFn: async () => {
      const scanFn = scanType === 'terraform'
        ? cspmScanApi.scanTerraform
        : cspmScanApi.scanCloudFormation;
      return scanFn({ content: codeInput, filename: `input.${scanType === 'terraform' ? 'tf' : 'yaml'}` });
    },
    onSuccess: (data) => {
      const findings = data?.findings || data?.misconfigurations || [];
      setResults({
        scan_id: data?.scan_id || `scan-${Date.now()}`,
        findings: findings as IaCFinding[],
        summary: data?.summary || {},
        scan_type: scanType,
        timestamp: new Date().toISOString(),
      });
      toast.success(`IaC scan complete — ${findings.length} findings`);
    },
    onError: () => toast.error('IaC scan failed'),
  });

  // Filter results
  const filteredFindings = useMemo(() => {
    if (!results?.findings) return [];
    if (!searchQuery) return results.findings;
    const q = searchQuery.toLowerCase();
    return results.findings.filter(f =>
      (f.title || '').toLowerCase().includes(q) ||
      (f.rule_id || '').toLowerCase().includes(q) ||
      (f.resource_type || '').toLowerCase().includes(q)
    );
  }, [results, searchQuery]);

  // Stats from results
  const stats = useMemo(() => {
    const findings = results?.findings || [];
    return {
      total: findings.length,
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
    };
  }, [results]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} transition={{ type: 'spring', stiffness: 150 }}
        className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-sky-400 via-blue-400 to-indigo-400 bg-clip-text text-transparent">
            Infrastructure as Code Scanning
          </h1>
          <p className="text-gray-400 mt-1">Scan Terraform, CloudFormation, and Kubernetes manifests for misconfigurations</p>
        </div>
        <Badge className="bg-primary/20 text-primary border-primary/30 border px-3 py-1">
          <Cloud className="w-3.5 h-3.5 mr-1.5" /> CSPM Scanner
        </Badge>
      </motion.div>

      {/* Scan Input */}
      <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileCode className="w-5 h-5 text-primary" />
            Scan Configuration
          </CardTitle>
          <CardDescription>Paste your IaC code or upload a file for security analysis</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Type Selector */}
          <div className="flex gap-2">
            {[
              { id: 'terraform' as const, label: 'Terraform (.tf)' },
              { id: 'cloudformation' as const, label: 'CloudFormation (.yaml)' },
            ].map(type => (
              <button
                key={type.id}
                onClick={() => {
                  setScanType(type.id);
                  setCodeInput(type.id === 'terraform' ? EXAMPLE_TERRAFORM : EXAMPLE_CLOUDFORMATION);
                }}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                  scanType === type.id
                    ? 'bg-primary/20 text-primary border border-primary/30'
                    : 'text-gray-400 hover:text-gray-300 border border-gray-700/30 hover:border-gray-600/40'
                }`}
              >
                {type.label}
              </button>
            ))}
          </div>

          {/* Code Input */}
          <Textarea
            value={codeInput}
            onChange={e => setCodeInput(e.target.value)}
            rows={12}
            className="font-mono text-sm bg-gray-950/50 border-gray-700/40"
            placeholder="Paste your IaC code here..."
          />

          {/* Scan Button */}
          <div className="flex justify-end gap-2">
            <Button
              onClick={() => scanMutation.mutate()}
              disabled={scanMutation.isPending || !codeInput.trim()}
            >
              {scanMutation.isPending ? (
                <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Scanning...</>
              ) : (
                <><Play className="w-4 h-4 mr-2" /> Run IaC Scan</>
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Results */}
      {results && (
        <>
          {/* Stats Row */}
          <motion.div variants={containerVariants} initial="hidden" animate="visible"
            className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {[
              { label: 'Total Findings', value: stats.total, color: 'text-blue-400', icon: Shield },
              { label: 'Critical', value: stats.critical, color: 'text-red-400', icon: AlertTriangle },
              { label: 'High', value: stats.high, color: 'text-orange-400', icon: AlertTriangle },
              { label: 'Medium', value: stats.medium, color: 'text-yellow-400', icon: AlertTriangle },
              { label: 'Low', value: stats.low, color: 'text-blue-400', icon: CheckCircle2 },
            ].map(stat => (
              <motion.div key={stat.label} variants={itemVariants}>
                <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
                        <p className="text-xs text-gray-400 mt-1">{stat.label}</p>
                      </div>
                      <stat.icon className={`w-5 h-5 ${stat.color} opacity-60`} />
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </motion.div>

          {/* Search */}
          <div className="relative max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <Input
              placeholder="Search findings..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="pl-10 bg-gray-900/40 border-gray-700/40"
            />
          </div>

          {/* Findings List */}
          <Card className="border-gray-700/30 bg-gray-900/30 backdrop-blur-md">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <BarChart3 className="w-5 h-5 text-primary" />
                Scan Results
              </CardTitle>
              <CardDescription>{filteredFindings.length} misconfiguration{filteredFindings.length !== 1 ? 's' : ''} found</CardDescription>
            </CardHeader>
            <CardContent>
              {filteredFindings.length === 0 ? (
                <div className="text-center py-8">
                  <CheckCircle2 className="w-12 h-12 text-green-500/40 mx-auto mb-4" />
                  <p className="text-gray-400">No misconfigurations found</p>
                </div>
              ) : (
                <motion.div variants={containerVariants} initial="hidden" animate="visible" className="space-y-2">
                  {filteredFindings.map((finding, i) => (
                    <motion.div key={finding.id || i} variants={itemVariants}
                      className="p-4 rounded-lg border border-gray-700/30 bg-gray-800/20 hover:bg-gray-800/40 transition-all">
                      <div className="flex items-start gap-3">
                        <div className={`w-1.5 self-stretch rounded-full ${
                          finding.severity === 'critical' ? 'bg-red-500' :
                          finding.severity === 'high' ? 'bg-orange-500' :
                          finding.severity === 'medium' ? 'bg-yellow-500' : 'bg-blue-500'
                        }`} />
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <span className="font-medium text-gray-100">{finding.title || finding.rule_id}</span>
                            <Badge className={`border text-[10px] ${severityColors[finding.severity] || severityColors.info}`}>
                              {(finding.severity || 'info').toUpperCase()}
                            </Badge>
                          </div>
                          {finding.description && (
                            <p className="text-sm text-gray-400 mt-1">{finding.description}</p>
                          )}
                          <div className="flex items-center gap-3 mt-2 text-xs text-gray-500">
                            {finding.resource_type && <span>Resource: {finding.resource_type}</span>}
                            {finding.resource_name && <span>Name: {finding.resource_name}</span>}
                            {finding.rule_id && <span className="font-mono">{finding.rule_id}</span>}
                          </div>
                          {finding.remediation && (
                            <div className="mt-2 p-2 rounded bg-green-500/5 border border-green-500/20">
                              <p className="text-xs text-green-400">Fix: {finding.remediation}</p>
                            </div>
                          )}
                        </div>
                      </div>
                    </motion.div>
                  ))}
                </motion.div>
              )}
            </CardContent>
          </Card>
        </>
      )}

      {/* Rules Count */}
      {!rulesLoading && Array.isArray(rules) && rules.length > 0 && (
        <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
          <CardContent className="py-3 px-4 flex items-center gap-3">
            <Shield className="w-5 h-5 text-primary" />
            <span className="text-sm text-gray-300">{rules.length} security rules loaded</span>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
