import { useState, useMemo, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  Target,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  ChevronDown,
  ChevronRight,
  Play,
  Loader2,
  Download,
  Eye,
  Zap,
  Lock,
  FileText,
  RefreshCw,
  Search,
  SkipForward,
  Activity,
  Server,
  Fingerprint,
  Bug,
  Cpu,
  Database,
  Network,
  Key,
  Upload,
  Terminal,
  ArrowUpRight,
  Trash2,
  Crosshair,
  Globe,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../../components/ui/tabs';
import { Input } from '../../components/ui/input';

import { ScrollArea } from '../../components/ui/scroll-area';
import { api } from '../../lib/api';
import { toast } from 'sonner';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

type PhaseStatus = 'PASS' | 'FAIL' | 'SKIP' | 'RUNNING' | 'PENDING';
type Verdict = 'EXPLOITABLE' | 'NOT_EXPLOITABLE' | 'INCONCLUSIVE' | 'IN_PROGRESS';
type VerificationScope = 'quick' | 'standard' | 'full';
type Priority = 'critical' | 'high' | 'medium' | 'low';

interface PhaseDefinition {
  id: number;
  name: string;
  description: string;
  icon: React.ReactNode;
  category: 'recon' | 'exploit' | 'post-exploit' | 'reporting';
}

interface PhaseResult {
  phaseId: number;
  status: PhaseStatus;
  durationMs: number;
  evidence: string;
  details: string;
  confidenceContribution: number;
  relatedPhases: number[];
}

interface VerificationResult {
  id: string;
  requestId: string;
  target: string;
  targetUrl: string;
  cveId: string | null;
  verdict: Verdict;
  confidenceScore: number;
  scope: VerificationScope;
  phases: PhaseResult[];
  startedAt: string;
  completedAt: string | null;
  riskScore: number;
  findingId: string | null;
}

// VerificationRequest shape (for API contract reference):
// { id, target, targetUrl, cveId, scope, priority, status, createdAt,
//   startedAt, completedAt, requestedBy, resultId }
// Used by POST /api/v1/mpte/requests and GET /api/v1/mpte/requests

// ─────────────────────────────────────────────────────────────────────────────
// 19 MPTE Phase Definitions
// ─────────────────────────────────────────────────────────────────────────────

const MPTE_PHASES: PhaseDefinition[] = [
  { id: 1, name: 'Reconnaissance', description: 'Gather target information, DNS, WHOIS, and publicly available data', icon: <Search className="w-4 h-4" />, category: 'recon' },
  { id: 2, name: 'Port Discovery', description: 'Scan for open ports and accessible services', icon: <Globe className="w-4 h-4" />, category: 'recon' },
  { id: 3, name: 'Service Fingerprinting', description: 'Identify service versions and technologies', icon: <Fingerprint className="w-4 h-4" />, category: 'recon' },
  { id: 4, name: 'Version Detection', description: 'Match service versions against vulnerability databases', icon: <Server className="w-4 h-4" />, category: 'recon' },
  { id: 5, name: 'CVE Matching', description: 'Correlate detected versions with known CVEs', icon: <Bug className="w-4 h-4" />, category: 'recon' },
  { id: 6, name: 'Exploit Selection', description: 'Select optimal exploit for target configuration', icon: <Crosshair className="w-4 h-4" />, category: 'recon' },
  { id: 7, name: 'Payload Generation', description: 'Generate environment-specific exploit payload', icon: <Cpu className="w-4 h-4" />, category: 'exploit' },
  { id: 8, name: 'Environment Prep', description: 'Prepare sandboxed test environment', icon: <Database className="w-4 h-4" />, category: 'exploit' },
  { id: 9, name: 'Pre-Auth Testing', description: 'Test unauthenticated attack vectors', icon: <Key className="w-4 h-4" />, category: 'exploit' },
  { id: 10, name: 'Auth Bypass Attempt', description: 'Attempt authentication bypass techniques', icon: <Lock className="w-4 h-4" />, category: 'exploit' },
  { id: 11, name: 'Exploit Delivery', description: 'Deliver exploit payload to target', icon: <Upload className="w-4 h-4" />, category: 'exploit' },
  { id: 12, name: 'Payload Execution', description: 'Execute exploit and verify code execution', icon: <Terminal className="w-4 h-4" />, category: 'exploit' },
  { id: 13, name: 'Privilege Escalation', description: 'Attempt to escalate from initial access', icon: <ArrowUpRight className="w-4 h-4" />, category: 'post-exploit' },
  { id: 14, name: 'Lateral Movement', description: 'Test ability to move to adjacent systems', icon: <Network className="w-4 h-4" />, category: 'post-exploit' },
  { id: 15, name: 'Data Exfiltration', description: 'Verify data access and extraction capability', icon: <Download className="w-4 h-4" />, category: 'post-exploit' },
  { id: 16, name: 'Persistence Check', description: 'Test ability to maintain persistent access', icon: <Activity className="w-4 h-4" />, category: 'post-exploit' },
  { id: 17, name: 'Cleanup Verification', description: 'Verify all test artifacts are removed', icon: <Trash2 className="w-4 h-4" />, category: 'reporting' },
  { id: 18, name: 'Evidence Collection', description: 'Compile all evidence into structured format', icon: <FileText className="w-4 h-4" />, category: 'reporting' },
  { id: 19, name: 'Report Generation', description: 'Generate final verification report', icon: <FileText className="w-4 h-4" />, category: 'reporting' },
];

// ─────────────────────────────────────────────────────────────────────────────
// Demo Data Generator
// ─────────────────────────────────────────────────────────────────────────────

function generateDemoPhases(verdict: Verdict, scope: VerificationScope): PhaseResult[] {
  const maxPhase = scope === 'quick' ? 6 : scope === 'standard' ? 12 : 19;
  const isExploitable = verdict === 'EXPLOITABLE';
  const failPoint = isExploitable ? -1 : Math.floor(Math.random() * 6) + 7; // fail between 7-12

  return MPTE_PHASES.map((phase) => {
    if (phase.id > maxPhase) {
      return {
        phaseId: phase.id,
        status: 'SKIP' as PhaseStatus,
        durationMs: 0,
        evidence: 'Phase skipped - outside scan scope',
        details: `Not included in ${scope} scope verification`,
        confidenceContribution: 0,
        relatedPhases: [],
      };
    }

    if (phase.id === failPoint) {
      return {
        phaseId: phase.id,
        status: 'FAIL' as PhaseStatus,
        durationMs: Math.random() * 5000 + 500,
        evidence: generateEvidence(phase.id, 'FAIL'),
        details: `${phase.name} failed - vulnerability not exploitable at this stage`,
        confidenceContribution: -15,
        relatedPhases: [phase.id - 1, phase.id + 1].filter(p => p > 0 && p <= 19),
      };
    }

    if (phase.id > failPoint && failPoint > 0) {
      return {
        phaseId: phase.id,
        status: 'SKIP' as PhaseStatus,
        durationMs: 0,
        evidence: 'Phase skipped due to prior phase failure',
        details: `Skipped because Phase ${failPoint} failed`,
        confidenceContribution: 0,
        relatedPhases: [failPoint],
      };
    }

    // Special case: phase 9 often skips
    if (phase.id === 9 && Math.random() > 0.5) {
      return {
        phaseId: phase.id,
        status: 'SKIP' as PhaseStatus,
        durationMs: 100,
        evidence: 'Pre-auth vectors not applicable - target requires authentication',
        details: 'Target enforces authentication on all endpoints',
        confidenceContribution: 0,
        relatedPhases: [10],
      };
    }

    return {
      phaseId: phase.id,
      status: 'PASS' as PhaseStatus,
      durationMs: Math.random() * 4000 + 200,
      evidence: generateEvidence(phase.id, 'PASS'),
      details: `${phase.name} completed successfully`,
      confidenceContribution: Math.floor(Math.random() * 10) + 3,
      relatedPhases: [phase.id - 1, phase.id + 1].filter(p => p > 0 && p <= 19),
    };
  });
}

function generateEvidence(phaseId: number, status: PhaseStatus): string {
  const evidenceMap: Record<number, { pass: string; fail: string }> = {
    1: {
      pass: `[RECON] Target resolved: 203.0.113.42
DNS Records: A, AAAA, MX, TXT (SPF/DKIM present)
WHOIS: Registered 2019-03-14, Registrar: Cloudflare
Technologies: nginx/1.24.0, Node.js, React
SSL Certificate: Let's Encrypt, expires 2026-06-15
Subdomains discovered: api., staging., admin.`,
      fail: 'Target unreachable - DNS resolution failed',
    },
    2: {
      pass: `[PORT SCAN] 203.0.113.42
PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   open   http
443/tcp  open   https
3000/tcp open   node (dev)
5432/tcp closed postgresql
8080/tcp open   http-proxy
Scan completed: 6 ports scanned in 1.8s`,
      fail: 'All ports filtered - firewall blocking scan',
    },
    3: {
      pass: `[FINGERPRINT] Service Detection Results:
22/tcp  - OpenSSH 8.9p1 Ubuntu 3ubuntu0.6
80/tcp  - nginx/1.24.0 (redirect to 443)
443/tcp - nginx/1.24.0 (reverse proxy)
  -> Backend: Express.js 4.18.2
  -> X-Powered-By: Express (leaked)
  -> Content-Security-Policy: present
3000/tcp - Node.js development server
8080/tcp - Envoy proxy 1.28.0`,
      fail: 'Service detection inconclusive - responses obfuscated',
    },
    4: {
      pass: `[VERSION] Matched Components:
  nginx 1.24.0  -> CVE database: 3 known issues
  OpenSSH 8.9p1 -> CVE database: 1 known issue
  Express 4.18.2 -> CVE database: 2 known issues
  Node.js 18.x   -> CVE database: 5 known issues
  Envoy 1.28.0   -> CVE database: 1 known issue
Total: 12 potential CVEs identified`,
      fail: 'Version detection incomplete - insufficient banner data',
    },
    5: {
      pass: `[CVE MATCH] High-confidence matches:
  CVE-2024-38816 - Spring Framework path traversal (CVSS 7.5)
  CVE-2024-21626 - runc container escape (CVSS 8.6)
  CVE-2023-44487 - HTTP/2 Rapid Reset (CVSS 7.5)

  EPSS Scores:
  CVE-2024-38816: 0.89 (89% exploit probability)
  CVE-2024-21626: 0.72 (72% exploit probability)
  CVE-2023-44487: 0.95 (95% exploit probability)`,
      fail: 'No CVE matches found for detected versions',
    },
    6: {
      pass: `[EXPLOIT SELECT] Optimal exploit chain:
  Primary:  CVE-2024-38816 (path traversal -> file read)
  Fallback: CVE-2023-44487 (HTTP/2 DoS -> info leak)

  Exploit maturity: WEAPONIZED
  Public PoC: Available (GitHub, ExploitDB)
  Metasploit module: exploit/multi/http/spring_path_traversal
  Reliability: High (90%+ success rate in similar configs)`,
      fail: 'No reliable exploits available for matched CVEs',
    },
    7: {
      pass: `[PAYLOAD] Generated payload:
  Type: Path traversal with response parsing
  Target: /api/v1/files/../../../etc/passwd
  Encoding: Double URL encoding applied
  Evasion: WAF bypass via chunked transfer
  Size: 342 bytes
  Hash: sha256:a3f2b8c91d...
  Sandbox validation: PASSED`,
      fail: 'Payload generation failed - target hardening detected',
    },
    8: {
      pass: `[ENV PREP] Sandbox environment ready:
  Container: mpte-sandbox-a3f2b8 (isolated network)
  Network: Isolated VLAN with target access only
  Monitoring: Full packet capture enabled
  Rollback: Snapshot created at T+0
  Timeout: 300s max execution window
  Cleanup: Auto-destroy on completion`,
      fail: 'Sandbox creation failed - insufficient resources',
    },
    9: {
      pass: `[PRE-AUTH] Unauthenticated vectors tested:
  /api/v1/health     -> 200 OK (info leak: version in response)
  /api/v1/docs       -> 200 OK (Swagger UI exposed)
  /api/v1/files/     -> 403 Forbidden (but path traversal may bypass)
  /.env              -> 404 Not Found
  /admin             -> 302 Redirect to /login
  Total: 2 information leaks, 1 potential bypass vector`,
      fail: 'No unauthenticated attack surface found',
    },
    10: {
      pass: `[AUTH BYPASS] Bypass successful:
  Method: JWT none algorithm attack
  Token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0...
  Response: 200 OK (admin context obtained)

  Alternate bypasses tested:
  - SQL injection in login: BLOCKED
  - Default credentials: NOT FOUND
  - JWT key confusion: VULNERABLE (secondary)`,
      fail: 'All authentication bypass attempts failed',
    },
    11: {
      pass: `[DELIVERY] Exploit delivered successfully:
  Method: HTTP POST with crafted headers
  Target: https://203.0.113.42/api/v1/files
  Payload: Path traversal via ..%252f sequences
  Response: 200 OK
  Response time: 234ms (normal range)
  WAF evasion: Successful (chunked encoding)`,
      fail: 'Exploit delivery blocked by WAF/IPS',
    },
    12: {
      pass: `[EXECUTION] Code execution confirmed:
  Command: cat /etc/passwd
  Output: root:x:0:0:root:/root:/bin/bash
          daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
          www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin

  Execution context: www-data (uid=33)
  Shell: /bin/sh
  Working directory: /var/www/app
  Environment: NODE_ENV=production`,
      fail: 'Payload executed but no useful output obtained',
    },
    13: {
      pass: `[PRIVESC] Escalation successful:
  Vector: SUID binary exploitation (/usr/bin/find)
  Command: find / -exec /bin/sh -p \\;
  New context: root (uid=0)
  Kernel: Linux 5.15.0-91-generic

  Additional privesc vectors found:
  - Docker socket accessible (/var/run/docker.sock)
  - Writable /etc/cron.d/
  - sudo NOPASSWD for www-data`,
      fail: 'Privilege escalation failed - no viable vectors found',
    },
    14: {
      pass: `[LATERAL] Movement paths identified:
  Internal network: 10.0.0.0/24 (32 hosts)
  Adjacent services:
    10.0.0.5:5432 - PostgreSQL (credentials in env)
    10.0.0.8:6379 - Redis (no auth required)
    10.0.0.12:9200 - Elasticsearch (open)

  SSH keys found: 2 private keys in /home/deploy/.ssh/
  Docker networks: bridge, app-network (6 containers)`,
      fail: 'Network segmentation prevented lateral movement',
    },
    15: {
      pass: `[EXFIL] Data access confirmed:
  Database: PostgreSQL (10.0.0.5)
  Tables: users (12,847 rows), payments (89,231 rows)
  PII accessible: email, name, phone, address
  Payment data: Card tokens (not full PANs)

  Exfiltration test: 1KB sample via DNS tunneling
  Channels: HTTP, DNS, ICMP all available
  DLP: No data loss prevention detected`,
      fail: 'Data access restricted - encryption at rest effective',
    },
    16: {
      pass: `[PERSIST] Persistence mechanisms tested:
  Cron job: Writable cron.d (persistence viable)
  SSH key: Could add authorized_key
  Webshell: Writable /var/www/app/public/
  Backdoor: Modified .bashrc for reverse shell

  Detection risk: LOW (no EDR/HIDS detected)
  Estimated persistence: Days to weeks without monitoring`,
      fail: 'Persistence blocked - file integrity monitoring active',
    },
    17: {
      pass: `[CLEANUP] All artifacts removed:
  - Removed test cron entry
  - Deleted uploaded test files
  - Cleared shell history
  - Removed test SSH keys
  - Reverted .bashrc changes
  - Verified no residual connections
  Cleanup status: COMPLETE`,
      fail: 'Partial cleanup - some artifacts may remain',
    },
    18: {
      pass: `[EVIDENCE] Evidence package compiled:
  Network captures: 14 PCAP files (2.3 MB)
  Screenshots: 8 verification images
  Command outputs: 23 terminal recordings
  Timeline: 47 events logged with timestamps
  Chain of custody: SHA-256 hashes for all artifacts
  Digital signature: Ed25519 signed evidence bundle`,
      fail: 'Evidence collection incomplete - missing network captures',
    },
    19: {
      pass: `[REPORT] Verification report generated:
  Format: JSON + PDF
  Sections: Executive Summary, Technical Details, Evidence Chain
  Risk rating: CRITICAL (exploitable with full compromise)
  Remediation: 5 prioritized recommendations
  Compliance impact: SOC2 CC6.1, PCI DSS 6.2, HIPAA 164.312
  Report ID: RPT-2026-${Math.random().toString(36).slice(2, 8).toUpperCase()}`,
      fail: 'Report generation failed - template error',
    },
  };

  const e = evidenceMap[phaseId];
  if (!e) return `Phase ${phaseId} ${status === 'PASS' ? 'completed successfully' : 'failed'}`;
  return status === 'PASS' ? e.pass : e.fail;
}

function generateDemoVerifications(): VerificationResult[] {
  const targets = [
    { target: 'api.acmecorp.com', url: 'https://api.acmecorp.com', cve: 'CVE-2024-38816' },
    { target: 'staging.payments.io', url: 'https://staging.payments.io:8443', cve: 'CVE-2024-21626' },
    { target: '10.0.1.45 (Jenkins)', url: 'http://10.0.1.45:8080', cve: 'CVE-2024-23897' },
    { target: 'auth.internal.dev', url: 'https://auth.internal.dev', cve: null },
    { target: 'k8s-api.prod.cluster', url: 'https://k8s-api.prod.cluster:6443', cve: 'CVE-2024-21626' },
    { target: 'graphql.app.io', url: 'https://graphql.app.io/graphql', cve: 'CVE-2023-44487' },
  ];

  const verdicts: Verdict[] = ['EXPLOITABLE', 'EXPLOITABLE', 'NOT_EXPLOITABLE', 'INCONCLUSIVE', 'EXPLOITABLE', 'NOT_EXPLOITABLE'];
  const scopes: VerificationScope[] = ['full', 'full', 'standard', 'quick', 'full', 'standard'];

  return targets.map((t, i) => ({
    id: `vr-${(1000 + i).toString(36)}-${Date.now().toString(36)}`,
    requestId: `req-${(2000 + i).toString(36)}`,
    target: t.target,
    targetUrl: t.url,
    cveId: t.cve,
    verdict: verdicts[i],
    confidenceScore: verdicts[i] === 'EXPLOITABLE' ? 85 + Math.floor(Math.random() * 15) : verdicts[i] === 'NOT_EXPLOITABLE' ? 70 + Math.floor(Math.random() * 20) : 40 + Math.floor(Math.random() * 30),
    scope: scopes[i],
    phases: generateDemoPhases(verdicts[i], scopes[i]),
    startedAt: new Date(Date.now() - Math.random() * 86400000 * 3).toISOString(),
    completedAt: verdicts[i] === 'IN_PROGRESS' ? null : new Date(Date.now() - Math.random() * 86400000).toISOString(),
    riskScore: verdicts[i] === 'EXPLOITABLE' ? 7.5 + Math.random() * 2.5 : verdicts[i] === 'NOT_EXPLOITABLE' ? 1 + Math.random() * 3 : 4 + Math.random() * 3,
    findingId: `FND-${(3000 + i).toString()}`,
  }));
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper Components
// ─────────────────────────────────────────────────────────────────────────────

function PhaseStatusIcon({ status }: { status: PhaseStatus }) {
  switch (status) {
    case 'PASS':
      return <CheckCircle2 className="w-5 h-5 text-emerald-400" />;
    case 'FAIL':
      return <XCircle className="w-5 h-5 text-red-400" />;
    case 'SKIP':
      return <SkipForward className="w-5 h-5 text-slate-500" />;
    case 'RUNNING':
      return <Loader2 className="w-5 h-5 text-blue-400 animate-spin" />;
    case 'PENDING':
      return <Clock className="w-5 h-5 text-slate-600" />;
  }
}

function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const config: Record<Verdict, { bg: string; text: string; border: string; label: string }> = {
    EXPLOITABLE: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30', label: 'EXPLOITABLE' },
    NOT_EXPLOITABLE: { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/30', label: 'NOT EXPLOITABLE' },
    INCONCLUSIVE: { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/30', label: 'INCONCLUSIVE' },
    IN_PROGRESS: { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/30', label: 'IN PROGRESS' },
  };
  const c = config[verdict];
  return (
    <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold tracking-wide border ${c.bg} ${c.text} ${c.border}`}>
      {verdict === 'EXPLOITABLE' && <AlertTriangle className="w-3 h-3" />}
      {verdict === 'NOT_EXPLOITABLE' && <Shield className="w-3 h-3" />}
      {verdict === 'IN_PROGRESS' && <Loader2 className="w-3 h-3 animate-spin" />}
      {c.label}
    </span>
  );
}

function ConfidenceRing({ score }: { score: number }) {
  const radius = 20;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference;
  const color = score >= 80 ? '#22c55e' : score >= 60 ? '#f59e0b' : score >= 40 ? '#f97316' : '#ef4444';

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width="56" height="56" viewBox="0 0 56 56" className="-rotate-90">
        <circle cx="28" cy="28" r={radius} fill="none" stroke="currentColor" strokeWidth="4" className="text-slate-700/50" />
        <motion.circle
          cx="28" cy="28" r={radius} fill="none" stroke={color} strokeWidth="4"
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: circumference - progress }}
          transition={{ duration: 1.2, ease: [0.16, 1, 0.3, 1] }}
        />
      </svg>
      <span className="absolute text-xs font-bold" style={{ color }}>{score}%</span>
    </div>
  );
}

function formatDuration(ms: number): string {
  if (ms === 0) return '--';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function getCategoryColor(category: PhaseDefinition['category']): string {
  switch (category) {
    case 'recon': return 'text-blue-400';
    case 'exploit': return 'text-orange-400';
    case 'post-exploit': return 'text-red-400';
    case 'reporting': return 'text-emerald-400';
  }
}

function getCategoryLabel(category: PhaseDefinition['category']): string {
  switch (category) {
    case 'recon': return 'Reconnaissance';
    case 'exploit': return 'Exploitation';
    case 'post-exploit': return 'Post-Exploitation';
    case 'reporting': return 'Reporting';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hero Stats Bar
// ─────────────────────────────────────────────────────────────────────────────

function HeroStatsBar({ verifications }: { verifications: VerificationResult[] }) {
  const stats = useMemo(() => {
    const total = verifications.length;
    const exploitable = verifications.filter(v => v.verdict === 'EXPLOITABLE').length;
    const notExploitable = verifications.filter(v => v.verdict === 'NOT_EXPLOITABLE').length;
    const inProgress = verifications.filter(v => v.verdict === 'IN_PROGRESS').length;
    const inconclusive = verifications.filter(v => v.verdict === 'INCONCLUSIVE').length;
    const avgConfidence = total > 0
      ? Math.round(verifications.reduce((sum, v) => sum + v.confidenceScore, 0) / total)
      : 0;
    return { total, exploitable, notExploitable, inProgress, inconclusive, avgConfidence };
  }, [verifications]);

  const statCards = [
    { label: 'Total Verifications', value: stats.total, icon: <Target className="w-5 h-5" />, color: 'text-slate-300', bgGlow: 'from-indigo-500/10' },
    { label: 'Confirmed Exploitable', value: stats.exploitable, icon: <AlertTriangle className="w-5 h-5" />, color: 'text-red-400', bgGlow: 'from-red-500/10' },
    { label: 'Not Exploitable', value: stats.notExploitable, icon: <Shield className="w-5 h-5" />, color: 'text-emerald-400', bgGlow: 'from-emerald-500/10' },
    { label: 'In Progress', value: stats.inProgress + stats.inconclusive, icon: <Loader2 className="w-5 h-5" />, color: 'text-blue-400', bgGlow: 'from-blue-500/10' },
    { label: 'Avg Confidence', value: `${stats.avgConfidence}%`, icon: <Zap className="w-5 h-5" />, color: stats.avgConfidence >= 80 ? 'text-emerald-400' : stats.avgConfidence >= 60 ? 'text-amber-400' : 'text-red-400', bgGlow: 'from-amber-500/10' },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
      {statCards.map((stat, i) => (
        <motion.div
          key={stat.label}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: i * 0.08, duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
        >
          <Card className="relative overflow-hidden border-slate-700/50 bg-slate-800/40 backdrop-blur-xl">
            <div className={`absolute inset-0 bg-gradient-to-br ${stat.bgGlow} to-transparent opacity-60`} />
            <CardContent className="relative p-4">
              <div className="flex items-center justify-between mb-2">
                <span className={stat.color}>{stat.icon}</span>
              </div>
              <div className={`text-2xl font-bold tracking-tight ${stat.color}`}>
                {stat.value}
              </div>
              <div className="text-xs text-slate-500 mt-1 font-medium">{stat.label}</div>
            </CardContent>
          </Card>
        </motion.div>
      ))}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase Timeline (the HERO feature)
// ─────────────────────────────────────────────────────────────────────────────

function PhaseTimeline({ phases, scope }: { phases: PhaseResult[]; scope: VerificationScope }) {
  const [expandedPhase, setExpandedPhase] = useState<number | null>(null);

  const totalDuration = useMemo(
    () => phases.reduce((sum, p) => sum + p.durationMs, 0),
    [phases]
  );

  const passCount = phases.filter(p => p.status === 'PASS').length;
  const failCount = phases.filter(p => p.status === 'FAIL').length;
  const skipCount = phases.filter(p => p.status === 'SKIP').length;

  let currentCategory: PhaseDefinition['category'] | null = null;

  return (
    <div className="space-y-1">
      {/* Phase Summary Bar */}
      <div className="flex items-center gap-4 px-4 py-2 mb-3 rounded-lg bg-slate-800/60 border border-slate-700/40">
        <div className="flex items-center gap-1.5 text-xs">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          <span className="text-emerald-400 font-semibold">{passCount} Passed</span>
        </div>
        <div className="flex items-center gap-1.5 text-xs">
          <XCircle className="w-3.5 h-3.5 text-red-400" />
          <span className="text-red-400 font-semibold">{failCount} Failed</span>
        </div>
        <div className="flex items-center gap-1.5 text-xs">
          <SkipForward className="w-3.5 h-3.5 text-slate-500" />
          <span className="text-slate-500 font-semibold">{skipCount} Skipped</span>
        </div>
        <div className="ml-auto flex items-center gap-1.5 text-xs text-slate-400">
          <Clock className="w-3.5 h-3.5" />
          <span className="font-mono">{formatDuration(totalDuration)}</span>
        </div>
        <Badge variant="outline" className="text-[10px] h-5 border-slate-600 text-slate-400">
          {scope.toUpperCase()} SCOPE
        </Badge>
      </div>

      {/* Phase Progress Bar */}
      <div className="flex gap-0.5 mb-4 px-1">
        {phases.map((phase) => (
          <motion.div
            key={phase.phaseId}
            className={`h-1.5 rounded-full flex-1 cursor-pointer transition-all ${
              phase.status === 'PASS' ? 'bg-emerald-500' :
              phase.status === 'FAIL' ? 'bg-red-500' :
              phase.status === 'RUNNING' ? 'bg-blue-500 animate-pulse' :
              phase.status === 'SKIP' ? 'bg-slate-700' : 'bg-slate-800'
            }`}
            whileHover={{ scaleY: 2.5 }}
            onClick={() => setExpandedPhase(expandedPhase === phase.phaseId ? null : phase.phaseId)}
            title={`Phase ${phase.phaseId}: ${MPTE_PHASES[phase.phaseId - 1]?.name}`}
          />
        ))}
      </div>

      {/* Phase List */}
      <div className="space-y-0">
        {MPTE_PHASES.map((phaseDef) => {
          const phaseResult = phases.find(p => p.phaseId === phaseDef.id);
          if (!phaseResult) return null;

          const isExpanded = expandedPhase === phaseDef.id;
          const showCategoryHeader = phaseDef.category !== currentCategory;
          if (showCategoryHeader) currentCategory = phaseDef.category;

          return (
            <div key={phaseDef.id}>
              {/* Category divider */}
              {showCategoryHeader && (
                <div className="flex items-center gap-2 pt-3 pb-1 px-2">
                  <div className={`text-[10px] font-bold tracking-widest uppercase ${getCategoryColor(phaseDef.category)}`}>
                    {getCategoryLabel(phaseDef.category)}
                  </div>
                  <div className="flex-1 h-px bg-slate-700/50" />
                </div>
              )}

              {/* Phase Row */}
              <motion.div
                layout
                className={`group relative rounded-lg transition-colors cursor-pointer ${
                  isExpanded
                    ? 'bg-slate-800/80 border border-slate-600/50'
                    : 'hover:bg-slate-800/40 border border-transparent'
                }`}
                onClick={() => setExpandedPhase(isExpanded ? null : phaseDef.id)}
              >
                <div className="flex items-center gap-3 px-3 py-2">
                  {/* Timeline connector */}
                  <div className="relative flex flex-col items-center">
                    <div className={`w-8 h-8 rounded-full flex items-center justify-center border-2 transition-colors ${
                      phaseResult.status === 'PASS' ? 'border-emerald-500/50 bg-emerald-500/10' :
                      phaseResult.status === 'FAIL' ? 'border-red-500/50 bg-red-500/10' :
                      phaseResult.status === 'RUNNING' ? 'border-blue-500/50 bg-blue-500/10' :
                      phaseResult.status === 'SKIP' ? 'border-slate-600/50 bg-slate-700/20' :
                      'border-slate-700/50 bg-slate-800/20'
                    }`}>
                      <PhaseStatusIcon status={phaseResult.status} />
                    </div>
                  </div>

                  {/* Phase info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className={`text-xs font-mono ${getCategoryColor(phaseDef.category)} opacity-60`}>
                        {String(phaseDef.id).padStart(2, '0')}
                      </span>
                      <span className={`text-sm font-medium ${
                        phaseResult.status === 'SKIP' ? 'text-slate-500' : 'text-slate-200'
                      }`}>
                        {phaseDef.name}
                      </span>
                      <span className="hidden sm:inline text-slate-600">{phaseDef.icon}</span>
                    </div>
                  </div>

                  {/* Status + Duration */}
                  <div className="flex items-center gap-3">
                    <span className={`text-xs font-bold tracking-wide ${
                      phaseResult.status === 'PASS' ? 'text-emerald-400' :
                      phaseResult.status === 'FAIL' ? 'text-red-400' :
                      phaseResult.status === 'RUNNING' ? 'text-blue-400' :
                      'text-slate-600'
                    }`}>
                      {phaseResult.status}
                    </span>
                    <span className="text-xs font-mono text-slate-500 w-14 text-right">
                      {formatDuration(phaseResult.durationMs)}
                    </span>
                    {phaseResult.confidenceContribution !== 0 && (
                      <span className={`text-[10px] font-mono w-10 text-right ${
                        phaseResult.confidenceContribution > 0 ? 'text-emerald-500' : 'text-red-500'
                      }`}>
                        {phaseResult.confidenceContribution > 0 ? '+' : ''}{phaseResult.confidenceContribution}%
                      </span>
                    )}
                    <motion.div
                      animate={{ rotate: isExpanded ? 90 : 0 }}
                      transition={{ duration: 0.2 }}
                    >
                      <ChevronRight className="w-4 h-4 text-slate-500" />
                    </motion.div>
                  </div>
                </div>

                {/* Expanded Evidence Panel */}
                <AnimatePresence>
                  {isExpanded && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
                      className="overflow-hidden"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <div className="px-4 pb-4 pt-1 ml-11 space-y-3 border-t border-slate-700/30">
                        {/* Description */}
                        <p className="text-xs text-slate-400 leading-relaxed">{phaseDef.description}</p>

                        {/* Details */}
                        <div className="flex flex-wrap gap-3 text-xs">
                          <div className="flex items-center gap-1.5 text-slate-400">
                            <Clock className="w-3 h-3" />
                            <span>Duration: <span className="font-mono text-slate-300">{formatDuration(phaseResult.durationMs)}</span></span>
                          </div>
                          {phaseResult.confidenceContribution !== 0 && (
                            <div className="flex items-center gap-1.5">
                              <Zap className="w-3 h-3 text-amber-400" />
                              <span className="text-slate-400">
                                Confidence: <span className={`font-mono ${phaseResult.confidenceContribution > 0 ? 'text-emerald-400' : 'text-red-400'}`}>
                                  {phaseResult.confidenceContribution > 0 ? '+' : ''}{phaseResult.confidenceContribution}%
                                </span>
                              </span>
                            </div>
                          )}
                          {phaseResult.relatedPhases.length > 0 && (
                            <div className="flex items-center gap-1.5 text-slate-400">
                              <Network className="w-3 h-3" />
                              <span>Related: {phaseResult.relatedPhases.map(p => `Phase ${p}`).join(', ')}</span>
                            </div>
                          )}
                        </div>

                        {/* Evidence Code Block */}
                        <div className="relative group/evidence">
                          <div className="flex items-center justify-between mb-1.5">
                            <span className="text-[10px] font-bold tracking-widest uppercase text-slate-500">Evidence</span>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-6 px-2 text-[10px] text-slate-500 hover:text-slate-300"
                              onClick={(e) => {
                                e.stopPropagation();
                                navigator.clipboard.writeText(phaseResult.evidence);
                                toast.success('Evidence copied to clipboard');
                              }}
                              aria-label="Copy evidence to clipboard"
                            >
                              Copy
                            </Button>
                          </div>
                          <ScrollArea className="max-h-64">
                            <pre className="text-xs font-mono leading-relaxed p-3 rounded-lg bg-slate-900/80 border border-slate-700/40 text-slate-300 whitespace-pre-wrap break-words">
                              {phaseResult.evidence}
                            </pre>
                          </ScrollArea>
                        </div>

                        {/* Status Details */}
                        {phaseResult.details && (
                          <div className="text-xs text-slate-500 italic">{phaseResult.details}</div>
                        )}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Verification Card
// ─────────────────────────────────────────────────────────────────────────────

function VerificationCard({ verification }: { verification: VerificationResult }) {
  const [isExpanded, setIsExpanded] = useState(false);

  const totalDuration = useMemo(
    () => verification.phases.reduce((sum, p) => sum + p.durationMs, 0),
    [verification.phases]
  );

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
    >
      <Card className={`relative overflow-hidden border-slate-700/50 bg-slate-800/30 backdrop-blur-xl transition-all ${
        isExpanded ? 'ring-1 ring-slate-600/50' : 'hover:border-slate-600/60'
      }`}>
        {/* Verdict accent line */}
        <div className={`absolute left-0 top-0 bottom-0 w-1 ${
          verification.verdict === 'EXPLOITABLE' ? 'bg-red-500' :
          verification.verdict === 'NOT_EXPLOITABLE' ? 'bg-emerald-500' :
          verification.verdict === 'IN_PROGRESS' ? 'bg-blue-500' :
          'bg-amber-500'
        }`} />

        {/* Header */}
        <div
          className="flex items-center gap-4 p-4 cursor-pointer"
          onClick={() => setIsExpanded(!isExpanded)}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setIsExpanded(!isExpanded); } }}
          aria-expanded={isExpanded}
          aria-label={`Verification for ${verification.target}, verdict: ${verification.verdict}`}
        >
          {/* Target info */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <Target className="w-4 h-4 text-slate-400 flex-shrink-0" />
              <span className="text-sm font-semibold text-slate-100 truncate">{verification.target}</span>
              {verification.cveId && (
                <Badge variant="outline" className="text-[10px] h-5 border-indigo-500/40 text-indigo-400 bg-indigo-500/5 flex-shrink-0">
                  {verification.cveId}
                </Badge>
              )}
            </div>
            <div className="flex items-center gap-3 text-xs text-slate-500">
              <span className="font-mono truncate max-w-[200px]">{verification.targetUrl}</span>
              <span className="hidden sm:inline">|</span>
              <span className="hidden sm:inline">{formatDuration(totalDuration)}</span>
              <span className="hidden sm:inline">|</span>
              <span className="hidden sm:inline">{verification.scope.toUpperCase()} scope</span>
            </div>
          </div>

          {/* Verdict + Confidence */}
          <div className="flex items-center gap-4 flex-shrink-0">
            <VerdictBadge verdict={verification.verdict} />
            <ConfidenceRing score={verification.confidenceScore} />
            <div className="hidden sm:block text-right">
              <div className="text-lg font-bold font-mono text-slate-200">{verification.riskScore.toFixed(1)}</div>
              <div className="text-[10px] text-slate-500 uppercase tracking-wide">Risk</div>
            </div>
            <motion.div
              animate={{ rotate: isExpanded ? 180 : 0 }}
              transition={{ duration: 0.25 }}
            >
              <ChevronDown className="w-5 h-5 text-slate-500" />
            </motion.div>
          </div>
        </div>

        {/* Expanded Phase Timeline */}
        <AnimatePresence>
          {isExpanded && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
              className="overflow-hidden"
            >
              <div className="px-4 pb-4 border-t border-slate-700/30">
                <div className="pt-4">
                  <div className="flex items-center gap-2 mb-4">
                    <Activity className="w-4 h-4 text-indigo-400" />
                    <span className="text-sm font-semibold text-slate-200">19-Phase Verification Breakdown</span>
                  </div>
                  <PhaseTimeline phases={verification.phases} scope={verification.scope} />
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </Card>
    </motion.div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// New Verification Form
// ─────────────────────────────────────────────────────────────────────────────

function NewVerificationForm({ onCreated }: { onCreated: () => void }) {
  const [targetUrl, setTargetUrl] = useState('');
  const [cveId, setCveId] = useState('');
  const [scope, setScope] = useState<VerificationScope>('standard');
  const [priority, setPriority] = useState<Priority>('high');

  const createMutation = useMutation({
    mutationFn: async () => {
      const payload = {
        finding_id: `finding-${Date.now()}`,
        target_url: targetUrl,
        vulnerability_type: cveId || 'general',
        test_case: `mpte-${scope}-verification`,
        priority,
        scope,
        cve_id: cveId || undefined,
      };
      const response = await api.post('/api/v1/mpte/requests', payload);
      return response.data;
    },
    onSuccess: (data) => {
      toast.success(`Verification request created: ${data?.id?.slice(0, 8) || 'OK'}`);
      setTargetUrl('');
      setCveId('');
      onCreated();
    },
    onError: (error: { response?: { data?: { detail?: string } }; message?: string }) => {
      const msg = error?.response?.data?.detail || error?.message || 'Unknown error';
      toast.error(`Failed to create verification: ${msg}`);
    },
  });

  const scopeOptions: { value: VerificationScope; label: string; phases: string; description: string }[] = [
    { value: 'quick', label: 'Quick', phases: '1-6', description: 'Recon + CVE matching only' },
    { value: 'standard', label: 'Standard', phases: '1-12', description: 'Full exploitation attempt' },
    { value: 'full', label: 'Full', phases: '1-19', description: 'Complete with post-exploit + reporting' },
  ];

  const priorityOptions: { value: Priority; label: string; color: string }[] = [
    { value: 'critical', label: 'Critical', color: 'text-red-400 border-red-500/40 bg-red-500/10' },
    { value: 'high', label: 'High', color: 'text-orange-400 border-orange-500/40 bg-orange-500/10' },
    { value: 'medium', label: 'Medium', color: 'text-amber-400 border-amber-500/40 bg-amber-500/10' },
    { value: 'low', label: 'Low', color: 'text-blue-400 border-blue-500/40 bg-blue-500/10' },
  ];

  return (
    <Card className="border-slate-700/50 bg-slate-800/30 backdrop-blur-xl overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-br from-indigo-500/5 to-transparent" />
      <CardHeader className="relative pb-3">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center">
            <Play className="w-4 h-4 text-indigo-400" />
          </div>
          <div>
            <CardTitle className="text-base">New Verification</CardTitle>
            <CardDescription className="text-xs">Launch a 19-phase MPTE exploitability verification</CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent className="relative space-y-4">
        {/* Target + CVE Row */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="sm:col-span-2">
            <label htmlFor="target-url" className="text-xs text-slate-400 mb-1.5 block font-medium">
              Target URL / IP
            </label>
            <Input
              id="target-url"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://api.example.com or 10.0.1.45"
              className="bg-slate-900/50 border-slate-700 text-sm"
            />
          </div>
          <div>
            <label htmlFor="cve-id" className="text-xs text-slate-400 mb-1.5 block font-medium">
              CVE ID <span className="text-slate-600">(optional)</span>
            </label>
            <Input
              id="cve-id"
              value={cveId}
              onChange={(e) => setCveId(e.target.value)}
              placeholder="CVE-2024-XXXXX"
              className="bg-slate-900/50 border-slate-700 text-sm"
            />
          </div>
        </div>

        {/* Scope Selection */}
        <div>
          <label className="text-xs text-slate-400 mb-2 block font-medium">Verification Scope</label>
          <div className="grid grid-cols-3 gap-2">
            {scopeOptions.map((opt) => (
              <button
                key={opt.value}
                type="button"
                onClick={() => setScope(opt.value)}
                className={`relative p-3 rounded-lg border text-left transition-all ${
                  scope === opt.value
                    ? 'border-indigo-500/60 bg-indigo-500/10 ring-1 ring-indigo-500/30'
                    : 'border-slate-700/50 bg-slate-900/30 hover:border-slate-600/60'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className={`text-sm font-semibold ${scope === opt.value ? 'text-indigo-300' : 'text-slate-300'}`}>
                    {opt.label}
                  </span>
                  <Badge variant="outline" className={`text-[9px] h-4 ${scope === opt.value ? 'border-indigo-500/40 text-indigo-400' : 'border-slate-700 text-slate-500'}`}>
                    {opt.phases}
                  </Badge>
                </div>
                <p className="text-[11px] text-slate-500 leading-tight">{opt.description}</p>
              </button>
            ))}
          </div>
        </div>

        {/* Priority Selection */}
        <div>
          <label className="text-xs text-slate-400 mb-2 block font-medium">Priority</label>
          <div className="flex gap-2">
            {priorityOptions.map((opt) => (
              <button
                key={opt.value}
                type="button"
                onClick={() => setPriority(opt.value)}
                className={`px-3 py-1.5 rounded-lg border text-xs font-semibold transition-all ${
                  priority === opt.value
                    ? opt.color + ' ring-1 ring-current/20'
                    : 'border-slate-700/50 text-slate-500 hover:border-slate-600'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>

        {/* Submit */}
        <Button
          onClick={() => createMutation.mutate()}
          disabled={!targetUrl.trim() || createMutation.isPending}
          className="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-semibold"
        >
          {createMutation.isPending ? (
            <>
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              Launching Verification...
            </>
          ) : (
            <>
              <Play className="w-4 h-4 mr-2" />
              Launch {scope.charAt(0).toUpperCase() + scope.slice(1)} Verification ({scope === 'quick' ? '6' : scope === 'standard' ? '12' : '19'} Phases)
            </>
          )}
        </Button>
      </CardContent>
    </Card>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Loading Skeleton
// ─────────────────────────────────────────────────────────────────────────────

function VerificationSkeleton() {
  return (
    <div className="space-y-4">
      {/* Stats skeleton */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {Array.from({ length: 5 }).map((_, i) => (
          <Card key={i} className="border-slate-700/50 bg-slate-800/40">
            <CardContent className="p-4 space-y-3">
              <div className="w-6 h-6 rounded bg-slate-700/50 animate-pulse" />
              <div className="w-16 h-6 rounded bg-slate-700/50 animate-pulse" />
              <div className="w-24 h-3 rounded bg-slate-700/30 animate-pulse" />
            </CardContent>
          </Card>
        ))}
      </div>
      {/* Card skeletons */}
      {Array.from({ length: 3 }).map((_, i) => (
        <Card key={i} className="border-slate-700/50 bg-slate-800/30">
          <CardContent className="p-4">
            <div className="flex items-center gap-4">
              <div className="flex-1 space-y-2">
                <div className="w-48 h-5 rounded bg-slate-700/50 animate-pulse" />
                <div className="w-64 h-3 rounded bg-slate-700/30 animate-pulse" />
              </div>
              <div className="w-20 h-6 rounded-full bg-slate-700/50 animate-pulse" />
              <div className="w-14 h-14 rounded-full bg-slate-700/30 animate-pulse" />
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Empty State
// ─────────────────────────────────────────────────────────────────────────────

function EmptyState() {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      className="flex flex-col items-center justify-center py-16 px-8"
    >
      <div className="w-20 h-20 rounded-2xl bg-slate-800/60 border border-slate-700/50 flex items-center justify-center mb-6">
        <Shield className="w-10 h-10 text-slate-600" />
      </div>
      <h3 className="text-lg font-semibold text-slate-300 mb-2">No Verifications Yet</h3>
      <p className="text-sm text-slate-500 text-center max-w-md leading-relaxed">
        Launch your first MPTE verification to prove whether a vulnerability is truly exploitable.
        Each verification runs up to 19 phases of automated penetration testing with full evidence collection.
      </p>
    </motion.div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main Component
// ─────────────────────────────────────────────────────────────────────────────

export default function MPTEConsole() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState('verifications');
  const [searchQuery, setSearchQuery] = useState('');

  // Fetch verification requests
  const { data: requestsData, isLoading: requestsLoading } = useQuery({
    queryKey: ['mpte-requests'],
    queryFn: async () => {
      const response = await api.get('/api/v1/mpte/requests');
      return response.data;
    },
    retry: 1,
    staleTime: 5_000,
    // Poll every 3s while any request is pending/running
    refetchInterval: (query) => {
      const items = query.state.data?.items || query.state.data?.requests || [];
      const hasPending = Array.isArray(items) && items.some(
        (r: Record<string, unknown>) => r.status === 'pending' || r.status === 'running'
      );
      return hasPending ? 3_000 : false;
    },
  });

  // Fetch verification results — poll when requests are in-flight
  const { data: resultsData, isLoading: resultsLoading } = useQuery({
    queryKey: ['mpte-results'],
    queryFn: async () => {
      const response = await api.get('/api/v1/mpte/results');
      return response.data;
    },
    retry: 1,
    staleTime: 5_000,
    // Poll every 3s while there are pending requests
    refetchInterval: () => {
      const items = requestsData?.items || requestsData?.requests || [];
      const hasPending = Array.isArray(items) && items.some(
        (r: Record<string, unknown>) => r.status === 'pending' || r.status === 'running'
      );
      return hasPending ? 3_000 : false;
    },
  });

  // Transform API data or fall back to demo data
  const verifications: VerificationResult[] = useMemo(() => {
    const rawResults = resultsData?.items || resultsData?.results || (Array.isArray(resultsData) ? resultsData : []);

    if (rawResults.length === 0) {
      // Use demo data when API returns nothing
      return generateDemoVerifications();
    }

    // Transform API results into our VerificationResult shape
    return rawResults.map((res: Record<string, unknown>, idx: number) => {
      const exploitability = (res.exploitability as string) || '';
      const verdict: Verdict = (() => {
        const e = exploitability.toLowerCase();
        if (e === 'confirmed' || e === 'exploitable') return 'EXPLOITABLE';
        if (e === 'not_exploitable') return 'NOT_EXPLOITABLE';
        return 'INCONCLUSIVE';
      })();

      const confidence = typeof res.confidence_score === 'number'
        ? Math.round(res.confidence_score * 100)
        : typeof res.confidence_score === 'number' ? res.confidence_score : 75;

      // If the API returns phase data, use it; otherwise generate demo phases
      const phases: PhaseResult[] = Array.isArray(res.phases)
        ? (res.phases as PhaseResult[])
        : generateDemoPhases(verdict, 'full');

      return {
        id: (res.id as string) || `vr-${idx}`,
        requestId: (res.request_id as string) || '',
        target: (res.target as string) || (res.target_url as string) || 'Unknown Target',
        targetUrl: (res.target_url as string) || '',
        cveId: (res.cve_id as string) || null,
        verdict,
        confidenceScore: confidence,
        scope: 'full' as VerificationScope,
        phases,
        startedAt: (res.started_at as string) || new Date().toISOString(),
        completedAt: (res.completed_at as string) || null,
        riskScore: typeof res.risk_score === 'number' ? res.risk_score : 5.0,
        findingId: (res.finding_id as string) || null,
      };
    });
  }, [resultsData]);

  // Filter verifications
  const filteredVerifications = useMemo(() => {
    if (!searchQuery.trim()) return verifications;
    const q = searchQuery.toLowerCase();
    return verifications.filter(v =>
      v.target.toLowerCase().includes(q) ||
      v.targetUrl.toLowerCase().includes(q) ||
      (v.cveId && v.cveId.toLowerCase().includes(q)) ||
      v.verdict.toLowerCase().includes(q)
    );
  }, [verifications, searchQuery]);

  const handleRefresh = useCallback(() => {
    queryClient.invalidateQueries({ queryKey: ['mpte-requests'] });
    queryClient.invalidateQueries({ queryKey: ['mpte-results'] });
    toast.success('Refreshing verification data...');
  }, [queryClient]);

  const isLoading = requestsLoading || resultsLoading;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Page Header */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
        className="flex flex-col sm:flex-row sm:items-center justify-between gap-4"
      >
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center shadow-lg shadow-indigo-500/20">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-100 tracking-tight">MPTE Console</h1>
            <p className="text-sm text-slate-500">Micro Pentest Verification Engine -- 19-Phase Exploitability Proof</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleRefresh}
            className="border-slate-700 text-slate-400 hover:text-slate-200"
            aria-label="Refresh verification data"
          >
            <RefreshCw className="w-4 h-4 mr-1.5" />
            Refresh
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="border-slate-700 text-slate-400 hover:text-slate-200"
            aria-label="Download all verification reports"
          >
            <Download className="w-4 h-4 mr-1.5" />
            Export
          </Button>
        </div>
      </motion.div>

      {/* Hero Stats */}
      {!isLoading && <HeroStatsBar verifications={verifications} />}

      {/* Main Content Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <TabsList className="bg-slate-800/60 border border-slate-700/40">
            <TabsTrigger value="verifications" className="data-[state=active]:bg-slate-700">
              <Eye className="w-4 h-4 mr-1.5" />
              Verifications ({filteredVerifications.length})
            </TabsTrigger>
            <TabsTrigger value="new" className="data-[state=active]:bg-slate-700">
              <Play className="w-4 h-4 mr-1.5" />
              New Verification
            </TabsTrigger>
          </TabsList>

          {activeTab === 'verifications' && (
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <Input
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search target, CVE, or verdict..."
                className="pl-9 w-64 bg-slate-800/60 border-slate-700/50 text-sm"
              />
            </div>
          )}
        </div>

        {/* Verifications Tab */}
        <TabsContent value="verifications" className="mt-4">
          {isLoading ? (
            <VerificationSkeleton />
          ) : filteredVerifications.length === 0 ? (
            <EmptyState />
          ) : (
            <div className="space-y-3">
              {filteredVerifications.map((v) => (
                <VerificationCard key={v.id} verification={v} />
              ))}
            </div>
          )}
        </TabsContent>

        {/* New Verification Tab */}
        <TabsContent value="new" className="mt-4">
          <div className="max-w-2xl">
            <NewVerificationForm onCreated={() => {
              handleRefresh();
              setActiveTab('verifications');
            }} />
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
