import { useLocation, useNavigate } from 'react-router-dom';
import { ChevronRight, Home } from 'lucide-react';

// Route-to-label mapping for human-readable breadcrumbs
const routeLabels: Record<string, string> = {
  '/': 'Command Dashboard',
  '/dashboard': 'Command Dashboard',
  '/executive': 'Executive View',
  '/ceo': 'Executive View',
  '/nerve-center': 'Nerve Center',
  '/ingest': 'Data Fabric',
  '/intelligence': 'Intelligence Hub',
  '/decisions': 'Decision Engine',
  '/remediation': 'Remediation Center',
  '/settings': 'Settings',
  '/copilot': 'AI Copilot',
  // Code
  '/code/code-scanning': 'Code Scanning',
  '/code/secrets-detection': 'Secrets Detection',
  '/code/iac-scanning': 'Infrastructure as Code',
  '/code/sbom-generation': 'SBOM Generation',
  '/code/inventory': 'Asset Inventory',
  // Cloud
  '/cloud/cloud-posture': 'Cloud Posture',
  '/cloud/container-security': 'Container Security',
  '/cloud/runtime-protection': 'Runtime Protection',
  '/cloud/threat-feeds': 'Threat Feeds',
  '/cloud/correlation': 'Finding Correlation',
  // Attack / Validate
  '/attack/attack-simulation': 'Attack Simulation',
  '/attack/attack-paths': 'Attack Paths',
  '/attack/mpte': 'MPTE Console',
  '/attack/micro-pentest': 'Micro Pentest',
  '/attack/reachability': 'Reachability Analysis',
  '/attack/sandbox': 'Sandbox Verification',
  '/attack/exploit-research': 'Exploit Research',
  '/validate/sandbox': 'Sandbox Verification',
  '/validate/fail-engine': 'FAIL Engine',
  // Protect / Remediate
  '/protect/remediation': 'Remediation Tasks',
  '/protect/autofix': 'AutoFix Dashboard',
  '/protect/playbooks': 'Playbooks',
  '/protect/playbook-editor': 'Playbook Editor',
  '/protect/bulk-operations': 'Bulk Operations',
  '/protect/workflows': 'Workflows',
  '/protect/collaboration': 'Collaboration',
  '/protect/integrations': 'Ticket Integrations',
  // AI Engine
  '/ai-engine/multi-llm': 'AI Consensus',
  '/ai-engine/algorithmic-lab': 'Algorithmic Lab',
  '/ai-engine/predictions': 'Risk Predictions',
  '/ai-engine/policies': 'Policy Engine',
  '/ai-engine/self-learning': 'Self-Learning Demo',
  '/ai-engine/ml-dashboard': 'ML Dashboard',
  // Evidence / Comply
  '/evidence/bundles': 'Evidence Bundles',
  '/evidence/slsa-provenance': 'SLSA Provenance',
  '/evidence/compliance': 'Compliance Dashboard',
  '/evidence/audit-trail': 'Audit Trail',
  '/evidence/audit-logs': 'Audit Trail',
  '/evidence/reports': 'Reports',
  '/evidence/analytics': 'Evidence Analytics',
  '/evidence/soc2': 'SOC2 Evidence',
  // Core
  '/core/knowledge-graph': 'Knowledge Graph',
  '/core/brain-pipeline': 'Brain Pipeline',
  '/core/exposure-cases': 'Exposure Cases',
  // Discover
  '/discover/scanners': 'Scanner Dashboard',
  '/discover/scanner-ingest': 'Scanner Ingest',
  // Feeds
  '/feeds/live': 'Live Feed',
  // Mission Control
  '/mission-control/sla': 'SLA Dashboard',
  // Settings
  '/settings/users': 'Users',
  '/settings/teams': 'Teams',
  '/settings/integrations': 'Integrations',
  '/settings/marketplace': 'Marketplace',
  '/settings/system-health': 'System Health',
  '/settings/webhooks': 'Webhooks',
  '/settings/overlay': 'Overlay Config',
  '/settings/overlay-config': 'Overlay Config',
  '/settings/logs': 'API Logs',
  '/settings/mcp-registry': 'MCP Registry',
};

// Route-to-space mapping
const routeToSpace: Record<string, { name: string; emoji: string; color: string }> = {
  '/': { name: 'Mission Control', emoji: '🎯', color: 'text-indigo-400' },
  '/dashboard': { name: 'Mission Control', emoji: '🎯', color: 'text-indigo-400' },
  '/executive': { name: 'Mission Control', emoji: '🎯', color: 'text-indigo-400' },
  '/ceo': { name: 'Mission Control', emoji: '🎯', color: 'text-indigo-400' },
  '/nerve-center': { name: 'Mission Control', emoji: '🎯', color: 'text-indigo-400' },
  '/core/brain-pipeline': { name: 'Mission Control', emoji: '🎯', color: 'text-indigo-400' },
  '/core/exposure-cases': { name: 'Mission Control', emoji: '🎯', color: 'text-indigo-400' },
  '/feeds/live': { name: 'Mission Control', emoji: '🎯', color: 'text-indigo-400' },
  '/mission-control/sla': { name: 'Mission Control', emoji: '🎯', color: 'text-indigo-400' },
  '/ai-engine/predictions': { name: 'Mission Control', emoji: '🎯', color: 'text-indigo-400' },
  '/ai-engine/multi-llm': { name: 'Mission Control', emoji: '🎯', color: 'text-indigo-400' },
  '/ai-engine/policies': { name: 'Mission Control', emoji: '🎯', color: 'text-indigo-400' },
  '/ai-engine/policy-engine': { name: 'Mission Control', emoji: '🎯', color: 'text-indigo-400' },
  '/ai-engine/self-learning': { name: 'Mission Control', emoji: '🎯', color: 'text-indigo-400' },
  // Discover
  '/discover/scanners': { name: 'Discover', emoji: '🔍', color: 'text-cyan-400' },
  '/discover/scanner-ingest': { name: 'Discover', emoji: '🔍', color: 'text-cyan-400' },
  '/code/code-scanning': { name: 'Discover', emoji: '🔍', color: 'text-cyan-400' },
  '/code/secrets-detection': { name: 'Discover', emoji: '🔍', color: 'text-cyan-400' },
  '/code/iac-scanning': { name: 'Discover', emoji: '🔍', color: 'text-cyan-400' },
  '/code/sbom-generation': { name: 'Discover', emoji: '🔍', color: 'text-cyan-400' },
  '/code/inventory': { name: 'Discover', emoji: '🔍', color: 'text-cyan-400' },
  '/cloud/cloud-posture': { name: 'Discover', emoji: '🔍', color: 'text-cyan-400' },
  '/cloud/container-security': { name: 'Discover', emoji: '🔍', color: 'text-cyan-400' },
  '/cloud/threat-feeds': { name: 'Discover', emoji: '🔍', color: 'text-cyan-400' },
  '/cloud/correlation': { name: 'Discover', emoji: '🔍', color: 'text-cyan-400' },
  '/core/knowledge-graph': { name: 'Discover', emoji: '🔍', color: 'text-cyan-400' },
  '/attack/attack-paths': { name: 'Discover', emoji: '🔍', color: 'text-cyan-400' },
  '/ingest': { name: 'Discover', emoji: '🔍', color: 'text-cyan-400' },
  '/intelligence': { name: 'Discover', emoji: '🔍', color: 'text-cyan-400' },
  // Validate
  '/attack/mpte': { name: 'Validate', emoji: '⚡', color: 'text-orange-400' },
  '/attack/micro-pentest': { name: 'Validate', emoji: '⚡', color: 'text-orange-400' },
  '/attack/sandbox': { name: 'Validate', emoji: '⚡', color: 'text-orange-400' },
  '/validate/sandbox': { name: 'Validate', emoji: '⚡', color: 'text-orange-400' },
  '/attack/attack-simulation': { name: 'Validate', emoji: '⚡', color: 'text-orange-400' },
  '/validate/fail-engine': { name: 'Validate', emoji: '⚡', color: 'text-orange-400' },
  '/attack/reachability': { name: 'Validate', emoji: '⚡', color: 'text-orange-400' },
  '/protect/playbooks': { name: 'Validate', emoji: '⚡', color: 'text-orange-400' },
  '/protect/playbook-editor': { name: 'Validate', emoji: '⚡', color: 'text-orange-400' },
  '/attack/exploit-research': { name: 'Validate', emoji: '⚡', color: 'text-orange-400' },
  // Remediate
  '/protect/remediation': { name: 'Remediate', emoji: '🔧', color: 'text-emerald-400' },
  '/protect/autofix': { name: 'Remediate', emoji: '🔧', color: 'text-emerald-400' },
  '/protect/bulk-operations': { name: 'Remediate', emoji: '🔧', color: 'text-emerald-400' },
  '/protect/workflows': { name: 'Remediate', emoji: '🔧', color: 'text-emerald-400' },
  '/protect/collaboration': { name: 'Remediate', emoji: '🔧', color: 'text-emerald-400' },
  '/protect/integrations': { name: 'Remediate', emoji: '🔧', color: 'text-emerald-400' },
  '/remediation': { name: 'Remediate', emoji: '🔧', color: 'text-emerald-400' },
  // Comply
  '/evidence/compliance': { name: 'Comply', emoji: '🛡️', color: 'text-violet-400' },
  '/evidence/bundles': { name: 'Comply', emoji: '🛡️', color: 'text-violet-400' },
  '/evidence/soc2': { name: 'Comply', emoji: '🛡️', color: 'text-violet-400' },
  '/evidence/slsa-provenance': { name: 'Comply', emoji: '🛡️', color: 'text-violet-400' },
  '/evidence/audit-trail': { name: 'Comply', emoji: '🛡️', color: 'text-violet-400' },
  '/evidence/audit-logs': { name: 'Comply', emoji: '🛡️', color: 'text-violet-400' },
  '/evidence/reports': { name: 'Comply', emoji: '🛡️', color: 'text-violet-400' },
  '/evidence/analytics': { name: 'Comply', emoji: '🛡️', color: 'text-violet-400' },
};

export default function Breadcrumbs() {
  const location = useLocation();
  const navigate = useNavigate();
  const pathname = location.pathname;

  // Don't show breadcrumbs on the root dashboard
  if (pathname === '/' || pathname === '/dashboard') return null;

  const space = routeToSpace[pathname];
  const pageLabel = routeLabels[pathname] || pathname.split('/').pop()?.replace(/-/g, ' ') || '';

  return (
    <nav aria-label="Breadcrumb" className="flex items-center gap-1.5 text-xs mb-4">
      {/* Home */}
      <button
        onClick={() => navigate('/')}
        className="flex items-center gap-1 text-muted-foreground hover:text-foreground transition-colors"
        aria-label="Go to dashboard"
      >
        <Home className="w-3 h-3" />
      </button>

      {/* Space */}
      {space && (
        <>
          <ChevronRight className="w-3 h-3 text-muted-foreground/40" />
          <span className={`flex items-center gap-1 ${space.color}`}>
            <span>{space.emoji}</span>
            <span className="font-medium">{space.name}</span>
          </span>
        </>
      )}

      {/* Current Page */}
      <ChevronRight className="w-3 h-3 text-muted-foreground/40" />
      <span className="text-foreground font-medium capitalize">{pageLabel}</span>
    </nav>
  );
}
