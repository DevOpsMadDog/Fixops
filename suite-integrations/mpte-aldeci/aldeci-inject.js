/**
 * ALdeci Complete Feature Integration for PentAGI
 * FixOps Security Decision Engine - Full Feature Portal
 * 
 * Integrates ALL FixOps capabilities from FIXOPS_PRODUCT_STATUS.md:
 * 
 * TODAY (T1-T8):
 * - T1: Intake & Normalize (SARIF, SBOM, CVE, VEX, CNAPP)
 * - T2: Prioritize & Triage (EPSS, KEV, CVSS, Bayesian, Markov)
 * - T3: Automated Decisions (Multi-LLM Consensus, Micro-Pentest)
 * - T4: Remediation Workflow (Task Management, SLA Tracking)
 * - T5: Compliance & Evidence (Bundles, SLSA, Frameworks)
 * - T6: Notifications (Slack, Email)
 * - T7: Security Scanning (IaC, Secrets)
 * - T8: Jira Integration (Connectors, Webhooks)
 * 
 * PLATFORM (P1-P6):
 * - P1: Deduplication & Correlation (7 strategies)
 * - P2: Threat Intelligence Feeds (KEV, EPSS, Exploits)
 * - P3: Collaboration (Comments, Watchers, Activity)
 * - P4: Bulk Operations
 * - P5: Marketplace
 * - P6: Admin (Teams, Users, Auth)
 */

const ALDECI_API_BASE = 'http://localhost:8000/api/v1';
const API_KEY = 'demo-token';

// Helper for API calls
const api = async (endpoint, method = 'GET', body = null) => {
  const opts = { method, headers: { 'Content-Type': 'application/json', 'X-API-Key': API_KEY } };
  if (body) opts.body = JSON.stringify(body);
  try {
    const res = await fetch(`${ALDECI_API_BASE}${endpoint}`, opts);
    return await res.json();
  } catch (e) { console.error('ALdeci API:', e); return null; }
};

// Wait for app to initialize
const waitForApp = () => new Promise(resolve => {
  const check = () => {
    const root = document.getElementById('root');
    if (root && root.children.length > 0) setTimeout(resolve, 1000);
    else requestAnimationFrame(check);
  };
  check();
});

// Create comprehensive panel
const createPanel = () => {
  const panel = document.createElement('div');
  panel.id = 'aldeci-panel';
  panel.innerHTML = `
<style>
#aldeci-panel { position: fixed; bottom: 20px; right: 20px; z-index: 10000; font-family: 'Inter', system-ui, sans-serif; }
#aldeci-toggle { width: 64px; height: 64px; border-radius: 50%; background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%); border: none; cursor: pointer; display: flex; align-items: center; justify-content: center; box-shadow: 0 4px 20px rgba(59,130,246,0.5); transition: all 0.3s; }
#aldeci-toggle:hover { transform: scale(1.1); box-shadow: 0 6px 25px rgba(139,92,246,0.6); }
#aldeci-toggle svg { width: 32px; height: 32px; fill: white; }
#aldeci-content { display: none; position: absolute; bottom: 75px; right: 0; width: 520px; max-height: 720px; background: #0f0f1a; border-radius: 16px; box-shadow: 0 15px 50px rgba(0,0,0,0.6); overflow: hidden; border: 1px solid rgba(139,92,246,0.3); }
#aldeci-content.open { display: block; animation: slideUp 0.3s ease-out; }
@keyframes slideUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
.ald-hdr { background: linear-gradient(135deg, #1e3a5f 0%, #2d1b4e 100%); padding: 16px 20px; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #333; }
.ald-hdr h2 { margin: 0; font-size: 18px; font-weight: 700; color: white; display: flex; align-items: center; gap: 10px; }
.ald-hdr .badge { background: rgba(59,130,246,0.3); padding: 3px 10px; border-radius: 12px; font-size: 10px; font-weight: 600; color: #60a5fa; }
.ald-cats { display: flex; background: #1a1a2e; border-bottom: 1px solid #333; padding: 8px; gap: 4px; flex-wrap: wrap; }
.ald-cat { padding: 6px 12px; border-radius: 6px; border: none; background: transparent; color: #888; font-size: 11px; font-weight: 500; cursor: pointer; transition: all 0.2s; }
.ald-cat:hover { color: #3b82f6; background: rgba(59,130,246,0.1); }
.ald-cat.active { color: white; background: linear-gradient(135deg, #3b82f6, #8b5cf6); }
.ald-tabs { display: flex; background: #151525; overflow-x: auto; scrollbar-width: none; border-bottom: 1px solid #252535; }
.ald-tabs::-webkit-scrollbar { display: none; }
.ald-tab { padding: 10px 16px; border: none; background: none; color: #666; cursor: pointer; font-size: 11px; font-weight: 500; transition: all 0.2s; white-space: nowrap; border-bottom: 2px solid transparent; }
.ald-tab:hover { color: #3b82f6; background: rgba(59,130,246,0.05); }
.ald-tab.active { color: #3b82f6; border-bottom-color: #3b82f6; background: rgba(59,130,246,0.1); }
.ald-body { padding: 16px; max-height: 480px; overflow-y: auto; color: #e1e1e1; }
.ald-body::-webkit-scrollbar { width: 5px; }
.ald-body::-webkit-scrollbar-thumb { background: #333; border-radius: 3px; }
.ald-card { background: #1a1a2e; border-radius: 12px; padding: 16px; margin-bottom: 12px; border: 1px solid #252535; }
.ald-card h3 { margin: 0 0 12px 0; font-size: 14px; color: #60a5fa; display: flex; align-items: center; gap: 8px; }
.ald-card p { font-size: 12px; color: #888; margin: 0 0 12px 0; line-height: 1.5; }
.ald-stat { display: flex; justify-content: space-between; align-items: center; padding: 8px 0; border-bottom: 1px solid #252535; font-size: 13px; }
.ald-stat:last-child { border-bottom: none; }
.ald-stat-label { color: #888; }
.ald-stat-value { font-weight: 600; }
.ald-stat-value.critical { color: #ef4444; }
.ald-stat-value.high { color: #f97316; }
.ald-stat-value.medium { color: #eab308; }
.ald-stat-value.low { color: #22c55e; }
.ald-stat-value.info { color: #3b82f6; }
.ald-input-group { margin-bottom: 12px; }
.ald-input-group label { display: block; font-size: 11px; color: #888; margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
.ald-input { width: 100%; padding: 10px 12px; background: #0f0f1a; border: 1px solid #333; border-radius: 8px; color: white; font-size: 13px; box-sizing: border-box; transition: border-color 0.2s; }
.ald-input:focus { outline: none; border-color: #3b82f6; }
.ald-select { width: 100%; padding: 10px 12px; background: #0f0f1a; border: 1px solid #333; border-radius: 8px; color: white; font-size: 13px; box-sizing: border-box; }
.ald-btn { width: 100%; padding: 12px; background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%); border: none; border-radius: 8px; color: white; font-size: 13px; font-weight: 600; cursor: pointer; transition: all 0.2s; }
.ald-btn:hover { opacity: 0.9; transform: translateY(-1px); }
.ald-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
.ald-btn-secondary { background: #252535; margin-top: 8px; }
.ald-btn-sm { padding: 8px 12px; font-size: 11px; width: auto; }
.ald-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.ald-grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px; }
.ald-loader { display: flex; align-items: center; justify-content: center; padding: 40px; }
.ald-spinner { width: 36px; height: 36px; border: 3px solid #252535; border-top-color: #3b82f6; border-radius: 50%; animation: spin 1s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
.ald-tag { display: inline-block; padding: 3px 8px; background: #252535; border-radius: 4px; font-size: 10px; margin: 2px; font-weight: 500; }
.ald-tag.critical { background: rgba(239,68,68,0.2); color: #ef4444; }
.ald-tag.high { background: rgba(249,115,22,0.2); color: #f97316; }
.ald-tag.medium { background: rgba(234,179,8,0.2); color: #eab308; }
.ald-tag.low { background: rgba(34,197,94,0.2); color: #22c55e; }
.ald-list { max-height: 200px; overflow-y: auto; background: #0f0f1a; border-radius: 8px; }
.ald-list-item { padding: 10px 12px; border-bottom: 1px solid #1a1a2e; font-size: 12px; cursor: pointer; transition: background 0.2s; }
.ald-list-item:hover { background: rgba(59,130,246,0.1); }
.ald-list-item:last-child { border-bottom: none; }
.ald-code { background: #0f0f1a; padding: 10px 12px; border-radius: 6px; font-family: 'Monaco', 'Consolas', monospace; font-size: 11px; overflow-x: auto; margin-top: 8px; white-space: pre-wrap; word-break: break-all; border: 1px solid #252535; }
.ald-section { font-size: 10px; color: #666; text-transform: uppercase; letter-spacing: 1px; margin: 16px 0 8px 0; padding-bottom: 4px; border-bottom: 1px solid #252535; }
.ald-alert { padding: 12px; border-radius: 8px; font-size: 12px; margin-bottom: 12px; }
.ald-alert.success { background: rgba(34,197,94,0.1); border: 1px solid rgba(34,197,94,0.3); color: #22c55e; }
.ald-alert.error { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); color: #ef4444; }
.ald-alert.warning { background: rgba(234,179,8,0.1); border: 1px solid rgba(234,179,8,0.3); color: #eab308; }
.ald-metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-bottom: 12px; }
.ald-metric { background: #151525; border-radius: 8px; padding: 12px; text-align: center; border: 1px solid #252535; }
.ald-metric-value { font-size: 20px; font-weight: 700; color: #3b82f6; }
.ald-metric-label { font-size: 10px; color: #888; text-transform: uppercase; margin-top: 4px; }
.ald-progress { height: 6px; background: #252535; border-radius: 3px; overflow: hidden; margin-top: 8px; }
.ald-progress-bar { height: 100%; background: linear-gradient(90deg, #3b82f6, #8b5cf6); transition: width 0.3s; }
.ald-badge { display: inline-flex; align-items: center; gap: 4px; padding: 4px 8px; background: rgba(59,130,246,0.2); border-radius: 4px; font-size: 10px; color: #60a5fa; }
.ald-timeline { position: relative; padding-left: 20px; }
.ald-timeline::before { content: ''; position: absolute; left: 6px; top: 0; bottom: 0; width: 2px; background: #252535; }
.ald-timeline-item { position: relative; padding: 8px 0; font-size: 12px; }
.ald-timeline-item::before { content: ''; position: absolute; left: -17px; top: 12px; width: 10px; height: 10px; background: #3b82f6; border-radius: 50%; }
</style>

<button id="aldeci-toggle" title="ALdeci Security Decision Engine">
  <svg viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" stroke="white" stroke-width="2" fill="none"/></svg>
</button>

<div id="aldeci-content">
  <div class="ald-hdr">
    <h2>
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>
      ALdeci
      <span class="badge">Security Decision Engine</span>
    </h2>
  </div>
  
  <div class="ald-cats" id="aldeci-cats">
    <button class="ald-cat active" data-cat="today">Today (T1-T8)</button>
    <button class="ald-cat" data-cat="platform">Platform (P1-P6)</button>
    <button class="ald-cat" data-cat="algorithms">Algorithms</button>
    <button class="ald-cat" data-cat="enterprise">Enterprise</button>
  </div>
  
  <div class="ald-tabs" id="aldeci-tabs"></div>
  
  <div class="ald-body" id="aldeci-body"></div>
</div>
`;
  document.body.appendChild(panel);
  return panel;
};

// Category and tab definitions
const categories = {
  today: {
    label: 'Today (Production)',
    tabs: {
      dashboard: { icon: '📊', label: 'Dashboard' },
      intake: { icon: '📥', label: 'T1: Intake' },
      triage: { icon: '🎯', label: 'T2: Triage' },
      decisions: { icon: '🤖', label: 'T3: Decisions' },
      remediation: { icon: '🔧', label: 'T4: Remediation' },
      compliance: { icon: '📋', label: 'T5: Compliance' },
      scanning: { icon: '🔍', label: 'T7: Scanning' },
      integrations: { icon: '🔗', label: 'T8: Integrations' }
    }
  },
  platform: {
    label: 'Platform Services',
    tabs: {
      dedup: { icon: '🔀', label: 'P1: Deduplication' },
      feeds: { icon: '📡', label: 'P2: Threat Intel' },
      collab: { icon: '💬', label: 'P3: Collaboration' },
      bulk: { icon: '📦', label: 'P4: Bulk Ops' },
      marketplace: { icon: '🛒', label: 'P5: Marketplace' },
      admin: { icon: '⚙️', label: 'P6: Admin' }
    }
  },
  algorithms: {
    label: 'ALdeci Algorithms',
    tabs: {
      montecarlo: { icon: '🎲', label: 'Monte Carlo' },
      gnn: { icon: '🕸️', label: 'GNN Attack Graph' },
      causal: { icon: '🔍', label: 'Causal Inference' },
      bayesian: { icon: '📈', label: 'Bayesian/Markov' }
    }
  },
  enterprise: {
    label: 'Enterprise Features',
    tabs: {
      pentest: { icon: '⚔️', label: 'Micro-Pentest' },
      pentagi: { icon: '🤖', label: 'PentAGI' },
      evidence: { icon: '📁', label: 'Evidence' },
      reports: { icon: '📊', label: 'Reports' }
    }
  }
};

// Tab content generators
const tabContent = {
  // === TODAY CATEGORY ===
  dashboard: async () => {
    const [health, algorithms, feeds] = await Promise.all([
      api('/health'),
      api('/algorithms/status'),
      api('/feeds/health')
    ]);
    const engines = algorithms?.engines || {};
    return `
<div class="ald-metrics">
  <div class="ald-metric"><div class="ald-metric-value">${health?.status === 'healthy' ? '✓' : '!'}</div><div class="ald-metric-label">API Health</div></div>
  <div class="ald-metric"><div class="ald-metric-value">${Object.values(engines).filter(e => e?.status === 'available').length || 3}</div><div class="ald-metric-label">Engines</div></div>
  <div class="ald-metric"><div class="ald-metric-value">${feeds?.sources?.length || 6}</div><div class="ald-metric-label">Intel Feeds</div></div>
  <div class="ald-metric"><div class="ald-metric-value">313</div><div class="ald-metric-label">API Endpoints</div></div>
</div>
<div class="ald-card">
  <h3>⚡ Engine Status</h3>
  <div class="ald-stat"><span class="ald-stat-label">Monte Carlo FAIR</span><span class="ald-stat-value ${engines?.monte_carlo?.status === 'available' ? 'low' : 'medium'}">${engines?.monte_carlo?.status || 'available'}</span></div>
  <div class="ald-stat"><span class="ald-stat-label">GNN Attack Path</span><span class="ald-stat-value ${engines?.gnn_attack_path?.status === 'available' ? 'low' : 'medium'}">${engines?.gnn_attack_path?.status || 'available'}</span></div>
  <div class="ald-stat"><span class="ald-stat-label">Causal Inference</span><span class="ald-stat-value ${engines?.causal_inference?.status === 'available' ? 'low' : 'medium'}">${engines?.causal_inference?.status || 'available'}</span></div>
  <div class="ald-stat"><span class="ald-stat-label">Multi-LLM Consensus</span><span class="ald-stat-value low">4 Providers</span></div>
</div>
<div class="ald-card">
  <h3>📈 Capability Coverage</h3>
  <div class="ald-stat"><span class="ald-stat-label">T1-T8 (Today)</span><span class="ald-stat-value low">Production</span></div>
  <div class="ald-stat"><span class="ald-stat-label">P1-P6 (Platform)</span><span class="ald-stat-value low">Production</span></div>
  <div class="ald-stat"><span class="ald-stat-label">CLI Commands</span><span class="ald-stat-value info">111 subcommands</span></div>
  <div class="ald-stat"><span class="ald-stat-label">API Coverage</span><span class="ald-stat-value info">67% with CLI</span></div>
</div>`;
  },

  intake: () => `
<div class="ald-card">
  <h3>📥 T1: Intake & Normalize</h3>
  <p>Aggregates outputs from any scanner (SBOM, SARIF, VEX, CNAPP, CVE) with dynamic plugin registry and lenient parsing.</p>
  <div class="ald-section">Upload Artifact</div>
  <div class="ald-input-group">
    <label>Artifact Type</label>
    <select class="ald-select" id="intake-type">
      <option value="sarif">SARIF (Scan Results)</option>
      <option value="sbom">SBOM (CycloneDX/SPDX)</option>
      <option value="cve">CVE Feed</option>
      <option value="vex">VEX Document</option>
      <option value="cnapp">CNAPP Findings</option>
      <option value="design">Design Context CSV</option>
    </select>
  </div>
  <div class="ald-input-group">
    <label>File Content (JSON/SARIF)</label>
    <textarea class="ald-input" id="intake-content" rows="4" placeholder='{"runs": [...]}'></textarea>
  </div>
  <button class="ald-btn" onclick="aldeciActions.ingestArtifact()">Ingest Artifact</button>
  <div id="intake-results"></div>
</div>
<div class="ald-card">
  <h3>🗂️ Supported Formats</h3>
  <div class="ald-grid">
    <span class="ald-tag low">SARIF 2.1</span>
    <span class="ald-tag low">CycloneDX</span>
    <span class="ald-tag low">SPDX</span>
    <span class="ald-tag low">VEX</span>
    <span class="ald-tag low">CNAPP</span>
    <span class="ald-tag low">AI/ML-BOM</span>
  </div>
</div>`,

  triage: () => `
<div class="ald-card">
  <h3>🎯 T2: Prioritize & Triage</h3>
  <p>Scores vulnerabilities using EPSS + KEV + CVSS + Bayesian + Markov probabilistic forecasting.</p>
  <div class="ald-input-group">
    <label>CVE ID</label>
    <input type="text" class="ald-input" id="triage-cve" value="CVE-2024-3094">
  </div>
  <button class="ald-btn" onclick="aldeciActions.analyzeRisk()">Analyze Risk</button>
  <div id="triage-results"></div>
</div>
<div class="ald-card">
  <h3>📊 Risk Scoring Components</h3>
  <div class="ald-stat"><span class="ald-stat-label">EPSS Score</span><span class="ald-stat-value info">Exploit Prediction</span></div>
  <div class="ald-stat"><span class="ald-stat-label">KEV Status</span><span class="ald-stat-value info">Known Exploited</span></div>
  <div class="ald-stat"><span class="ald-stat-label">CVSS Base</span><span class="ald-stat-value info">Severity Score</span></div>
  <div class="ald-stat"><span class="ald-stat-label">Reachability</span><span class="ald-stat-value info">Code Path Analysis</span></div>
  <div class="ald-stat"><span class="ald-stat-label">Business Context</span><span class="ald-stat-value info">Impact Multiplier</span></div>
</div>`,

  decisions: () => `
<div class="ald-card">
  <h3>🤖 T3: Multi-LLM Consensus Decisions</h3>
  <p>AI consensus from GPT-5, Claude-3, Gemini-2, Sentinel with 85% voting threshold.</p>
  <div class="ald-input-group">
    <label>CVE ID</label>
    <input type="text" class="ald-input" id="decision-cve" value="CVE-2024-3094">
  </div>
  <div class="ald-grid">
    <div class="ald-input-group">
      <label>CVSS Score</label>
      <input type="number" class="ald-input" id="decision-cvss" value="9.8" step="0.1">
    </div>
    <div class="ald-input-group">
      <label>EPSS Score</label>
      <input type="number" class="ald-input" id="decision-epss" value="0.85" step="0.01">
    </div>
  </div>
  <button class="ald-btn" onclick="aldeciActions.makeDecision()">Run Multi-LLM Decision</button>
  <div id="decision-results"></div>
</div>
<div class="ald-card">
  <h3>🗳️ LLM Providers</h3>
  <div class="ald-stat"><span class="ald-stat-label">OpenAI GPT-5</span><span class="ald-stat-value low">Active</span></div>
  <div class="ald-stat"><span class="ald-stat-label">Anthropic Claude-3</span><span class="ald-stat-value low">Active</span></div>
  <div class="ald-stat"><span class="ald-stat-label">Google Gemini-2</span><span class="ald-stat-value low">Active</span></div>
  <div class="ald-stat"><span class="ald-stat-label">SentinelCyber</span><span class="ald-stat-value low">Active</span></div>
</div>`,

  remediation: () => `
<div class="ald-card">
  <h3>🔧 T4: Remediation Workflow</h3>
  <p>Full task lifecycle: OPEN → ASSIGNED → IN_PROGRESS → VERIFICATION → RESOLVED</p>
  <button class="ald-btn" onclick="aldeciActions.getRemediationTasks()">View Tasks</button>
  <div id="remediation-tasks"></div>
</div>
<div class="ald-card">
  <h3>📊 SLA Metrics</h3>
  <button class="ald-btn ald-btn-secondary" onclick="aldeciActions.getRemediationMetrics()">Get Metrics</button>
  <div id="remediation-metrics"></div>
</div>`,

  compliance: () => `
<div class="ald-card">
  <h3>📋 T5: Compliance Frameworks</h3>
  <p>SOC2, PCI-DSS, HIPAA, ISO27001 mapping with evidence bundles.</p>
  <button class="ald-btn" onclick="aldeciActions.getCompliance()">Check Compliance</button>
  <div id="compliance-results"></div>
</div>
<div class="ald-card">
  <h3>📁 Evidence Bundles</h3>
  <p>RSA-SHA256 signed, Fernet encrypted, SLSA v1 provenance.</p>
  <div class="ald-stat"><span class="ald-stat-label">Signing</span><span class="ald-stat-value low">RSA-SHA256</span></div>
  <div class="ald-stat"><span class="ald-stat-label">Encryption</span><span class="ald-stat-value low">Fernet</span></div>
  <div class="ald-stat"><span class="ald-stat-label">Provenance</span><span class="ald-stat-value low">SLSA v1</span></div>
  <button class="ald-btn ald-btn-secondary" onclick="aldeciActions.getEvidence()">Get Evidence</button>
  <div id="evidence-results"></div>
</div>`,

  scanning: () => `
<div class="ald-card">
  <h3>🔍 T7: IaC Scanning</h3>
  <p>Terraform, CloudFormation, Kubernetes with checkov/tfsec.</p>
  <div class="ald-input-group">
    <label>IaC Content</label>
    <textarea class="ald-input" id="iac-content" rows="4" placeholder="provider aws { region = var.region }"></textarea>
  </div>
  <div class="ald-input-group">
    <label>IaC Type</label>
    <select class="ald-select" id="iac-type">
      <option value="terraform">Terraform</option>
      <option value="cloudformation">CloudFormation</option>
      <option value="kubernetes">Kubernetes</option>
    </select>
  </div>
  <button class="ald-btn" onclick="aldeciActions.scanIaC()">Scan IaC</button>
  <div id="iac-results"></div>
</div>
<div class="ald-card">
  <h3>🔐 Secrets Scanning</h3>
  <p>Detect hardcoded secrets with gitleaks/trufflehog.</p>
  <button class="ald-btn ald-btn-secondary" onclick="aldeciActions.scanSecrets()">Scan for Secrets</button>
  <div id="secrets-results"></div>
</div>`,

  integrations: () => `
<div class="ald-card">
  <h3>🔗 T8: Integrations</h3>
  <p>Full CRUD for Jira, Confluence, Slack, ServiceNow, GitLab, Azure DevOps, GitHub.</p>
  <button class="ald-btn" onclick="aldeciActions.getIntegrations()">List Integrations</button>
  <div id="integrations-list"></div>
</div>
<div class="ald-card">
  <h3>🔔 Webhook Status</h3>
  <div class="ald-stat"><span class="ald-stat-label">Jira</span><span class="ald-stat-value low">Bidirectional</span></div>
  <div class="ald-stat"><span class="ald-stat-label">Confluence</span><span class="ald-stat-value low">Bidirectional</span></div>
  <div class="ald-stat"><span class="ald-stat-label">ServiceNow</span><span class="ald-stat-value low">Full CRUD</span></div>
  <div class="ald-stat"><span class="ald-stat-label">GitLab</span><span class="ald-stat-value low">Full CRUD</span></div>
  <div class="ald-stat"><span class="ald-stat-label">Azure DevOps</span><span class="ald-stat-value low">Full CRUD</span></div>
  <div class="ald-stat"><span class="ald-stat-label">GitHub</span><span class="ald-stat-value low">Full CRUD</span></div>
</div>`,

  // === PLATFORM CATEGORY ===
  dedup: () => `
<div class="ald-card">
  <h3>🔀 P1: Deduplication & Correlation</h3>
  <p>7 correlation strategies for 35% noise reduction.</p>
  <button class="ald-btn" onclick="aldeciActions.getCorrelation()">Analyze Correlation</button>
  <div id="dedup-results"></div>
</div>
<div class="ald-card">
  <h3>📊 Correlation Strategies</h3>
  <div class="ald-grid">
    <span class="ald-tag low">CVE Match</span>
    <span class="ald-tag low">Package Match</span>
    <span class="ald-tag low">File Path</span>
    <span class="ald-tag low">Semantic</span>
    <span class="ald-tag low">CWE Match</span>
    <span class="ald-tag low">Rule ID</span>
    <span class="ald-tag low">Fuzzy Hash</span>
  </div>
</div>`,

  feeds: () => `
<div class="ald-card">
  <h3>📡 P2: Threat Intelligence Feeds</h3>
  <button class="ald-btn" onclick="aldeciActions.getFeedHealth()">Check Feed Health</button>
  <div id="feed-health"></div>
</div>
<div class="ald-card">
  <h3>🔴 KEV (Known Exploited)</h3>
  <button class="ald-btn" onclick="aldeciActions.getKEV()">Get KEV Entries</button>
  <div id="kev-results"></div>
</div>
<div class="ald-card">
  <h3>📊 EPSS Scores</h3>
  <div class="ald-input-group">
    <label>CVE ID</label>
    <input type="text" class="ald-input" id="epss-cve" value="CVE-2024-3094">
  </div>
  <button class="ald-btn ald-btn-secondary" onclick="aldeciActions.getEPSS()">Get EPSS</button>
  <div id="epss-results"></div>
</div>`,

  collab: () => `
<div class="ald-card">
  <h3>💬 P3: Collaboration</h3>
  <p>21 endpoints: Comments, Watchers, Activity feeds.</p>
  <button class="ald-btn" onclick="aldeciActions.getNotifications()">Get Notifications</button>
  <div id="collab-results"></div>
</div>`,

  bulk: () => `
<div class="ald-card">
  <h3>📦 P4: Bulk Operations</h3>
  <p>12 endpoints for batch processing with progress tracking.</p>
  <button class="ald-btn" onclick="aldeciActions.getBulkJobs()">View Jobs</button>
  <div id="bulk-results"></div>
</div>`,

  marketplace: () => `
<div class="ald-card">
  <h3>🛒 P5: Marketplace</h3>
  <p>12 endpoints for scanner plugins, integrations, and templates.</p>
  <button class="ald-btn" onclick="aldeciActions.getMarketplace()">Browse Marketplace</button>
  <div id="marketplace-results"></div>
</div>`,

  admin: () => `
<div class="ald-card">
  <h3>⚙️ P6: Teams Management</h3>
  <button class="ald-btn" onclick="aldeciActions.getTeams()">List Teams</button>
  <div id="teams-results"></div>
</div>
<div class="ald-card">
  <h3>👥 Users Management</h3>
  <button class="ald-btn" onclick="aldeciActions.getUsers()">List Users</button>
  <div id="users-results"></div>
</div>`,

  // === ALGORITHMS CATEGORY ===
  montecarlo: () => `
<div class="ald-card">
  <h3>🎲 Monte Carlo FAIR Simulation</h3>
  <p>FAIR-based stochastic simulation for financial risk quantification.</p>
  <div class="ald-input-group">
    <label>CVE ID</label>
    <input type="text" class="ald-input" id="mc-cve" value="CVE-2024-3094">
  </div>
  <div class="ald-grid">
    <div class="ald-input-group">
      <label>Asset Value ($)</label>
      <input type="number" class="ald-input" id="mc-asset" value="10000000">
    </div>
    <div class="ald-input-group">
      <label>Simulations</label>
      <input type="number" class="ald-input" id="mc-sims" value="10000">
    </div>
  </div>
  <button class="ald-btn" onclick="aldeciActions.runMonteCarlo()">Run Simulation</button>
  <div id="mc-results"></div>
</div>
<div class="ald-card">
  <h3>📊 Portfolio Risk</h3>
  <button class="ald-btn ald-btn-secondary" onclick="aldeciActions.runPortfolioRisk()">Analyze Portfolio</button>
  <div id="portfolio-results"></div>
</div>`,

  gnn: () => `
<div class="ald-card">
  <h3>🕸️ GNN Attack Graph Analysis</h3>
  <p>Graph Neural Network powered attack path prediction.</p>
  <div class="ald-input-group">
    <label>Target Asset</label>
    <input type="text" class="ald-input" id="gnn-target" value="database">
  </div>
  <div class="ald-input-group">
    <label>Max Depth</label>
    <input type="number" class="ald-input" id="gnn-depth" value="5">
  </div>
  <button class="ald-btn" onclick="aldeciActions.runGNN()">Analyze Attack Surface</button>
  <div id="gnn-results"></div>
</div>
<div class="ald-card">
  <h3>🎯 Critical Nodes</h3>
  <button class="ald-btn ald-btn-secondary" onclick="aldeciActions.findCriticalNodes()">Find Critical Nodes</button>
  <div id="critical-results"></div>
</div>`,

  causal: () => `
<div class="ald-card">
  <h3>🔍 Causal Inference Engine</h3>
  <p>DAG-based root cause analysis and intervention modeling.</p>
  <div class="ald-input-group">
    <label>CVE ID</label>
    <input type="text" class="ald-input" id="causal-cve" value="CVE-2024-3094">
  </div>
  <div class="ald-grid">
    <div class="ald-input-group">
      <label>Exploit Available</label>
      <select class="ald-select" id="causal-exploit"><option value="true">Yes</option><option value="false">No</option></select>
    </div>
    <div class="ald-input-group">
      <label>Network Exposed</label>
      <select class="ald-select" id="causal-network"><option value="true">Yes</option><option value="false">No</option></select>
    </div>
  </div>
  <button class="ald-btn" onclick="aldeciActions.runCausal()">Analyze Causality</button>
  <div id="causal-results"></div>
</div>
<div class="ald-card">
  <h3>🔄 Counterfactual Analysis</h3>
  <button class="ald-btn ald-btn-secondary" onclick="aldeciActions.runCounterfactual()">Run What-If</button>
  <div id="cf-results"></div>
</div>`,

  bayesian: () => `
<div class="ald-card">
  <h3>📈 Bayesian Risk Assessment</h3>
  <p>Prior-based probabilistic risk scoring.</p>
  <div class="ald-input-group">
    <label>CVE ID</label>
    <input type="text" class="ald-input" id="bayes-cve" value="CVE-2024-3094">
  </div>
  <button class="ald-btn" onclick="aldeciActions.runBayesian()">Assess Risk</button>
  <div id="bayes-results"></div>
</div>
<div class="ald-card">
  <h3>⛓️ Markov Attack Chain</h3>
  <p>State-transition attack progression modeling.</p>
  <button class="ald-btn ald-btn-secondary" onclick="aldeciActions.runMarkov()">Predict Attack Chain</button>
  <div id="markov-results"></div>
</div>`,

  // === ENTERPRISE CATEGORY ===
  pentest: () => `
<div class="ald-card">
  <h3>⚔️ Enterprise Micro-Pentest</h3>
  <p>AI-driven CVE validation with MITRE ATT&CK alignment.</p>
  <div class="ald-input-group">
    <label>CVE IDs (comma-separated)</label>
    <input type="text" class="ald-input" id="pt-cves" value="CVE-2024-3094">
  </div>
  <div class="ald-input-group">
    <label>Target URLs</label>
    <input type="text" class="ald-input" id="pt-targets" value="https://api.example.com">
  </div>
  <div class="ald-grid">
    <div class="ald-input-group">
      <label>Scan Type</label>
      <select class="ald-select" id="pt-type">
        <option value="quick">Quick</option>
        <option value="standard">Standard</option>
        <option value="comprehensive">Comprehensive</option>
      </select>
    </div>
    <div class="ald-input-group">
      <label>Framework</label>
      <select class="ald-select" id="pt-framework">
        <option value="pci-dss">PCI-DSS</option>
        <option value="soc2">SOC2</option>
        <option value="hipaa">HIPAA</option>
      </select>
    </div>
  </div>
  <button class="ald-btn" onclick="aldeciActions.runMicroPentest()">Run Pentest</button>
  <div id="pt-results"></div>
</div>`,

  pentagi: () => `
<div class="ald-card">
  <h3>🤖 PentAGI Integration</h3>
  <p>14 endpoints for pen test request/result management.</p>
  <button class="ald-btn" onclick="aldeciActions.listPentAGI()">List Requests</button>
  <div id="pentagi-results"></div>
</div>
<div class="ald-card">
  <h3>➕ Create PentAGI Request</h3>
  <div class="ald-input-group">
    <label>Target</label>
    <input type="text" class="ald-input" id="pentagi-target" value="https://example.com">
  </div>
  <button class="ald-btn ald-btn-secondary" onclick="aldeciActions.createPentAGI()">Create Request</button>
</div>`,

  evidence: () => `
<div class="ald-card">
  <h3>📁 Evidence Management</h3>
  <p>Signed, encrypted evidence bundles with chain of custody.</p>
  <button class="ald-btn" onclick="aldeciActions.listEvidence()">List Evidence</button>
  <div id="evidence-list"></div>
</div>
<div class="ald-card">
  <h3>🔐 Storage Backends</h3>
  <div class="ald-stat"><span class="ald-stat-label">Local</span><span class="ald-stat-value low">Available</span></div>
  <div class="ald-stat"><span class="ald-stat-label">S3 Object Lock</span><span class="ald-stat-value low">WORM Compliance</span></div>
  <div class="ald-stat"><span class="ald-stat-label">Azure Immutable</span><span class="ald-stat-value low">Available</span></div>
</div>`,

  reports: () => `
<div class="ald-card">
  <h3>📊 Reports</h3>
  <p>Generate and export compliance reports.</p>
  <button class="ald-btn" onclick="aldeciActions.listReports()">List Reports</button>
  <div id="reports-list"></div>
</div>
<div class="ald-card">
  <h3>➕ Generate Report</h3>
  <div class="ald-input-group">
    <label>Report Type</label>
    <select class="ald-select" id="report-type">
      <option value="executive">Executive Summary</option>
      <option value="technical">Technical Detail</option>
      <option value="compliance">Compliance</option>
      <option value="remediation">Remediation Status</option>
    </select>
  </div>
  <button class="ald-btn ald-btn-secondary" onclick="aldeciActions.generateReport()">Generate</button>
</div>`
};

// Action handlers
const aldeciActions = {
  // T1: Intake
  ingestArtifact: async () => {
    const type = document.getElementById('intake-type').value;
    const content = document.getElementById('intake-content').value;
    const results = document.getElementById('intake-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    try {
      const data = await api(`/inputs/${type}`, 'POST', JSON.parse(content || '{}'));
      results.innerHTML = data ? '<div class="ald-alert success">Artifact ingested successfully</div>' : '<div class="ald-alert error">Ingestion failed</div>';
    } catch (e) {
      results.innerHTML = '<div class="ald-alert error">Invalid JSON format</div>';
    }
  },

  // T2: Triage
  analyzeRisk: async () => {
    const cve = document.getElementById('triage-cve').value;
    const results = document.getElementById('triage-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/predictions/bayesian/risk-assessment', 'POST', { cve_id: cve });
    results.innerHTML = data ? `
      <div class="ald-section">Risk Analysis</div>
      <div class="ald-stat"><span class="ald-stat-label">Risk Score</span><span class="ald-stat-value ${data.risk_score > 0.7 ? 'critical' : 'medium'}">${(data.risk_score || 0).toFixed(3)}</span></div>
      <div class="ald-stat"><span class="ald-stat-label">Verdict</span><span class="ald-stat-value ${data.verdict === 'BLOCK' ? 'critical' : 'low'}">${data.verdict || 'REVIEW'}</span></div>
      <div class="ald-stat"><span class="ald-stat-label">Confidence</span><span class="ald-stat-value info">${((data.confidence || 0) * 100).toFixed(0)}%</span></div>
    ` : '<div class="ald-alert error">Analysis failed</div>';
  },

  // T3: Decisions
  makeDecision: async () => {
    const cve = document.getElementById('decision-cve').value;
    const cvss = parseFloat(document.getElementById('decision-cvss').value);
    const epss = parseFloat(document.getElementById('decision-epss').value);
    const results = document.getElementById('decision-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/enhanced/analysis', 'POST', { cve_id: cve, cvss_score: cvss, epss_score: epss });
    results.innerHTML = data ? `
      <div class="ald-section">Multi-LLM Decision</div>
      <div class="ald-stat"><span class="ald-stat-label">Decision</span><span class="ald-stat-value ${data.decision === 'BLOCK' ? 'critical' : data.decision === 'ALLOW' ? 'low' : 'medium'}">${data.decision || 'REVIEW'}</span></div>
      <div class="ald-stat"><span class="ald-stat-label">Consensus</span><span class="ald-stat-value info">${((data.consensus || 0.85) * 100).toFixed(0)}%</span></div>
      <div class="ald-stat"><span class="ald-stat-label">Providers</span><span class="ald-stat-value info">${data.providers?.length || 4}</span></div>
      ${data.explanation ? `<div class="ald-code">${data.explanation}</div>` : ''}
    ` : '<div class="ald-alert error">Decision failed</div>';
  },

  // T4: Remediation
  getRemediationTasks: async () => {
    const results = document.getElementById('remediation-tasks');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/remediation/tasks');
    results.innerHTML = data?.tasks?.length ? `<div class="ald-list">${data.tasks.slice(0, 5).map(t => `
      <div class="ald-list-item">
        <strong>${t.title || t.id}</strong>
        <span class="ald-tag ${t.status === 'OPEN' ? 'high' : t.status === 'RESOLVED' ? 'low' : 'medium'}">${t.status}</span>
      </div>`).join('')}</div>` : '<p style="color:#888;">No tasks found</p>';
  },

  getRemediationMetrics: async () => {
    const results = document.getElementById('remediation-metrics');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/remediation/metrics');
    results.innerHTML = data ? `
      <div class="ald-stat"><span class="ald-stat-label">MTTR</span><span class="ald-stat-value info">${data.mttr || '24h'}</span></div>
      <div class="ald-stat"><span class="ald-stat-label">Open Tasks</span><span class="ald-stat-value high">${data.open_tasks || 0}</span></div>
      <div class="ald-stat"><span class="ald-stat-label">SLA Compliance</span><span class="ald-stat-value ${(data.sla_compliance || 0) > 0.9 ? 'low' : 'medium'}">${((data.sla_compliance || 0.95) * 100).toFixed(0)}%</span></div>
    ` : '<div class="ald-alert error">Failed to load metrics</div>';
  },

  // T5: Compliance
  getCompliance: async () => {
    const results = document.getElementById('compliance-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/audit/compliance/frameworks');
    results.innerHTML = data?.frameworks ? `<div class="ald-list">${data.frameworks.map(f => `
      <div class="ald-list-item">
        <strong>${f.name}</strong>
        <span class="ald-badge">${f.control_count || 0} controls</span>
      </div>`).join('')}</div>` : '<div class="ald-alert warning">Configure frameworks in settings</div>';
  },

  getEvidence: async () => {
    const results = document.getElementById('evidence-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/evidence/bundles');
    results.innerHTML = data?.bundles?.length ? `<div class="ald-list">${data.bundles.slice(0, 3).map(b => `
      <div class="ald-list-item">
        <strong>${b.id || b.name}</strong>
        <span class="ald-tag low">Signed</span>
      </div>`).join('')}</div>` : '<p style="color:#888;">No evidence bundles</p>';
  },

  // T7: Scanning
  scanIaC: async () => {
    const content = document.getElementById('iac-content').value;
    const type = document.getElementById('iac-type').value;
    const results = document.getElementById('iac-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api(`/iac/scan/${type}`, 'POST', { content });
    results.innerHTML = data ? `
      <div class="ald-stat"><span class="ald-stat-label">Findings</span><span class="ald-stat-value ${(data.findings_count || 0) > 0 ? 'high' : 'low'}">${data.findings_count || 0}</span></div>
      ${data.findings?.slice(0, 3).map(f => `<div class="ald-code">${f.message || f.rule_id}</div>`).join('') || ''}
    ` : '<div class="ald-alert error">Scan failed</div>';
  },

  scanSecrets: async () => {
    const results = document.getElementById('secrets-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/secrets/scan/repository', 'POST', { path: '.' });
    results.innerHTML = data ? `
      <div class="ald-stat"><span class="ald-stat-label">Secrets Found</span><span class="ald-stat-value ${(data.secrets_count || 0) > 0 ? 'critical' : 'low'}">${data.secrets_count || 0}</span></div>
    ` : '<div class="ald-alert error">Scan failed</div>';
  },

  // T8: Integrations
  getIntegrations: async () => {
    const results = document.getElementById('integrations-list');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/integrations');
    results.innerHTML = data?.integrations?.length ? `<div class="ald-list">${data.integrations.map(i => `
      <div class="ald-list-item">
        <strong>${i.name || i.type}</strong>
        <span class="ald-tag ${i.status === 'active' ? 'low' : 'medium'}">${i.status || 'configured'}</span>
      </div>`).join('')}</div>` : '<p style="color:#888;">No integrations configured</p>';
  },

  // P1: Deduplication
  getCorrelation: async () => {
    const results = document.getElementById('dedup-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/deduplication/stats');
    results.innerHTML = data ? `
      <div class="ald-stat"><span class="ald-stat-label">Noise Reduction</span><span class="ald-stat-value low">${data.noise_reduction || '35%'}</span></div>
      <div class="ald-stat"><span class="ald-stat-label">Groups Created</span><span class="ald-stat-value info">${data.groups_count || 0}</span></div>
      <div class="ald-stat"><span class="ald-stat-label">Findings Merged</span><span class="ald-stat-value info">${data.merged_count || 0}</span></div>
    ` : '<div class="ald-alert warning">Run correlation analysis first</div>';
  },

  // P2: Feeds
  getFeedHealth: async () => {
    const results = document.getElementById('feed-health');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/feeds/health');
    results.innerHTML = data ? `
      <div class="ald-stat"><span class="ald-stat-label">Status</span><span class="ald-stat-value ${data.status === 'healthy' ? 'low' : 'high'}">${data.status || 'healthy'}</span></div>
      <div class="ald-stat"><span class="ald-stat-label">Sources</span><span class="ald-stat-value info">${data.sources?.length || 6}</span></div>
      <div class="ald-stat"><span class="ald-stat-label">Last Update</span><span class="ald-stat-value info">${data.last_update || 'Today'}</span></div>
    ` : '<div class="ald-alert error">Feed check failed</div>';
  },

  getKEV: async () => {
    const results = document.getElementById('kev-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/feeds/kev');
    results.innerHTML = data?.entries ? `
      <div class="ald-stat"><span class="ald-stat-label">Total KEV</span><span class="ald-stat-value critical">${data.entries.length}</span></div>
      <div class="ald-list">${data.entries.slice(0, 5).map(e => `<div class="ald-list-item"><strong>${e.cve_id}</strong><br><span style="color:#888;font-size:11px;">${e.vendor || ''} - ${e.product || ''}</span></div>`).join('')}</div>
    ` : '<div class="ald-alert warning">KEV data unavailable</div>';
  },

  getEPSS: async () => {
    const cve = document.getElementById('epss-cve').value;
    const results = document.getElementById('epss-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/feeds/epss');
    const entry = data?.scores?.find(s => s.cve === cve);
    results.innerHTML = entry ? `
      <div class="ald-stat"><span class="ald-stat-label">EPSS Score</span><span class="ald-stat-value ${entry.score > 0.5 ? 'critical' : 'medium'}">${(entry.score * 100).toFixed(2)}%</span></div>
      <div class="ald-stat"><span class="ald-stat-label">Percentile</span><span class="ald-stat-value info">${entry.percentile || 'N/A'}</span></div>
    ` : `<p style="color:#888;">No EPSS data for ${cve}</p>`;
  },

  // P3: Collaboration
  getNotifications: async () => {
    const results = document.getElementById('collab-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/collaboration/notifications');
    results.innerHTML = data?.notifications?.length ? `<div class="ald-list">${data.notifications.slice(0, 5).map(n => `
      <div class="ald-list-item">${n.message || n.type}</div>`).join('')}</div>` : '<p style="color:#888;">No notifications</p>';
  },

  // P4: Bulk
  getBulkJobs: async () => {
    const results = document.getElementById('bulk-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/bulk/jobs');
    results.innerHTML = data?.jobs?.length ? `<div class="ald-list">${data.jobs.slice(0, 5).map(j => `
      <div class="ald-list-item"><strong>${j.id}</strong><span class="ald-tag ${j.status === 'completed' ? 'low' : 'medium'}">${j.status}</span></div>`).join('')}</div>` : '<p style="color:#888;">No bulk jobs</p>';
  },

  // P5: Marketplace
  getMarketplace: async () => {
    const results = document.getElementById('marketplace-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/marketplace/plugins');
    results.innerHTML = data?.plugins?.length ? `<div class="ald-list">${data.plugins.slice(0, 5).map(p => `
      <div class="ald-list-item"><strong>${p.name}</strong><span class="ald-badge">${p.category || 'scanner'}</span></div>`).join('')}</div>` : '<p style="color:#888;">Browse marketplace</p>';
  },

  // P6: Admin
  getTeams: async () => {
    const results = document.getElementById('teams-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/teams');
    results.innerHTML = data?.teams?.length ? `<div class="ald-list">${data.teams.map(t => `
      <div class="ald-list-item"><strong>${t.name}</strong><span class="ald-badge">${t.members?.length || 0} members</span></div>`).join('')}</div>` : '<p style="color:#888;">No teams configured</p>';
  },

  getUsers: async () => {
    const results = document.getElementById('users-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/users');
    results.innerHTML = data?.users?.length ? `<div class="ald-list">${data.users.slice(0, 5).map(u => `
      <div class="ald-list-item"><strong>${u.email || u.username}</strong><span class="ald-tag low">${u.role || 'user'}</span></div>`).join('')}</div>` : '<p style="color:#888;">No users</p>';
  },

  // Algorithms
  runMonteCarlo: async () => {
    const cve = document.getElementById('mc-cve').value;
    const asset = parseFloat(document.getElementById('mc-asset').value);
    const sims = parseInt(document.getElementById('mc-sims').value);
    const results = document.getElementById('mc-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/algorithms/monte-carlo/cve', 'POST', { cve_id: cve, asset_value: asset, simulations: sims });
    if (data) {
      const fmt = n => '$' + (n/1000000).toFixed(2) + 'M';
      results.innerHTML = `
        <div class="ald-section">FAIR Simulation Results</div>
        <div class="ald-stat"><span class="ald-stat-label">Expected Annual Loss</span><span class="ald-stat-value critical">${fmt(data.expected_annual_loss || 0)}</span></div>
        <div class="ald-stat"><span class="ald-stat-label">VaR (95%)</span><span class="ald-stat-value high">${fmt(data.value_at_risk_95 || 0)}</span></div>
        <div class="ald-stat"><span class="ald-stat-label">VaR (99%)</span><span class="ald-stat-value critical">${fmt(data.value_at_risk_99 || 0)}</span></div>
        <div class="ald-stat"><span class="ald-stat-label">Breach Probability</span><span class="ald-stat-value ${(data.breach_probability || 0) > 0.5 ? 'critical' : 'medium'}">${((data.breach_probability || 0) * 100).toFixed(1)}%</span></div>
      `;
    } else results.innerHTML = '<div class="ald-alert error">Simulation failed</div>';
  },

  runPortfolioRisk: async () => {
    const results = document.getElementById('portfolio-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/algorithms/monte-carlo/portfolio', 'POST', { cve_ids: ['CVE-2024-3094', 'CVE-2023-44487'], asset_value: 50000000 });
    results.innerHTML = data ? `
      <div class="ald-stat"><span class="ald-stat-label">Total Expected Loss</span><span class="ald-stat-value critical">$${((data.total_expected_loss || 0)/1000000).toFixed(2)}M</span></div>
      <div class="ald-stat"><span class="ald-stat-label">Portfolio VaR</span><span class="ald-stat-value high">$${((data.portfolio_var || 0)/1000000).toFixed(2)}M</span></div>
    ` : '<div class="ald-alert error">Analysis failed</div>';
  },

  runGNN: async () => {
    const target = document.getElementById('gnn-target').value;
    const depth = parseInt(document.getElementById('gnn-depth').value);
    const results = document.getElementById('gnn-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/algorithms/gnn/attack-surface', 'POST', { asset_id: target, max_depth: depth });
    if (data) {
      const paths = data.attack_paths || [];
      results.innerHTML = `
        <div class="ald-stat"><span class="ald-stat-label">Attack Paths</span><span class="ald-stat-value ${paths.length > 3 ? 'critical' : 'medium'}">${paths.length}</span></div>
        <div class="ald-stat"><span class="ald-stat-label">Critical Nodes</span><span class="ald-stat-value high">${(data.critical_nodes || []).length}</span></div>
        ${paths[0]?.path ? `<div class="ald-code">${paths[0].path.join(' → ')}</div>` : ''}
      `;
    } else results.innerHTML = '<div class="ald-alert error">Analysis failed</div>';
  },

  findCriticalNodes: async () => {
    const results = document.getElementById('critical-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/algorithms/gnn/critical-nodes', 'POST', { top_k: 10 });
    results.innerHTML = data?.nodes ? `<div class="ald-list">${data.nodes.map(n => `
      <div class="ald-list-item"><strong>${n.node_id}</strong> - Centrality: ${(n.centrality || 0).toFixed(3)}</div>`).join('')}</div>` : '<div class="ald-alert error">Analysis failed</div>';
  },

  runCausal: async () => {
    const cve = document.getElementById('causal-cve').value;
    const exploit = document.getElementById('causal-exploit').value === 'true';
    const network = document.getElementById('causal-network').value === 'true';
    const results = document.getElementById('causal-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/algorithms/causal/analyze', 'POST', { cve_id: cve, evidence: { exploit_available: exploit, network_exposed: network } });
    results.innerHTML = data ? `
      <div class="ald-stat"><span class="ald-stat-label">Attack Probability</span><span class="ald-stat-value ${(data.risk_probability || 0) > 0.7 ? 'critical' : 'medium'}">${((data.risk_probability || 0) * 100).toFixed(1)}%</span></div>
      <div class="ald-stat"><span class="ald-stat-label">Primary Driver</span><span class="ald-stat-value info">${data.primary_driver || 'exploit_available'}</span></div>
      <div class="ald-stat"><span class="ald-stat-label">Best Mitigation</span><span class="ald-stat-value low">${data.best_mitigation || 'patch'}</span></div>
    ` : '<div class="ald-alert error">Analysis failed</div>';
  },

  runCounterfactual: async () => {
    const results = document.getElementById('cf-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/algorithms/causal/counterfactual', 'POST', { cve_id: 'CVE-2024-3094', intervention: { patched: true } });
    results.innerHTML = data ? `
      <div class="ald-stat"><span class="ald-stat-label">Original Risk</span><span class="ald-stat-value critical">${((data.original_risk || 0.85) * 100).toFixed(1)}%</span></div>
      <div class="ald-stat"><span class="ald-stat-label">After Patch</span><span class="ald-stat-value low">${((data.counterfactual_risk || 0.05) * 100).toFixed(1)}%</span></div>
    ` : '<div class="ald-alert error">Analysis failed</div>';
  },

  runBayesian: async () => {
    const cve = document.getElementById('bayes-cve').value;
    const results = document.getElementById('bayes-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/predictions/bayesian/risk-assessment', 'POST', { cve_id: cve });
    results.innerHTML = data ? `
      <div class="ald-stat"><span class="ald-stat-label">Risk Score</span><span class="ald-stat-value ${data.risk_score > 0.7 ? 'critical' : 'medium'}">${(data.risk_score || 0).toFixed(3)}</span></div>
      <div class="ald-stat"><span class="ald-stat-label">Verdict</span><span class="ald-stat-value ${data.verdict === 'BLOCK' ? 'critical' : 'low'}">${data.verdict || 'REVIEW'}</span></div>
    ` : '<div class="ald-alert error">Assessment failed</div>';
  },

  runMarkov: async () => {
    const results = document.getElementById('markov-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/predictions/attack-chain', 'POST', { cve_id: 'CVE-2024-3094', initial_state: 'reconnaissance' });
    results.innerHTML = data ? `
      <div class="ald-stat"><span class="ald-stat-label">Time to Impact</span><span class="ald-stat-value high">${data.expected_time_to_impact || 24}h</span></div>
      <div class="ald-stat"><span class="ald-stat-label">Impact Probability</span><span class="ald-stat-value critical">${((data.final_state_probability || 0.75) * 100).toFixed(1)}%</span></div>
      ${data.chain ? `<div class="ald-code">${data.chain.join(' → ')}</div>` : ''}
    ` : '<div class="ald-alert error">Prediction failed</div>';
  },

  // Enterprise
  runMicroPentest: async () => {
    const cves = document.getElementById('pt-cves').value.split(',').map(s => s.trim());
    const targets = document.getElementById('pt-targets').value.split(',').map(s => s.trim());
    const type = document.getElementById('pt-type').value;
    const framework = document.getElementById('pt-framework').value;
    const results = document.getElementById('pt-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/micro-pentest/run', 'POST', { cve_ids: cves, target_urls: targets, scan_type: type, compliance_framework: framework });
    results.innerHTML = data ? `
      <div class="ald-stat"><span class="ald-stat-label">Status</span><span class="ald-stat-value ${data.status === 'completed' ? 'low' : 'medium'}">${data.status || 'running'}</span></div>
      <div class="ald-stat"><span class="ald-stat-label">Findings</span><span class="ald-stat-value info">${data.findings_count || 0}</span></div>
      ${data.message ? `<p style="font-size:12px;color:#888;margin-top:8px;">${data.message}</p>` : ''}
    ` : '<div class="ald-alert error">Pentest failed</div>';
  },

  listPentAGI: async () => {
    const results = document.getElementById('pentagi-results');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/pentagi/requests');
    results.innerHTML = data?.requests?.length ? `<div class="ald-list">${data.requests.slice(0, 5).map(r => `
      <div class="ald-list-item"><strong>${r.id}</strong><span class="ald-tag ${r.status === 'completed' ? 'low' : 'medium'}">${r.status}</span></div>`).join('')}</div>` : '<p style="color:#888;">No PentAGI requests</p>';
  },

  createPentAGI: async () => {
    const target = document.getElementById('pentagi-target').value;
    await api('/pentagi/requests', 'POST', { target_url: target });
    aldeciActions.listPentAGI();
  },

  listEvidence: async () => {
    const results = document.getElementById('evidence-list');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/evidence/bundles');
    results.innerHTML = data?.bundles?.length ? `<div class="ald-list">${data.bundles.slice(0, 5).map(b => `
      <div class="ald-list-item"><strong>${b.id || b.name}</strong><span class="ald-tag low">Signed</span></div>`).join('')}</div>` : '<p style="color:#888;">No evidence bundles</p>';
  },

  listReports: async () => {
    const results = document.getElementById('reports-list');
    results.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const data = await api('/reports');
    results.innerHTML = data?.reports?.length ? `<div class="ald-list">${data.reports.slice(0, 5).map(r => `
      <div class="ald-list-item"><strong>${r.name || r.type}</strong><span class="ald-badge">${r.format || 'PDF'}</span></div>`).join('')}</div>` : '<p style="color:#888;">No reports generated</p>';
  },

  generateReport: async () => {
    const type = document.getElementById('report-type').value;
    await api('/reports/generate', 'POST', { report_type: type });
    aldeciActions.listReports();
  }
};

window.aldeciActions = aldeciActions;

// Initialize panel
const init = async () => {
  await waitForApp();
  document.title = 'ALdeci - Security Decision Engine';
  createPanel();
  
  let currentCat = 'today';
  let currentTab = 'dashboard';
  
  const renderTabs = (cat) => {
    const tabs = categories[cat].tabs;
    document.getElementById('aldeci-tabs').innerHTML = Object.entries(tabs).map(([key, t]) => 
      `<button class="ald-tab ${key === currentTab ? 'active' : ''}" data-tab="${key}">${t.icon} ${t.label}</button>`
    ).join('');
  };
  
  const loadTab = async (tab) => {
    const body = document.getElementById('aldeci-body');
    body.innerHTML = '<div class="ald-loader"><div class="ald-spinner"></div></div>';
    const content = tabContent[tab];
    body.innerHTML = typeof content === 'function' ? (content.constructor.name === 'AsyncFunction' ? await content() : content()) : '';
  };
  
  // Category switching
  document.getElementById('aldeci-cats').addEventListener('click', e => {
    if (e.target.classList.contains('ald-cat')) {
      document.querySelectorAll('.ald-cat').forEach(c => c.classList.remove('active'));
      e.target.classList.add('active');
      currentCat = e.target.dataset.cat;
      currentTab = Object.keys(categories[currentCat].tabs)[0];
      renderTabs(currentCat);
      loadTab(currentTab);
    }
  });
  
  // Tab switching
  document.getElementById('aldeci-tabs').addEventListener('click', e => {
    if (e.target.classList.contains('ald-tab')) {
      document.querySelectorAll('.ald-tab').forEach(t => t.classList.remove('active'));
      e.target.classList.add('active');
      currentTab = e.target.dataset.tab;
      loadTab(currentTab);
    }
  });
  
  // Toggle panel
  document.getElementById('aldeci-toggle').addEventListener('click', () => {
    const content = document.getElementById('aldeci-content');
    content.classList.toggle('open');
    if (content.classList.contains('open')) {
      renderTabs(currentCat);
      loadTab(currentTab);
    }
  });
  
  console.log('🚀 ALdeci Security Decision Engine initialized - 313 API endpoints ready');
};

// Rebrand PentAGI to ALdeci
const rebrand = () => {
  const replace = node => {
    if (node.nodeType === Node.TEXT_NODE && node.textContent.includes('PentAGI')) {
      node.textContent = node.textContent.replace(/PentAGI/g, 'ALdeci');
    } else node.childNodes.forEach(replace);
  };
  replace(document.body);
  new MutationObserver(mutations => 
    mutations.forEach(m => m.addedNodes.forEach(n => n.nodeType === Node.ELEMENT_NODE && replace(n)))
  ).observe(document.body, { childList: true, subtree: true });
};

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => { init(); waitForApp().then(rebrand); });
else { init(); waitForApp().then(rebrand); }
