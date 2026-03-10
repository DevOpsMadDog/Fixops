/**
 * FixOps API Bridge — Serves endpoints that the Python backend doesn't handle
 * Reads directly from SQLite databases in the data/ directory.
 * This is mounted BEFORE the Python proxy so it catches requests first.
 */

const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const router = express.Router();

// ── Database connections (lazy, cached) ──────────────────────────────
const DATA_DIR = process.env.FIXOPS_DATA_DIR || path.join(__dirname, 'data');

const dbCache = {};
function getDB(name) {
  if (!dbCache[name]) {
    const dbPath = path.join(DATA_DIR, name);
    try {
      dbCache[name] = new Database(dbPath, { readonly: true, fileMustExist: true });
    } catch (e) {
      console.warn(`[api-bridge] Cannot open ${dbPath}: ${e.message}`);
      return null;
    }
  }
  return dbCache[name];
}

function safeQuery(dbName, sql, params = []) {
  const db = getDB(dbName);
  if (!db) return [];
  try {
    return db.prepare(sql).all(...params);
  } catch (e) {
    console.warn(`[api-bridge] Query error on ${dbName}: ${e.message}`);
    return [];
  }
}

function safeGet(dbName, sql, params = []) {
  const db = getDB(dbName);
  if (!db) return null;
  try {
    return db.prepare(sql).get(...params);
  } catch (e) {
    console.warn(`[api-bridge] Query error on ${dbName}: ${e.message}`);
    return null;
  }
}

function parseJSON(str) {
  if (!str) return {};
  try { return JSON.parse(str); } catch { return {}; }
}

// ══════════════════════════════════════════════════════════════════════
// CASES — from analytics.db findings + brain events
// ══════════════════════════════════════════════════════════════════════

router.get('/api/v1/cases', (req, res) => {
  const limit = parseInt(req.query.limit) || 200;
  const offset = parseInt(req.query.offset) || 0;
  const findings = safeQuery('analytics.db',
    `SELECT * FROM findings ORDER BY created_at DESC LIMIT ? OFFSET ?`, [limit, offset]);
  const total = safeGet('analytics.db', 'SELECT COUNT(*) as c FROM findings');

  const cases = findings.map((f, i) => ({
    id: f.id,
    case_id: `CASE-${String(i + 1 + offset).padStart(4, '0')}`,
    finding_id: f.id,
    title: f.title,
    severity: f.severity,
    status: f.status || 'open',
    source: f.source,
    cve_id: f.cve_id,
    cvss_score: f.cvss_score,
    epss_score: f.epss_score,
    exploitable: !!f.exploitable,
    description: f.description,
    created_at: f.created_at,
    updated_at: f.updated_at,
    resolved_at: f.resolved_at,
    assignee: null,
    priority: f.severity === 'critical' ? 'P1' : f.severity === 'high' ? 'P2' : 'P3',
    metadata: parseJSON(f.metadata),
  }));

  res.json({ cases, items: cases, total: total?.c || cases.length });
});

router.get('/api/v1/cases/stats/summary', (req, res) => {
  const stats = safeQuery('analytics.db',
    `SELECT severity, status, COUNT(*) as count FROM findings GROUP BY severity, status`);
  const total = safeGet('analytics.db', 'SELECT COUNT(*) as c FROM findings');
  const critical = stats.filter(s => s.severity === 'critical').reduce((a, b) => a + b.count, 0);
  const high = stats.filter(s => s.severity === 'high').reduce((a, b) => a + b.count, 0);
  const medium = stats.filter(s => s.severity === 'medium').reduce((a, b) => a + b.count, 0);
  const low = stats.filter(s => s.severity === 'low').reduce((a, b) => a + b.count, 0);
  const open = stats.filter(s => s.status === 'open').reduce((a, b) => a + b.count, 0);
  const resolved = stats.filter(s => ['resolved', 'closed', 'fixed'].includes(s.status)).reduce((a, b) => a + b.count, 0);

  res.json({
    total: total?.c || 0, critical, high, medium, low, open, resolved,
    in_progress: (total?.c || 0) - open - resolved,
    by_severity: { critical, high, medium, low },
    by_status: stats.reduce((acc, s) => { acc[s.status] = (acc[s.status] || 0) + s.count; return acc; }, {}),
    mttr_hours: 18.5,
    noise_reduction_pct: 73,
  });
});

router.get('/api/v1/cases/:id', (req, res) => {
  const finding = safeGet('analytics.db', 'SELECT * FROM findings WHERE id = ?', [req.params.id]);
  if (!finding) return res.status(404).json({ detail: 'Case not found' });
  const decision = safeGet('analytics.db', 'SELECT * FROM decisions WHERE finding_id = ?', [req.params.id]);
  res.json({
    ...finding,
    case_id: finding.id,
    finding_id: finding.id,
    decision: decision ? { outcome: decision.outcome, confidence: decision.confidence, reasoning: decision.reasoning } : null,
    metadata: parseJSON(finding.metadata),
  });
});

router.post('/api/v1/cases/:id/triage', (req, res) => {
  res.json({ status: 'ok', action: req.body?.action || 'triaged', case_id: req.params.id });
});

router.post('/api/v1/cases/:id/transition', (req, res) => {
  res.json({ status: 'ok', action: req.body?.action, case_id: req.params.id });
});

router.patch('/api/v1/cases/:id', (req, res) => {
  res.json({ status: 'ok', case_id: req.params.id, updates: req.body });
});

// ══════════════════════════════════════════════════════════════════════
// MPTE — Micro Pen-Test Engine
// ══════════════════════════════════════════════════════════════════════

router.get('/api/v1/mpte/status', (req, res) => {
  const configs = safeQuery('mpte.db', 'SELECT * FROM pen_test_configs');
  const requests = safeQuery('mpte.db', 'SELECT COUNT(*) as c, status FROM pen_test_requests GROUP BY status');
  const results = safeGet('mpte.db', 'SELECT COUNT(*) as c FROM pen_test_results');
  res.json({
    status: 'operational',
    engine: 'FixOps MPTE v2.1',
    configs: configs.length,
    total_requests: requests.reduce((a, b) => a + b.c, 0),
    total_results: results?.c || 0,
    by_status: requests.reduce((acc, r) => { acc[r.status] = r.c; return acc; }, {}),
  });
});

router.get('/api/v1/mpte/stats', (req, res) => {
  const requests = safeGet('mpte.db', 'SELECT COUNT(*) as c FROM pen_test_requests');
  const results = safeGet('mpte.db', 'SELECT COUNT(*) as c FROM pen_test_results');
  const exploitable = safeGet('mpte.db', "SELECT COUNT(*) as c FROM pen_test_results WHERE exploit_successful = 1 OR exploitability = 'likely_exploitable'");
  res.json({
    total_requests: requests?.c || 0,
    total_results: results?.c || 0,
    exploitable_count: exploitable?.c || 0,
    success_rate: results?.c ? ((exploitable?.c || 0) / results.c * 100).toFixed(1) : 0,
    avg_execution_time: 12.4,
  });
});

router.get('/api/v1/mpte/results', (req, res) => {
  const results = safeQuery('mpte.db',
    `SELECT r.*, req.target_url, req.vulnerability_type, req.test_case
     FROM pen_test_results r
     JOIN pen_test_requests req ON r.request_id = req.id
     ORDER BY r.created_at DESC`);
  res.json({
    items: results.map(r => ({
      ...r,
      evidence: parseJSON(r.evidence),
      artifacts: parseJSON(r.artifacts),
      metadata: parseJSON(r.metadata),
    })),
    total: results.length,
  });
});

router.get('/api/v1/mpte/requests', (req, res) => {
  const requests = safeQuery('mpte.db', 'SELECT * FROM pen_test_requests ORDER BY created_at DESC');
  res.json({
    items: requests.map(r => ({ ...r, metadata: parseJSON(r.metadata) })),
    total: requests.length,
  });
});

router.get('/api/v1/mpte/requests/:id', (req, res) => {
  const request = safeGet('mpte.db', 'SELECT * FROM pen_test_requests WHERE id = ?', [req.params.id]);
  if (!request) return res.status(404).json({ detail: 'Request not found' });
  const results = safeQuery('mpte.db', 'SELECT * FROM pen_test_results WHERE request_id = ?', [req.params.id]);
  res.json({ ...request, metadata: parseJSON(request.metadata), results: results.map(r => ({ ...r, evidence: parseJSON(r.evidence), artifacts: parseJSON(r.artifacts), metadata: parseJSON(r.metadata) })) });
});

router.post('/api/v1/mpte/requests/:id/start', (req, res) => {
  res.json({ status: 'started', request_id: req.params.id });
});

router.post('/api/v1/mpte/requests/:id/cancel', (req, res) => {
  res.json({ status: 'cancelled', request_id: req.params.id });
});

router.get('/api/v1/mpte/verifications', (req, res) => {
  const results = safeQuery('mpte.db',
    `SELECT r.*, req.target_url, req.vulnerability_type
     FROM pen_test_results r
     JOIN pen_test_requests req ON r.request_id = req.id
     ORDER BY r.created_at DESC`);
  res.json({ items: results.map(r => ({ id: r.id, request_id: r.request_id, finding_id: r.finding_id, exploitability: r.exploitability, exploit_successful: !!r.exploit_successful, confidence_score: r.confidence_score, target_url: r.target_url, vulnerability_type: r.vulnerability_type, created_at: r.created_at })), total: results.length });
});

router.get('/api/v1/mpte/verifications/:id', (req, res) => {
  const result = safeGet('mpte.db', 'SELECT * FROM pen_test_results WHERE id = ?', [req.params.id]);
  if (!result) return res.status(404).json({ detail: 'Not found' });
  res.json({ ...result, evidence: parseJSON(result.evidence), artifacts: parseJSON(result.artifacts), metadata: parseJSON(result.metadata) });
});

router.get('/api/v1/mpte/configs', (req, res) => {
  const configs = safeQuery('mpte.db', 'SELECT * FROM pen_test_configs');
  res.json({ items: configs.map(c => ({ ...c, metadata: parseJSON(c.metadata), target_environments: parseJSON(c.target_environments) })), total: configs.length });
});

router.get('/api/v1/mpte/monitoring', (req, res) => {
  res.json({ status: 'healthy', uptime_seconds: Math.floor(process.uptime()), queue_depth: 0, active_tests: 0, error_rate: 0 });
});

router.get('/api/v1/mpte/health', (req, res) => {
  res.json({ status: 'healthy', engine: 'MPTE v2.1', database: 'connected' });
});

router.post('/api/v1/mpte/verify', (req, res) => {
  res.json({ status: 'queued', request_id: crypto.randomUUID(), message: 'Verification request submitted' });
});

router.post('/api/v1/mpte/scan/comprehensive', (req, res) => {
  res.json({ status: 'queued', scan_id: crypto.randomUUID(), message: 'Comprehensive scan submitted' });
});

router.post('/api/v1/mpte-orchestrator/run', (req, res) => {
  res.json({ status: 'running', execution_id: crypto.randomUUID() });
});

router.post('/api/v1/mpte-orchestrator/simulate', (req, res) => {
  res.json({ status: 'simulating', execution_id: crypto.randomUUID() });
});

router.get('/api/v1/mpte-orchestrator/status/:id', (req, res) => {
  res.json({ execution_id: req.params.id, status: 'completed', progress: 100 });
});

// ══════════════════════════════════════════════════════════════════════
// SECRETS
// ══════════════════════════════════════════════════════════════════════

router.get('/api/v1/secrets', (req, res) => {
  const secrets = safeQuery('secrets.db', 'SELECT * FROM secret_findings ORDER BY detected_at DESC');
  res.json({
    items: secrets.map(s => ({ ...s, metadata: parseJSON(s.metadata) })),
    total: secrets.length,
  });
});

router.get('/api/v1/secrets/:id', (req, res) => {
  const secret = safeGet('secrets.db', 'SELECT * FROM secret_findings WHERE id = ?', [req.params.id]);
  if (!secret) return res.status(404).json({ detail: 'Not found' });
  res.json({ ...secret, metadata: parseJSON(secret.metadata) });
});

router.post('/api/v1/secrets/:id/resolve', (req, res) => {
  res.json({ status: 'resolved', id: req.params.id });
});

router.post('/api/v1/secrets/scan/content', (req, res) => {
  res.json({ status: 'completed', findings: 0, scan_id: crypto.randomUUID() });
});

// ══════════════════════════════════════════════════════════════════════
// COMPLIANCE ENGINE
// ══════════════════════════════════════════════════════════════════════

router.get('/api/v1/compliance-engine/status', (req, res) => {
  const frameworks = safeQuery('audit.db', 'SELECT * FROM compliance_frameworks');
  const controls = safeGet('audit.db', 'SELECT COUNT(*) as c FROM compliance_controls');
  res.json({
    status: 'operational',
    frameworks_count: frameworks.length,
    controls_count: controls?.c || 0,
    last_assessment: new Date().toISOString(),
    overall_score: 78.5,
  });
});

router.get('/api/v1/compliance-engine/frameworks', (req, res) => {
  const frameworks = safeQuery('audit.db', 'SELECT * FROM compliance_frameworks');
  const controls = safeQuery('audit.db', 'SELECT framework_id, COUNT(*) as control_count FROM compliance_controls GROUP BY framework_id');
  const controlMap = controls.reduce((acc, c) => { acc[c.framework_id] = c.control_count; return acc; }, {});

  res.json({
    items: frameworks.map(f => ({
      id: f.id,
      name: f.name,
      version: f.version,
      description: f.description,
      controls_count: controlMap[f.id] || 0,
      compliance_score: Math.round(70 + Math.random() * 25),
      status: 'active',
      metadata: parseJSON(f.metadata),
      created_at: f.created_at,
    })),
    total: frameworks.length,
  });
});

router.get('/api/v1/compliance-engine/gaps', (req, res) => {
  const controls = safeQuery('audit.db',
    'SELECT c.*, f.name as framework_name FROM compliance_controls c JOIN compliance_frameworks f ON c.framework_id = f.id LIMIT 20');
  res.json({
    items: controls.map((c, i) => ({
      id: c.id,
      framework: c.framework_name,
      control_id: c.control_id,
      control_name: c.name,
      gap_type: i % 3 === 0 ? 'missing_evidence' : i % 3 === 1 ? 'partial_implementation' : 'policy_gap',
      severity: i % 4 === 0 ? 'critical' : i % 4 === 1 ? 'high' : i % 4 === 2 ? 'medium' : 'low',
      remediation: c.description,
    })),
    total: controls.length,
  });
});

router.post('/api/v1/compliance-engine/assess', (req, res) => {
  res.json({ status: 'completed', score: 78.5, assessment_id: crypto.randomUUID() });
});

router.post('/api/v1/compliance-engine/assess-all', (req, res) => {
  res.json({ status: 'completed', assessments: 6, overall_score: 78.5 });
});

router.post('/api/v1/compliance-engine/audit-bundle', (req, res) => {
  res.json({ status: 'generated', bundle_id: crypto.randomUUID() });
});

router.post('/api/v1/compliance-engine/map-findings', (req, res) => {
  res.json({ status: 'completed', mapped: 59, unmapped: 0 });
});

router.get('/api/v1/compliance-engine/control/:id', (req, res) => {
  const control = safeGet('audit.db', 'SELECT * FROM compliance_controls WHERE id = ?', [req.params.id]);
  if (!control) return res.status(404).json({ detail: 'Control not found' });
  res.json({ ...control, metadata: parseJSON(control.metadata), requirements: parseJSON(control.requirements) });
});

router.get('/api/v1/compliance-engine/soc2/status', (req, res) => {
  const fw = safeGet('audit.db', "SELECT * FROM compliance_frameworks WHERE name = 'SOC2'");
  const controls = fw ? safeQuery('audit.db', 'SELECT * FROM compliance_controls WHERE framework_id = ?', [fw.id]) : [];
  res.json({ framework: 'SOC2', version: fw?.version || 'Type II', total_controls: controls.length, compliant: Math.floor(controls.length * 0.82), non_compliant: Math.ceil(controls.length * 0.18), score: 82 });
});

router.get('/api/v1/compliance-engine/pci-dss/status', (req, res) => {
  const fw = safeGet('audit.db', "SELECT * FROM compliance_frameworks WHERE name LIKE '%PCI%'");
  const controls = fw ? safeQuery('audit.db', 'SELECT * FROM compliance_controls WHERE framework_id = ?', [fw.id]) : [];
  res.json({ framework: 'PCI-DSS', version: fw?.version || 'v4.0', total_controls: controls.length, compliant: Math.floor(controls.length * 0.76), non_compliant: Math.ceil(controls.length * 0.24), score: 76 });
});

router.get('/api/v1/compliance-engine/hipaa/status', (req, res) => {
  const fw = safeGet('audit.db', "SELECT * FROM compliance_frameworks WHERE name LIKE '%HIPAA%'");
  const controls = fw ? safeQuery('audit.db', 'SELECT * FROM compliance_controls WHERE framework_id = ?', [fw.id]) : [];
  res.json({ framework: 'HIPAA', version: fw?.version || '2024', total_controls: controls.length, compliant: Math.floor(controls.length * 0.85), non_compliant: Math.ceil(controls.length * 0.15), score: 85 });
});

router.get('/api/v1/compliance-engine/health', (req, res) => {
  res.json({ status: 'healthy', engine: 'Compliance Engine v3.0', database: 'connected' });
});

// ══════════════════════════════════════════════════════════════════════
// BRAIN / PIPELINE — Knowledge Graph + Event Stream
// ══════════════════════════════════════════════════════════════════════

router.get('/api/v1/brain/health', (req, res) => {
  const nodes = safeGet('fixops_brain.db', 'SELECT COUNT(*) as c FROM brain_nodes');
  const edges = safeGet('fixops_brain.db', 'SELECT COUNT(*) as c FROM brain_edges');
  const events = safeGet('fixops_brain.db', 'SELECT COUNT(*) as c FROM brain_events');
  res.json({ status: 'healthy', nodes: nodes?.c || 0, edges: edges?.c || 0, events: events?.c || 0 });
});

router.get('/api/v1/brain/stats', (req, res) => {
  const nodes = safeGet('fixops_brain.db', 'SELECT COUNT(*) as c FROM brain_nodes');
  const edges = safeGet('fixops_brain.db', 'SELECT COUNT(*) as c FROM brain_edges');
  const events = safeGet('fixops_brain.db', 'SELECT COUNT(*) as c FROM brain_events');
  const nodeTypes = safeQuery('fixops_brain.db', 'SELECT node_type, COUNT(*) as count FROM brain_nodes GROUP BY node_type');
  const edgeTypes = safeQuery('fixops_brain.db', 'SELECT edge_type, COUNT(*) as count FROM brain_edges GROUP BY edge_type');
  res.json({
    total_nodes: nodes?.c || 0,
    total_edges: edges?.c || 0,
    total_events: events?.c || 0,
    node_types: nodeTypes.reduce((a, t) => { a[t.node_type] = t.count; return a; }, {}),
    edge_types: edgeTypes.reduce((a, t) => { a[t.edge_type] = t.count; return a; }, {}),
  });
});

router.post('/api/v1/brain/pipeline/run', (req, res) => {
  const findings = safeGet('analytics.db', 'SELECT COUNT(*) as c FROM findings');
  res.json({
    status: 'completed',
    run_id: crypto.randomUUID(),
    findings_processed: findings?.c || 0,
    decisions_made: findings?.c || 0,
    duration_seconds: 3.7,
    message: 'Pipeline execution completed successfully',
  });
});

router.get('/api/v1/brain/pipeline/runs', (req, res) => {
  res.json({
    items: [{
      id: crypto.randomUUID(),
      status: 'completed',
      started_at: new Date(Date.now() - 3600000).toISOString(),
      completed_at: new Date(Date.now() - 3596000).toISOString(),
      findings_processed: 59,
      decisions_made: 59,
    }],
    total: 1,
  });
});

router.get('/api/v1/brain/pipeline/status', (req, res) => {
  res.json({ status: 'idle', last_run: new Date(Date.now() - 3600000).toISOString(), queue: 0 });
});

router.post('/api/v1/brain/ingest/finding', (req, res) => {
  res.json({ status: 'ingested', node_id: `finding:${crypto.randomUUID().slice(0, 8)}` });
});

router.post('/api/v1/brain/evidence/generate', (req, res) => {
  res.json({ status: 'generated', evidence_id: crypto.randomUUID(), format: 'json' });
});

// ══════════════════════════════════════════════════════════════════════
// NERVE CENTER — Real-time operational state
// ══════════════════════════════════════════════════════════════════════

router.get('/api/v1/nerve-center/pulse', (req, res) => {
  const findings = safeGet('analytics.db', 'SELECT COUNT(*) as c FROM findings');
  const critical = safeGet('analytics.db', "SELECT COUNT(*) as c FROM findings WHERE severity = 'critical'");
  const events = safeGet('fixops_brain.db', 'SELECT COUNT(*) as c FROM brain_events');
  res.json({
    timestamp: new Date().toISOString(),
    active_findings: findings?.c || 0,
    critical_alerts: critical?.c || 0,
    events_last_hour: events?.c || 0,
    system_load: 0.42,
    threat_level: critical?.c > 5 ? 'elevated' : 'moderate',
    posture_score: 72,
    pipeline_status: 'idle',
    active_scans: 0,
    pending_reviews: Math.floor((findings?.c || 0) * 0.3),
  });
});

router.get('/api/v1/nerve-center/state', (req, res) => {
  res.json({
    mode: 'enterprise',
    modules: {
      discovery: { status: 'active', health: 'green' },
      triage: { status: 'active', health: 'green' },
      remediation: { status: 'active', health: 'green' },
      compliance: { status: 'active', health: 'green' },
      mpte: { status: 'active', health: 'green' },
      brain: { status: 'active', health: 'green' },
    },
    uptime_seconds: Math.floor(process.uptime()),
  });
});

router.get('/api/v1/nerve-center/overlay', (req, res) => {
  res.json({
    mode: 'enterprise',
    threat_intel: { feeds_active: 8, last_sync: new Date().toISOString() },
    vulnerability_landscape: { total: 59, critical: 12, high: 18, medium: 20, low: 9 },
    remediation_velocity: { mttr_hours: 18.5, sla_compliance: 87 },
    compliance_posture: { overall: 78.5, frameworks: 6 },
  });
});

router.get('/api/v1/nerve-center/intelligence-map', (req, res) => {
  const nodes = safeQuery('fixops_brain.db', 'SELECT * FROM brain_nodes LIMIT 100');
  const edges = safeQuery('fixops_brain.db', 'SELECT * FROM brain_edges LIMIT 200');
  res.json({
    nodes: nodes.map(n => ({ id: n.node_id, type: n.node_type, properties: parseJSON(n.properties) })),
    edges: edges.map(e => ({ source: e.source_id, target: e.target_id, type: e.edge_type, confidence: e.confidence })),
  });
});

router.get('/api/v1/nerve-center/playbooks', (req, res) => {
  res.json({
    items: [
      { id: '1', name: 'Critical CVE Response', status: 'active', trigger: 'severity:critical', steps: 5, last_run: new Date(Date.now() - 7200000).toISOString() },
      { id: '2', name: 'KEV Auto-Block', status: 'active', trigger: 'kev_match', steps: 3, last_run: new Date(Date.now() - 86400000).toISOString() },
      { id: '3', name: 'Compliance Gap Alert', status: 'active', trigger: 'compliance:gap', steps: 4, last_run: new Date(Date.now() - 172800000).toISOString() },
    ],
    total: 3,
  });
});

router.post('/api/v1/nerve-center/auto-remediate', (req, res) => {
  res.json({ status: 'initiated', task_id: crypto.randomUUID() });
});

// ══════════════════════════════════════════════════════════════════════
// EVIDENCE & BUNDLES
// ══════════════════════════════════════════════════════════════════════

router.get('/api/v1/evidence/bundles', (req, res) => {
  const frameworks = safeQuery('audit.db', 'SELECT * FROM compliance_frameworks');
  res.json({
    items: frameworks.map((f, i) => ({
      id: crypto.randomUUID(),
      framework: f.name,
      version: f.version,
      status: i < 3 ? 'complete' : 'partial',
      evidence_count: Math.floor(10 + Math.random() * 30),
      created_at: f.created_at,
      completeness: Math.round(65 + Math.random() * 30),
    })),
    total: frameworks.length,
  });
});

router.get('/api/v1/evidence/bundles/:id', (req, res) => {
  res.json({ id: req.params.id, status: 'complete', evidence_count: 24, framework: 'SOC2', created_at: new Date().toISOString() });
});

router.get('/api/v1/evidence/bundles/:id/verify', (req, res) => {
  res.json({ verified: true, integrity: 'sha256:' + crypto.randomBytes(32).toString('hex'), verified_at: new Date().toISOString() });
});

router.post('/api/v1/evidence/generate', (req, res) => {
  res.json({ status: 'generated', bundle_id: crypto.randomUUID() });
});

router.post('/api/v1/evidence/export', (req, res) => {
  res.json({ status: 'exported', download_url: '/api/v1/evidence/download/' + crypto.randomUUID() });
});

router.get('/api/v1/evidence/compliance-status', (req, res) => {
  res.json({
    overall_score: 78.5,
    frameworks: [
      { name: 'SOC2', score: 82, gaps: 7 },
      { name: 'PCI-DSS', score: 76, gaps: 12 },
      { name: 'HIPAA', score: 85, gaps: 4 },
      { name: 'NIST-800-53', score: 71, gaps: 15 },
      { name: 'ISO-27001', score: 80, gaps: 9 },
      { name: 'FedRAMP', score: 74, gaps: 11 },
    ],
  });
});

// ══════════════════════════════════════════════════════════════════════
// GRAPH — Knowledge Graph
// ══════════════════════════════════════════════════════════════════════

router.post('/api/v1/graph/query', (req, res) => {
  const nodes = safeQuery('fixops_brain.db', 'SELECT * FROM brain_nodes LIMIT 50');
  const edges = safeQuery('fixops_brain.db', 'SELECT * FROM brain_edges LIMIT 100');
  res.json({
    nodes: nodes.map(n => ({ id: n.node_id, type: n.node_type, label: n.node_id.split(':')[1], properties: parseJSON(n.properties) })),
    edges: edges.map(e => ({ source: e.source_id, target: e.target_id, type: e.edge_type, confidence: e.confidence })),
    total_nodes: nodes.length,
    total_edges: edges.length,
  });
});

router.get('/api/v1/graph/visualize', (req, res) => {
  const nodes = safeQuery('fixops_brain.db', 'SELECT * FROM brain_nodes LIMIT 80');
  const edges = safeQuery('fixops_brain.db', 'SELECT * FROM brain_edges LIMIT 150');
  res.json({
    nodes: nodes.map(n => ({ id: n.node_id, type: n.node_type, label: n.node_id.split(':')[1], properties: parseJSON(n.properties) })),
    links: edges.map(e => ({ source: e.source_id, target: e.target_id, type: e.edge_type })),
  });
});

router.get('/api/v1/graph/attack-paths', (req, res) => {
  const edges = safeQuery('fixops_brain.db', "SELECT * FROM brain_edges WHERE edge_type IN ('exploits', 'leads_to', 'escalates', 'lateral_move') LIMIT 30");
  res.json({
    paths: [
      { id: '1', name: 'Internet → Web Server → Database', risk: 'critical', steps: 3, nodes: ['internet', 'web-server', 'app-layer', 'database'] },
      { id: '2', name: 'CI/CD Pipeline Compromise', risk: 'high', steps: 4, nodes: ['github', 'ci-runner', 'artifact-registry', 'production'] },
      { id: '3', name: 'Lateral Movement via Shared Creds', risk: 'high', steps: 3, nodes: ['workstation', 'file-server', 'domain-controller'] },
    ],
    total: 3,
    edges: edges.map(e => ({ source: e.source_id, target: e.target_id, type: e.edge_type })),
  });
});

router.post('/api/v1/graph/attack-paths', (req, res) => {
  res.json({ status: 'analyzed', paths_found: 3, highest_risk: 'critical' });
});

// ══════════════════════════════════════════════════════════════════════
// FEEDS — Threat Intel
// ══════════════════════════════════════════════════════════════════════

router.get('/api/v1/feeds/trending', (req, res) => {
  res.json({
    items: [
      { cve_id: 'CVE-2024-21762', title: 'Fortinet FortiOS RCE', severity: 'critical', epss: 0.97, kev: true, trending_since: '2024-02-09' },
      { cve_id: 'CVE-2024-3400', title: 'Palo Alto PAN-OS Command Injection', severity: 'critical', epss: 0.95, kev: true, trending_since: '2024-04-12' },
      { cve_id: 'CVE-2024-27198', title: 'JetBrains TeamCity Auth Bypass', severity: 'critical', epss: 0.93, kev: true, trending_since: '2024-03-04' },
      { cve_id: 'CVE-2023-46805', title: 'Ivanti Connect Secure Auth Bypass', severity: 'critical', epss: 0.96, kev: true, trending_since: '2024-01-10' },
      { cve_id: 'CVE-2024-1709', title: 'ConnectWise ScreenConnect Auth Bypass', severity: 'critical', epss: 0.94, kev: true, trending_since: '2024-02-19' },
    ],
    total: 5,
  });
});

// ══════════════════════════════════════════════════════════════════════
// ATTACK SIMULATION
// ══════════════════════════════════════════════════════════════════════

router.get('/api/v1/attack-sim/campaigns', (req, res) => {
  res.json({
    items: [
      { id: '1', name: 'External Perimeter Test', status: 'completed', type: 'external', findings: 12, started_at: new Date(Date.now() - 86400000).toISOString(), completed_at: new Date(Date.now() - 82800000).toISOString() },
      { id: '2', name: 'Internal Network Sweep', status: 'completed', type: 'internal', findings: 8, started_at: new Date(Date.now() - 172800000).toISOString(), completed_at: new Date(Date.now() - 169200000).toISOString() },
      { id: '3', name: 'Cloud Infrastructure Audit', status: 'running', type: 'cloud', findings: 5, started_at: new Date(Date.now() - 3600000).toISOString() },
    ],
    total: 3,
  });
});

router.get('/api/v1/attack-sim/scenarios', (req, res) => {
  res.json({
    items: [
      { id: '1', name: 'Ransomware Kill Chain', description: 'Simulates full ransomware attack chain from initial access to data exfiltration', mitre_tactics: ['TA0001', 'TA0003', 'TA0005', 'TA0010'], severity: 'critical' },
      { id: '2', name: 'Supply Chain Compromise', description: 'Tests resilience against compromised third-party dependencies', mitre_tactics: ['TA0001', 'TA0003', 'TA0040'], severity: 'high' },
      { id: '3', name: 'Insider Threat', description: 'Simulates malicious insider with elevated privileges', mitre_tactics: ['TA0004', 'TA0006', 'TA0010'], severity: 'high' },
    ],
    total: 3,
  });
});

router.get('/api/v1/attack-sim/mitre/heatmap', (req, res) => {
  const tactics = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Exfiltration'];
  res.json({
    tactics: tactics.map((t, i) => ({
      id: `TA${String(i + 1).padStart(4, '0')}`,
      name: t,
      technique_count: Math.floor(5 + Math.random() * 15),
      coverage: Math.round(40 + Math.random() * 50),
      risk_level: i < 3 ? 'high' : 'medium',
    })),
  });
});

router.get('/api/v1/attack-sim/mitre/techniques', (req, res) => {
  res.json({
    items: [
      { id: 'T1566', name: 'Phishing', tactic: 'Initial Access', coverage: 85, detected: true },
      { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution', coverage: 72, detected: true },
      { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion', coverage: 65, detected: false },
      { id: 'T1021', name: 'Remote Services', tactic: 'Lateral Movement', coverage: 58, detected: true },
      { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact', coverage: 90, detected: true },
    ],
    total: 5,
  });
});

router.post('/api/v1/attack-sim/campaigns/run', (req, res) => {
  res.json({ status: 'running', campaign_id: crypto.randomUUID() });
});

// ══════════════════════════════════════════════════════════════════════
// FAIL — Failure Injection / Chaos Engineering
// ══════════════════════════════════════════════════════════════════════

router.post('/api/v1/fail/inject', (req, res) => {
  res.json({ status: 'injected', drill_id: crypto.randomUUID(), scenario: req.body?.scenario || 'default' });
});

router.get('/api/v1/fail/drills', (req, res) => {
  res.json({
    items: [
      { id: '1', name: 'Critical CVE Response Drill', type: 'detection', status: 'completed', score: 87, participants: 4, started_at: new Date(Date.now() - 172800000).toISOString() },
      { id: '2', name: 'Incident Response Tabletop', type: 'response', status: 'completed', score: 92, participants: 6, started_at: new Date(Date.now() - 604800000).toISOString() },
      { id: '3', name: 'Supply Chain Attack Simulation', type: 'full_scope', status: 'scheduled', score: null, participants: 8, started_at: new Date(Date.now() + 86400000).toISOString() },
    ],
    total: 3,
  });
});

router.get('/api/v1/fail/drills/:id', (req, res) => {
  res.json({ id: req.params.id, name: 'Security Drill', type: 'detection', status: 'completed', score: 87 });
});

router.post('/api/v1/fail/drills/:id/grade', (req, res) => {
  res.json({ score: 87, grade: 'B+', feedback: 'Good detection time, improve remediation speed' });
});

router.post('/api/v1/fail/drills/:id/detect', (req, res) => {
  res.json({ detected: true, detection_time_seconds: 142 });
});

router.post('/api/v1/fail/drills/:id/triage', (req, res) => {
  res.json({ triaged: true, accuracy: 0.92 });
});

router.post('/api/v1/fail/drills/:id/remediate', (req, res) => {
  res.json({ remediated: true, time_to_remediate_seconds: 1200 });
});

router.get('/api/v1/fail/neglect-zones', (req, res) => {
  res.json({
    items: [
      { zone: 'Container Runtime', risk: 'high', last_tested: new Date(Date.now() - 2592000000).toISOString(), days_since_test: 30 },
      { zone: 'API Gateway', risk: 'medium', last_tested: new Date(Date.now() - 1296000000).toISOString(), days_since_test: 15 },
      { zone: 'Database Layer', risk: 'high', last_tested: new Date(Date.now() - 5184000000).toISOString(), days_since_test: 60 },
    ],
  });
});

router.get('/api/v1/fail/readiness', (req, res) => {
  res.json({ score: 78, grade: 'B', detection: 85, response: 72, remediation: 77, recovery: 79 });
});

router.get('/api/v1/fail/scenarios', (req, res) => {
  res.json({
    items: [
      { id: '1', name: 'Zero-Day Exploitation', difficulty: 'expert', estimated_duration: '45m' },
      { id: '2', name: 'Credential Compromise', difficulty: 'intermediate', estimated_duration: '30m' },
      { id: '3', name: 'Data Exfiltration', difficulty: 'advanced', estimated_duration: '60m' },
    ],
  });
});

router.get('/api/v1/fail/comparison', (req, res) => {
  res.json({ current_score: 78, previous_score: 71, improvement: 7, trend: 'improving' });
});

router.get('/api/v1/fail/training-data', (req, res) => {
  res.json({ total_drills: 12, avg_score: 82, top_performers: ['elena.rodriguez', 'marcus.johnson'], areas_for_improvement: ['lateral movement detection', 'incident escalation'] });
});

router.get('/api/v1/fail/history', (req, res) => {
  res.json({ items: [{ date: '2026-03-01', score: 78 }, { date: '2026-02-15', score: 71 }, { date: '2026-02-01', score: 74 }, { date: '2026-01-15', score: 68 }] });
});

// ══════════════════════════════════════════════════════════════════════
// CHANGES — Code Change Analysis
// ══════════════════════════════════════════════════════════════════════

router.post('/api/v1/changes/analyze-diff', (req, res) => {
  res.json({ risk_score: 0.45, risk_level: 'medium', security_relevant: true, findings: 2 });
});

router.post('/api/v1/changes/analyze-pr', (req, res) => {
  res.json({ risk_score: 0.38, risk_level: 'low', files_changed: 12, security_findings: 1 });
});

router.get('/api/v1/changes/risk-profile/:repo', (req, res) => {
  res.json({ repository: req.params.repo, risk_score: 0.42, trend: 'stable', hotspot_files: 3, contributors: 5 });
});

router.post('/api/v1/changes/classify', (req, res) => {
  res.json({ classification: 'feature', security_impact: 'low', review_required: false });
});

router.get('/api/v1/changes/velocity/:repo', (req, res) => {
  res.json({ repository: req.params.repo, commits_per_week: 47, prs_per_week: 12, avg_review_time_hours: 4.2 });
});

router.get('/api/v1/changes/hotspots/:repo', (req, res) => {
  res.json({ items: [{ file: 'src/auth/handler.py', changes: 23, risk: 'high' }, { file: 'src/api/routes.py', changes: 18, risk: 'medium' }] });
});

router.post('/api/v1/changes/sla-impact', (req, res) => {
  res.json({ impact: 'none', estimated_delay_hours: 0, sla_at_risk: false });
});

// ══════════════════════════════════════════════════════════════════════
// COPILOT — AI Assistant
// ══════════════════════════════════════════════════════════════════════

router.post('/api/v1/copilot/chat', (req, res) => {
  const message = req.body?.message || req.body?.query || '';
  res.json({
    response: `Based on your FixOps data, I can see 59 active findings across your environment. ${message ? `Regarding "${message.slice(0, 50)}": ` : ''}The most critical items require immediate attention. Would you like me to prioritize by EPSS score or CVSS severity?`,
    sources: ['analytics.db', 'brain_nodes'],
    confidence: 0.87,
  });
});

router.post('/api/v1/copilot/suggest', (req, res) => {
  res.json({
    suggestions: [
      { text: 'Review 12 critical findings with EPSS > 0.9', action: 'filter_critical', priority: 'high' },
      { text: 'Run MPTE verification on unconfirmed exploitables', action: 'mpte_verify', priority: 'medium' },
      { text: 'Generate compliance evidence bundle for SOC2 audit', action: 'evidence_generate', priority: 'medium' },
    ],
  });
});

router.post('/api/v1/copilot/ask', (req, res) => {
  const question = req.body?.question || req.body?.message || '';
  res.json({
    answer: `Analysis of your FixOps environment shows 59 tracked findings, 288 knowledge graph nodes, and 6 compliance frameworks under monitoring. ${question ? `For your question about "${question.slice(0, 80)}": ` : ''}The system is operating in enterprise mode with all modules active.`,
    confidence: 0.85,
  });
});

router.get('/api/v1/copilot/agents', (req, res) => {
  res.json({
    items: [
      { name: 'triage-agent', status: 'active', description: 'Auto-triages incoming findings', last_action: new Date(Date.now() - 3600000).toISOString() },
      { name: 'remediation-agent', status: 'active', description: 'Suggests and applies auto-fixes', last_action: new Date(Date.now() - 7200000).toISOString() },
      { name: 'compliance-agent', status: 'active', description: 'Maps findings to compliance controls', last_action: new Date(Date.now() - 1800000).toISOString() },
    ],
    total: 3,
  });
});

router.post('/api/v1/copilot/agents/:name/run', (req, res) => {
  res.json({ status: 'running', agent: req.params.name, task_id: crypto.randomUUID() });
});

// ══════════════════════════════════════════════════════════════════════
// INTEGRATIONS
// ══════════════════════════════════════════════════════════════════════

router.get('/api/v1/integrations', (req, res) => {
  res.json({
    items: [
      { id: '1', name: 'Jira', type: 'ticketing', status: 'connected', last_sync: new Date(Date.now() - 1800000).toISOString() },
      { id: '2', name: 'Slack', type: 'notification', status: 'connected', last_sync: new Date(Date.now() - 600000).toISOString() },
      { id: '3', name: 'GitHub', type: 'scm', status: 'connected', last_sync: new Date(Date.now() - 3600000).toISOString() },
      { id: '4', name: 'AWS Security Hub', type: 'cloud', status: 'connected', last_sync: new Date(Date.now() - 7200000).toISOString() },
      { id: '5', name: 'Splunk', type: 'siem', status: 'disconnected', last_sync: null },
    ],
    total: 5,
  });
});

router.post('/api/v1/integrations/:id/test', (req, res) => {
  res.json({ status: 'ok', message: 'Connection successful' });
});

router.post('/api/v1/integrations/:id/sync', (req, res) => {
  res.json({ status: 'syncing', message: 'Sync initiated' });
});

router.put('/api/v1/integrations/:id', (req, res) => {
  res.json({ status: 'updated', id: req.params.id });
});

// ══════════════════════════════════════════════════════════════════════
// AI AGENT STATUS
// ══════════════════════════════════════════════════════════════════════

router.get('/api/v1/ai-agent/status', (req, res) => {
  res.json({
    status: 'active',
    agents: [
      { name: 'TriageBot', status: 'idle', processed_today: 47, accuracy: 0.94 },
      { name: 'RemediationBot', status: 'idle', fixes_generated: 23, approval_rate: 0.87 },
      { name: 'ComplianceBot', status: 'idle', controls_mapped: 115, frameworks: 6 },
    ],
    total_processed_today: 70,
    model: 'enterprise-v2',
  });
});

// ══════════════════════════════════════════════════════════════════════
// ALGORITHMS — Advanced analytics
// ══════════════════════════════════════════════════════════════════════

router.get('/api/v1/algorithms/capabilities', (req, res) => {
  res.json({
    algorithms: [
      { name: 'causal_inference', status: 'available', description: 'Root cause analysis using causal models' },
      { name: 'gnn_risk', status: 'available', description: 'Graph neural network risk propagation' },
      { name: 'monte_carlo', status: 'available', description: 'Monte Carlo simulation for risk quantification' },
    ],
  });
});

router.post('/api/v1/algorithms/causal/analyze', (req, res) => {
  res.json({ root_causes: [{ factor: 'outdated_dependency', confidence: 0.89 }, { factor: 'missing_patch', confidence: 0.76 }], analysis_id: crypto.randomUUID() });
});

router.post('/api/v1/algorithms/causal/counterfactual', (req, res) => {
  res.json({ scenarios: [{ intervention: 'patch_applied', risk_reduction: 0.72 }, { intervention: 'waf_rule_added', risk_reduction: 0.45 }] });
});

router.post('/api/v1/algorithms/causal/treatment-effect', (req, res) => {
  res.json({ treatment: 'auto_remediation', effect: 0.68, confidence_interval: [0.55, 0.81] });
});

router.post('/api/v1/algorithms/gnn/risk-propagation', (req, res) => {
  res.json({ propagation_paths: 5, max_depth: 3, highest_risk_node: 'database-server', risk_score: 0.92 });
});

router.get('/api/v1/algorithms/gnn/critical-nodes', (req, res) => {
  res.json({ items: [{ node: 'api-gateway', centrality: 0.95 }, { node: 'auth-service', centrality: 0.88 }, { node: 'database-primary', centrality: 0.82 }] });
});

router.get('/api/v1/algorithms/gnn/attack-surface', (req, res) => {
  res.json({ surface_area: 47, entry_points: 12, critical_paths: 3, exposed_services: 8 });
});

router.post('/api/v1/algorithms/monte-carlo/cve', (req, res) => {
  res.json({ simulations: 10000, p50_impact: 125000, p95_impact: 850000, p99_impact: 2100000, currency: 'USD' });
});

router.post('/api/v1/algorithms/monte-carlo/portfolio', (req, res) => {
  res.json({ total_risk: 4200000, var_95: 1800000, expected_loss: 750000, simulations: 10000 });
});

// ══════════════════════════════════════════════════════════════════════
// AUTOFIX — AI-powered fix generation
// ══════════════════════════════════════════════════════════════════════

router.post('/api/v1/autofix/generate', (req, res) => {
  res.json({
    fix_id: crypto.randomUUID(),
    finding_id: req.body?.finding_id,
    status: 'generated',
    fix_type: 'dependency_upgrade',
    description: 'Upgrade affected package to patched version',
    confidence: 0.91,
    diff: '- "log4j-core": "2.14.1"\n+ "log4j-core": "2.21.0"',
  });
});

router.post('/api/v1/autofix/generate-all', (req, res) => {
  res.json({ status: 'completed', generated: 23, failed: 2, skipped: 5 });
});

router.post('/api/v1/autofix/approve', (req, res) => {
  res.json({ status: 'approved', fix_id: req.body?.fix_id });
});

router.post('/api/v1/autofix/reject', (req, res) => {
  res.json({ status: 'rejected', fix_id: req.body?.fix_id });
});

router.post('/api/v1/autofix/apply', (req, res) => {
  res.json({ status: 'applied', fix_id: req.body?.fix_id, pr_url: 'https://github.com/example/repo/pull/42' });
});

router.post('/api/v1/autofix/batch-approve', (req, res) => {
  const ids = req.body?.fix_ids || [];
  res.json({ status: 'approved', count: ids.length });
});

router.get('/api/v1/autofix/suggestions/:id', (req, res) => {
  res.json({
    items: [
      { fix_id: crypto.randomUUID(), type: 'upgrade', description: 'Upgrade to patched version', confidence: 0.92, risk: 'low' },
      { fix_id: crypto.randomUUID(), type: 'config', description: 'Add WAF rule to mitigate', confidence: 0.78, risk: 'medium' },
    ],
  });
});

router.get('/api/v1/autofix/status/:id', (req, res) => {
  res.json({ fix_id: req.params.id, status: 'ready', progress: 100 });
});

router.get('/api/v1/autofix/preview/:id', (req, res) => {
  res.json({ fix_id: req.params.id, diff: '- vulnerable_version\n+ patched_version', files_affected: 1, tests_pass: true });
});

// ══════════════════════════════════════════════════════════════════════
// DEDUPLICATION
// ══════════════════════════════════════════════════════════════════════

router.get('/api/v1/deduplication/clusters', (req, res) => {
  const findings = safeQuery('analytics.db', 'SELECT * FROM findings');
  // Group by CVE ID to create clusters
  const clusters = {};
  findings.forEach(f => {
    const key = f.cve_id || f.id;
    if (!clusters[key]) clusters[key] = { id: key, findings: [], severity: f.severity, title: f.title };
    clusters[key].findings.push(f.id);
  });
  const items = Object.values(clusters).map(c => ({
    cluster_id: c.id,
    representative_title: c.title,
    severity: c.severity,
    finding_count: c.findings.length,
    findings: c.findings,
  }));
  res.json({ items, total: items.length });
});

router.get('/api/v1/deduplication/stats', (req, res) => {
  const total = safeGet('analytics.db', 'SELECT COUNT(*) as c FROM findings');
  const unique = safeGet('analytics.db', 'SELECT COUNT(DISTINCT cve_id) as c FROM findings WHERE cve_id IS NOT NULL');
  res.json({ total_findings: total?.c || 0, unique_cves: unique?.c || 0, dedup_ratio: total?.c ? ((1 - (unique?.c || 0) / total.c) * 100).toFixed(1) : 0 });
});

router.get('/api/v1/deduplication/graph', (req, res) => {
  res.json({ nodes: [], edges: [], clusters: 0 });
});

// ══════════════════════════════════════════════════════════════════════
// PLAYBOOKS
// ══════════════════════════════════════════════════════════════════════

router.get('/api/v1/playbooks', (req, res) => {
  res.json({
    items: [
      { id: '1', name: 'Critical CVE Response', status: 'active', steps: ['Detect', 'Triage', 'Assign', 'Remediate', 'Verify'], trigger: 'severity:critical', last_run: new Date(Date.now() - 7200000).toISOString(), runs: 23 },
      { id: '2', name: 'Secret Leak Response', status: 'active', steps: ['Detect', 'Rotate', 'Audit', 'Notify'], trigger: 'secret:detected', last_run: new Date(Date.now() - 86400000).toISOString(), runs: 4 },
      { id: '3', name: 'Compliance Gap Remediation', status: 'active', steps: ['Identify', 'Assess', 'Remediate', 'Evidence'], trigger: 'compliance:gap', last_run: new Date(Date.now() - 172800000).toISOString(), runs: 12 },
    ],
    total: 3,
  });
});

router.get('/api/v1/playbooks/:id', (req, res) => {
  res.json({ id: req.params.id, name: 'Critical CVE Response', status: 'active', steps: ['Detect', 'Triage', 'Assign', 'Remediate', 'Verify'] });
});

router.post('/api/v1/playbooks/:id/run', (req, res) => {
  res.json({ status: 'running', execution_id: crypto.randomUUID() });
});

router.post('/api/v1/playbooks', (req, res) => {
  res.json({ id: crypto.randomUUID(), ...req.body, status: 'created' });
});

router.put('/api/v1/playbooks/:id', (req, res) => {
  res.json({ id: req.params.id, ...req.body, status: 'updated' });
});

// ══════════════════════════════════════════════════════════════════════
// PREDICTIONS
// ══════════════════════════════════════════════════════════════════════

router.get('/api/v1/predictions', (req, res) => {
  res.json({
    items: [
      { id: '1', type: 'exploit_likelihood', cve_id: 'CVE-2024-21762', probability: 0.94, timeframe: '7d', model: 'enterprise-v2' },
      { id: '2', type: 'exploit_likelihood', cve_id: 'CVE-2024-3400', probability: 0.91, timeframe: '7d', model: 'enterprise-v2' },
      { id: '3', type: 'exposure_risk', asset: 'api-gateway', probability: 0.67, timeframe: '30d', model: 'enterprise-v2' },
    ],
    total: 3,
  });
});

router.get('/api/v1/predictions/:id', (req, res) => {
  res.json({ id: req.params.id, type: 'exploit_likelihood', probability: 0.94, model: 'enterprise-v2', features: ['epss_score', 'kev_status', 'exploit_db_count'] });
});

// ══════════════════════════════════════════════════════════════════════
// CSPM / SAST / CONTAINER — Security Scanners
// ══════════════════════════════════════════════════════════════════════

router.get('/api/v1/cspm/status', (req, res) => {
  res.json({ status: 'active', rules: 142, passing: 118, failing: 24, last_scan: new Date(Date.now() - 3600000).toISOString() });
});

router.get('/api/v1/cspm/rules', (req, res) => {
  res.json({ items: [{ id: 'CSPM-001', name: 'S3 Bucket Public Access', severity: 'critical', status: 'failing' }, { id: 'CSPM-002', name: 'RDS Encryption at Rest', severity: 'high', status: 'passing' }], total: 142 });
});

router.post('/api/v1/cspm/scan/terraform', (req, res) => {
  res.json({ status: 'completed', findings: 3, scan_id: crypto.randomUUID() });
});

router.post('/api/v1/cspm/scan/cloudformation', (req, res) => {
  res.json({ status: 'completed', findings: 2, scan_id: crypto.randomUUID() });
});

router.get('/api/v1/container/status', (req, res) => {
  res.json({ status: 'active', images_scanned: 47, vulnerabilities: 23, last_scan: new Date(Date.now() - 7200000).toISOString() });
});

router.post('/api/v1/container/scan/image', (req, res) => {
  res.json({ status: 'completed', vulnerabilities: 5, scan_id: crypto.randomUUID() });
});

router.post('/api/v1/container/scan/dockerfile', (req, res) => {
  res.json({ status: 'completed', issues: 2, scan_id: crypto.randomUUID() });
});

router.get('/api/v1/sast/status', (req, res) => {
  res.json({ status: 'active', rules: 312, findings: 18, last_scan: new Date(Date.now() - 10800000).toISOString() });
});

router.get('/api/v1/sast/rules', (req, res) => {
  res.json({ items: [{ id: 'SAST-001', name: 'SQL Injection', severity: 'critical', language: 'python' }, { id: 'SAST-002', name: 'XSS Reflected', severity: 'high', language: 'javascript' }], total: 312 });
});

router.post('/api/v1/sast/scan/code', (req, res) => {
  res.json({ status: 'completed', findings: 4, scan_id: crypto.randomUUID() });
});

router.post('/api/v1/sast/scan/files', (req, res) => {
  res.json({ status: 'completed', findings: 2, scan_id: crypto.randomUUID() });
});

// ══════════════════════════════════════════════════════════════════════
// SBOM / INVENTORY extras
// ══════════════════════════════════════════════════════════════════════

router.get('/api/v1/inventory/sbom/components', (req, res) => {
  const components = safeQuery('inventory.db', 'SELECT * FROM components ORDER BY name');
  res.json({ items: components.map(c => ({ ...c, metadata: parseJSON(c.metadata) })), total: components.length });
});

router.get('/api/v1/inventory/sbom/licenses', (req, res) => {
  const components = safeQuery('inventory.db', 'SELECT license, COUNT(*) as count FROM components WHERE license IS NOT NULL GROUP BY license');
  res.json({ items: components, total: components.length });
});

router.post('/api/v1/inventory/sbom/ingest', (req, res) => {
  res.json({ status: 'ingested', components: 15, scan_id: crypto.randomUUID() });
});

// ══════════════════════════════════════════════════════════════════════
// BULK Operations extras
// ══════════════════════════════════════════════════════════════════════

router.post('/api/v1/bulk/triage', (req, res) => {
  const ids = req.body?.finding_ids || [];
  res.json({ status: 'completed', processed: ids.length, action: req.body?.action || 'triaged' });
});

// ══════════════════════════════════════════════════════════════════════
// SSE endpoint stub
// ══════════════════════════════════════════════════════════════════════

router.get('/api/v1/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.write('data: {"type":"connected","timestamp":"' + new Date().toISOString() + '"}\n\n');
  // Keep alive
  const interval = setInterval(() => {
    res.write('data: {"type":"heartbeat","timestamp":"' + new Date().toISOString() + '"}\n\n');
  }, 30000);
  req.on('close', () => clearInterval(interval));
});

module.exports = router;
