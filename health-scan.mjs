import { chromium } from 'playwright';

const BASE = 'http://localhost:5190';
const ROUTES = [
  // Mission Control
  { path: '/', name: 'CommandDashboard' },
  { path: '/mission-control', name: 'CommandDashboard (alias)' },
  { path: '/mission-control/executive', name: 'ExecutiveView' },
  { path: '/mission-control/sla', name: 'SLADashboard' },
  { path: '/mission-control/live-feed', name: 'LiveFeed' },
  { path: '/mission-control/risk', name: 'RiskOverview' },
  // Discover
  { path: '/discover', name: 'FindingExplorer' },
  { path: '/discover/code', name: 'CodeScanning' },
  { path: '/discover/secrets', name: 'SecretsDetection' },
  { path: '/discover/iac', name: 'IaCScanning' },
  { path: '/discover/cloud', name: 'CloudPosture' },
  { path: '/discover/containers', name: 'ContainerSecurity' },
  { path: '/discover/sbom', name: 'SBOMInventory' },
  { path: '/discover/graph', name: 'KnowledgeGraph' },
  { path: '/discover/attack-paths', name: 'AttackPaths' },
  { path: '/discover/threats', name: 'ThreatFeeds' },
  { path: '/discover/correlation', name: 'CorrelationEngine' },
  { path: '/discover/data-fabric', name: 'DataFabric' },
  // Validate
  { path: '/validate', name: 'MPTEConsole' },
  { path: '/validate/mpte', name: 'MPTEConsole (alias)' },
  { path: '/validate/simulation', name: 'AttackSimulation' },
  { path: '/validate/fail', name: 'FAILEngine' },
  { path: '/validate/playbooks', name: 'Playbooks' },
  { path: '/validate/playbooks/editor', name: 'PlaybookEditor' },
  { path: '/validate/reachability', name: 'Reachability' },
  // Remediate
  { path: '/remediate', name: 'RemediationCenter' },
  { path: '/remediate/autofix', name: 'AutoFix' },
  { path: '/remediate/bulk', name: 'BulkOperations' },
  { path: '/remediate/collaborate', name: 'Collaboration' },
  { path: '/remediate/workflows', name: 'Workflows' },
  { path: '/remediate/cases', name: 'ExposureCases' },
  { path: '/remediate/tickets', name: 'TicketIntegration' },
  // Comply
  { path: '/comply', name: 'ComplianceDashboard' },
  { path: '/comply/evidence', name: 'EvidenceVault' },
  { path: '/comply/bundles', name: 'EvidenceBundles' },
  { path: '/comply/soc2', name: 'SOC2Evidence' },
  { path: '/comply/slsa', name: 'SLSAProvenance' },
  { path: '/comply/audit', name: 'AuditTrail' },
  { path: '/comply/reports', name: 'Reports' },
  { path: '/comply/analytics', name: 'Analytics' },
  { path: '/comply/export', name: 'EvidenceExportCenter' },
  // Settings
  { path: '/settings', name: 'SettingsHub' },
  { path: '/settings/integrations', name: 'Integrations' },
  { path: '/settings/users', name: 'UsersPage' },
  { path: '/settings/teams', name: 'Teams' },
  { path: '/settings/marketplace', name: 'Marketplace' },
  { path: '/settings/policies', name: 'Policies' },
  { path: '/settings/health', name: 'SystemHealth' },
  { path: '/settings/logs', name: 'LogViewer' },
  // AI
  { path: '/ai', name: 'CopilotDashboard' },
  // Onboarding
  { path: '/onboarding', name: 'OnboardingWizard' },
];

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await context.newPage();

  const results = { ok: [], crashed: [], errors: [] };

  for (const route of ROUTES) {
    const consoleErrors = [];
    const jsErrors = [];

    page.on('console', msg => {
      if (msg.type() === 'error') consoleErrors.push(msg.text().slice(0, 200));
    });
    page.on('pageerror', err => {
      jsErrors.push(err.message.slice(0, 300));
    });

    try {
      await page.goto(`${BASE}${route.path}`, { waitUntil: 'networkidle', timeout: 15000 });
      await page.waitForTimeout(2000);

      // Check for error boundary fallback
      const hasErrorBoundary = await page.locator('text=Something went wrong').count() > 0;
      const hasErrorBoundary2 = await page.locator('text=Application Error').count() > 0;
      const hasReactError = await page.locator('text=Cannot read properties').count() > 0;
      const hasChunkError = await page.locator('text=Loading chunk').count() > 0;

      if (hasErrorBoundary || hasErrorBoundary2 || hasReactError || hasChunkError || jsErrors.length > 0) {
        results.crashed.push({
          name: route.name,
          path: route.path,
          jsErrors: jsErrors.slice(0, 3),
          errorBoundary: hasErrorBoundary || hasErrorBoundary2,
          consoleErrors: consoleErrors.filter(e => !e.includes('404') && !e.includes('favicon')).slice(0, 3)
        });
      } else {
        results.ok.push({ name: route.name, path: route.path });
      }
    } catch (err) {
      results.errors.push({
        name: route.name,
        path: route.path,
        error: err.message.slice(0, 200)
      });
    }

    // Remove listeners for next page
    page.removeAllListeners('console');
    page.removeAllListeners('pageerror');
  }

  await browser.close();

  console.log(`\n${'='.repeat(60)}`);
  console.log(`HEALTH SCAN RESULTS`);
  console.log(`${'='.repeat(60)}`);
  console.log(`\n✅ OK: ${results.ok.length} pages`);
  results.ok.forEach(r => console.log(`   ${r.name} → ${r.path}`));
  
  console.log(`\n❌ CRASHED: ${results.crashed.length} pages`);
  results.crashed.forEach(r => {
    console.log(`   ${r.name} → ${r.path}`);
    if (r.jsErrors.length) console.log(`      JS: ${r.jsErrors[0]}`);
    if (r.consoleErrors.length) console.log(`      Console: ${r.consoleErrors[0]}`);
  });

  console.log(`\n⚠️ TIMEOUT/ERROR: ${results.errors.length} pages`);
  results.errors.forEach(r => console.log(`   ${r.name} → ${r.path}: ${r.error}`));

  console.log(`\n${'='.repeat(60)}`);
  console.log(`TOTAL: ${results.ok.length} OK / ${results.crashed.length} CRASHED / ${results.errors.length} ERROR`);
  console.log(`${'='.repeat(60)}\n`);
})();
