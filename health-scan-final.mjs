import { chromium } from 'playwright';
const BASE = 'http://localhost:5190';
const ROUTES = [
  '/', '/mission-control', '/mission-control/executive', '/mission-control/sla',
  '/mission-control/live-feed', '/mission-control/risk',
  '/discover', '/discover/code', '/discover/secrets', '/discover/iac',
  '/discover/cloud', '/discover/containers', '/discover/sbom', '/discover/graph',
  '/discover/attack-paths', '/discover/threats', '/discover/correlation', '/discover/data-fabric',
  '/validate', '/validate/mpte', '/validate/simulation', '/validate/fail',
  '/validate/playbooks', '/validate/playbooks/editor', '/validate/reachability',
  '/remediate', '/remediate/autofix', '/remediate/bulk', '/remediate/collaborate',
  '/remediate/workflows', '/remediate/cases', '/remediate/tickets',
  '/comply', '/comply/evidence', '/comply/bundles', '/comply/soc2', '/comply/slsa',
  '/comply/audit', '/comply/reports', '/comply/analytics', '/comply/export',
  '/settings', '/settings/integrations', '/settings/users', '/settings/teams',
  '/settings/marketplace', '/settings/policies', '/settings/health', '/settings/logs',
  '/ai', '/ai/brain', '/ai/consensus', '/ai/algorithms', '/ai/ml', '/ai/predictions',
  '/onboarding'
];
(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  let ok = 0, crashed = 0;
  for (const r of ROUTES) {
    const errors = [];
    page.on('pageerror', err => errors.push(err.message.slice(0, 100)));
    try {
      await page.goto(`${BASE}${r}`, { waitUntil: 'networkidle', timeout: 12000 });
      await page.waitForTimeout(1000);
      const hasErr = await page.locator('text=Something went wrong').count() > 0;
      if (errors.length > 0 || hasErr) {
        console.log(`❌ ${r} → ${errors[0] || 'Error boundary'}`);
        crashed++;
      } else {
        ok++;
      }
    } catch (e) {
      console.log(`❌ ${r} → TIMEOUT`);
      crashed++;
    }
    page.removeAllListeners('pageerror');
  }
  await browser.close();
  console.log(`\n✅ ${ok} OK / ❌ ${crashed} CRASHED / Total ${ROUTES.length}`);
})();
