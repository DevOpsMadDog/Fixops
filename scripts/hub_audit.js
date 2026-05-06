// Hub load error audit — Multica #4002
// Usage: node scripts/hub_audit.js
const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

const SCREENSHOT_DIR = path.join(__dirname, '../docs/deploy_smoke_2026-05-04');
fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });

const HUBS = [
  { name: 'root',                  url: 'http://localhost:5173/' },
  { name: 'executive',             url: 'http://localhost:5173/executive' },
  { name: 'discover-asset-inventory', url: 'http://localhost:5173/discover/asset-inventory' },
  { name: 'discover-vuln-intel',   url: 'http://localhost:5173/discover/vuln-intel' },
  { name: 'discover-identity-governance', url: 'http://localhost:5173/discover/identity-governance' },
  { name: 'discover-architect',    url: 'http://localhost:5173/discover/architect' },
  { name: 'protect-crypto-trust',  url: 'http://localhost:5173/protect/crypto-trust' },
  { name: 'respond-incident-knowledge', url: 'http://localhost:5173/respond/incident-knowledge' },
  { name: 'comply-auditor',        url: 'http://localhost:5173/comply/auditor' },
  { name: 'comply-dpo',            url: 'http://localhost:5173/comply/dpo' },
  { name: 'developer',             url: 'http://localhost:5173/developer' },
];

async function auditHub(page, hub) {
  const consoleErrors = [];
  const networkCalls = [];

  page.on('console', msg => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  });

  page.on('response', async resp => {
    const url = resp.url();
    if (url.includes('/api/v1') || url.includes('/api/')) {
      networkCalls.push({ url: url.replace('http://localhost:8000', ''), status: resp.status() });
    }
  });

  try {
    await page.goto(hub.url, { waitUntil: 'networkidle', timeout: 15000 });
  } catch (e) {
    // networkidle timeout — still capture what we have
  }
  // Extra wait for lazy-loaded data
  await page.waitForTimeout(2000);

  const screenshotPath = path.join(SCREENSHOT_DIR, `hub_${hub.name}_loaded.png`);
  await page.screenshot({ path: screenshotPath, fullPage: false });

  return { name: hub.name, url: hub.url, consoleErrors, networkCalls };
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  const results = [];

  for (const hub of HUBS) {
    const context = await browser.newContext();
    const page = await context.newPage();
    console.log(`Auditing: ${hub.name} ...`);
    const result = await auditHub(page, hub);
    results.push(result);
    await context.close();
  }

  await browser.close();

  // Print structured results
  for (const r of results) {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`HUB: ${r.name} (${r.url})`);
    console.log(`Console errors (${r.consoleErrors.length}):`);
    r.consoleErrors.slice(0, 5).forEach(e => console.log(`  ERROR: ${e.substring(0, 200)}`));
    console.log(`API calls (${r.networkCalls.length}):`);
    r.networkCalls.forEach(c => console.log(`  ${c.status} ${c.url}`));
  }

  // Write JSON for analysis
  fs.writeFileSync(
    path.join(__dirname, '../docs/deploy_smoke_2026-05-04/hub_audit_results.json'),
    JSON.stringify(results, null, 2)
  );
  console.log('\nDone. Results in docs/deploy_smoke_2026-05-04/hub_audit_results.json');
})();
