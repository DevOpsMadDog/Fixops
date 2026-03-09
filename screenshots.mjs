import { chromium } from 'playwright';
const BASE = 'http://localhost:5190';
(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  
  const pages = [
    ['/', 'dashboard'],
    ['/discover', 'findings'],
    ['/validate/mpte', 'mpte'],
    ['/ai/brain', 'brain-pipeline'],
    ['/ai/consensus', 'multi-llm'],
    ['/comply', 'compliance'],
    ['/remediate', 'remediation'],
    ['/validate/fail', 'fail-engine'],
  ];

  for (const [route, name] of pages) {
    // Navigate via sidebar click for proper SPA routing
    await page.goto(`${BASE}${route}`, { waitUntil: 'networkidle', timeout: 15000 });
    await page.waitForTimeout(2000);
    await page.screenshot({ path: `/home/user/workspace/ss-${name}.png`, fullPage: false });
    console.log(`📸 ${name}`);
  }
  
  await browser.close();
  console.log('All screenshots done');
})();
