import { chromium } from 'playwright';
const BASE = 'http://localhost:5190';
(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  
  async function nav(route, name) {
    await page.goto(`${BASE}${route}`, { waitUntil: 'networkidle', timeout: 15000 });
    await page.waitForTimeout(2500);
    await page.screenshot({ path: `/home/user/workspace/ss-${name}.png` });
    console.log(`📸 ${name}`);
  }

  // SPA pages load via hash/history - use client-side nav
  await page.goto(BASE, { waitUntil: 'networkidle', timeout: 15000 });
  await page.waitForTimeout(2000);
  
  // Use evaluate to navigate via React Router
  const routes = [
    ['/', '01-dashboard'],
    ['/discover', '02-findings'],
    ['/validate/mpte', '03-mpte'],
    ['/validate/fail', '04-fail'],
    ['/remediate', '05-remediate'],
    ['/comply', '06-comply'],
    ['/ai/brain', '07-brain'],
    ['/ai/consensus', '08-llm'],
    ['/ai/predictions', '09-predictions'],
    ['/settings', '10-settings'],
  ];

  for (const [route, name] of routes) {
    await page.evaluate((r) => window.history.pushState({}, '', r), route);
    await page.evaluate(() => window.dispatchEvent(new PopStateEvent('popstate')));
    await page.waitForTimeout(2500);
    await page.screenshot({ path: `/home/user/workspace/ss-${name}.png` });
    console.log(`📸 ${name}`);
  }

  await browser.close();
  console.log('\n✅ Done');
})();
