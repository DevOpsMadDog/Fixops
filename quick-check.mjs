import { chromium } from 'playwright';
const BASE = 'http://localhost:5190';
const ROUTES = [
  '/ai/brain', '/ai/consensus', '/ai/algorithms', '/ai/ml', '/ai/predictions'
];
(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  for (const r of ROUTES) {
    const errors = [];
    page.on('pageerror', err => errors.push(err.message.slice(0, 150)));
    try {
      await page.goto(`${BASE}${r}`, { waitUntil: 'networkidle', timeout: 15000 });
      await page.waitForTimeout(1500);
      const hasError = await page.locator('text=Something went wrong').count() > 0;
      const title = await page.locator('h1').first().textContent().catch(() => '—');
      console.log(`${errors.length === 0 && !hasError ? '✅' : '❌'} ${r} → "${title}" ${errors.length > 0 ? `ERRORS: ${errors[0]}` : ''}`);
    } catch (e) {
      console.log(`❌ ${r} → TIMEOUT: ${e.message.slice(0, 100)}`);
    }
    page.removeAllListeners('pageerror');
  }
  await browser.close();
})();
