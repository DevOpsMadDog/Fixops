import { chromium } from 'playwright';
const BASE = 'http://localhost:5190';
(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  
  await page.goto(`${BASE}/ai/brain`, { waitUntil: 'networkidle', timeout: 15000 });
  await page.waitForTimeout(2000);
  await page.screenshot({ path: '/home/user/workspace/ai-brain.png', fullPage: false });
  console.log('Brain Pipeline screenshot saved');

  await page.goto(`${BASE}/ai/consensus`, { waitUntil: 'networkidle', timeout: 15000 });
  await page.waitForTimeout(2000);
  await page.screenshot({ path: '/home/user/workspace/ai-consensus.png', fullPage: false });
  console.log('MultiLLM screenshot saved');

  await page.goto(`${BASE}/ai/predictions`, { waitUntil: 'networkidle', timeout: 15000 });
  await page.waitForTimeout(2000);
  await page.screenshot({ path: '/home/user/workspace/ai-predictions.png', fullPage: false });
  console.log('Predictions screenshot saved');

  await browser.close();
})();
