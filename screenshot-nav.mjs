import { chromium } from 'playwright';
const BASE = 'http://localhost:5190';
(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });

  // Go directly to the AI brain page
  await page.goto(`${BASE}/ai/brain`, { waitUntil: 'networkidle', timeout: 15000 });
  await page.waitForTimeout(3000);
  
  // Check what h1 is on the page
  const h1s = await page.locator('h1').allTextContents();
  console.log('H1 tags:', h1s);
  
  // Check if Brain Pipeline content exists
  const brainText = await page.locator('text=Brain Pipeline').count();
  const decisionText = await page.locator('text=12-Step Decision Pipeline').count();
  console.log('Brain Pipeline text count:', brainText, 'Decision Pipeline:', decisionText);
  
  await page.screenshot({ path: '/home/user/workspace/ai-brain2.png', fullPage: false });
  
  // Try via sidebar
  // First expand AI Engine
  const aiEngine = page.locator('text=AI Engine');
  if (await aiEngine.count() > 0) {
    await aiEngine.click();
    await page.waitForTimeout(500);
    const brainLink = page.locator('text=Brain Pipeline');
    if (await brainLink.count() > 0) {
      await brainLink.click();
      await page.waitForTimeout(3000);
      await page.screenshot({ path: '/home/user/workspace/ai-brain3.png', fullPage: false });
      const h1s2 = await page.locator('h1').allTextContents();
      console.log('After nav H1:', h1s2);
    }
  }
  
  await browser.close();
})();
