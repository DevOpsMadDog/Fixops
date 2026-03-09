import { chromium } from 'playwright';
const BASE = 'http://localhost:5190';
(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  
  // Start at homepage - this loads the SPA router
  await page.goto(BASE, { waitUntil: 'networkidle', timeout: 15000 });
  await page.waitForTimeout(3000);
  
  // Screenshot dashboard with real data
  await page.screenshot({ path: '/home/user/workspace/ss-01-dashboard.png' });
  console.log('📸 Dashboard (home)');
  
  // Navigate to Discover
  await page.click('text=Discover');
  await page.waitForTimeout(500);
  await page.click('text=Finding Explorer');
  await page.waitForTimeout(2000);
  await page.screenshot({ path: '/home/user/workspace/ss-02-findings.png' });
  console.log('📸 Finding Explorer');

  // Navigate to MPTE Console
  await page.click('text=Validate');
  await page.waitForTimeout(500);
  await page.click('text=MPTE Console');
  await page.waitForTimeout(2000);
  await page.screenshot({ path: '/home/user/workspace/ss-03-mpte.png' });
  console.log('📸 MPTE Console');

  // Navigate to FAIL Engine
  await page.click('text=FAIL Engine');
  await page.waitForTimeout(2000);
  await page.screenshot({ path: '/home/user/workspace/ss-04-fail.png' });
  console.log('📸 FAIL Engine');

  // Navigate to Remediate
  await page.click('text=Remediate');
  await page.waitForTimeout(500);
  await page.click('text=Remediation Center');
  await page.waitForTimeout(2000);
  await page.screenshot({ path: '/home/user/workspace/ss-05-remediate.png' });
  console.log('📸 Remediation Center');

  // Navigate to Comply
  await page.click('text=Comply');
  await page.waitForTimeout(500);
  await page.click('text=Compliance Dashboard');
  await page.waitForTimeout(2000);
  await page.screenshot({ path: '/home/user/workspace/ss-06-comply.png' });
  console.log('📸 Compliance Dashboard');

  // Navigate to AI Engine / Brain Pipeline
  await page.click('text=AI Engine');
  await page.waitForTimeout(500);
  await page.click('text=Brain Pipeline');
  await page.waitForTimeout(2000);
  await page.screenshot({ path: '/home/user/workspace/ss-07-brain.png' });
  console.log('📸 Brain Pipeline');

  // Multi-LLM Consensus
  await page.click('text=Multi-LLM Consensus');
  await page.waitForTimeout(2000);
  await page.screenshot({ path: '/home/user/workspace/ss-08-llm.png' });
  console.log('📸 Multi-LLM Consensus');

  // Predictions
  await page.click('text=Predictions');
  await page.waitForTimeout(2000);
  await page.screenshot({ path: '/home/user/workspace/ss-09-predictions.png' });
  console.log('📸 Predictions');

  await browser.close();
  console.log('\n✅ All screenshots done');
})();
