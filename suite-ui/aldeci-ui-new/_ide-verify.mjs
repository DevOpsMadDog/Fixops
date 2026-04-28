import { chromium } from 'playwright';

const TOKEN = 'fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_';
const ORG = 'juice-shop-corp';

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1680, height: 1000 } });
await ctx.addInitScript(({ token, org }) => {
  localStorage.setItem('aldeci.authToken', token);
  localStorage.setItem('aldeci.orgId', org);
  localStorage.setItem('aldeci.authStrategy', 'token');
}, { token: TOKEN, org: ORG });

const page = await ctx.newPage();

const errors = [];
page.on('console', msg => { if (msg.type() === 'error') errors.push('[console] ' + msg.text()); });
page.on('pageerror', e => errors.push('[pageerror] ' + e.message));

// path-based routing: /ide-backend (no hash)
await page.goto('http://localhost:5173/ide-backend', { waitUntil: 'domcontentloaded', timeout: 30000 });
await page.waitForTimeout(2500);

// Wait until tree is rendered (Explorer card)
try {
  await page.waitForSelector('text=Explorer', { timeout: 20000 });
  console.log('Explorer panel rendered');
} catch (e) {
  console.log('Explorer not visible — saving debug screenshot');
  await page.screenshot({ path: '/tmp/ide-debug.png', fullPage: true });
  const body = await page.evaluate(() => document.body.innerText.slice(0, 600));
  console.log('BODY:', body);
  errors.forEach(x => console.log(x));
  await browser.close();
  process.exit(1);
}

// Wait for tree data (look for any file or folder name from juice-shop)
await page.waitForTimeout(2500);
await page.screenshot({ path: '/tmp/ide-1-loaded.png', fullPage: false });
console.log('snap 1: /tmp/ide-1-loaded.png');

// Click Gruntfile.js (root file)
const gruntButton = page.locator('button:has-text("Gruntfile.js")').first();
const gruntCount = await gruntButton.count();
console.log('Gruntfile.js count:', gruntCount);
if (gruntCount > 0) {
  await gruntButton.click();
  await page.waitForTimeout(4000);  // Monaco lazy-loads
  await page.screenshot({ path: '/tmp/ide-2-file-open.png', fullPage: false });
  console.log('snap 2: /tmp/ide-2-file-open.png');
} else {
  // Fallback: click any file in tree
  const anyFile = page.locator('button[type="button"]').filter({ hasText: /\.\w+$/ }).first();
  if (await anyFile.count() > 0) {
    await anyFile.click();
    await page.waitForTimeout(4000);
    await page.screenshot({ path: '/tmp/ide-2-file-open.png', fullPage: false });
    console.log('snap 2 (fallback): /tmp/ide-2-file-open.png');
  }
}

// Snapshot diff
const diffBtn = page.locator('button:has-text("Diff A")');
if (await diffBtn.count() > 0 && await diffBtn.isEnabled()) {
  await diffBtn.click();
  await page.waitForTimeout(1500);
  await page.screenshot({ path: '/tmp/ide-3-diff.png', fullPage: false });
  console.log('snap 3: /tmp/ide-3-diff.png');
} else {
  console.log('Diff button not enabled (need 2 distinct snapshots)');
}

console.log('--- errors ---');
errors.forEach(e => console.log(e));

await browser.close();
console.log('DONE');
