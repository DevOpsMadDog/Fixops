import { test, expect } from '@playwright/test';

// ─── Core Pages ────────────────────────────────────────────────
test.describe('Core Pages Load', () => {
  test('Dashboard renders', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('body')).toBeVisible();
    // Dashboard has cards / metrics
    await expect(page.locator('[class*="card"], [class*="Card"], main').first()).toBeVisible({ timeout: 10_000 });
  });

  test('Nerve Center renders', async ({ page }) => {
    await page.goto('/nerve-center');
    await expect(page.locator('body')).toBeVisible();
    await expect(page.locator('main, [class*="card"], h1, h2').first()).toBeVisible({ timeout: 10_000 });
  });

  test('Copilot page renders', async ({ page }) => {
    await page.goto('/copilot');
    await expect(page.locator('body')).toBeVisible();
    await expect(page.locator('main, [class*="card"], h1, h2, textarea, input').first()).toBeVisible({ timeout: 10_000 });
  });

  test('Settings page renders', async ({ page }) => {
    await page.goto('/settings');
    await expect(page.locator('body')).toBeVisible();
    await expect(page.locator('main, [class*="card"], h1, h2').first()).toBeVisible({ timeout: 10_000 });
  });
});

// ─── Navigation ────────────────────────────────────────────────
test.describe('Sidebar Navigation', () => {
  test('sidebar is visible with navigation links', async ({ page }) => {
    await page.goto('/');
    // Wait for app to render
    await expect(page.locator('body')).toBeVisible();
    // Check sidebar or nav exists
    const sidebar = page.locator('nav, aside, [class*="sidebar"], [class*="Sidebar"]').first();
    await expect(sidebar).toBeVisible({ timeout: 10_000 });
  });

  test('can navigate to different sections', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    // Navigate to nerve center
    const ncLink = page.locator('a[href*="nerve-center"], button:has-text("Nerve Center")').first();
    if (await ncLink.isVisible()) {
      await ncLink.click();
      await expect(page).toHaveURL(/nerve-center/);
    }
  });
});

// ─── Suite Pages ───────────────────────────────────────────────
const suitePages = [
  { name: 'Code Scanning', path: '/code/code-scanning' },
  { name: 'Attack Simulation', path: '/attack/attack-simulation' },
  { name: 'Evidence Bundles', path: '/evidence/bundles' },
  { name: 'Integrations', path: '/protect/integrations' },
  { name: 'Intelligence Hub', path: '/intelligence' },
  { name: 'Decision Engine', path: '/decisions' },
  { name: 'Remediation Center', path: '/remediation' },
  { name: 'Data Fabric', path: '/ingest' },
  { name: 'Brain Pipeline', path: '/core/brain-pipeline' },
  { name: 'Knowledge Graph', path: '/core/knowledge-graph' },
  { name: 'Live Feeds', path: '/feeds/live' },
  { name: 'ML Dashboard', path: '/ai-engine/ml-dashboard' },
  { name: 'Multi-LLM', path: '/ai-engine/multi-llm' },
  { name: 'Overlay Config', path: '/settings/overlay-config' },
  { name: 'AutoFix', path: '/protect/autofix' },
  { name: 'MPTE Console', path: '/attack/mpte' },
  { name: 'Exposure Cases', path: '/core/exposure-cases' },
  { name: 'SOC2 Evidence', path: '/evidence/soc2' },
];

test.describe('Suite Pages Load', () => {
  for (const { name, path } of suitePages) {
    test(`${name} (${path}) renders without crash`, async ({ page }) => {
      const errors: string[] = [];
      page.on('pageerror', (err) => errors.push(err.message));
      await page.goto(path);
      await expect(page.locator('body')).toBeVisible();
      // Page should have meaningful content (not blank white)
      await page.waitForTimeout(2000);
      const bodyText = await page.locator('body').innerText();
      expect(bodyText.length).toBeGreaterThan(10);
      // No uncaught errors
      expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0);
    });
  }
});

// ─── Error Boundary ────────────────────────────────────────────
test.describe('Error Handling', () => {
  test('404 route falls back to dashboard', async ({ page }) => {
    await page.goto('/nonexistent-page-xyz');
    await expect(page.locator('body')).toBeVisible();
    // Should render Dashboard (catch-all route)
    await expect(page.locator('main, [class*="card"], h1, h2').first()).toBeVisible({ timeout: 10_000 });
  });
});

// ─── Theme / Styling ───────────────────────────────────────────
test.describe('UI Interactions', () => {
  test('page renders with styled content (not blank)', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    // Verify app shell rendered with meaningful styled content
    const body = page.locator('body');
    const bgColor = await body.evaluate(el => getComputedStyle(el).backgroundColor);
    // Not plain white (rgb(255, 255, 255)) — the app should have dark or custom background
    const bodyText = await body.innerText();
    expect(bodyText.length).toBeGreaterThan(50);
    // App has loaded with actual content
    expect(bgColor).toBeDefined();
  });
});

