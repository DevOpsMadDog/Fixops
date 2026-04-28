/**
 * Lighthouse perf runner with auth bypass.
 *
 * Strategy:
 *  1. Launch Chrome via CDP (chrome-launcher, bundled with lighthouse CLI).
 *  2. Open a blank tab, set localStorage keys that trigger the FIXOPS_VISUAL_VERIFY
 *     bypass in auth.tsx — this makes RequireAuth pass without a real JWT.
 *  3. Attach Lighthouse to the same Chrome instance via --port.
 *  4. Collect LCP, FCP, TBT, CLS, Speed Index, perf score.
 *  5. Write per-hero JSON to docs/perf/<hero>.json.
 */

import { execSync, spawn } from "child_process";
import { writeFileSync, mkdirSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUTDIR = __dirname;
const BASE = "http://localhost:5173";

const HEROES = [
  { name: "root",       path: "/" },
  { name: "issues",     path: "/issues" },
  { name: "brain",      path: "/brain" },
  { name: "compliance", path: "/compliance" },
  { name: "assets",     path: "/assets" },
  { name: "admin",      path: "/admin" },
];

// Chrome binary
const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

// Pick a random free port for CDP
function randomPort() {
  return 9222 + Math.floor(Math.random() * 1000);
}

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function runHero(hero) {
  const port = randomPort();
  const url = `${BASE}${hero.path}`;
  const outPath = join(OUTDIR, `${hero.name}.json`);

  // 1. Launch Chrome with remote debugging
  const chrome = spawn(CHROME, [
    `--remote-debugging-port=${port}`,
    "--headless=new",
    "--no-sandbox",
    "--disable-gpu",
    "--disable-extensions",
    "--user-data-dir=/tmp/lh-profile-" + hero.name + "-" + port,
  ], { stdio: "ignore" });

  await sleep(2000); // wait for Chrome to be ready

  // 2. Use CDP to set localStorage bypass keys before Lighthouse navigates
  try {
    // Fetch the list of targets via CDP HTTP endpoint
    const targetsResp = await fetch(`http://localhost:${port}/json/list`);
    const targets = await targetsResp.json();
    const target = targets[0];

    if (target && target.webSocketDebuggerUrl) {
      // Use CDP via fetch to Runtime.evaluate on the about:blank page
      // We'll use the /json/new endpoint to open the target URL first
      const newTabResp = await fetch(`http://localhost:${port}/json/new?${encodeURIComponent(BASE)}`);
      const newTab = await newTabResp.json();
      await sleep(1500);

      // Now CDP-evaluate localStorage setup via the activate+Runtime.evaluate flow
      // Use a simple HTTP-based CDP command through the /json endpoint
      // Since we can't WebSocket easily in this script, we use a small node eval
      const cdpScript = `
        const WebSocket = require('ws');
        const ws = new WebSocket(${JSON.stringify(newTab.webSocketDebuggerUrl || target.webSocketDebuggerUrl)});
        let id = 1;
        ws.on('open', () => {
          // Navigate to the hero URL first
          ws.send(JSON.stringify({id: id++, method: 'Page.navigate', params: {url: ${JSON.stringify(BASE)}}}));
          setTimeout(() => {
            // Set localStorage bypass keys
            ws.send(JSON.stringify({id: id++, method: 'Runtime.evaluate', params: {
              expression: [
                "localStorage.setItem('FIXOPS_VISUAL_VERIFY', '1')",
                "localStorage.setItem('aldeci.authStrategy', 'token')",
                "localStorage.setItem('aldeci.authToken', 'aldeci-demo-key')",
                "localStorage.setItem('aldeci.authUser', JSON.stringify({id:'dev-user',email:'dev@verify',first_name:'Dev',last_name:'Verify',role:'admin',department:'platform'}))",
                "localStorage.setItem('aldeci.orgId', 'juice-shop-corp')",
              ].join(';')
            }}));
            setTimeout(() => { ws.close(); process.exit(0); }, 500);
          }, 1500);
        });
        ws.on('error', (e) => { console.error(e.message); process.exit(1); });
      `;

      try {
        execSync(`node -e ${JSON.stringify(cdpScript)}`, { timeout: 8000 });
      } catch(e) {
        // ws module may not be available — fall through, Lighthouse will still run
        console.warn(`[${hero.name}] CDP localStorage seeding skipped: ${e.message.slice(0,80)}`);
      }
    }
  } catch (e) {
    console.warn(`[${hero.name}] CDP setup warning: ${e.message.slice(0,80)}`);
  }

  await sleep(500);

  // 3. Run Lighthouse attached to this Chrome instance
  try {
    execSync(
      `npx lighthouse "${url}" \
        --port=${port} \
        --only-categories=performance \
        --output=json \
        --output-path="${outPath}" \
        --disable-storage-reset \
        --chrome-flags="--headless=new --no-sandbox --disable-gpu" \
        --quiet`,
      { timeout: 120000, stdio: "pipe" }
    );
    console.log(`[${hero.name}] DONE -> ${outPath}`);
  } catch (e) {
    console.error(`[${hero.name}] Lighthouse error: ${e.message.slice(0, 200)}`);
  } finally {
    chrome.kill();
  }
}

// Run sequentially to avoid port conflicts
for (const hero of HEROES) {
  console.log(`\nRunning ${hero.name} (${hero.path})...`);
  await runHero(hero);
}
console.log("\nAll heroes done.");
