const { chromium } = require("playwright");
(async () => {
  const b = await chromium.launch({ headless: true });
  const ctx = await b.newContext();
  await ctx.addInitScript(() => {
    window.localStorage.setItem("FIXOPS_VISUAL_VERIFY", "1");
    window.localStorage.setItem("aldeci.orgId", "juice-shop-corp");
  });
  const p = await ctx.newPage();
  p.on("console", (msg) => console.log(`[${msg.type()}]`, msg.text().slice(0, 300)));
  p.on("pageerror", (err) => console.log(`[pageerror]`, err.message.slice(0, 300)));
  await p.goto("http://localhost:5173/security-findings", { waitUntil: "networkidle", timeout: 15000 });
  await p.waitForTimeout(2000);
  // Dump rendered HTML structure
  const url = await p.url();
  const title = await p.title();
  const bodyChildClasses = await p.evaluate(() => {
    const root = document.getElementById("root");
    return {
      rootHTML: root?.innerHTML?.slice(0, 800) || "NO ROOT",
      hash: window.location.hash,
      pathname: window.location.pathname,
      h1Count: document.querySelectorAll("h1").length,
      h2Count: document.querySelectorAll("h2").length,
      firstH1: document.querySelector("h1")?.textContent || "NONE",
      firstH2: document.querySelector("h2")?.textContent || "NONE",
      allHeadings: Array.from(document.querySelectorAll("h1,h2,h3")).slice(0,5).map(h => `${h.tagName}: ${h.textContent?.slice(0,100)}`),
    };
  });
  console.log("URL:", url);
  console.log("title:", title);
  console.log("hash:", bodyChildClasses.hash);
  console.log("pathname:", bodyChildClasses.pathname);
  console.log("h1Count:", bodyChildClasses.h1Count);
  console.log("h2Count:", bodyChildClasses.h2Count);
  console.log("firstH1:", bodyChildClasses.firstH1);
  console.log("firstH2:", bodyChildClasses.firstH2);
  console.log("headings:", bodyChildClasses.allHeadings);
  await b.close();
})();
