// Screenshots each <section> of diagrams.html into ../diagrams/<name>.png
const { chromium } = require("playwright");
const path = require("path");
const names = { d1: "1-blockchain-merkle-structure", d2: "2-pending-pool-flow",
                d3: "3-copy-state-machine-and-queue", d4: "4-token-reward-flow",
                d5: "5-mining-workflow", d6: "6-fraud-detection-pipeline" };
(async () => {
  const browser = await chromium.launch({ executablePath: "/opt/pw-browsers/chromium-1194/chrome-linux/chrome" });
  const page = await browser.newPage({ deviceScaleFactor: 2.5, viewport: { width: 900, height: 1200 } });
  await page.goto("file://" + path.join(__dirname, "diagrams.html"));
  await page.waitForTimeout(400);
  for (const [id, name] of Object.entries(names)) {
    await page.locator("#" + id).screenshot({ path: path.join(__dirname, "..", "diagrams", name + ".png") });
    console.log(name);
  }
  await browser.close();
})();
