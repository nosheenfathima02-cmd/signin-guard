// Usage: node shoot.js <page.html> <out.png> [fullPage]
const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: { width: 1100, height: 700 } });
  await p.goto('file://' + process.argv[2]);
  await p.waitForTimeout(600);
  const el = await p.$('.win');
  if (el) await el.screenshot({ path: process.argv[3] });
  else await p.screenshot({ path: process.argv[3], fullPage: true });
  await b.close();
})();
