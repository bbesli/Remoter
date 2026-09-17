#!/usr/bin/env node
/*
 * Takes the README's screenshots from the demo page, on invented data.
 *
 * The demo page (`apps/desktop/ui/demo.html`) is the real interface with the
 * core's answers replaced by `apps/desktop/ui/src/demo/fixtures.ts`, so the
 * pictures show no real host, address or account. This drives it in headless
 * Firefox and writes PNGs to `docs/images/`.
 *
 *   npm --prefix apps/desktop/ui run dev          # in another terminal
 *   npm install --prefix /tmp/shots puppeteer-core
 *   PUPPETEER_CORE=/tmp/shots/node_modules/puppeteer-core \
 *     node scripts/readme-screenshots.cjs
 *
 * FIREFOX names the browser binary when it is not /usr/bin/firefox, and
 * DEMO_URL the dev server when it is not on its usual port.
 */

"use strict";

const path = require("node:path");
const puppeteer = require(process.env.PUPPETEER_CORE || "puppeteer-core");

const DEMO = process.env.DEMO_URL || "http://localhost:5273/demo.html";
const OUT = path.join(__dirname, "..", "docs", "images");

const SHOTS = [
  // The terminal draws on a canvas, which has no text to wait for; the status
  // bar says the session is up.
  { file: "main.png", query: "shot=main&theme=dark", ready: "Connected" },
  { file: "export.png", query: "shot=export&theme=dark", ready: "Another application" },
  { file: "editor.png", query: "shot=editor&theme=light", ready: "Connect through" },
  { file: "audit.png", query: "shot=audit&theme=light", ready: "Data exported" },
];

async function main() {
  const browser = await puppeteer.launch({
    browser: "firefox",
    executablePath: process.env.FIREFOX || "/usr/bin/firefox",
    headless: true,
    defaultViewport: { width: 1440, height: 900, deviceScaleFactor: 1 },
  });
  try {
    for (const shot of SHOTS) {
      const page = await browser.newPage();
      await page.goto(`${DEMO}?${shot.query}`, { waitUntil: "load" });
      await page.waitForFunction(
        (text) => document.body.innerText.includes(text),
        { timeout: 20000 },
        shot.ready,
      );
      // Transitions and the terminal's first paint settle.
      await new Promise((resolve) => setTimeout(resolve, 1200));
      await page.screenshot({ path: path.join(OUT, shot.file) });
      await page.close();
      process.stdout.write(`wrote docs/images/${shot.file}\n`);
    }
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exit(1);
});
