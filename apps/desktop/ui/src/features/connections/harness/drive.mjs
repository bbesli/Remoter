/**
 * Drives `harness.tsx` with real mouse input, in a real Chromium.
 *
 * The input goes through `Input.dispatchMouseEvent` over the Chrome DevTools
 * Protocol, which is the browser's own input pipeline: the compositor does the
 * hit test, the renderer synthesises the pointer events, and pointer capture
 * behaves the way it does on a user's machine. That is the whole point —
 * `fireEvent.pointerMove(row, …)` in jsdom skips every one of those decisions,
 * and every defect this gesture has shipped lived in one of them.
 *
 * Electron is used only as a Chromium that can be scripted without a package
 * install; WebView2 cannot be run here, and Chromium is the closest engine.
 *
 * Run it from `apps/desktop/ui`, with any Electron new enough to take an ESM
 * main script (28 or later); the one below is whatever the machine has:
 *
 *   npx vite --port 5399 --strictPort &
 *   /usr/lib/electron42/electron --no-sandbox --ozone-platform=x11 \
 *     src/features/connections/harness/drive.mjs
 *
 * It prints one JSON object per scenario, then a summary line, and exits. The
 * window is shown rather than hidden on purpose: a hidden window's compositor
 * is what does the hit test for synthetic input, and a test that cannot be
 * seen failing is how this component got into this state.
 */

/* global console, setTimeout --
   This file runs in Electron's main process, not in the page. The lint config
   gives browser globals to `.ts`/`.tsx` alone, so the two this uses are
   declared here rather than by widening the config for everything. */

import { app, BrowserWindow } from "electron";

const PAGE = "http://localhost:5399/src/features/connections/harness/index.html";

/** Row height in the rendered tree; measured, not assumed. */
let rowHeight = 0;

const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

function evaluate(win, expression) {
  return win.webContents.executeJavaScript(expression, true);
}

async function waitForTree(win) {
  for (let i = 0; i < 200; i += 1) {
    const ready = await evaluate(
      win,
      `Boolean(window.harness) && document.querySelectorAll('[role="treeitem"]').length > 5`,
    );
    if (ready) return;
    await sleep(50);
  }
  throw new Error("the tree never rendered");
}

async function mouse(dbg, type, x, y, buttons) {
  await dbg.sendCommand("Input.dispatchMouseEvent", {
    type,
    x,
    y,
    button: "left",
    buttons,
    clickCount: type === "mouseMoved" ? 0 : 1,
    pointerType: "mouse",
  });
}

async function key(dbg, code, keyName, modifiers) {
  for (const type of ["keyDown", "keyUp"]) {
    await dbg.sendCommand("Input.dispatchKeyEvent", {
      type,
      code,
      key: keyName,
      windowsVirtualKeyCode: code === "ArrowUp" ? 38 : 0,
      nativeVirtualKeyCode: code === "ArrowUp" ? 38 : 0,
      modifiers,
    });
  }
}

/** Press at a point, travel to another in the steps a mouse takes, release. */
async function drag(dbg, from, to, step = 6) {
  await mouse(dbg, "mousePressed", from.x, from.y, 1);
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const distance = Math.hypot(dx, dy);
  const steps = Math.max(1, Math.ceil(distance / step));
  for (let i = 1; i <= steps; i += 1) {
    await mouse(dbg, "mouseMoved", from.x + (dx * i) / steps, from.y + (dy * i) / steps, 1);
    await sleep(8);
  }
  await mouse(dbg, "mouseReleased", to.x, to.y, 0);
}

/** Wait until the move calls stop arriving, so a scenario reads a settled tree. */
async function settle(win) {
  let last = -1;
  for (let i = 0; i < 120; i += 1) {
    const count = await evaluate(win, `window.harness.moves().length`);
    if (count === last && i > 2) return count;
    last = count;
    await sleep(60);
  }
  return last;
}

/** The point `fraction` of the way down a node's row. */
async function pointIn(win, nodeId, fraction) {
  const box = await evaluate(win, `window.harness.rect(${JSON.stringify(nodeId)})`);
  if (box === null) throw new Error(`no row for ${nodeId}`);
  rowHeight = box.height;
  return { x: box.left + 18, y: box.top + box.height * fraction, box };
}

async function open(win, query = "") {
  await win.loadURL(PAGE + query);
  await waitForTree(win);
  await evaluate(win, `window.harness.reset()`);
}

/** Put a row on screen without touching the pointer, then measure it. */
async function scrollTo(win, nodeId) {
  await evaluate(
    win,
    `document.getElementById("tree-row-tree:${nodeId}").scrollIntoView({ block: "center" }), true`,
  );
  await sleep(120);
}

/**
 * A probe that records what the browser did with each move, from inside.
 *
 * `sourceId` is the row the press lands on, which is the element the tree
 * asks for the capture on — asking the *first* row instead was the mistake
 * that made the first run of this report "nobody held the capture".
 */
function probeFor(sourceId) {
  return `
  window.__probe = { targets: [], captured: [], pointerIds: [] };
  document.addEventListener("pointermove", (e) => {
    const t = e.target;
    window.__probe.targets.push(t instanceof Element ? (t.id || t.getAttribute("role") || t.tagName) : "?");
    window.__probe.pointerIds.push(e.pointerId);
    const row = document.getElementById("tree-row-tree:${sourceId}");
    const scroller = document.querySelector('[role="tree"]');
    window.__probe.captured.push([
      Boolean(row && row.hasPointerCapture(e.pointerId)),
      Boolean(scroller && scroller.hasPointerCapture(e.pointerId)),
    ]);
  }, true);
  true;
`;
}

/** Turn pointer capture off entirely, to see what the gesture does without it. */
const NO_CAPTURE = `
  Element.prototype.setPointerCapture = function () {};
  true;
`;

/** Redirect every capture onto the scroller — the arrangement ADR-0014 claims. */
const CAPTURE_ON_SCROLLER = `
  const real = Element.prototype.setPointerCapture;
  Element.prototype.setPointerCapture = function (id) {
    const scroller = document.querySelector('[role="tree"]');
    real.call(scroller ?? this, id);
  };
  true;
`;

const results = [];
function record(name, data) {
  results.push({ scenario: name, ...data });
  console.log(`### ${name} ${JSON.stringify(data)}`);
}

async function main() {
  const win = new BrowserWindow({
    width: 420,
    height: 1000,
    x: 0,
    y: 0,
    show: true,
    webPreferences: { backgroundThrottling: false },
  });
  const dbg = win.webContents.debugger;
  dbg.attach("1.3");

  // ---- 1. a drop on a separator row -------------------------------------
  await open(win);
  {
    const from = await pointIn(win, "s001", 0.5);
    const to = await pointIn(win, "sep1", 0.5);
    await mouse(dbg, "mousePressed", from.x, from.y, 1);
    const steps = Math.ceil(Math.abs(to.y - from.y) / 6);
    for (let i = 1; i <= steps; i += 1) {
      await mouse(dbg, "mouseMoved", to.x, from.y + ((to.y - from.y) * i) / steps, 1);
      await sleep(8);
    }
    // While the pointer is still down: the indicator has to be drawn on the
    // separator, and an absolutely positioned indicator needs the row to be a
    // containing block or it is drawn against the scroller instead.
    const indicator = await evaluate(
      win,
      `(() => {
         const el = document.querySelector('[data-drop-id="sep1"]');
         return { className: el.className, position: getComputedStyle(el).position };
       })()`,
    );
    await mouse(dbg, "mouseReleased", to.x, to.y, 0);
    await settle(win);
    const nodes = await evaluate(win, `window.harness.nodes()`);
    const moved = nodes.find((n) => n.id === "s001");
    record("separator-drop", {
      separatorHasDropId: await evaluate(
        win,
        `Boolean(document.querySelector('[data-drop-id="sep1"]'))`,
      ),
      indicatorDrawn: /drop(Before|After)/.test(indicator.className),
      indicatorPosition: indicator.position,
      movedParent: moved.parentId,
      movedSortOrder: moved.sortOrder,
      topLevelOrder: await evaluate(win, `window.harness.order(null)`),
      moves: await evaluate(win, `window.harness.moves().length`),
      live: await evaluate(win, `window.harness.live()`),
      refusalShown: await evaluate(
        win,
        `window.harness.text().includes("The entry was not moved")`,
      ),
    });
  }

  // ---- 2. a click with a wobble in it ------------------------------------
  for (const wobble of [3, 4, 6, 8, 12]) {
    await open(win);
    const from = await pointIn(win, "s005", 0.5);
    await mouse(dbg, "mousePressed", from.x, from.y, 1);
    await mouse(dbg, "mouseMoved", from.x + wobble, from.y + 1, 1);
    await sleep(20);
    await mouse(dbg, "mouseReleased", from.x + wobble, from.y + 1, 0);
    await sleep(250);
    record(`click-wobble-${wobble}px`, {
      refusalShown: await evaluate(
        win,
        `window.harness.text().includes("The entry was not moved")`,
      ),
      selfRefusalShown: await evaluate(
        win,
        `window.harness.text().includes("cannot be dropped onto itself")`,
      ),
      live: await evaluate(win, `window.harness.live()`),
      selected: await evaluate(win, `window.harness.selected()`),
      moves: await evaluate(win, `window.harness.moves().length`),
    });
  }

  // ---- 3. one reorder, counted -------------------------------------------
  await open(win);
  {
    const before = await evaluate(win, `window.harness.order(null)`);
    const from = await pointIn(win, "s005", 0.5);
    const to = await pointIn(win, "s003", 0.1);
    await drag(dbg, from, to);
    const moves = await settle(win);
    record("reorder-cost", {
      siblingsBefore: before.length,
      moves,
      topLevelOrder: await evaluate(win, `window.harness.order(null)`),
      live: await evaluate(win, `window.harness.live()`),
    });
  }

  // ---- 4. Ctrl+ArrowUp, counted ------------------------------------------
  await open(win);
  {
    const at = await pointIn(win, "s010", 0.5);
    await mouse(dbg, "mousePressed", at.x, at.y, 1);
    await mouse(dbg, "mouseReleased", at.x, at.y, 0);
    await sleep(120);
    await key(dbg, "ArrowUp", "ArrowUp", 2);
    const moves = await settle(win);
    record("keyboard-cost", {
      moves,
      topLevelOrder: await evaluate(win, `window.harness.order(null)`),
      live: await evaluate(win, `window.harness.live()`),
    });
  }

  // ---- 5. where the capture lands, and whether the drag still works -------
  for (const [name, setup] of [
    ["capture-as-shipped", "true;"],
    ["capture-disabled", NO_CAPTURE],
    ["capture-on-scroller", CAPTURE_ON_SCROLLER],
  ]) {
    await open(win);
    await evaluate(win, setup);
    await evaluate(win, probeFor("s001"));
    const from = await pointIn(win, "s001", 0.5);
    const to = await pointIn(win, "f1", 0.5);
    await drag(dbg, from, to);
    await settle(win);
    const probe = await evaluate(win, `window.__probe`);
    const nodes = await evaluate(win, `window.harness.nodes()`);
    record(name, {
      movedParent: nodes.find((n) => n.id === "s001").parentId,
      berlinOrder: await evaluate(win, `window.harness.order("f1")`),
      pointerIds: [...new Set(probe.pointerIds)],
      // Which element the browser delivered each move to, deduplicated in
      // order: this is the decision jsdom cannot make for us.
      targets: probe.targets.filter((t, i) => t !== probe.targets[i - 1]),
      rowHeldCapture: probe.captured.some(([row]) => row),
      scrollerHeldCapture: probe.captured.some(([, scroller]) => scroller),
      live: await evaluate(win, `window.harness.live()`),
      selectedAfterDrag: await evaluate(win, `window.harness.selected()`),
    });
  }

  // ---- 5b. the click a press produces, with each capture arrangement ------
  //
  // ADR-0014 and the comment on `capture()` both claimed the capture goes on
  // the row so that "the click after a drag still belongs to the row it came
  // from". `wobble` is a press that crosses the drag threshold and comes back
  // down on the row it started on — the case that claim is about.
  for (const [name, setup, wobble] of [
    ["click-as-shipped", "true;", 0],
    ["click-capture-on-scroller", CAPTURE_ON_SCROLLER, 0],
    ["click-after-wobble-as-shipped", "true;", 12],
    ["click-after-wobble-capture-on-scroller", CAPTURE_ON_SCROLLER, 12],
  ]) {
    await open(win);
    await evaluate(win, setup);
    const at = await pointIn(win, "s005", 0.5);
    await mouse(dbg, "mousePressed", at.x, at.y, 1);
    if (wobble > 0) {
      await mouse(dbg, "mouseMoved", at.x + wobble, at.y, 1);
      await mouse(dbg, "mouseMoved", at.x, at.y, 1);
    }
    await mouse(dbg, "mouseReleased", at.x, at.y, 0);
    await sleep(200);
    record(name, { selected: await evaluate(win, `window.harness.selected()`) });
  }

  // ---- 5c. boundary events while the pointer is captured -----------------
  for (const [name, setup] of [
    ["leaving-the-sidebar-as-shipped", "true;"],
    ["leaving-the-sidebar-no-capture", NO_CAPTURE],
  ]) {
    await open(win);
    await evaluate(win, setup);
    await evaluate(
      win,
      `window.__leaves = 0;
       document.querySelector('[role="tree"]').addEventListener("pointerleave", () => { window.__leaves += 1; });
       true;`,
    );
    const from = await pointIn(win, "s001", 0.5);
    const back = await pointIn(win, "f1", 0.5);
    await mouse(dbg, "mousePressed", from.x, from.y, 1);
    for (let i = 1; i <= 6; i += 1) await mouse(dbg, "mouseMoved", from.x + i * 60, from.y, 1);
    const outside = await evaluate(win, `window.harness.text().includes("The entry was not moved")`);
    // Back over a folder, which must plan again rather than stay cleared.
    await mouse(dbg, "mouseMoved", back.x, back.y, 1);
    await sleep(40);
    await mouse(dbg, "mouseReleased", back.x, back.y, 0);
    await settle(win);
    const nodes = await evaluate(win, `window.harness.nodes()`);
    record(name, {
      scrollerPointerLeaves: await evaluate(win, `window.__leaves`),
      refusalWhileOutside: outside,
      movedParentAfterComingBack: nodes.find((n) => n.id === "s001").parentId,
    });
  }

  // ---- 6. a drag that leaves the window ----------------------------------
  await open(win);
  {
    const from = await pointIn(win, "s001", 0.5);
    await mouse(dbg, "mousePressed", from.x, from.y, 1);
    for (let i = 1; i <= 8; i += 1) await mouse(dbg, "mouseMoved", from.x + i * 40, from.y, 1);
    // Far outside the window's own width, which is where a drag that has lost
    // the pointer stops producing moves at all.
    const seen = await evaluate(win, `window.harness.text().includes("srv-001")`);
    await mouse(dbg, "mouseReleased", from.x + 320, from.y, 0);
    await settle(win);
    record("drag-outside-window", {
      stillRendered: seen,
      moves: await evaluate(win, `window.harness.moves().length`),
      topLevelOrder: await evaluate(win, `window.harness.order(null)`),
    });
  }

  // ---- 7. the four-hundred-entry tree, dragged end to middle --------------
  //
  // The one gesture the local search cannot make cheap: a node carried from
  // one end of a list with no gaps anywhere to the middle of it, where the
  // nearest slack is half a list away. The drag is real input throughout; the
  // scroller is moved between the press and the release the way the edge
  // scroll would move it, only faster than 350 pixels a second.
  await open(win, "?servers=400");
  {
    const costs = [];
    for (const [source, target] of [
      ["s400", "s201"],
      ["s399", "s202"],
    ]) {
      await evaluate(win, `window.harness.reset()`);
      await scrollTo(win, source);
      const from = await pointIn(win, source, 0.5);
      await mouse(dbg, "mousePressed", from.x, from.y, 1);
      for (let i = 1; i <= 4; i += 1) await mouse(dbg, "mouseMoved", from.x, from.y - i * 6, 1);
      await scrollTo(win, target);
      const to = await pointIn(win, target, 0.1);
      await mouse(dbg, "mouseMoved", to.x, to.y, 1);
      await sleep(40);
      await mouse(dbg, "mouseReleased", to.x, to.y, 0);
      costs.push({ source, target, moves: await settle(win) });
    }
    const order = await evaluate(win, `window.harness.order(null)`);
    record("four-hundred-entries", {
      siblings: order.length,
      costs,
      // Where the two dragged entries actually came to rest.
      around: order.slice(order.indexOf("s400") - 2, order.indexOf("s400") + 3),
      live: await evaluate(win, `window.harness.live()`),
    });
  }

  // ---- 8. a run of calls that stops in the middle ------------------------
  //
  // The respace buys its two calls by handing a sibling the sort order the
  // moved entry has not vacated yet, so the calls are not independent: stop
  // after the first and two siblings share an order. `?failAt=` refuses the
  // call by number, which is the only way to reach this from outside.
  for (const failAt of ["2", "2,3"]) {
    await open(win, `?failAt=${failAt}`);
    const at = await pointIn(win, "s010", 0.5);
    await mouse(dbg, "mousePressed", at.x, at.y, 1);
    await mouse(dbg, "mouseReleased", at.x, at.y, 0);
    await sleep(120);
    await evaluate(win, `window.harness.reset()`);
    await key(dbg, "ArrowUp", "ArrowUp", 2);
    await settle(win);
    record(`half-applied-run-failAt-${failAt}`, {
      calls: await evaluate(
        win,
        `window.harness.moves().map((c) => [c.args.id, c.args.sortOrder])`,
      ),
      // Empty is the whole point: the run was walked back along the states the
      // vault had already been in.
      duplicates: await evaluate(win, `window.harness.duplicates()`),
      around: (await evaluate(win, `window.harness.order(null)`)).slice(9, 14),
      live: await evaluate(win, `window.harness.live()`),
      failureShown: await evaluate(
        win,
        `window.harness.text().includes("The entry was not moved")`,
      ),
    });
  }

  // ---- 9. the separator, dragged ------------------------------------------
  await open(win);
  {
    const from = await pointIn(win, "sep1", 0.5);
    const to = await pointIn(win, "f1", 0.2);
    await drag(dbg, from, to);
    await settle(win);
    record("separator-dragged", {
      moves: await evaluate(win, `window.harness.moves().length`),
      topOfTree: (await evaluate(win, `window.harness.order(null)`)).slice(0, 3),
      live: await evaluate(win, `window.harness.live()`),
    });
  }

  // ---- 10. what the tree says during two hundred vault writes -------------
  await open(win, "?servers=400");
  {
    // Watched rather than polled: the fake core answers in a microtask, so a
    // poll from outside the page can miss two hundred writes entirely, and
    // "the bar was never there" and "the bar was there for four milliseconds"
    // are not the same finding.
    await evaluate(
      win,
      `window.__bar = { now: [], max: [], text: [] };
       new MutationObserver(() => {
         const bar = document.querySelector('[role="progressbar"]');
         if (bar === null) return;
         window.__bar.now.push(Number(bar.getAttribute("aria-valuenow")));
         window.__bar.max.push(Number(bar.getAttribute("aria-valuemax")));
         window.__bar.text.push(bar.getAttribute("aria-valuetext"));
       }).observe(document.body, {
         subtree: true,
         childList: true,
         attributes: true,
         attributeFilter: ["aria-valuenow"],
       });
       true;`,
    );
    await scrollTo(win, "s400");
    const from = await pointIn(win, "s400", 0.5);
    await mouse(dbg, "mousePressed", from.x, from.y, 1);
    for (let i = 1; i <= 4; i += 1) await mouse(dbg, "mouseMoved", from.x, from.y - i * 6, 1);
    await scrollTo(win, "s201");
    const to = await pointIn(win, "s201", 0.1);
    await mouse(dbg, "mouseMoved", to.x, to.y, 1);
    await sleep(40);
    await mouse(dbg, "mouseReleased", to.x, to.y, 0);

    const moves = await settle(win);
    const bar = await evaluate(win, `window.__bar`);
    record("progress-over-two-hundred-writes", {
      moves,
      // Every value the bar actually showed, not a poll that might miss it.
      // Against this fake core the writes resolve in microtasks, so the whole
      // run is over in milliseconds; against a vault each one is an fsync.
      valuesShown: bar.now.length,
      distinct: [...new Set(bar.now)].length,
      first: bar.now[0] ?? null,
      last: bar.now[bar.now.length - 1] ?? null,
      max: bar.max[bar.max.length - 1] ?? null,
      text: bar.text[bar.text.length - 1] ?? null,
      barGoneAfterwards: await evaluate(
        win,
        `document.querySelector('[role="progressbar"]') === null`,
      ),
    });
  }

  console.log(`### rowHeight ${rowHeight}`);
  console.log(`### done ${results.length}`);
}

app.whenReady().then(async () => {
  try {
    await main();
  } catch (err) {
    console.log(`### error ${String(err && err.stack ? err.stack : err)}`);
  }
  app.exit(0);
});
