#!/usr/bin/env node
// Load-test the Brave/Chromium extension headlessly over the DevTools protocol.
//
//   CHROME=/path/to/chrome node scripts/test-extension.mjs
//
// It loads extension/ unpacked, registers the native-messaging host (pointing at
// engine/bin/sentinel with a throwaway SENTINEL_HOME), then checks that:
//   1. the service worker starts and the native host answers (popup status),
//   2. navigating to a look-alike phishing URL lands on the interstitial with reasons,
//   3. a normal site is NOT interrupted.
// Network access is not required: the flagged navigation is intercepted before it loads.
// On macOS, point CHROME at "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser".

import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, mkdirSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const EXT = join(ROOT, "extension");
const EXT_ID = "hkjkodcckmeegnfhjjmcajmnadcgnmbm";
const CHROME = process.env.CHROME || "/opt/meta-chromium/chrome";
const PORT = 9333 + Math.floor(Math.random() * 500);

const tmp = mkdtempSync(join(tmpdir(), "sentinel-ext-"));
const profile = join(tmp, "profile");
const sentinelHome = join(tmp, "home");
mkdirSync(join(profile, "NativeMessagingHosts"), { recursive: true });
mkdirSync(sentinelHome, { recursive: true });
const wrapper = join(tmp, "sentinel-host");
writeFileSync(wrapper, `#!/bin/sh\nSENTINEL_HOME='${sentinelHome}' exec python3 '${join(ROOT, "engine/bin/sentinel")}' "$@"\n`);
chmodSync(wrapper, 0o755);
const hostManifest = JSON.stringify({ name: "com.sentinel.host", description: "Sentinel local engine", path: wrapper,
  type: "stdio", allowed_origins: [`chrome-extension://${EXT_ID}/`] });
// Linux looks in <user-data-dir>/NativeMessagingHosts; also cover the per-user default dirs.
writeFileSync(join(profile, "NativeMessagingHosts", "com.sentinel.host.json"), hostManifest);

const results = [];
const ok = (name, cond, detail = "") => { results.push([cond, name, detail]); console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? "  — " + detail : ""}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const chrome = spawn(CHROME, [
  `--user-data-dir=${profile}`, `--remote-debugging-port=${PORT}`, "--headless=new", "--no-first-run",
  "--no-default-browser-check", "--no-sandbox", "--disable-gpu", `--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`,
  "about:blank"], { stdio: ["ignore", "ignore", "pipe"] });
let stderr = "";
chrome.stderr.on("data", (d) => { stderr += d; });

async function json(path) {
  for (let i = 0; i < 50; i++) {
    try { return await (await fetch(`http://127.0.0.1:${PORT}${path}`)).json(); } catch { await sleep(200); }
  }
  throw new Error("DevTools not reachable\n" + stderr.slice(-2000));
}

class CDP {
  constructor(url) { this.ws = new WebSocket(url); this.id = 0; this.waiting = new Map();
    this.ws.onmessage = (m) => { const d = JSON.parse(m.data); if (d.id && this.waiting.has(d.id)) { this.waiting.get(d.id)(d); this.waiting.delete(d.id); } }; }
  open() { return new Promise((r, j) => { this.ws.onopen = r; this.ws.onerror = j; }); }
  send(method, params = {}, sessionId) { const id = ++this.id; this.ws.send(JSON.stringify({ id, method, params, sessionId }));
    return new Promise((r) => this.waiting.set(id, r)); }
}

async function evalIn(cdp, targetId, expr) {
  const { result } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
  const r = await cdp.send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true }, result.sessionId);
  return r.result && r.result.result ? r.result.result.value : undefined;
}

async function targets(cdp) { return (await cdp.send("Target.getTargets")).result.targetInfos; }

async function navigateNewTab(cdp, url) {
  const { result } = await cdp.send("Target.createTarget", { url: "about:blank" });
  const t = result.targetId;
  const att = await cdp.send("Target.attachToTarget", { targetId: t, flatten: true });
  await cdp.send("Page.navigate", { url }, att.result.sessionId);
  return t;
}

try {
  const ver = await json("/json/version");
  const cdp = new CDP(ver.webSocketDebuggerUrl);
  await cdp.open();

  // 1. Service worker running?
  let sw;
  for (let i = 0; i < 30 && !sw; i++) {
    sw = (await targets(cdp)).find((t) => t.type === "service_worker" && t.url.startsWith(`chrome-extension://${EXT_ID}/`));
    if (!sw) await sleep(300);
  }
  ok("extension loads with pinned ID and service worker starts", !!sw, sw ? sw.url : "no service worker for " + EXT_ID);

  // Popup status (native host connection).
  const popup = await navigateNewTab(cdp, `chrome-extension://${EXT_ID}/popup.html`);
  let engineText = "";
  for (let i = 0; i < 20; i++) {
    await sleep(400);
    engineText = await evalIn(cdp, popup, "document.getElementById('engine').textContent");
    if (engineText && !engineText.startsWith("Connecting")) break;
  }
  ok("native host connects from popup", /Local engine connected/.test(engineText || ""), engineText);

  // 2. Flagged navigation -> interstitial.
  const bad = "https://paypal.com.secure-verify.xyz/login";
  const tab = await navigateNewTab(cdp, bad);
  let info;
  for (let i = 0; i < 25; i++) {
    await sleep(400);
    info = (await targets(cdp)).find((t) => t.targetId === tab);
    if (info && info.url.includes("interstitial.html")) break;
  }
  ok("look-alike URL is redirected to the interstitial", info && info.url.includes("interstitial.html"), info && info.url);
  if (info && info.url.includes("interstitial.html")) {
    await sleep(500);
    const page = await evalIn(cdp, tab, `({badge: document.getElementById('badge').textContent,
      url: document.getElementById('url').textContent,
      reasons: [...document.querySelectorAll('#reasons li')].map(li => li.textContent),
      source: document.getElementById('source').textContent,
      buttons: [...document.querySelectorAll('.actions button')].map(b => b.textContent)})`);
    ok("interstitial shows verdict, URL and reasons", page.badge === "Dangerous" && page.url === bad && page.reasons.length > 0,
       JSON.stringify(page));
    ok("interstitial offers Go back / Proceed / Always allow", page.buttons.length === 3, page.buttons.join(" | "));
    ok("verdict came from the local engine (native host)", /full local engine check/.test(page.source), page.source);
  }

  // 3. Normal site is not interrupted.
  const good = await navigateNewTab(cdp, "https://www.google.com/");
  await sleep(3000);
  const ginfo = (await targets(cdp)).find((t) => t.targetId === good);
  ok("normal site is not interrupted", ginfo && !ginfo.url.includes("interstitial.html"), ginfo && ginfo.url);

  await cdp.send("Browser.close");
} catch (e) {
  ok("harness", false, String(e));
} finally {
  chrome.kill("SIGTERM");
  await sleep(300);
  rmSync(tmp, { recursive: true, force: true });
}
const failed = results.filter((r) => !r[0]).length;
console.log(`\n${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
