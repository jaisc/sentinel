// Sentinel Link Guard — MV3 service worker.
//
// Before a top-level navigation to an external site, check the URL:
//   1. instant offline heuristics (heuristics.js), then
//   2. the local Sentinel engine over native messaging (Safe Browsing + VirusTotal, keys in the
//      macOS Keychain — this extension never sees an API key).
// If the URL is flagged, the tab is sent to interstitial.html: what the URL is, why it was
// flagged, Proceed / Go back / Always allow this site.

import { analyzeUrl, registrable, isPrivate } from "./heuristics.js";

const HOST_NAME = "com.sentinel.host";
const NATIVE_TIMEOUT_MS = 4000;
// Reasons that are not worth interrupting a click for on their own (the redirect target is checked too).
const MINOR = new Set(["url_shortener", "url_risky_tld", "url_deep_subdomains", "url_download", "url_insecure_login"]);

// ---------------------------------------------------------------------------------------------
// Native messaging (persistent port, request ids; falls back to heuristics if unavailable)

let port = null;
let nextId = 1;
const pending = new Map();
let nativeStatus = { connected: false, error: "not tried yet", keys: {} };

function connect() {
  try {
    port = chrome.runtime.connectNative(HOST_NAME);
  } catch (e) {
    nativeStatus = { connected: false, error: String(e), keys: {} };
    port = null;
    return null;
  }
  port.onMessage.addListener((msg) => {
    // The host answers strictly in order; resolve the oldest pending request.
    const first = pending.keys().next();
    if (first.done) return;
    const { resolve, timer } = pending.get(first.value);
    clearTimeout(timer);
    pending.delete(first.value);
    resolve(msg);
  });
  port.onDisconnect.addListener(() => {
    const err = chrome.runtime.lastError ? chrome.runtime.lastError.message : "disconnected";
    nativeStatus = { connected: false, error: err, keys: {} };
    for (const { resolve, timer } of pending.values()) { clearTimeout(timer); resolve(null); }
    pending.clear();
    port = null;
  });
  return port;
}

function native(req) {
  return new Promise((resolve) => {
    if (!port && !connect()) return resolve(null);
    const id = nextId++;
    const timer = setTimeout(() => { pending.delete(id); resolve(null); }, NATIVE_TIMEOUT_MS);
    pending.set(id, { resolve, timer });
    try {
      port.postMessage(req);
    } catch (e) {
      clearTimeout(timer);
      pending.delete(id);
      resolve(null);
    }
  });
}

async function ping() {
  const r = await native({ type: "ping" });
  nativeStatus = r && r.ok ? { connected: true, error: "", keys: r.keys || {}, version: r.version }
                           : { connected: false, error: nativeStatus.error || "no response", keys: {} };
  return nativeStatus;
}

// ---------------------------------------------------------------------------------------------
// Storage helpers: always-allow (local, synced to the engine allowlist) and allow-once (session)

async function getSet(area, key) {
  const v = await chrome.storage[area].get(key);
  return new Set(v[key] || []);
}

async function addToSet(area, key, value) {
  const s = await getSet(area, key);
  s.add(value);
  await chrome.storage[area].set({ [key]: [...s] });
}

async function settings() {
  const v = await chrome.storage.local.get({ enabled: true, stats: { checked: 0, warned: 0 } });
  return v;
}

async function bumpStat(name) {
  const v = await settings();
  v.stats[name] = (v.stats[name] || 0) + 1;
  await chrome.storage.local.set({ stats: v.stats });
}

// ---------------------------------------------------------------------------------------------
// The check

function shouldInterrupt(result) {
  if (!result || result.verdict === "clean") return false;
  if (result.verdict === "dangerous") return true;
  return (result.reasons || []).some((r) => r.points >= 20 && !MINOR.has(r.code));
}

async function checkUrl(url, { deep = false, navigation = false } = {}) {
  const local = analyzeUrl(url);
  const res = await native({ type: "check", url, deep, navigation });
  if (res && res.verdict) {
    return { ...res, source: "engine" };
  }
  return { ...local, url, source: "heuristics-only", reputation: {},
           note: "The local Sentinel engine isn't connected, so only offline checks ran (no Safe Browsing / VirusTotal)." };
}

async function showWarning(tabId, result, mode) {
  const id = crypto.randomUUID();
  await chrome.storage.session.set({ ["warn:" + id]: { ...result, mode, tabId, at: Date.now() } });
  const page = chrome.runtime.getURL("interstitial.html") + "?id=" + id;
  if (mode === "navigation") {
    await chrome.tabs.update(tabId, { url: page });
  } else {
    await chrome.tabs.create({ url: page });
  }
}

const inFlight = new Map(); // tabId -> url (dedupe onBeforeNavigate + onCommitted)

async function guardNavigation(details) {
  if (details.frameId !== 0) return;
  let u;
  try { u = new URL(details.url); } catch { return; }
  if (!/^https?:$/.test(u.protocol)) return;
  const host = u.hostname.toLowerCase();
  if (isPrivate(host)) return;
  const { enabled } = await settings();
  if (!enabled) return;
  const site = registrable(host);
  const always = await getSet("local", "allowSites");
  const once = await getSet("session", "allowOnce");
  if (always.has(site) || once.has(details.url) || once.has("site:" + site)) return;

  // Same-site navigations are not "external": skip them.
  const prev = (await chrome.storage.session.get("tabSite:" + details.tabId))["tabSite:" + details.tabId];
  if (prev && prev === site && details.transitionType !== "typed") return;

  // Remember where the user was, so "Go back" never returns to a flagged page that already loaded.
  const backUrl = (await chrome.storage.session.get("tabUrl:" + details.tabId))["tabUrl:" + details.tabId] || "";

  if (inFlight.get(details.tabId) === details.url) return;
  inFlight.set(details.tabId, details.url);
  try {
    // Cached verdicts for this browser session (hashed key, not a history list).
    const key = "v:" + (await sha256(details.url));
    let result = (await chrome.storage.session.get(key))[key];
    if (!result) {
      result = await checkUrl(details.url, { navigation: true });
      await chrome.storage.session.set({ [key]: result });
    }
    await bumpStat("checked");
    if (shouldInterrupt(result)) {
      await bumpStat("warned");
      await showWarning(details.tabId, { ...result, backUrl: backUrl === details.url ? "" : backUrl }, "navigation");
    }
  } finally {
    inFlight.delete(details.tabId);
  }
}

async function sha256(s) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 32);
}

chrome.webNavigation.onBeforeNavigate.addListener((d) => { guardNavigation(d).catch(console.error); });

chrome.webNavigation.onCommitted.addListener(async (d) => {
  if (d.frameId !== 0) return;
  let u;
  try { u = new URL(d.url); } catch { return; }
  if (!/^https?:$/.test(u.protocol)) return;
  // Server-side redirects (e.g. a shortener) don't fire onBeforeNavigate for the final URL: check it here.
  if ((d.transitionQualifiers || []).includes("server_redirect")) {
    guardNavigation({ ...d, transitionType: "redirect" }).catch(console.error);
  }
  await chrome.storage.session.set({ ["tabSite:" + d.tabId]: registrable(u.hostname), ["tabUrl:" + d.tabId]: d.url });
});

chrome.tabs.onRemoved.addListener((tabId) => { chrome.storage.session.remove(["tabSite:" + tabId, "tabUrl:" + tabId]); });

// ---------------------------------------------------------------------------------------------
// Context menu: "Check this link with Sentinel"

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "sentinel-check-link", title: "Check this link with Sentinel", contexts: ["link"] });
  chrome.contextMenus.create({ id: "sentinel-check-page", title: "Check this page with Sentinel", contexts: ["page"] });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const url = info.menuItemId === "sentinel-check-link" ? info.linkUrl : (info.pageUrl || (tab && tab.url));
  if (!url) return;
  const result = await checkUrl(url, { deep: true });
  await showWarning(tab ? tab.id : -1, result, "manual");
});

// ---------------------------------------------------------------------------------------------
// Messages from interstitial.html and popup.html

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (msg.type === "proceed") {
      await addToSet("session", "allowOnce", msg.url);
      native({ type: "proceeded", url: msg.url });
      sendResponse({ ok: true });
    } else if (msg.type === "alwaysAllow") {
      const site = registrable(new URL(msg.url).hostname);
      await addToSet("local", "allowSites", site);
      native({ type: "allow", host: site });
      sendResponse({ ok: true, site });
    } else if (msg.type === "status") {
      const st = await ping();
      const s = await settings();
      const allow = [...(await getSet("local", "allowSites"))];
      sendResponse({ native: st, enabled: s.enabled, stats: s.stats, allowSites: allow });
    } else if (msg.type === "setEnabled") {
      await chrome.storage.local.set({ enabled: !!msg.enabled });
      sendResponse({ ok: true });
    } else if (msg.type === "removeAllow") {
      const s = await getSet("local", "allowSites");
      s.delete(msg.site);
      await chrome.storage.local.set({ allowSites: [...s] });
      sendResponse({ ok: true });
    } else if (msg.type === "check") {
      sendResponse(await checkUrl(msg.url, { deep: true }));
    } else {
      sendResponse({ ok: false });
    }
  })();
  return true; // async response
});
