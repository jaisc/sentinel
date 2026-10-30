// Offline URL heuristics — a compact port of engine/sentinel/urlcheck.py, used instantly
// before (and, if the native host is missing, instead of) the full local engine check.

export const SHORTENERS = new Set([
  "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
  "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "lnkd.in", "s.id", "v.gd", "bl.ink", "short.io",
  "adf.ly", "qrco.de", "clck.ru", "x.gd", "surl.li", "u.to",
]);

export const BRANDS = {
  google: ["google.com", "google.ca", "gmail.com", "youtube.com"], gmail: ["gmail.com", "google.com"],
  yahoo: ["yahoo.com", "yahoo.ca"], apple: ["apple.com", "icloud.com", "apple.ca"], icloud: ["icloud.com", "apple.com"],
  paypal: ["paypal.com", "paypal.ca", "paypal.me"], amazon: ["amazon.com", "amazon.ca", "amazonaws.com"],
  microsoft: ["microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com"],
  outlook: ["outlook.com", "live.com", "microsoft.com"], facebook: ["facebook.com", "fb.com", "meta.com"],
  instagram: ["instagram.com"], netflix: ["netflix.com"], linkedin: ["linkedin.com"], dropbox: ["dropbox.com"],
  docusign: ["docusign.com", "docusign.net"], github: ["github.com", "github.io"], coinbase: ["coinbase.com"],
  binance: ["binance.com"], brave: ["brave.com"], interac: ["interac.ca"],
  canadapost: ["canadapost.ca", "canadapost-postescanada.ca"], royalbank: ["rbc.com", "royalbank.com", "rbcroyalbank.com"],
  rbcroyalbank: ["rbcroyalbank.com", "rbc.com"], scotiabank: ["scotiabank.com"], desjardins: ["desjardins.com"],
  tdbank: ["td.com", "tdbank.com"], cibc: ["cibc.com"], wellsfargo: ["wellsfargo.com"], chase: ["chase.com"],
  sasktel: ["sasktel.com", "sasktel.net"], saskpower: ["saskpower.com"], adobe: ["adobe.com"],
};

const MULTI = new Set(["co.uk", "org.uk", "com.au", "co.nz", "co.jp", "com.br", "gc.ca", "sk.ca", "on.ca",
  "qc.ca", "bc.ca", "ab.ca", "github.io", "herokuapp.com", "web.app", "pages.dev", "netlify.app",
  "vercel.app", "blogspot.com", "azurewebsites.net", "appspot.com", "workers.dev", "ngrok-free.app"]);

const ACCOUNT_WORDS = new Set(["login", "logon", "signin", "secure", "security", "verify", "verification", "account",
  "accounts", "support", "update", "id", "billing", "help", "service", "alert", "wallet", "auth", "pay", "payment",
  "online", "bank", "confirm", "center", "centre", "team", "recovery", "unlock", "refund", "invoice", "notice",
  "customer", "my", "web", "mail", "app", "store", "delivery", "track", "tracking", "gift", "prize", "reward", "claim"]);

const CONFUSABLES = [["rn", "m"], ["vv", "w"], ["0", "o"], ["1", "l"], ["3", "e"], ["5", "s"], ["4", "a"], ["7", "t"]];

export function registrable(host) {
  host = (host || "").toLowerCase().replace(/\.$/, "");
  if (isIp(host)) return host;
  const l = host.split(".");
  if (l.length <= 2) return host;
  const last2 = l.slice(-2).join(".");
  return MULTI.has(last2) ? l.slice(-3).join(".") : last2;
}

export function isIp(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[") || /^0x[0-9a-f]+$|^\d{8,10}$/i.test(host);
}

export function isPrivate(host) {
  if (host === "localhost" || /\.(local|localhost|internal|lan|home\.arpa)$/.test(host)) return true;
  return /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host) || host === "[::1]";
}

function skeleton(s) {
  s = s.toLowerCase();
  for (const [a, b] of CONFUSABLES) s = s.split(a).join(b);
  return s;
}

function editDistance(a, b) {
  if (Math.abs(a.length - b.length) > 3) return 4;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) cur.push(Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] !== b[j - 1] ? 1 : 0)));
    prev = cur;
  }
  return prev[b.length];
}

function isAccountWord(t) {
  if (ACCOUNT_WORDS.has(t)) return true;
  for (const w of ACCOUNT_WORDS) if (w.length >= 4 && t.startsWith(w) && ACCOUNT_WORDS.has(t.slice(w.length))) return true;
  return false;
}

function legitBrandDomain(d) {
  return Object.values(BRANDS).some((list) => list.includes(d));
}

export function lookalike(host) {
  const domain = registrable(host);
  if (!domain || isIp(domain) || legitBrandDomain(domain)) return null;
  const core = domain.split(".")[0];
  const sk = skeleton(core);
  for (const [brand, legit] of Object.entries(BRANDS)) {
    if (brand.length < 4) continue;
    if (sk === brand && core !== brand) return [`uses look-alike characters to imitate ${legit[0]}`, 90];
    if (brand.length >= 6 && core !== brand && editDistance(sk, brand) === 1) return [`is one letter away from ${legit[0]}`, 70];
  }
  const tokens = sk.split(/[-_]/).filter(Boolean);
  for (const [brand, legit] of Object.entries(BRANDS)) {
    if (brand.length < 4) continue;
    let rest = [];
    if (tokens.includes(brand) && tokens.length > 1) rest = tokens.filter((t) => t !== brand);
    else if (sk.startsWith(brand) && sk !== brand) rest = [sk.slice(brand.length)];
    else if (sk.endsWith(brand) && sk !== brand) rest = [sk.slice(0, -brand.length)];
    rest = rest.flatMap((t) => t.split(/[-_]/)).filter(Boolean);
    if (rest.some(isAccountWord)) return [`contains the name '${brand}' but is not an official ${legit[0]} domain`, 60];
  }
  const sub = host.endsWith(domain) ? host.slice(0, -domain.length).replace(/\.$/, "") : "";
  if (sub) {
    for (const legit of Object.values(BRANDS)) {
      for (const d of legit) {
        if (`.${sub}.`.includes(`.${d}.`)) return [`puts '${d}' at the front, but the real site is ${domain}`, 100];
      }
    }
  }
  return null;
}

// Returns {verdict, score, reasons:[{code, points, title, why}]}
export function analyzeUrl(url) {
  const reasons = [];
  let u;
  try { u = new URL(url); } catch { return { verdict: "clean", score: 0, reasons }; }
  if (!/^https?:$/.test(u.protocol)) return { verdict: "clean", score: 0, reasons };
  const host = u.hostname.toLowerCase();
  if (u.username) {
    reasons.push({ code: "url_userinfo", points: 100, title: `The link hides its real destination behind an '@' — the real site is ${host}`,
      why: "Everything before '@' is ignored by the browser." });
  }
  if (isIp(host) && !isPrivate(host)) {
    reasons.push({ code: "url_ip_host", points: 35, title: `The link goes to a raw IP address (${host})`,
      why: "Real companies use domain names; raw IPs are common in phishing and malware links." });
  }
  const domain = registrable(host);
  if (SHORTENERS.has(host) || SHORTENERS.has(domain)) {
    reasons.push({ code: "url_shortener", points: 25, title: `The link uses a URL shortener (${domain})`,
      why: "Shorteners hide where the link really goes." });
  }
  if (host.includes("xn--")) {
    reasons.push({ code: "url_punycode", points: 30, title: "The address uses international characters",
      why: "Some letters from other alphabets look identical to English ones and can imitate real sites." });
  }
  const look = lookalike(host);
  if (look) {
    reasons.push({ code: "url_lookalike", points: look[1], title: `The address ${domain} ${look[0]}`,
      why: "Look-alike addresses are the #1 phishing trick: the page will look real but steal what you type." });
  }
  const score = reasons.reduce((s, r) => s + r.points, 0);
  return { verdict: score >= 100 ? "dangerous" : score >= 20 ? "caution" : "clean", score, reasons };
}
