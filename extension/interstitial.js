const params = new URLSearchParams(location.search);
const id = params.get("id");
const $ = (s) => document.getElementById(s);

function text(el, s) { el.textContent = s; }

async function load() {
  const key = "warn:" + id;
  const data = (await chrome.storage.session.get(key))[key];
  if (!data) {
    text($("headline"), "This warning has expired");
    text($("advice"), "Go back and try the link again.");
    $("proceed").hidden = true;
    $("always").hidden = true;
    return;
  }
  const v = data.verdict || "clean";
  const label = { dangerous: "Dangerous", caution: "Caution", clean: "No problems found" }[v] || v;
  const badge = $("badge");
  text(badge, label);
  badge.className = "badge " + v;
  document.body.classList.add(v);
  text($("url"), data.url);
  if (data.mode === "manual") {
    text($("headline"), v === "clean" ? "Sentinel found no problems with this link" : "Sentinel flagged this link");
    $("proceed").textContent = "Open the link";
    $("back").textContent = "Close";
  } else {
    text($("headline"), v === "dangerous" ? "This site is likely dangerous" : "Be careful with this site");
  }
  const ul = $("reasons");
  const reasons = (data.reasons || []).filter((r) => r.points > 0);
  if (!reasons.length) {
    const li = document.createElement("li");
    li.textContent = "Nothing suspicious was found.";
    ul.appendChild(li);
  }
  for (const r of reasons) {
    const li = document.createElement("li");
    const b = document.createElement("strong");
    b.textContent = r.title;
    li.appendChild(b);
    if (r.why) {
      const s = document.createElement("span");
      s.textContent = " — " + r.why;
      li.appendChild(s);
    }
    ul.appendChild(li);
  }
  const rep = data.reputation || {};
  const bits = [];
  if (rep.safebrowsing) bits.push("Google Safe Browsing: " + rep.safebrowsing.status);
  if (rep.virustotal) bits.push("VirusTotal: " + rep.virustotal.status);
  if (data.note) bits.push(data.note);
  text($("note"), bits.join(" · "));
  text($("advice"), v === "clean"
    ? "You can open it."
    : "Don't enter passwords, card numbers or personal details on this site. If an email or message sent you here, " +
      "go to the company's website by typing its address yourself instead.");
  text($("source"), data.source === "engine" ? "(full local engine check" + (data.event_id ? ", report saved" : "") + ")" : "(offline checks only)");

  $("back").onclick = () => {
    if (data.mode === "manual") { window.close(); return; }
    chrome.tabs.getCurrent((tab) => chrome.tabs.update(tab.id, { url: data.backUrl || "chrome://newtab/" }));
  };
  $("proceed").onclick = async () => {
    await chrome.runtime.sendMessage({ type: "proceed", url: data.url });
    location.replace(data.url);
  };
  $("always").onclick = async () => {
    const r = await chrome.runtime.sendMessage({ type: "alwaysAllow", url: data.url });
    $("always").textContent = "Always allowed: " + (r && r.site ? r.site : "this site");
    await chrome.runtime.sendMessage({ type: "proceed", url: data.url });
    location.replace(data.url);
  };
}

load();
