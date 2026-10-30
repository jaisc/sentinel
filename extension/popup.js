const $ = (s) => document.getElementById(s);

async function refresh() {
  const st = await chrome.runtime.sendMessage({ type: "status" });
  $("enabled").checked = st.enabled;
  const n = st.native || {};
  const el = $("engine");
  if (n.connected) {
    const keys = n.keys || {};
    el.className = "status ok";
    el.textContent = "Local engine connected (v" + (n.version || "?") + "). Safe Browsing: " +
      (keys.safebrowsing ? "on" : "no key") + " · VirusTotal: " + (keys.virustotal ? "on" : "no key");
  } else {
    el.className = "status warn";
    el.textContent = "Local engine not connected — offline checks only. Run setup.sh on this Mac. (" + (n.error || "") + ")";
  }
  const s = st.stats || {};
  $("stats").textContent = (s.checked || 0) + " links checked · " + (s.warned || 0) + " warnings";
  const ul = $("allow");
  ul.textContent = "";
  for (const site of st.allowSites || []) {
    const li = document.createElement("li");
    li.textContent = site + " ";
    const b = document.createElement("button");
    b.textContent = "remove";
    b.className = "link";
    b.onclick = async () => { await chrome.runtime.sendMessage({ type: "removeAllow", site }); refresh(); };
    li.appendChild(b);
    ul.appendChild(li);
  }
  if (!(st.allowSites || []).length) ul.innerHTML = "<li class='muted'>None</li>";
}

$("enabled").onchange = async (e) => {
  await chrome.runtime.sendMessage({ type: "setEnabled", enabled: e.target.checked });
};

$("checkForm").onsubmit = async (e) => {
  e.preventDefault();
  const out = $("checkResult");
  out.textContent = "Checking…";
  const r = await chrome.runtime.sendMessage({ type: "check", url: $("checkUrl").value.trim() });
  out.textContent = "";
  const h = document.createElement("strong");
  h.className = r.verdict;
  h.textContent = { dangerous: "Dangerous", caution: "Caution", clean: "No problems found" }[r.verdict] || r.verdict;
  out.appendChild(h);
  for (const reason of (r.reasons || []).filter((x) => x.points > 0)) {
    const d = document.createElement("div");
    d.textContent = "• " + reason.title;
    out.appendChild(d);
  }
};

refresh();
