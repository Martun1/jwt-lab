// app.js: wires the JWT Lab UI to the pure functions in jwt.js.
"use strict";
const $ = (id) => document.getElementById(id);
let current = null;

const SAMPLES = {
  // HS256 signed with the secret "secret" — the classic weak default
  weak: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDIzIiwibmFtZSI6Ik1hcnRpbiIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMDM2MDB9.",
  none: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMDIzIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzAwMDAwMDAwfQ.",
  leaky: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MiIsImVtYWlsIjoibWFydGluQGV4YW1wbGUuY29tIiwicGFzc3dvcmQiOiJodW50ZXIyIiwiYXBpX2tleSI6InNrX2xpdmVfMTIzIiwiaXNBZG1pbiI6ZmFsc2V9.",
};

async function fillSignature(sampleKey) {
  // sign the weak/leaky samples with "secret" so the demo is realistic
  if (sampleKey === "none") return SAMPLES.none;
  const j = parseJwt(SAMPLES[sampleKey] + "x"); // placeholder sig, re-sign below
  return forge(j.header, j.payload, "secret");
}

function badge(alg) {
  const el = $("algBadge");
  el.textContent = alg || "—";
  el.className = "badge " + (!alg || alg.toLowerCase() === "none" ? "crit" : /^HS/.test(alg) ? "warn" : "ok");
}

const SEV_CLASS = { CRITICAL: "crit", HIGH: "high", MEDIUM: "med", LOW: "low", INFO: "info" };

function render() {
  const raw = $("token").value.trim();
  $("tokenError").textContent = "";
  if (!raw) { $("header").textContent = $("payload").textContent = ""; $("audit").innerHTML = ""; badge(""); $("verify").textContent = ""; return; }
  try {
    current = parseJwt(raw);
  } catch (e) {
    $("tokenError").textContent = "⚠ " + e.message;
    $("audit").innerHTML = ""; badge("");
    return;
  }
  $("header").textContent = JSON.stringify(current.header, null, 2);
  $("payload").textContent = JSON.stringify(current.payload, null, 2);
  badge(current.header.alg);
  $("claimsInfo").textContent = Object.keys(current.payload).join(", ");
  const findings = audit(current);
  $("audit").innerHTML = findings.length
    ? findings.map((f) => `<li class="${SEV_CLASS[f.severity]}"><span class="sev">${f.severity}</span><div><b>${esc(f.title)}</b><small>${esc(f.detail)}</small></div></li>`).join("")
    : '<li class="ok2">✔ No obvious issues found</li>';
  verify();
}

async function verify() {
  if (!current || !/^HS/.test(current.header.alg || "")) { $("verify").textContent = ""; return; }
  const ok = await verifyHS256(current, $("secret").value);
  $("verify").textContent = ok ? "✔ signature valid" : "✘ signature invalid";
  $("verify").className = "verify " + (ok ? "good" : "bad");
}

const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

function readEdited() {
  const h = JSON.parse($("header").textContent);
  const p = JSON.parse($("payload").textContent);
  return { h, p };
}

// ---- events ----
$("token").addEventListener("input", render);
$("secret").addEventListener("input", verify);

document.querySelectorAll(".chip").forEach((c) => c.addEventListener("click", async () => {
  const s = c.dataset.sample;
  if (s === "clear") { $("token").value = ""; $("output").value = ""; render(); return; }
  $("token").value = await fillSignature(s);
  render();
}));

$("resign").addEventListener("click", async () => {
  try {
    const { h, p } = readEdited();
    h.alg = "HS256";
    $("output").value = await forge(h, p, $("secret").value);
  } catch (e) { $("output").value = "error: " + e.message; }
});

$("attackNone").addEventListener("click", async () => {
  try {
    const { h, p } = readEdited();
    h.alg = "none";
    $("output").value = await forge(h, p);
  } catch (e) { $("output").value = "error: " + e.message; }
});

$("copy").addEventListener("click", () => {
  $("output").select();
  navigator.clipboard?.writeText($("output").value);
  $("copy").textContent = "Copied ✓";
  setTimeout(() => ($("copy").textContent = "Copy"), 1200);
});

let userWords = null;
$("wordfile").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  userWords = (await file.text()).split(/\r?\n/).map((w) => w.trim()).filter(Boolean);
  $("crackResult").innerHTML = `<span class="muted">Loaded ${userWords.length.toLocaleString()} words from ${esc(file.name)}. Click "Crack".</span>`;
});

$("crack").addEventListener("click", async () => {
  if (!current) { $("crackResult").textContent = "Load a token first."; return; }
  if (!/^HS/.test(current.header.alg || "")) { $("crackResult").innerHTML = '<span class="bad">Only HMAC (HS256) tokens can be cracked this way.</span>'; return; }
  const words = userWords || DEMO_WORDLIST;
  $("crackResult").innerHTML = '<span class="muted">Trying…</span>';
  $("bar").style.width = "0%";
  const res = await crackHS256(current, words, (t, total) => { $("bar").style.width = (100 * t / total) + "%"; });
  $("bar").style.width = "100%";
  if (res.secret !== null) {
    $("secret").value = res.secret;
    verify();
    $("crackResult").innerHTML = `<div class="found">🔓 Secret found: <code>${esc(res.secret)}</code></div>
      <small>${res.tried.toLocaleString()} guesses in ${res.ms} ms. Now you can forge any token — edit the payload and re-sign.</small>`;
  } else {
    $("crackResult").innerHTML = `<span class="muted">Not in the wordlist (${res.tried.toLocaleString()} tried in ${res.ms} ms). Try a bigger list — a strong random secret should survive this.</span>`;
  }
});

// start with the weak sample
(async () => { $("token").value = await fillSignature("weak"); render(); })();
