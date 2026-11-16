// jwt.js: JWT parsing, security audit, HS256 signing & dictionary cracking.
// Pure functions, works in browsers and Node 18+ (uses WebCrypto).
// Author: Martin Ivanov (Martun1) | License: MIT
"use strict";

const subtle = (typeof crypto !== "undefined" ? crypto : require("node:crypto").webcrypto).subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

// ------------------------------------------------------------------ base64url
function b64urlEncode(bytes) {
  if (typeof bytes === "string") bytes = enc.encode(bytes);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecodeBytes(s) {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("invalid base64url characters");
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

const b64urlDecode = (s) => dec.decode(b64urlDecodeBytes(s));

// ------------------------------------------------------------------ parse
function parseJwt(token) {
  token = (token || "").trim().replace(/^Bearer\s+/i, "");
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error(`a JWT has 3 parts separated by dots, found ${parts.length}`);
  let header, payload;
  try { header = JSON.parse(b64urlDecode(parts[0])); } catch { throw new Error("header is not valid base64url JSON"); }
  try { payload = JSON.parse(b64urlDecode(parts[1])); } catch { throw new Error("payload is not valid base64url JSON"); }
  return { token, header, payload, signature: parts[2], signingInput: `${parts[0]}.${parts[1]}`, parts };
}

// ------------------------------------------------------------------ HMAC
async function hmacKey(secret) {
  return subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

async function signHS256(signingInput, secret) {
  const sig = await subtle.sign("HMAC", await hmacKey(secret), enc.encode(signingInput));
  return b64urlEncode(new Uint8Array(sig));
}

async function verifyHS256(jwt, secret) {
  return (await signHS256(jwt.signingInput, secret)) === jwt.signature;
}

/** Build a token. alg "none" produces an unsigned token (attack demo). */
async function forge(header, payload, secret = "") {
  const input = `${b64urlEncode(JSON.stringify(header))}.${b64urlEncode(JSON.stringify(payload))}`;
  if (String(header.alg).toLowerCase() === "none") return `${input}.`;
  if (header.alg !== "HS256") throw new Error("this lab can only sign HS256 or 'none'");
  return `${input}.${await signHS256(input, secret)}`;
}

/** Dictionary attack. onProgress(tried, total) is called every `chunk` words. */
async function crackHS256(jwt, words, onProgress = () => {}, chunk = 250) {
  const t0 = Date.now();
  const data = enc.encode(jwt.signingInput);
  for (let i = 0; i < words.length; i++) {
    const key = await subtle.importKey("raw", enc.encode(words[i]), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = b64urlEncode(new Uint8Array(await subtle.sign("HMAC", key, data)));
    if (sig === jwt.signature) return { secret: words[i], tried: i + 1, ms: Date.now() - t0 };
    if (i % chunk === 0) { onProgress(i, words.length); await new Promise((r) => setTimeout(r, 0)); }
  }
  return { secret: null, tried: words.length, ms: Date.now() - t0 };
}

// ------------------------------------------------------------------ audit
const SENSITIVE = /pass(word)?|pwd|secret|ssn|credit|card|cvv|iban|api[_-]?key|private/i;
const PRIVILEGE = /^(admin|isadmin|is_admin|role|roles|scope|scopes|groups|permissions|privilege)$/i;

function audit(jwt, now = Date.now() / 1000) {
  const f = [];
  const add = (severity, title, detail) => f.push({ severity, title, detail });
  const { header: h, payload: p } = jwt;
  const alg = String(h.alg ?? "");

  if (!alg || alg.toLowerCase() === "none")
    add("CRITICAL", "alg: none (unsigned token)", "Anyone can change the payload. Servers must reject 'none' explicitly.");
  else if (/^HS/.test(alg))
    add("MEDIUM", `Symmetric algorithm ${alg}`, "Security depends entirely on the secret. Weak secrets can be cracked offline. Try the cracker.");
  if (/^HS/.test(alg) && jwt.signature === "")
    add("HIGH", "Empty signature", "The token claims HMAC but carries no signature.");
  if (h.jku || h.x5u)
    add("HIGH", `Header '${h.jku ? "jku" : "x5u"}' points to a key URL`, "If the server fetches keys from this URL, an attacker can host their own key (SSRF / key injection).");
  if (h.jwk)
    add("HIGH", "Embedded 'jwk' header", "Servers that trust an embedded public key accept attacker-signed tokens (CVE-2018-0114 pattern).");
  if (typeof h.kid === "string" && /(\.\.\/|['";]|\|)/.test(h.kid))
    add("HIGH", "Suspicious 'kid' header", `kid = ${h.kid}: path traversal or injection payload targeting key lookup.`);

  if (p.exp === undefined) add("HIGH", "No expiration (exp)", "A stolen token works forever.");
  else if (typeof p.exp === "number") {
    if (p.exp < now) add("INFO", "Token is expired", `Expired ${ago(now - p.exp)} ago.`);
    const iat = typeof p.iat === "number" ? p.iat : null;
    if (iat && p.exp - iat > 86400 * 7) add("MEDIUM", "Very long lifetime", `Valid for ${ago(p.exp - iat)}. Prefer short-lived access tokens + refresh tokens.`);
  }
  if (typeof p.nbf === "number" && p.nbf > now) add("INFO", "Not valid yet (nbf in the future)", `Becomes valid in ${ago(p.nbf - now)}.`);
  if (typeof p.iat === "number" && p.iat > now + 300) add("MEDIUM", "Issued in the future (iat)", "Clock skew or a forged token.");
  if (!p.iss) add("LOW", "No issuer (iss)", "Servers can't check who created the token.");
  if (!p.aud) add("LOW", "No audience (aud)", "The token could be replayed against other services that share the key.");

  for (const [k, v] of Object.entries(p)) {
    if (SENSITIVE.test(k)) add("HIGH", `Sensitive data in payload: "${k}"`, "JWT payloads are only base64-encoded, not encrypted. Anyone can read them.");
    if (PRIVILEGE.test(k)) add("INFO", `Privilege claim "${k}": ${JSON.stringify(v)}`, "A juicy target: if the signature can be bypassed, change this value.");
  }
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  return f.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
}

function ago(sec) {
  sec = Math.abs(Math.round(sec));
  if (sec < 120) return `${sec}s`;
  if (sec < 7200) return `${Math.round(sec / 60)} min`;
  if (sec < 172800) return `${Math.round(sec / 3600)} h`;
  return `${Math.round(sec / 86400)} days`;
}

if (typeof module !== "undefined")
  module.exports = { b64urlEncode, b64urlDecode, parseJwt, signHS256, verifyHS256, forge, crackHS256, audit };
