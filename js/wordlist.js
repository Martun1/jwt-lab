// A small demo wordlist of JWT secrets that appear in tutorials, docs and starter
// templates — the ones developers forget to change before shipping. This is for the
// built-in demo only; load a real wordlist (rockyou, etc.) via the file picker in the UI.
"use strict";
const DEMO_WORDLIST = [
  "secret", "secretkey", "secret_key", "mysecret", "jwt_secret", "jwtsecret", "jwt-secret",
  "supersecret", "changeme", "change_me", "password", "your-256-bit-secret", "your_jwt_secret",
  "keyboardcat", "keyboard_cat", "s3cr3t", "default", "test", "dev", "node", "express",
];
if (typeof module !== "undefined") module.exports = { DEMO_WORDLIST };
