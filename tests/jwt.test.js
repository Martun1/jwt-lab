const test = require("node:test");
const assert = require("node:assert");
const jwt = require("../js/jwt.js");
const { DEMO_WORDLIST } = require("../js/wordlist.js");

test("round-trips base64url", () => {
  assert.equal(jwt.b64urlDecode(jwt.b64urlEncode("Hello, world! <>?")), "Hello, world! <>?");
});

test("parses a JWT into header/payload", () => {
  const t = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwibmFtZSI6Ik1hcnRpbiJ9.abc";
  const j = jwt.parseJwt(t);
  assert.equal(j.header.alg, "HS256");
  assert.equal(j.payload.name, "Martin");
});

test("rejects malformed tokens", () => {
  assert.throws(() => jwt.parseJwt("not.a"));
  assert.throws(() => jwt.parseJwt("a.b.c"));
});

test("signs and verifies HS256", async () => {
  const token = await jwt.forge({ alg: "HS256", typ: "JWT" }, { sub: "1", role: "user" }, "secret");
  const j = jwt.parseJwt(token);
  assert.ok(await jwt.verifyHS256(j, "secret"));
  assert.ok(!(await jwt.verifyHS256(j, "wrong")));
});

test("matches a known jwt.io test vector", async () => {
  const sig = await jwt.signHS256(
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
    "your-256-bit-secret");
  assert.equal(sig, "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
});

test("forges alg:none (unsigned)", async () => {
  const t = await jwt.forge({ alg: "none", typ: "JWT" }, { role: "admin" });
  assert.ok(t.endsWith("."));
  assert.equal(jwt.parseJwt(t).header.alg, "none");
});

test("cracks a weak secret from the demo list", async () => {
  const token = await jwt.forge({ alg: "HS256", typ: "JWT" }, { sub: "1" }, "keyboardcat");
  const res = await jwt.crackHS256(jwt.parseJwt(token), DEMO_WORDLIST);
  assert.equal(res.secret, "keyboardcat");
});

test("does not crack a strong secret", async () => {
  const token = await jwt.forge({ alg: "HS256", typ: "JWT" }, { sub: "1" }, "9f3b!X2q_Zr7@Lm0pV");
  const res = await jwt.crackHS256(jwt.parseJwt(token), DEMO_WORDLIST);
  assert.equal(res.secret, null);
});

test("audit flags alg:none, missing exp, sensitive and privilege claims", () => {
  const j = jwt.parseJwt("eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4iLCJwYXNzd29yZCI6IngifQ.");
  const titles = jwt.audit(j).map((f) => f.title).join(" | ");
  assert.match(titles, /alg: none/);
  assert.match(titles, /No expiration/);
  assert.match(titles, /Sensitive data/);
  assert.match(titles, /Privilege claim/);
});
