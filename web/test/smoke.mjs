// DOM smoke test for the SSLKnife web UI.
//
// Loads app.js into jsdom, points fetch at a running `sslknife server` using
// a bearer token, visits every route and certificate tab, and fails on any
// script error.
//
//   BASE=https://127.0.0.1:18443 TOKEN=... NODE_TLS_REJECT_UNAUTHORIZED=0 node smoke.mjs
import { JSDOM, VirtualConsole } from "jsdom";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const base = process.env.BASE || "https://127.0.0.1:18443";
const token = process.env.TOKEN;
if (!token) {
  console.error("TOKEN is required");
  process.exit(2);
}
const staticDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "static");
const html = fs.readFileSync(path.join(staticDir, "index.html"), "utf8").replace(/<script[^>]*><\/script>/, "");
const js = fs.readFileSync(path.join(staticDir, "app.js"), "utf8");

const errors = [];
const vc = new VirtualConsole();
vc.on("error", (e) => errors.push("console.error: " + e));
vc.on("jsdomError", (e) => errors.push("jsdom: " + (e.stack || e.message)));
const dom = new JSDOM(html, { url: base + "/", runScripts: "outside-only", virtualConsole: vc, pretendToBeVisual: true });
const w = dom.window;
w.fetch = async (url, opts = {}) => {
  const r = await fetch(base + url, { ...opts, headers: { ...(opts.headers || {}), Authorization: "Bearer " + token } });
  const text = await r.text();
  return { ok: r.ok, status: r.status, statusText: r.statusText, text: async () => text };
};
w.confirm = () => false;
w.addEventListener("error", (e) => errors.push("window: " + e.message));
w.addEventListener("unhandledrejection", (e) => errors.push("rejection: " + e.reason));
w.eval(js);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const app = () => w.document.getElementById("app");
async function visit(hash) {
  w.location.hash = hash;
  await sleep(700);
  const text = app().textContent;
  if (/^Error/.test(text.trim())) errors.push(`${hash}: ${text.trim().slice(0, 200)}`);
  if (!hash.endsWith("/raw") && /\bnull\b|\bundefined\b|\[object Object\]/.test(text)) errors.push(`${hash}: rendered a JS placeholder: ${text.slice(0, 200)}`);
  console.log("ok", hash);
}

await sleep(700);
for (const hash of ["#/", "#/certs", "#/keys", "#/tls", "#/ct", "#/import", "#/search?q=example"]) await visit(hash);
const certs = JSON.parse(await (await w.fetch("/api/v1/certificates")).text());
if (certs.length) {
  for (const tab of ["overview", "sans", "chain", "extensions", "findings", "raw", "pem", "ct", "history"]) {
    await visit(`#/certs/${certs[0].id}/${tab}`);
  }
}
if (errors.length) {
  console.error("\n" + errors.join("\n"));
  process.exit(1);
}
console.log("UI smoke test passed");
