// SSLKnife web UI. Plain ES module, no dependencies, no build step.
// All DOM is built with textContent (never innerHTML from data), so values
// coming from certificates or servers cannot inject markup.

const app = document.getElementById("app");
let csrf = "";

// ---------------------------------------------------------------- helpers

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else if (k === "dataset") Object.assign(el.dataset, v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === undefined || c === null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

class APIError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function api(path, { method = "GET", body } = {}) {
  const headers = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-CSRF-Token"] = csrf;
  const res = await fetch("/api/v1" + path, {
    method, headers, credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!res.ok) {
    if (res.status === 401) location.reload();
    throw new APIError(res.status, (data && data.error) || res.statusText);
  }
  return data;
}

function toast(message, isError = false) {
  const box = document.getElementById("toast");
  const msg = h("div", { class: "msg" + (isError ? " error" : "") }, message);
  box.append(msg);
  setTimeout(() => msg.remove(), isError ? 8000 : 4000);
}

const day = (iso) => (iso ? iso.slice(0, 10) : "");
const dateTime = (iso) => (iso ? iso.replace("T", " ").replace(/\.\d+/, "").replace("Z", " UTC") : "");
const colon = (hex) => (hex || "").toUpperCase().match(/.{1,2}/g)?.join(":") || "";

function pill(text, level) { return h("span", { class: "pill " + level }, text); }

const certLevels = { OK: "good", CA: "info", WARNING: "warn", CRITICAL: "bad", EXPIRED: "bad", NOT_YET_VALID: "bad" };
const ctLevels = { known: "good", new: "warn", changed: "warn", unexpected: "bad", expired: "neutral" };
const sevLevels = { critical: "bad", high: "bad", medium: "warn", low: "info", info: "neutral", error: "bad", warning: "warn", notice: "neutral" };
const strengthLevels = { modern: "good", acceptable: "good", deprecated: "warn", weak: "bad", insecure: "bad" };

function certStatus(c) { return pill(c.status, certLevels[c.status] || "neutral"); }
function tags(list) { return (list || []).map((t) => h("span", { class: "tag" }, t)); }

function table(columns, rows, onClick) {
  if (!rows || rows.length === 0) return h("div", { class: "empty" }, "Nothing here yet.");
  return h("table", {},
    h("thead", {}, h("tr", {}, columns.map((c) => h("th", { class: c.cls }, c.title)))),
    h("tbody", {}, rows.map((r) => h("tr", { class: onClick ? "link" : "", onclick: onClick ? () => onClick(r) : null },
      columns.map((c) => h("td", { class: c.cls }, c.render(r)))))));
}

function kv(pairs) {
  return h("dl", { class: "kv" }, pairs.filter(([, v]) => v !== undefined && v !== null && v !== "" && !(Array.isArray(v) && v.length === 0))
    .map(([k, v]) => [h("dt", {}, k), h("dd", {}, Array.isArray(v) ? v.map((x) => h("div", {}, x)) : v)]));
}

function panel(title, ...content) { return h("section", { class: "panel" }, title ? h("h2", {}, title) : null, content); }

function loading(text = "Loading") { return h("div", { class: "muted" }, h("span", { class: "spinner" }), " ", text, "…"); }

function render(...nodes) { app.replaceChildren(...nodes); }

function certColumns() {
  return [
    { title: "Name / CN", render: (c) => [h("div", {}, c.name || c.common_name || c.subject), c.name ? h("div", { class: "sub" }, c.common_name) : null] },
    { title: "Issuer", render: (c) => h("div", { class: "truncate" }, cnOf(c.issuer)) },
    { title: "Expires", render: (c) => day(c.not_after) },
    { title: "Days", cls: "num", render: (c) => (c.status === "EXPIRED" ? "—" : c.days_remaining) },
    { title: "Key", render: (c) => c.key },
    { title: "Tags", render: (c) => tags(c.tags) },
    { title: "Status", render: certStatus },
  ];
}

function cnOf(dn) {
  const m = /(?:^|,)\s*CN=([^,]+)/.exec(dn || "");
  return m ? m[1] : dn;
}

const goCert = (c) => { location.hash = "#/certs/" + c.id; };

// ---------------------------------------------------------------- dashboard

async function dashboard() {
  render(loading());
  const d = await api("/dashboard");
  const c = d.counts;
  const stat = (label, value, cls = "", href) => h(href ? "a" : "div", { class: "stat " + cls, href }, h("span", { class: "label" }, label), h("span", { class: "value" }, value));
  render(
    h("div", { class: "stats" },
      stat("Certificates", c.certificates, "", "#/certs"),
      stat("Private keys", c.private_keys, "", "#/keys"),
      stat("SSH keys", c.ssh_keys, "", "#/keys"),
      stat("CT watches", c.ct_watches, "", "#/ct"),
      stat("Expiring", c.expiring, c.expiring ? "warn" : "", "#/certs?q=" + encodeURIComponent("status:expiring")),
      stat("Expired", c.expired, c.expired ? "bad" : "", "#/certs?q=status:expired"),
      stat("TLS endpoints", c.tls_endpoints, "", "#/tls"),
      stat("CT new / unexpected (7d)", `${d.ct.new + d.ct.changed} / ${d.ct.unexpected}`, d.ct.unexpected ? "bad" : "", "#/ct"),
    ),
    h("div", { class: "grid two" },
      panel("Expiring certificates", table(certColumns().filter((x) => x.title !== "Tags"), d.expiring, goCert)),
      panel("Weak TLS configuration findings", d.weak_findings.length === 0 ? h("div", { class: "empty" }, "No medium or higher findings in the latest scans.") :
        d.weak_findings.map((f) => h("div", { class: "finding " + f.finding.severity },
          h("div", {}, pill(f.finding.severity.toUpperCase(), sevLevels[f.finding.severity]), " ", h("b", {}, f.target), " ", f.finding.what)))),
      panel("CT discoveries", table([
        { title: "Status", render: (o) => pill(o.status, ctLevels[o.status]) },
        { title: "Names", render: (o) => h("div", { class: "truncate" }, o.dns_names.join(", ")) },
        { title: "Issuer", render: (o) => o.issuer_name || cnOf(o.issuer) },
        { title: "Seen", render: (o) => day(o.first_seen) },
      ], d.ct_discoveries, () => { location.hash = "#/ct"; })),
      panel("Recent TLS scans", table([
        { title: "Target", render: (s) => s.target },
        { title: "Kind", render: (s) => s.kind },
        { title: "Version", render: (s) => (s.snapshot.versions && s.snapshot.versions.length ? s.snapshot.versions.join(" + ") : s.snapshot.negotiated_version) },
        { title: "Trusted", render: (s) => (s.snapshot.trusted ? pill("yes", "good") : pill("no", "bad")) },
        { title: "When", render: (s) => dateTime(s.scanned_at) },
      ], d.recent_scans, (s) => { location.hash = "#/tls/scan/" + s.id; })),
      panel("Recently added certificates", table(certColumns().filter((x) => x.title !== "Issuer"), d.recent_certificates, goCert)),
    ),
  );
}

// ---------------------------------------------------------------- certificates

async function certList(params) {
  const q = params.get("q") || "";
  const input = h("input", { type: "search", value: q, placeholder: "Query, e.g. issuer:DigiCert expires:<90d tag:production", style: "flex:1" });
  const form = h("form", { class: "row", onsubmit: (e) => { e.preventDefault(); location.hash = "#/certs?q=" + encodeURIComponent(input.value); } },
    input, h("button", { class: "primary" }, "Search"), h("a", { href: "#/import" }, "Import…"));
  render(h("h1", {}, "Certificates"), form, h("div", { style: "height:10px" }), loading());
  try {
    const list = await api("/certificates?q=" + encodeURIComponent(q));
    render(h("h1", {}, "Certificates ", h("span", { class: "muted" }, `(${list.length})`)), form, h("div", { style: "height:10px" }),
      panel(null, table(certColumns(), list, goCert)));
  } catch (e) {
    render(h("h1", {}, "Certificates"), form, h("p", { class: "muted" }, e.message));
  }
}

async function certDetail(id, tab = "overview") {
  render(loading());
  const d = await api("/certificates/" + encodeURIComponent(id));
  const s = d.summary, info = d.details;
  const tabs = ["Overview", "SANs", "Chain", "Extensions", "Findings", "Raw", "PEM", "CT", "History"];
  const body = h("div", {});
  const tabBar = h("div", { class: "tabs" }, tabs.map((t) => h("button", {
    class: t.toLowerCase() === tab ? "active" : "",
    onclick: () => { history.replaceState(null, "", "#/certs/" + s.id + "/" + t.toLowerCase()); certDetailTab(t.toLowerCase(), d, body, tabBar); },
  }, t === "CT" ? `CT (${d.ct.length})` : t === "Findings" ? `Findings (${d.findings.filter((f) => f.severity !== "notice").length})` : t)));

  const tagInput = h("input", { placeholder: "add tag", size: 12 });
  const actions = h("div", { class: "row" },
    h("a", { href: "/api/v1/certificates/" + s.id + "/pem", download: "certificate.pem" }, h("button", {}, "Download PEM")),
    h("form", { class: "row", onsubmit: async (e) => {
      e.preventDefault();
      if (!tagInput.value.trim()) return;
      try { await api(`/certificates/${s.id}/tags`, { method: "POST", body: { tags: [tagInput.value.trim()] } }); certDetail(s.id, tab); }
      catch (err) { toast(err.message, true); }
    } }, tagInput),
    h("button", { class: "danger", onclick: async () => {
      if (!confirm(`Delete certificate ${s.common_name || s.id}?`)) return;
      try { await api("/certificates/" + s.id, { method: "DELETE" }); toast("Deleted"); location.hash = "#/certs"; }
      catch (err) { toast(err.message, true); }
    } }, "Delete"));

  render(
    h("h1", {}, s.name || s.common_name || s.subject, " ", certStatus(s)),
    h("div", { class: "row muted small" }, h("span", { class: "mono" }, s.id), "·", s.key, "·", "expires " + day(s.not_after), tags(s.tags)),
    h("div", { style: "height:8px" }), actions, tabBar, body);
  certDetailTab(tab, d, body, tabBar);
}

function chainView(chain, currentId) {
  // Root first, like the roadmap's DigiCert → intermediate → leaf picture.
  const items = [...chain].reverse();
  const nodes = [];
  items.forEach((c, i) => {
    if (i > 0) nodes.push(h("div", { class: "arrow" }, "↓"));
    nodes.push(h("a", { class: "node" + (c.id === currentId ? " current" : ""), href: "#/certs/" + c.id },
      h("div", {}, c.common_name || c.subject, " ", certStatus(c)),
      h("div", { class: "muted small" }, c.key, " · expires ", day(c.not_after))));
  });
  const top = items[0];
  if (top && !top.self_signed) {
    nodes.unshift(h("div", { class: "arrow" }, "↓"));
    nodes.unshift(h("div", { class: "node muted" }, cnOf(top.issuer), h("div", { class: "small" }, "issuer not stored")));
  }
  return h("div", { class: "chain" }, nodes);
}

function certDetailTab(tab, d, body, tabBar) {
  for (const b of tabBar.children) b.classList.toggle("active", b.textContent.toLowerCase().startsWith(tab));
  const s = d.summary, i = d.details;
  let content;
  switch (tab) {
    case "sans":
      content = kv([["DNS", i.sans.dns], ["IP", i.sans.ip], ["Email", i.sans.email], ["URI", i.sans.uri]]);
      if (!i.sans.dns.length && !i.sans.ip.length && !i.sans.email.length && !i.sans.uri.length) content = h("div", { class: "empty" }, "No subject alternative names.");
      break;
    case "chain":
      content = [chainView(d.chain, s.id), d.issued.length ? [h("h2", { style: "margin-top:16px" }, `Issued by this certificate (${d.issued.length})`), table(certColumns(), d.issued, goCert)] : null];
      break;
    case "extensions":
      content = [
        kv([
          ["Basic constraints", i.basic_constraints ? `CA:${i.basic_constraints.ca}${i.basic_constraints.path_len !== undefined ? ", pathlen:" + i.basic_constraints.path_len : ""}${i.basic_constraints.critical ? " (critical)" : ""}` : ""],
          ["Key usage", (i.key_usage || []).join(", ")],
          ["Extended key usage", (i.extended_key_usage || []).join(", ")],
          ["Subject key ID", h("span", { class: "mono" }, i.subject_key_id || "")],
          ["Authority key ID", h("span", { class: "mono" }, i.authority_key_id || "")],
          ["CRL distribution", i.crl_distribution_points],
          ["OCSP", i.ocsp_servers], ["CA issuers", i.ca_issuers],
          ["Policies", (i.policies || []).map((p) => p.oid + (p.name ? ` (${p.name})` : ""))],
          ["Must-Staple", i.must_staple ? "yes" : ""],
          ["SCTs", (i.scts || []).map((x) => `${dateTime(x.timestamp)}  ${x.log_id}`)],
        ]),
        h("h2", { style: "margin-top:16px" }, "All extensions"),
        table([
          { title: "OID", render: (e) => h("span", { class: "mono" }, e.oid) },
          { title: "Name", render: (e) => e.name || h("span", { class: "muted" }, "unknown") },
          { title: "Critical", render: (e) => (e.critical ? pill("critical", e.known ? "info" : "bad") : "") },
          { title: "Size", cls: "num", render: (e) => e.size },
        ], i.extensions),
      ];
      break;
    case "findings":
      content = d.findings.length === 0 ? h("div", { class: "empty" }, "No issues found.") : d.findings.map(findingView);
      break;
    case "raw":
      content = h("pre", {}, JSON.stringify(i, (k, v) => (k === "pem" ? undefined : v), 2));
      break;
    case "pem":
      content = h("pre", {}, i.pem);
      break;
    case "ct":
      content = table(obsColumns(false), d.ct);
      break;
    case "history":
      content = table([
        { title: "Target", render: (x) => x.target },
        { title: "Kind", render: (x) => x.kind },
        { title: "Version", render: (x) => x.snapshot.negotiated_version },
        { title: "When", render: (x) => dateTime(x.scanned_at) },
      ], d.history, (x) => { location.hash = "#/tls/scan/" + x.id; });
      break;
    default:
      content = h("div", { class: "grid two" },
        panel("Certificate", kv([
          ["Subject", i.subject.dn], ["Issuer", i.issuer.dn], ["Serial", h("span", { class: "mono" }, i.serial)],
          ["Type", [i.is_ca ? "CA" : "end-entity", i.self_signed ? "self-signed" : ""].filter(Boolean).join(", ")],
          ["Not before", dateTime(i.validity.not_before)], ["Not after", dateTime(i.validity.not_after)],
          ["Remaining", `${i.validity.days_remaining} days (lifetime ${i.validity.lifetime_days} days)`],
          ["Signature", [i.signature_algorithm, " ", i.signature_strength !== "modern" ? pill(i.signature_strength, "warn") : null]],
          ["Warnings", i.warnings],
        ])),
        panel("Key and identity", kv([
          ["Public key", [i.public_key.description, " ", pill(i.public_key.strength, strengthLevels[i.public_key.strength] || "neutral")]],
          ["SHA-256", h("span", { class: "mono" }, colon(i.fingerprints.sha256))],
          ["SHA-1 (legacy)", h("span", { class: "mono muted" }, colon(i.fingerprints.sha1))],
          ["SPKI SHA-256", h("span", { class: "mono" }, i.public_key.spki_sha256)],
          ["Private key", s.key_id ? "stored in vault (" + s.key_id + ")" : "not stored"],
          ["Source", s.source], ["Imported", dateTime(s.imported_at)], ["CT monitoring", s.ct_monitored ? "watched" : "not watched"],
          ["Notes", d.notes.map((n) => `${day(n.created_at)}  ${n.body}`)],
        ])),
        panel("Chain", chainView(d.chain, s.id)));
  }
  body.replaceChildren(...[content].flat(Infinity).filter((x) => x !== null && x !== undefined));
}

function findingView(f) {
  return h("div", { class: "finding " + f.severity },
    h("div", {}, pill(f.severity.toUpperCase(), sevLevels[f.severity] || "neutral"), " ", h("b", {}, f.what), f.certificate ? h("span", { class: "muted" }, "  " + f.certificate) : null),
    h("div", { class: "why" }, f.why),
    f.evidence ? h("div", { class: "evidence" }, f.evidence) : null,
    f.reference ? h("div", { class: "muted small" }, f.reference) : null);
}

// ---------------------------------------------------------------- import

function importView() {
  const text = h("textarea", { placeholder: "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----", spellcheck: "false" });
  const name = h("input", { placeholder: "friendly name (optional)" });
  const tagsIn = h("input", { placeholder: "tags, comma separated" });
  const out = h("div", {});
  render(h("h1", {}, "Import certificates"),
    panel(null,
      h("p", { class: "muted" }, "Paste PEM certificates (a chain is fine). Private keys are never accepted through the web interface; use ", h("code", {}, "sslknife key import"), "."),
      text, h("div", { style: "height:8px" }),
      h("div", { class: "row" }, name, tagsIn, h("button", { class: "primary", onclick: async () => {
        try {
          const r = await api("/certificates", { method: "POST", body: { pem: text.value, name: name.value, tags: tagsIn.value.split(",").map((x) => x.trim()).filter(Boolean) } });
          out.replaceChildren(
            h("p", {}, `${r.created} new, ${r.certificates.length - r.created} already stored.`,
              r.ignored_private_keys ? h("span", { class: "muted" }, ` Ignored ${r.ignored_private_keys} private key(s).`) : null),
            table(certColumns(), r.certificates, goCert));
        } catch (e) { toast(e.message, true); }
      } }, "Import"))),
    out);
}

// ---------------------------------------------------------------- keys

async function keysView() {
  render(loading());
  const [ks, ssh] = await Promise.all([api("/keys"), api("/ssh/keys")]);
  render(h("h1", {}, "Keys"),
    h("p", { class: "muted small" }, "Key material never leaves the vault through the web interface. Export with ", h("code", {}, "sslknife key export"), "."),
    h("div", { class: "grid" },
      panel("Private and public keys", table([
        { title: "Name", render: (k) => k.name || h("span", { class: "mono muted" }, k.id) },
        { title: "Algorithm", render: (k) => k.description },
        { title: "Private", render: (k) => (k.has_private_key ? pill("stored", "good") : pill("public only", "neutral")) },
        { title: "SPKI SHA-256", render: (k) => h("span", { class: "mono" }, k.spki_sha256.slice(0, 32) + "…") },
        { title: "Tags", render: (k) => tags(k.tags) },
        { title: "Imported", render: (k) => day(k.imported_at) },
      ], ks)),
      panel("SSH keys", table([
        { title: "Name", render: (k) => k.name || h("span", { class: "mono muted" }, k.id) },
        { title: "Type", render: (k) => `${k.type} (${k.bits})` },
        { title: "Fingerprint", render: (k) => h("span", { class: "mono" }, k.fingerprint_sha256) },
        { title: "Comment", render: (k) => k.comment },
        { title: "Private", render: (k) => (k.has_private_key ? pill(k.passphrase_protected ? "stored, passphrase" : "stored", "good") : pill("public only", "neutral")) },
        { title: "Tags", render: (k) => tags(k.tags) },
      ], ssh))));
}

// ---------------------------------------------------------------- TLS analyzer

const protocols = ["", "tls", "https", "smtp", "smtps", "imap", "imaps", "pop3", "pop3s", "ldap", "ldaps", "ftp", "xmpp", "postgres", "mysql", "mqtts", "redis"];

async function tlsView(params) {
  const host = h("input", { placeholder: "api.example.com", value: params.get("host") || "", required: true, style: "min-width:280px" });
  const port = h("input", { placeholder: "443", value: params.get("port") || "", size: 6 });
  const proto = h("select", {}, protocols.map((p) => h("option", { value: p }, p || "Auto")));
  const save = h("input", { type: "checkbox", checked: true });
  const result = h("div", {});
  const run = async (kind) => {
    if (!host.value.trim()) { host.focus(); return; }
    const target = port.value.trim() ? `${host.value.trim()}:${port.value.trim()}` : host.value.trim();
    result.replaceChildren(loading(kind === "scan" ? `Scanning ${target} (versions, ciphers, groups)` : `Connecting to ${target}`));
    for (const b of buttons) b.disabled = true;
    try {
      const r = await api("/tls/" + kind, { method: "POST", body: { target, protocol: proto.value, save: save.checked } });
      result.replaceChildren(kind === "scan" ? scanResult(r) : inspectResult(r));
    } catch (e) {
      result.replaceChildren(h("div", { class: "finding high" }, h("b", {}, "Failed: "), e.message));
    } finally { for (const b of buttons) b.disabled = false; }
  };
  const buttons = [h("button", { class: "primary", type: "submit" }, "Analyze"), h("button", { type: "button", onclick: () => run("scan") }, "Full scan")];
  const form = h("form", { class: "row", onsubmit: (e) => { e.preventDefault(); run("inspect"); } },
    h("label", {}, "Host ", host), h("label", {}, "Port ", port), h("label", {}, "Protocol ", proto), buttons, h("label", { class: "check" }, save, "save to history"));
  render(h("h1", {}, "TLS analyzer"), panel(null, form,
    h("p", { class: "muted small" }, "Only scan systems you are authorised to test. Probes are non-destructive.")), h("div", { style: "height:12px" }), result);
  const endpoints = await api("/tls/endpoints").catch(() => []);
  if (endpoints.length && !result.childNodes.length) {
    result.replaceChildren(panel("Known endpoints", table([
      { title: "Target", render: (e) => e.target },
      { title: "Protocol", render: (e) => e.protocol },
      { title: "Last seen", render: (e) => dateTime(e.last_seen) },
    ], endpoints, (e) => { host.value = e.host; port.value = e.port; run("inspect"); })));
  }
}

function verdict(ok, good, bad) { return ok ? pill(good, "good") : pill(bad, "bad"); }

function inspectResult(r, compact = false) {
  const c = r.certificate || {};
  const v = r.validation, t = r.tls;
  const head = h("section", { class: "panel" },
    h("div", { class: "summary-grid" },
      h("div", {}, h("span", { class: "muted" }, "Protocol"), `${r.protocol.protocol.toUpperCase()} (${r.protocol.method}, by ${r.protocol.detected_by})`),
      h("div", {}, h("span", { class: "muted" }, "TLS"), t.version || "—"),
      h("div", {}, h("span", { class: "muted" }, "Cipher"), t.cipher || "—"),
      h("div", {}, h("span", { class: "muted" }, "Key exchange"), t.key_exchange_group || "—"),
      h("div", {}, h("span", { class: "muted" }, "Certificate key"), c.public_key ? c.public_key.description : "—"),
      h("div", {}, h("span", { class: "muted" }, "ALPN"), t.alpn || "—"),
      h("div", {}, h("span", { class: "muted" }, "Chain"), v.trusted && !(v.missing_intermediates || []).length ? pill("trusted", "good") : v.trusted ? pill("incomplete", "warn") : pill("untrusted", "bad")),
      h("div", {}, h("span", { class: "muted" }, "Hostname"), verdict(v.hostname_valid, "valid", "mismatch")),
      h("div", {}, h("span", { class: "muted" }, "Expires"), c.validity ? `${day(c.validity.not_after)} (${c.validity.days_remaining} d)` : "—"),
      h("div", {}, h("span", { class: "muted" }, "OCSP stapling"), r.ocsp && r.ocsp.stapled ? pill(r.ocsp.status || "yes", r.ocsp.status === "revoked" ? "bad" : "good") : "no"),
    ),
    c.sans ? h("div", { style: "margin-top:8px" }, h("span", { class: "muted" }, "SAN: "), [...c.sans.dns, ...c.sans.ip].slice(0, 30).join(", "),
      c.sans.dns.length + c.sans.ip.length > 30 ? ` … (+${c.sans.dns.length + c.sans.ip.length - 30})` : "") : null,
    r.error ? h("p", { class: "muted" }, r.error) : null);
  if (compact) return head;
  return h("div", {}, h("h2", {}, r.target, "  ", h("span", { class: "muted" }, r.connected_to + " · " + r.duration)), head, h("div", { style: "height:8px" }),
    details("Session", kv([["Version", t.version], ["Cipher", [t.cipher, " ", t.cipher_strength && t.cipher_strength !== "modern" ? pill(t.cipher_strength, strengthLevels[t.cipher_strength]) : null]],
      ["Key exchange group", t.key_exchange_group], ["ALPN", t.alpn], ["Offered ALPN", (t.offered_alpn || []).join(", ")],
      ["HelloRetryRequest", t.hello_retry_request ? "yes" : "no"], ["SCTs in handshake", t.scts_in_handshake],
      ["Session resumption", t.session_resumption === undefined ? "" : t.session_resumption ? "yes" : "no"],
      ["SNI", r.sni], ["Resolved", (r.resolved_ips || []).join(", ")], ["STARTTLS transcript", r.starttls_transcript]])),
    details("Certificate chain as sent", table([
      { title: "#", render: (x) => x.position },
      { title: "Subject", render: (x) => cnOf(x.subject) },
      { title: "Issuer", render: (x) => cnOf(x.issuer) },
      { title: "Key", render: (x) => x.key },
      { title: "Expires", render: (x) => day(x.not_after) },
      { title: "Order", render: (x) => (x.position === r.chain.length - 1 || x.issued_by_next ? "" : pill("next is not issuer", "warn")) },
    ], r.chain)),
    details("Validation", kv([["Trust store", v.trust_store], ["Trusted", v.trusted ? "yes" : "no"], ["Verified chain", (v.verified_chain || []).join(" → ")],
      ["Supplied by verifier", (v.missing_intermediates || []).join(", ")], ["Error", v.error], ["Hostname", v.hostname]])),
    details(`Certificate findings (${r.certificate_findings.filter((f) => f.severity !== "notice").length})`, r.certificate_findings.length ? r.certificate_findings.map(findingView) : h("div", { class: "empty" }, "None.")),
    details("Raw JSON", h("pre", {}, JSON.stringify(r, null, 2))));
}

function details(title, ...content) {
  return h("details", {}, h("summary", {}, title), h("div", { class: "body" }, content));
}

function scanResult(r) {
  const levels = { good: "good", bad: "bad", warn: "warn", info: "neutral" };
  return h("div", {},
    h("h2", {}, r.connection.target, "  ", h("span", { class: "muted" }, r.duration)),
    inspectResult(r.connection, true), h("div", { style: "height:8px" }),
    panel("TLS security summary", h("div", { class: "summary-grid" }, r.summary.map((s) =>
      h("div", {}, h("span", {}, s.check), h("span", {}, pill(s.status, levels[s.level] || "neutral"), s.detail ? h("span", { class: "muted small" }, " " + s.detail) : null))))),
    h("div", { style: "height:8px" }),
    details(`Findings (${r.findings.length})`, r.findings.length ? r.findings.map(findingView) : h("div", { class: "empty" }, "No findings.")),
    details("Cipher suites", (r.ciphers || []).slice().reverse().map((cr) => [
      h("h2", { style: "margin-top:8px" }, cr.version, cr.server_order === undefined ? "" : cr.server_order ? "  (server order)" : "  (client order)"),
      table([
        { title: "Suite", render: (x) => h("span", { class: "mono" }, x.name) },
        { title: "Strength", render: (x) => pill(x.strength, strengthLevels[x.strength] || "neutral") },
        { title: "Key exchange", render: (x) => (x.key_exchange_params ? (x.key_exchange_params.kind === "DH" ? `DH ${x.key_exchange_params.bits}` : `ECDH ${x.key_exchange_params.group}`) : x.key_exchange) },
        { title: "Notes", render: (x) => h("span", { class: "muted small" }, (x.reasons || []).join("; ")) },
      ], cr.suites)])),
    details("Key exchange groups", kv([["TLS 1.3", (r.groups.tls13 || []).join(", ")], ["TLS 1.2 ECDHE", (r.groups.tls12 || []).join(", ")]])),
    details("Behaviour", kv([["Secure renegotiation", fmtBool(r.behaviour.secure_renegotiation)], ["Fallback SCSV", fmtBool(r.behaviour.fallback_scsv)],
      ["Compression", fmtBool(r.behaviour.compression)], ["Session tickets", fmtBool(r.behaviour.session_tickets)],
      ["Extended master secret", fmtBool(r.behaviour.extended_master_secret)], ["Server extensions", (r.behaviour.server_extensions || []).join(", ")]])),
    details("Full inspection", inspectResult(r.connection)),
    details("Raw JSON", h("pre", {}, JSON.stringify(r, null, 2))));
}

const fmtBool = (b) => (b === undefined ? "" : b ? "yes" : "no");

async function storedScan(id) {
  render(loading());
  const r = await api("/tls/scans/" + encodeURIComponent(id));
  render(h("h1", {}, "Recorded observation"), r.connection ? scanResult(r) : inspectResult(r));
}

// ---------------------------------------------------------------- CT

function obsColumns(withAck = true, reload) {
  const cols = [
    { title: "Status", render: (o) => [pill(o.status, ctLevels[o.status] || "neutral"), o.acknowledged ? h("span", { class: "muted small" }, " ack") : null, o.revoked ? h("span", { class: "muted small" }, " revoked") : null] },
    { title: "Names", render: (o) => h("div", { class: "truncate" }, o.dns_names.join(", ")) },
    { title: "Issuer", render: (o) => [o.issuer_name || cnOf(o.issuer), h("div", { class: "sub" }, cnOf(o.issuer))] },
    { title: "Valid", render: (o) => `${day(o.not_before)} → ${day(o.not_after)}` },
    { title: "Watch", render: (o) => o.watch },
    { title: "Why", render: (o) => h("span", { class: "muted small" }, o.reason) },
  ];
  if (withAck) cols.push({ title: "", render: (o) => (o.acknowledged || o.status === "known" ? "" : h("button", { onclick: async (e) => {
    e.stopPropagation();
    try { await api(`/ct/observations/${o.id}/ack`, { method: "POST" }); reload(); } catch (err) { toast(err.message, true); }
  } }, "Acknowledge")) });
  return cols;
}

async function ctView(params) {
  render(loading());
  const status = params.get("status") || "";
  const [watches, obs] = await Promise.all([api("/ct/watches"), api("/ct/observations?limit=200&status=" + encodeURIComponent(status))]);
  const reload = () => ctView(params);
  const domain = h("input", { placeholder: "*.example.com", required: true });
  const checkBtn = h("button", { onclick: async () => {
    checkBtn.disabled = true; checkBtn.replaceChildren(h("span", { class: "spinner" }), " Checking…");
    try {
      const r = await api("/ct/check", { method: "POST" });
      const added = r.watches.reduce((n, w) => n + w.new_observations.length, 0);
      const errors = r.watches.filter((w) => w.error).map((w) => `${w.watch}: ${w.error}`);
      toast(`CT check: ${added} new observation(s)` + (r.auto_watched ? `, ${r.auto_watched} watch(es) added` : ""));
      errors.forEach((e) => toast(e, true));
      reload();
    } catch (e) { toast(e.message, true); checkBtn.disabled = false; checkBtn.textContent = "Check now"; }
  } }, "Check now");
  const filter = h("select", { onchange: (e) => { location.hash = "#/ct?status=" + e.target.value; } },
    ["", "unexpected", "changed", "new", "known", "expired"].map((s) => h("option", { value: s, selected: s === status }, s || "all statuses")));
  render(h("h1", {}, "Certificate Transparency"),
    h("div", { class: "grid two" },
      panel("Watches",
        h("form", { class: "row", onsubmit: async (e) => {
          e.preventDefault();
          try { await api("/ct/watches", { method: "POST", body: { domain: domain.value } }); reload(); } catch (err) { toast(err.message, true); }
        } }, domain, h("button", { class: "primary" }, "Watch"), checkBtn),
        h("div", { style: "height:8px" }),
        table([
          { title: "Watch", render: (w) => w.watch },
          { title: "Source", render: (w) => w.source },
          { title: "Last checked", render: (w) => (w.last_checked ? dateTime(w.last_checked) : h("span", { class: "muted" }, "never")) },
          { title: "Seen", cls: "num", render: (w) => Object.values(w.by_status).reduce((a, b) => a + b, 0) },
          { title: "Unexpected", cls: "num", render: (w) => w.by_status.unexpected || 0 },
          { title: "", render: (w) => h("button", { class: "danger", onclick: async () => {
            if (!confirm(`Stop watching ${w.watch}?`)) return;
            try { await api("/ct/watches/" + w.id, { method: "DELETE" }); reload(); } catch (err) { toast(err.message, true); }
          } }, "Remove") },
        ], watches)),
      panel("How to read this", h("p", { class: "muted" },
        "known: stored in SSLKnife · changed: same names as a stored certificate, different certificate · new: from a CA already used for these names · unexpected: from a CA not seen before for these names. Unexpected does not mean malicious; acknowledge issuances you recognise."))),
    h("div", { style: "height:12px" }),
    panel(null, h("div", { class: "row" }, h("h2", { style: "margin:0" }, `Observations (${obs.length})`), filter), h("div", { style: "height:6px" }), table(obsColumns(true, reload), obs)));
}

// ---------------------------------------------------------------- search

async function searchView(params) {
  const q = params.get("q") || "";
  render(loading(`Searching ${q}`));
  const r = await api("/search?q=" + encodeURIComponent(q));
  render(h("h1", {}, "Search ", h("span", { class: "mono muted" }, q)),
    h("div", { class: "grid" },
      panel(`Certificates (${r.certificates.length})`, table(certColumns(), r.certificates, goCert)),
      r.keys.length ? panel(`Keys (${r.keys.length})`, table([
        { title: "Name", render: (k) => k.name || k.id }, { title: "Algorithm", render: (k) => k.description },
        { title: "Private", render: (k) => (k.has_private_key ? "yes" : "no") }, { title: "Tags", render: (k) => tags(k.tags) }], r.keys)) : null,
      r.ssh_keys.length ? panel(`SSH keys (${r.ssh_keys.length})`, table([
        { title: "Name", render: (k) => k.name || k.id }, { title: "Type", render: (k) => k.type },
        { title: "Fingerprint", render: (k) => h("span", { class: "mono" }, k.fingerprint_sha256) }], r.ssh_keys)) : null));
}

// ---------------------------------------------------------------- router

async function route() {
  const hash = location.hash.slice(1) || "/";
  const [path, query = ""] = hash.split("?");
  const params = new URLSearchParams(query);
  const parts = path.split("/").filter(Boolean);
  for (const a of document.querySelectorAll("#nav a")) {
    const target = a.getAttribute("href").slice(1);
    a.classList.toggle("active", target === "/" ? parts.length === 0 : path.startsWith(target));
  }
  try {
    switch (parts[0]) {
      case undefined: await dashboard(); break;
      case "certs": parts[1] ? await certDetail(decodeURIComponent(parts[1]), parts[2]) : await certList(params); break;
      case "import": importView(); break;
      case "keys": await keysView(); break;
      case "tls": parts[1] === "scan" ? await storedScan(parts[2]) : await tlsView(params); break;
      case "ct": await ctView(params); break;
      case "search": await searchView(params); break;
      default: render(h("h1", {}, "Not found"));
    }
  } catch (e) {
    render(h("h1", {}, "Error"), h("p", {}, e.message));
  }
}

document.getElementById("global-search").addEventListener("submit", (e) => {
  e.preventDefault();
  const q = e.target.q.value.trim();
  if (q) location.hash = "#/search?q=" + encodeURIComponent(q);
});

window.addEventListener("hashchange", route);

(async () => {
  try {
    const s = await api("/session");
    csrf = s.csrf_token || "";
    document.getElementById("version").textContent = s.version ? "v" + s.version : "";
  } catch { /* the page reloads on 401 */ }
  route();
})();
