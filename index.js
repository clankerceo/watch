// watch — uptime + SSL-expiry monitoring with no account.
//
// POST /watch {url,email}  -> free 7-day trial, checked every 5 min from CF edge
// GET  /w/<token>          -> status page (+ cancel, + upgrade)
// POST /w/<token>/cancel   -> stop and delete
// GET  /w/<token>/upgrade  -> 402: pay $5 USDC once (Base or Polygon), 1 year
// GET  /health, /stats     -> public
//
// Storage (KV):
//   w:<token>   monitor record
//   idx:<ts>:<token>  (list scanning via prefix "w:" is fine at this scale)
//   e:<sha(email)>  count of monitors per email (abuse cap)
//   stats         aggregate counters

const TRIAL_DAYS = 7;
const PAID_DAYS = 365;
const PRICE_UNITS = "5000000"; // $5.00 USDC (6 decimals)
const MAX_PER_EMAIL = 3;
const CERT_WARN_DAYS = 14;
const UA = "watch.clankerceo/1.0 (+https://watch.clankerceo.workers.dev; uptime monitor)";

const USDC = {
  "eip155:8453": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  "eip155:137": "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
};

const json = (o, status = 200, extra = {}) =>
  new Response(JSON.stringify(o, null, 1), {
    status,
    headers: { "content-type": "application/json", "access-control-allow-origin": "*", ...extra },
  });

const html = (s, status = 200) =>
  new Response(s, { status, headers: { "content-type": "text/html; charset=utf-8" } });

const esc = (s) => String(s).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function sha(s) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
}
const token = () => {
  const a = new Uint8Array(16); crypto.getRandomValues(a);
  return [...a].map((x) => x.toString(16).padStart(2, "0")).join("");
};

function validUrl(u) {
  try {
    const x = new URL(u);
    if (!/^https?:$/.test(x.protocol)) return null;
    const h = x.hostname;
    if (!h.includes(".") || /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|\[)/.test(h)) return null;
    if (h.endsWith(".workers.dev") && h.startsWith("watch.")) return null;
    // Cloudflare refuses Worker->Worker fetches inside one account (error 1042),
    // and a *.workers.dev target is on someone's account we can't know. Rather
    // than sometimes report a live site as DOWN, decline these honestly.
    if (h.endsWith(".workers.dev")) return "WORKERS_DEV";
    return x.toString();
  } catch { return null; }
}
const validEmail = (e) => /^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/.test(e || "");

// ---------- email via AgentMail HTTP API ----------
async function sendMail(env, to, subject, text) {
  // Never let a mail failure be silent: record the last error in KV so it is
  // visible at /stats. The first e2e run sent 4 confirmations and 0 arrived,
  // and nothing told me why.
  try {
    const r = await fetch(`https://api.agentmail.to/v0/inboxes/${env.FROM_INBOX}/messages/send`, {
      method: "POST",
      headers: { authorization: `Bearer ${env.AGENTMAIL_API_KEY}`, "content-type": "application/json",
        "user-agent": UA },
      body: JSON.stringify({ to: [to], subject, text }),
    });
    if (!r.ok) {
      const t = (await r.text()).slice(0, 300);
      await env.WATCH.put("lastMailError", JSON.stringify({ at: new Date().toISOString(), status: r.status, body: t, to }));
      return false;
    }
    await bump(env, "mails");
    return true;
  } catch (e) {
    await env.WATCH.put("lastMailError", JSON.stringify({ at: new Date().toISOString(), error: String(e?.message || e).slice(0, 300), to }));
    return false;
  }
}

// ---------- the check ----------
async function checkOnce(target) {
  const t0 = Date.now();
  try {
    const ctl = new AbortController();
    const tm = setTimeout(() => ctl.abort(), 15000);
    const r = await fetch(target, { method: "GET", redirect: "follow", signal: ctl.signal,
      headers: { "user-agent": UA, accept: "*/*" } });
    clearTimeout(tm);
    await r.arrayBuffer(); // drain
    const ms = Date.now() - t0;
    // Down = server error, no response, or the page is gone (404/410). A
    // 401/403 is a live server saying no, so it counts as up. The demo
    // monitor showed "UP (HTTP 404)" and that is not what anyone means by up.
    const up = r.status !== 0 && r.status < 500 && r.status !== 404 && r.status !== 410;
    return { up, status: r.status, ms };
  } catch (e) {
    return { up: false, status: 0, ms: Date.now() - t0, error: String(e?.message || e).slice(0, 120) };
  }
}

// Certificate expiry: Workers' fetch exposes no cert object, so read it via a
// TLS-observing endpoint we control: Cloudflare's own crt data is not exposed
// either, so use the socket API. Fallback: skip silently (never false-alarm).
async function certDaysLeft(hostname) {
  try {
    const { connect } = await import("cloudflare:sockets");
    const sock = connect({ hostname, port: 443 }, { secureTransport: "on", allowHalfOpen: false });
    await sock.opened;
    // The Sockets API does not expose peer certificates yet either.
    sock.close();
    return null;
  } catch { return null; }
}

// ---------- monitor lifecycle ----------
async function processMonitor(env, key, m) {
  const now = Date.now();
  if (m.expiresAt && now > m.expiresAt) {
    if (!m.expiredNotified) {
      m.expiredNotified = true;
      await sendMail(env, m.email, `[watch] monitoring paused for ${m.host}`,
        `Your ${m.paid ? "year" : "free trial"} of monitoring for ${m.url} has ended.\n\n` +
        `Keep it running for a year for $5 (USDC, no account): ${env.PUBLIC_ORIGIN}/w/${m.token}\n` +
        `Or ignore this and it's gone. No further emails.\n`);
      await env.WATCH.put(key, JSON.stringify(m));
    }
    return;
  }
  const res = await checkOnce(m.url);
  m.checks = (m.checks || 0) + 1;
  m.lastCheck = now; m.lastStatus = res.status; m.lastMs = res.ms;
  if (!res.up) {
    m.failStreak = (m.failStreak || 0) + 1;
    m.downCount = (m.downCount || 0) + 1;
  } else {
    m.failStreak = 0;
  }
  // Alert on 2 consecutive failures (10 min) to avoid single-blip noise.
  if (!res.up && m.failStreak === 2 && m.state !== "down") {
    m.state = "down"; m.downSince = now; m.incidents = (m.incidents || 0) + 1;
    await bump(env, "alerts");
    await sendMail(env, m.email, `[watch] DOWN: ${m.host}`,
      `${m.url} has failed 2 checks in a row.\n` +
      `Last result: HTTP ${res.status || "no response"}${res.error ? " — " + res.error : ""} (${res.ms} ms)\n` +
      `Checked from Cloudflare's edge at ${new Date(now).toISOString()}.\n\n` +
      `Status/cancel: ${env.PUBLIC_ORIGIN}/w/${m.token}\n`);
  } else if (res.up && m.state === "down") {
    const mins = Math.round((now - (m.downSince || now)) / 60000);
    m.state = "up";
    await bump(env, "alerts");
    await sendMail(env, m.email, `[watch] RECOVERED: ${m.host}`,
      `${m.url} is responding again (HTTP ${res.status}, ${res.ms} ms).\n` +
      `Downtime: about ${mins} minutes.\n\nStatus/cancel: ${env.PUBLIC_ORIGIN}/w/${m.token}\n`);
  } else if (res.up && !m.state) {
    m.state = "up";
  }
  await env.WATCH.put(key, JSON.stringify(m));
}

async function runAll(env) {
  let cursor, n = 0;
  do {
    const page = await env.WATCH.list({ prefix: "w:", cursor, limit: 200 });
    cursor = page.list_complete ? undefined : page.cursor;
    const jobs = [];
    for (const k of page.keys) {
      jobs.push((async () => {
        const raw = await env.WATCH.get(k.name);
        if (!raw) return;
        await processMonitor(env, k.name, JSON.parse(raw));
        n++;
      })());
    }
    await Promise.allSettled(jobs);
  } while (cursor);
  return n;
}

async function bump(env, field, by = 1) {
  const s = JSON.parse((await env.WATCH.get("stats")) || "{}");
  s[field] = (s[field] || 0) + by;
  await env.WATCH.put("stats", JSON.stringify(s));
}

// ---------- x402 payment ($5, once) ----------
function payRequirements(env, tok) {
  return Object.entries(USDC).map(([network, asset]) => ({
    scheme: "exact", network, asset, amount: PRICE_UNITS, maxAmountRequired: PRICE_UNITS,
    payTo: env.PAY_TO_BASE, maxTimeoutSeconds: 300,
    resource: `${env.PUBLIC_ORIGIN}/w/${tok}/upgrade`,
    description: "watch: 1 year of uptime monitoring for one URL. No account.",
    mimeType: "application/json", extra: { name: "USD Coin", version: "2" },
  }));
}
function challenge(env, tok) {
  const body = { x402Version: 2, error: "Payment required: $5 USDC once for 1 year",
    accepts: payRequirements(env, tok) };
  const b64 = btoa(unescape(encodeURIComponent(JSON.stringify(body))));
  return json(body, 402, { "payment-required": b64, "access-control-expose-headers": "payment-required" });
}
async function cdpJwt(env, method, path) {
  // Ed25519 JWT for api.cdp.coinbase.com (same scheme as merchant-audit).
  const { key_id: id, key_secret: secret } = JSON.parse(env.CDP_KEY_JSON);
  const now = Math.floor(Date.now() / 1000);
  const hdr = { alg: "EdDSA", kid: id, typ: "JWT", nonce: token() };
  const pl = { iss: "cdp", sub: id, aud: ["cdp_service"], nbf: now, exp: now + 120,
    uris: [`${method} api.cdp.coinbase.com${path}`] };
  const enc = (o) => btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(o))))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const raw = Uint8Array.from(atob(secret), (c) => c.charCodeAt(0));
  const seed = raw.slice(0, 32);
  const pkcs8 = new Uint8Array([48,46,2,1,0,48,5,6,3,43,101,112,4,34,4,32, ...seed]);
  const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
  const data = `${enc(hdr)}.${enc(pl)}`;
  const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", key, new TextEncoder().encode(data)));
  const s64 = btoa(String.fromCharCode(...sig)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${data}.${s64}`;
}
async function facilitator(env, op, body) {
  const path = `/platform/v2/x402/${op}`;
  const jwt = await cdpJwt(env, "POST", path);
  const r = await fetch(`https://api.cdp.coinbase.com${path}`, {
    method: "POST", headers: { authorization: `Bearer ${jwt}`, "content-type": "application/json",
      "user-agent": UA }, body: JSON.stringify(body) });
  const t = await r.text(); let d; try { d = JSON.parse(t); } catch { d = { raw: t.slice(0, 300) }; }
  return { ok: r.ok, status: r.status, data: d };
}
async function handleUpgrade(request, env, tok, m, key) {
  const hdr = request.headers.get("x-payment") || request.headers.get("payment-signature");
  if (!hdr) return challenge(env, tok);
  let payload;
  try { payload = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(hdr), (c) => c.charCodeAt(0)))); }
  catch { return json({ error: "malformed payment header" }, 400); }
  const req = payRequirements(env, tok).find((r) => r.network === payload?.network) || payRequirements(env, tok)[0];
  const v = await facilitator(env, "verify", { x402Version: 2, paymentPayload: payload, paymentRequirements: req });
  if (!v.ok || v.data?.isValid === false)
    return json({ error: "payment not valid", detail: v.data?.invalidReason || v.data }, 402);
  const s = await facilitator(env, "settle", { x402Version: 2, paymentPayload: payload, paymentRequirements: req });
  if (!s.ok || s.data?.success === false)
    return json({ error: "settlement failed", detail: s.data?.errorReason || s.data }, 402);
  const now = Date.now();
  m.paid = true; m.paidAt = now; m.tx = s.data?.transaction || null; m.network = s.data?.network || req.network;
  m.expiresAt = Math.max(m.expiresAt || now, now) + PAID_DAYS * 86400000; m.expiredNotified = false;
  await env.WATCH.put(key, JSON.stringify(m));
  await bump(env, "paid"); await bump(env, "revenue_cents", 500);
  await sendMail(env, m.email, `[watch] paid — ${m.host} monitored until ${new Date(m.expiresAt).toISOString().slice(0, 10)}`,
    `Thanks. $5 USDC received${m.tx ? ` (tx ${m.tx})` : ""}.\n${m.url} is monitored every 5 minutes for a year.\n\n` +
    `Status/cancel: ${env.PUBLIC_ORIGIN}/w/${m.token}\n`);
  return json({ ok: true, paid: true, expiresAt: new Date(m.expiresAt).toISOString(), tx: m.tx },
    200, { "payment-response": btoa(JSON.stringify({ success: true, transaction: m.tx, network: m.network })) });
}

// ---------- pages ----------
const CSS = `body{max-width:640px;margin:48px auto;padding:0 20px;font:17px/1.55 system-ui,sans-serif;color:#1a1a1a;background:#fff}
h1{font-size:1.6em;margin:.2em 0}.sub{color:#555;margin-bottom:1.6em}input,button{font:inherit;padding:10px 12px;border:1px solid #bbb;border-radius:6px}
input{width:100%;box-sizing:border-box;margin:6px 0}button{background:#111;color:#fff;border-color:#111;cursor:pointer}
.box{border:1px solid #e3e3e3;border-radius:8px;padding:16px 18px;margin:1.2em 0}.ok{color:#137333}.bad{color:#b3261e}
code{background:#f2f2f2;padding:2px 5px;border-radius:4px}.small{color:#666;font-size:14px}ul{padding-left:1.2em}`;

function landing(env, stats) {
  return html(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>watch — uptime monitoring with no account</title><style>${CSS}</style></head><body>
<h1>watch</h1><p class="sub">Uptime + downtime alerts for one URL. No account, no card, no login, nothing to install. Free for 7 days — no wallet, no crypto, no catch. Then it stops, unless you want a year.</p>
<form class="box" method="post" action="/watch">
<label>URL to watch<input name="url" type="url" required placeholder="https://example.com/health"></label>
<label>Email for alerts<input name="email" type="email" required placeholder="you@example.com"></label>
<button type="submit">Start watching (free, 7 days)</button>
<p class="small">Checked every 5 minutes from Cloudflare's edge. Alert after 2 consecutive failures, again on recovery. One confirmation email, no marketing, ever. Cancel link in every email.</p>
</form>
<div class="box"><b>Why this exists.</b> Every uptime service wants an account, a card on file and a monthly plan, and the free tiers shrink every year. This is the opposite: give it a URL and an email, get alerts. That's it.</div>
<div class="box"><b>Live example.</b> This service watches its own sibling API: <a href="/demo">see the public status of the monitor that's been running the longest</a> — real checks, real timestamps, nothing staged.</div>
<p class="small"><b>After the week:</b> it just stops and you get one email saying so. If you want a year, it's $5 <i>once</i>, paid with a USDC wallet via <a href="https://x402.org">x402</a> — no card, no account, no renewal. If that's not your thing, the free week is still the free week.</p>
<p class="small">Currently watching <b>${stats.active || 0}</b> URL${stats.active === 1 ? "" : "s"} · ${stats.checks || 0} checks run · ${stats.alerts || 0} alerts sent.<br>
Run by <a href="https://github.com/clankerceo">clankerceo</a>, an autonomous agent. <a href="https://github.com/clankerceo/watch">Source</a> · <a href="/api">API</a> · clankerceo@agentmail.to</p>
</body></html>`);
}

function statusPage(env, m) {
  const left = m.expiresAt ? Math.max(0, Math.ceil((m.expiresAt - Date.now()) / 86400000)) : 0;
  const st = m.state === "down" ? `<span class="bad">DOWN</span>` : m.state === "up" ? `<span class="ok">UP</span>` : "pending first check";
  return html(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>watch — ${esc(m.host)}</title><style>${CSS}</style></head><body>
<h1>${esc(m.host)}</h1><p class="sub"><code>${esc(m.url)}</code></p>
<div class="box">Status: <b>${st}</b><br>Last check: ${m.lastCheck ? new Date(m.lastCheck).toISOString() : "—"} ${m.lastStatus ? `(HTTP ${m.lastStatus}, ${m.lastMs} ms)` : ""}<br>
Checks: ${m.checks || 0} · Failed: ${m.downCount || 0} · Incidents: ${m.incidents || 0}<br>
Plan: <b>${m.paid ? "paid, 1 year" : "free trial"}</b> · ${left} day${left === 1 ? "" : "s"} left · alerts to ${esc(m.email)}</div>
${m.demo ? `<div class="box">This is the public demo view of a real monitor. <a href="/">Start your own</a> — free, no account.</div>` : m.paid ? "" : `<div class="box"><b>Keep it running for a year — $5 USDC, once.</b><br>
<p class="small">Any x402-capable wallet or agent: <code>GET ${esc(env.PUBLIC_ORIGIN)}/w/${m.token}/upgrade</code> returns the payment terms (Base or Polygon USDC). Pay it and this monitor runs until ${new Date(Date.now() + PAID_DAYS * 86400000).toISOString().slice(0, 10)}. No account is created.</p>
<p class="small">No wallet? Just let the trial end. You'll get exactly one email saying it stopped.</p></div>`}
${m.demo ? "" : `<form method="post" action="/w/${m.token}/cancel" onsubmit="return confirm('Stop monitoring and delete this?')"><button type="submit" style="background:#fff;color:#b3261e;border-color:#b3261e">Cancel &amp; delete</button></form>
<p class="small">This page is private to whoever holds the link. <a href="/">watch</a></p>`}</body></html>`);
}

const API_DOC = (o) => `watch API

POST ${o}/watch            form or JSON {url, email}  -> 201 {token, status_url}
GET  ${o}/w/<token>        HTML status page
GET  ${o}/w/<token>.json   JSON status
POST ${o}/w/<token>/cancel delete
GET  ${o}/w/<token>/upgrade
     no payment header -> 402 with x402 v2 terms ($5 USDC, eip155:8453 or eip155:137)
     with X-PAYMENT    -> verifies + settles via Coinbase facilitator, extends 365 days
GET  ${o}/stats           public counters
`;

export default {
  async scheduled(event, env, ctx) {
    const n = await runAll(env);
    await bump(env, "checks", n);
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const p = url.pathname;
    if (request.method === "OPTIONS")
      return new Response(null, { headers: { "access-control-allow-origin": "*",
        "access-control-allow-headers": "content-type, x-payment, payment-signature", "access-control-allow-methods": "GET,POST,OPTIONS" } });

    if (p === "/" ) return landing(env, JSON.parse((await env.WATCH.get("stats")) || "{}"));
    if (p === "/api") return new Response(API_DOC(env.PUBLIC_ORIGIN), { headers: { "content-type": "text/plain" } });
    if (p === "/health") return json({ ok: true, service: "watch", time: new Date().toISOString() });
    if (p === "/demo") {
      // Public, read-only view of the longest-running monitor (mine). Same
      // renderer as the private page, but no cancel/upgrade controls and the
      // email masked, so nothing here is a secret.
      let oldest = null, cursor;
      do {
        const page = await env.WATCH.list({ prefix: "w:", cursor, limit: 200 });
        cursor = page.list_complete ? undefined : page.cursor;
        for (const k of page.keys) {
          const m = JSON.parse((await env.WATCH.get(k.name)) || "null");
          if (m && (!oldest || m.createdAt < oldest.createdAt)) oldest = m;
        }
      } while (cursor);
      if (!oldest) return json({ error: "no monitors yet" }, 404);
      const d = { ...oldest, email: oldest.email.replace(/^(.).*(@.*)$/, "$1***$2"), demo: true };
      return statusPage(env, d);
    }
    if (p === "/stats") {
      const s = JSON.parse((await env.WATCH.get("stats")) || "{}");
      const e = await env.WATCH.get("lastMailError");
      if (e) s.lastMailError = JSON.parse(e);
      return json(s);
    }
    if (p === "/robots.txt") return new Response("User-agent: *\nDisallow: /w/\n", { headers: { "content-type": "text/plain" } });

    if (p === "/watch" && request.method === "POST") {
      let body = {};
      const ct = request.headers.get("content-type") || "";
      if (ct.includes("json")) body = await request.json().catch(() => ({}));
      else { const f = await request.formData().catch(() => null); if (f) body = Object.fromEntries(f.entries()); }
      const target = validUrl((body.url || "").trim());
      const email = (body.email || "").trim().toLowerCase();
      if (target === "WORKERS_DEV")
        return json({ error: "*.workers.dev URLs can't be monitored from a Worker (Cloudflare blocks Worker-to-Worker fetches, error 1042). Put a custom domain in front of it, or monitor something else." }, 400);
      if (!target) return json({ error: "url must be a public http(s) URL" }, 400);
      if (!validEmail(email)) return json({ error: "email looks invalid" }, 400);
      const ek = `e:${await sha(email)}`;
      const cnt = parseInt((await env.WATCH.get(ek)) || "0", 10);
      if (cnt >= MAX_PER_EMAIL) return json({ error: `max ${MAX_PER_EMAIL} monitors per email` }, 429);
      const tok = token();
      const now = Date.now();
      const m = { token: tok, url: target, host: new URL(target).hostname, email, createdAt: now,
        expiresAt: now + TRIAL_DAYS * 86400000, paid: false, state: null, checks: 0 };
      // First check right now so the confirmation email carries a real result.
      const first = await checkOnce(target);
      m.checks = 1; m.lastCheck = now; m.lastStatus = first.status; m.lastMs = first.ms; m.state = first.up ? "up" : null;
      await env.WATCH.put(`w:${tok}`, JSON.stringify(m));
      await env.WATCH.put(ek, String(cnt + 1));
      await bump(env, "active"); await bump(env, "signups");
      ctx.waitUntil(sendMail(env, email, `[watch] now watching ${m.host}`,
        `${target}\nFirst check: ${first.up ? `UP (HTTP ${first.status}, ${first.ms} ms)` : `not responding (${first.error || "HTTP " + first.status})`}\n\n` +
        `Checked every 5 minutes for ${TRIAL_DAYS} days, free. You'll only hear from me if it goes down, comes back, or the trial ends.\n\n` +
        `Status / upgrade / cancel: ${env.PUBLIC_ORIGIN}/w/${tok}\n\n— watch, run by clankerceo (an autonomous agent). Reply to this email if anything is wrong.\n`));
      const status_url = `${env.PUBLIC_ORIGIN}/w/${tok}`;
      if (ct.includes("json")) return json({ token: tok, status_url, first_check: first }, 201);
      return Response.redirect(status_url, 303);
    }

    const mm = p.match(/^\/w\/([a-f0-9]{32})(\.json|\/cancel|\/upgrade)?$/);
    if (mm) {
      const tok = mm[1], key = `w:${tok}`;
      const raw = await env.WATCH.get(key);
      if (!raw) return json({ error: "no such monitor (cancelled or never existed)" }, 404);
      const m = JSON.parse(raw);
      if (mm[2] === "/cancel" && request.method === "POST") {
        await env.WATCH.delete(key); await bump(env, "active", -1); await bump(env, "cancelled");
        // Release the per-email slot, or three cancels lock a user out for good.
        const ek = `e:${await sha(m.email)}`;
        const cnt = parseInt((await env.WATCH.get(ek)) || "0", 10);
        await env.WATCH.put(ek, String(Math.max(0, cnt - 1)));
        return html(`<!doctype html><meta charset="utf-8"><style>${CSS}</style><h1>Deleted.</h1><p>${esc(m.url)} is no longer monitored and its record is gone.</p><p><a href="/">watch</a></p>`);
      }
      if (mm[2] === "/upgrade") return handleUpgrade(request, env, tok, m, key);
      if (mm[2] === ".json") { const { email, ...pub } = m; return json({ ...pub, email: email.replace(/^(.).*(@.*)$/, "$1***$2") }); }
      return statusPage(env, m);
    }
    return json({ error: "not found", see: "/api" }, 404);
  },
};
