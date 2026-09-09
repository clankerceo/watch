// watch — uptime + SSL-expiry monitoring with no account.
//
// POST /watch {url,email}  -> free 7-day trial, checked every minute from CF edge
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
  let res = await checkOnce(m.url);
  m.checks = (m.checks || 0) + 1;
  // Confirm a failure immediately instead of waiting for the next tick: the
  // #1 complaint about free monitors (r/devops, 88 comments) is that a 5-min
  // interval + 2-strike rule means 10+ minutes to hear about an outage.
  // One retry after 20s turns "two ticks" into "~20 seconds" while still
  // filtering single-request blips.
  if (!res.up) {
    await new Promise((r) => setTimeout(r, 20000));
    const again = await checkOnce(m.url);
    m.checks++;
    if (again.up) res = again;           // blip: treat as up
    else res = { ...again, confirmed: true };
  }
  m.lastCheck = now; m.lastStatus = res.status; m.lastMs = res.ms;
  await recordHistory(env, m, res.up, res.ms);
  if (!res.up) {
    m.failStreak = (m.failStreak || 0) + 1;
    m.downCount = (m.downCount || 0) + 1;
  } else {
    m.failStreak = 0;
  }
  if (res.confirmed && m.state !== "down") {
    m.state = "down"; m.downSince = now; m.incidents = (m.incidents || 0) + 1;
    await bump(env, "alerts");
    await sendMail(env, m.email, `[watch] DOWN: ${m.host}`,
      `${m.url} failed a check and failed again 20 seconds later.\n` +
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

// Free-plan Workers allow ~50 subrequests per invocation and each monitor
// needs up to 2 (check + retry) plus KV I/O. Above ~20 monitors, rotate:
// each minute handles the slice that is due, ordered by staleness, so every
// monitor is still checked within a few minutes and none is silently skipped.
const PER_TICK = 20;
async function runAll(env) {
  let cursor; const all = [];
  do {
    const page = await env.WATCH.list({ prefix: "w:", cursor, limit: 1000 });
    cursor = page.list_complete ? undefined : page.cursor;
    for (const k of page.keys) all.push(k.name);
  } while (cursor);
  if (all.length <= PER_TICK) {
    await Promise.allSettled(all.map(async (k) => {
      const raw = await env.WATCH.get(k); if (raw) await processMonitor(env, k, JSON.parse(raw)); }));
    return all.length;
  }
  // Too many for one tick: load lastCheck for all (KV reads are cheap and
  // not counted as subrequests), pick the PER_TICK stalest.
  const recs = (await Promise.all(all.map(async (k) => {
    const raw = await env.WATCH.get(k); return raw ? [k, JSON.parse(raw)] : null; }))).filter(Boolean);
  recs.sort((a, b) => (a[1].lastCheck || 0) - (b[1].lastCheck || 0));
  const due = recs.slice(0, PER_TICK);
  await Promise.allSettled(due.map(([k, m]) => processMonitor(env, k, m)));
  await env.WATCH.put("stats:backlog", JSON.stringify({ monitors: recs.length, perTick: PER_TICK,
    effectiveIntervalMin: Math.ceil(recs.length / PER_TICK) }));
  return due.length;
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
  if (m.tx) await env.WATCH.put(`tx:${m.tx}`, JSON.stringify({ token: tok, at: now, network: m.network, via: "x402" }));
  m.expiresAt = Math.max(m.expiresAt || now, now) + PAID_DAYS * 86400000; m.expiredNotified = false;
  await env.WATCH.put(key, JSON.stringify(m));
  await bump(env, "paid"); await bump(env, "revenue_cents", 500);
  await sendMail(env, m.email, `[watch] paid — ${m.host} monitored until ${new Date(m.expiresAt).toISOString().slice(0, 10)}`,
    `Thanks. $5 USDC received${m.tx ? ` (tx ${m.tx})` : ""}.\n${m.url} is monitored every minute for a year.\n\n` +
    `Status/cancel: ${env.PUBLIC_ORIGIN}/w/${m.token}\n`);
  return json({ ok: true, paid: true, expiresAt: new Date(m.expiresAt).toISOString(), tx: m.tx },
    200, { "payment-response": btoa(JSON.stringify({ success: true, transaction: m.tx, network: m.network })) });
}

// ---------- plain-transfer claim (no x402 client needed) ----------
// A human sends exactly 5 USDC to PAY_TO from any wallet/exchange, then clicks
// "activate". We scan ERC-20 Transfer logs to PAY_TO on both chains since the
// monitor was created, take the first 5.00 USDC transfer whose tx hash has
// not been claimed by any monitor, and bind it. First-come-first-served is
// fair here: the sender got a monitor for their money, and nobody who did
// not pay can claim (they'd need an unclaimed 5 USDC transfer to exist).
const RPC = {
  "eip155:8453": ["https://mainnet.base.org", "https://base-rpc.publicnode.com", "https://base.drpc.org"],
  "eip155:137": ["https://polygon-bor-rpc.publicnode.com", "https://polygon.drpc.org"],
};
const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
// Public RPCs cap eth_getLogs at 10k blocks (publicnode/drpc; 1rpc is 50!).
// Scan in 9k windows newest-first. 8 windows = 72k blocks ≈ 40h on Base (2s)
// and ≈ 44h on Polygon (2.2s); a paying human clicks within that.
const WINDOW = 9000, WINDOWS = 8;

async function rpcCall(urls, method, params) {
  let err;
  for (const u of urls) {
    try {
      const r = await fetch(u, { method: "POST", headers: { "content-type": "application/json", "user-agent": UA },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
      const j = await r.json();
      if (j.error) throw new Error(j.error.message);
      return j.result;
    } catch (e) { err = e; }
  }
  throw err || new Error("all rpcs failed");
}

async function findUnclaimedPayment(env, sinceMs) {
  const padded = "0x" + env.PAY_TO_BASE.slice(2).toLowerCase().padStart(64, "0");
  for (const [network, asset] of Object.entries(USDC)) {
    const urls = RPC[network];
    let logs = [];
    try {
      const latest = parseInt(await rpcCall(urls, "eth_blockNumber", []), 16);
      for (let w = 0; w < WINDOWS; w++) {
        const to = latest - w * WINDOW, from = Math.max(0, to - WINDOW + 1);
        const part = await rpcCall(urls, "eth_getLogs", [{ address: asset, fromBlock: "0x" + from.toString(16),
          toBlock: "0x" + to.toString(16), topics: [TRANSFER_TOPIC, null, padded] }]);
        logs.push(...(part || []).reverse());   // newest first overall
        if (logs.some((l) => parseInt(l.data, 16) === 5000000)) break; // found candidates; stop paging
      }
    } catch (e) { await env.WATCH.put("lastScanError", JSON.stringify({ network, at: new Date().toISOString(), err: String(e?.message || e).slice(0, 200) })); continue; }
    for (const lg of logs) {
      const value = parseInt(lg.data, 16);
      if (value !== 5000000) continue;
      const key = `tx:${lg.transactionHash}`;
      if (await env.WATCH.get(key)) continue;           // already bound to a monitor
      // block timestamp so a transfer from before the monitor existed can't be claimed
      let ts = 0;
      try { const b = await rpcCall(urls, "eth_getBlockByNumber", [lg.blockNumber, false]); ts = parseInt(b.timestamp, 16) * 1000; } catch {}
      if (ts && ts < sinceMs - 3600000) continue;
      return { tx: lg.transactionHash, network, from: "0x" + lg.topics[1].slice(26), ts };
    }
  }
  return null;
}

async function handleClaim(env, tok, m, key) {
  if (m.paid) return Response.redirect(`${env.PUBLIC_ORIGIN}/w/${tok}`, 303);
  const hit = await findUnclaimedPayment(env, m.createdAt);
  if (!hit) {
    return html(`<!doctype html><meta charset="utf-8"><style>${CSS}</style><h1>Not seen yet</h1>
<p>No unclaimed 5 USDC transfer to <code>${env.PAY_TO_BASE}</code> on Base or Polygon since this monitor was created.</p>
<ul class="small"><li>Transfers usually confirm in under a minute — wait 60 seconds and try again.</li>
<li>It must be <b>exactly 5 USDC</b> (not 4.99 after fees, not 5 USDT).</li>
<li>Base and Polygon only. Ethereum mainnet, Arbitrum, Solana etc. are not scanned.</li></ul>
<p><a href="/w/${tok}">Back</a> · <a href="/w/${tok}/claim" onclick="event.preventDefault();fetch('/w/${tok}/claim',{method:'POST'}).then(()=>location.reload())">Try again</a> · questions: clankerceo@agentmail.to</p>`, 404);
  }
  await handleClaimHit(env, key, m, hit);
  return Response.redirect(`${env.PUBLIC_ORIGIN}/w/${tok}`, 303);
}

async function handleClaimHit(env, key, m, hit) {
  const now = Date.now();
  await env.WATCH.put(`tx:${hit.tx}`, JSON.stringify({ token: m.token, at: now, network: hit.network }));
  m.paid = true; m.paidAt = now; m.tx = hit.tx; m.network = hit.network; m.paidVia = "transfer"; m.payer = hit.from;
  m.expiresAt = Math.max(m.expiresAt || now, now) + PAID_DAYS * 86400000; m.expiredNotified = false;
  await env.WATCH.put(key, JSON.stringify(m));
  await bump(env, "paid"); await bump(env, "revenue_cents", 500);
  await sendMail(env, m.email, `[watch] paid — ${m.host} monitored until ${new Date(m.expiresAt).toISOString().slice(0, 10)}`,
    `Thanks. 5 USDC received (tx ${hit.tx} on ${hit.network}).\n${m.url} is monitored every minute for a year.\n\nStatus/cancel: ${env.PUBLIC_ORIGIN}/w/${m.token}\n`);
}

// ---------- public status pages (/s/<slug>) ----------
// A monitor owner names a slug from their private page; the slug maps to
// their monitor(s). Public page shows current state + last 24h of hourly
// history, nothing private (no email, no token). Free with any monitor: a
// public status page is the thing people actually asked for (r/devops thread,
// @dmkenney), and every one of them links back here.
const slugOk = (s) => /^[a-z0-9](?:[a-z0-9-]{1,30}[a-z0-9])?$/.test(s) && !["api", "demo", "stats", "health", "watch", "w", "s", "study", "admin", "status"].includes(s);

async function recordHistory(env, m, up, ms) {
  // hourly buckets, 48 kept; cheap enough to do on every check
  const h = new Date().toISOString().slice(0, 13);
  const hist = m.hist || [];
  let cur = hist[hist.length - 1];
  if (!cur || cur.h !== h) { cur = { h, n: 0, ok: 0, ms: 0 }; hist.push(cur); }
  cur.n++; cur.ok += up ? 1 : 0; cur.ms += ms || 0;
  m.hist = hist.slice(-48);
}

function publicStatusPage(env, slug, mons) {
  const overall = mons.every((m) => m.state === "up") ? "All systems operational"
    : mons.some((m) => m.state === "down") ? "Partial outage" : "Checking…";
  const rows = mons.map((m) => {
    const hist = (m.hist || []).slice(-24);
    const bars = hist.map((b) => {
      const pct = b.n ? b.ok / b.n : 1;
      const col = pct === 1 ? "#137333" : pct >= 0.9 ? "#e0a800" : "#b3261e";
      return `<span title="${b.h}:00 UTC — ${b.ok}/${b.n} ok, avg ${Math.round(b.ms / Math.max(1, b.n))} ms" style="display:inline-block;width:10px;height:26px;margin-right:2px;background:${col};border-radius:2px"></span>`;
    }).join("");
    const up24 = hist.reduce((a, b) => a + b.ok, 0), n24 = hist.reduce((a, b) => a + b.n, 0);
    const st = m.state === "down" ? `<span class="bad">DOWN</span>` : m.state === "up" ? `<span class="ok">UP</span>` : "pending";
    return `<div class="box"><b>${esc(m.label || m.host)}</b> &nbsp; ${st}<br>
<div style="margin:8px 0">${bars || '<span class="small">collecting…</span>'}</div>
<span class="small">${n24 ? `${(100 * up24 / n24).toFixed(2)}% of checks OK, last 24h` : ""} · last check ${m.lastCheck ? new Date(m.lastCheck).toISOString().slice(11, 16) + " UTC" : "—"}${m.lastMs ? `, ${m.lastMs} ms` : ""}</span></div>`;
  }).join("");
  return html(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="60"><title>${esc(slug)} — status</title><style>${CSS}</style></head><body>
<h1>${esc(slug)}</h1><p class="sub"><b>${overall}</b> · checked every minute from Cloudflare's edge · auto-refreshes</p>
${rows}
<p class="small">Powered by <a href="/">watch</a> — uptime monitoring with no account. <a href="/s/${esc(slug)}.json">JSON</a></p></body></html>`);
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
<p class="small">Checked <b>every minute</b> from Cloudflare's edge. A failure is re-checked 20 seconds later before you're alerted, so a single blip stays quiet and a real outage reaches you in about a minute. Recovery email when it's back. One confirmation email, no marketing, ever. Cancel link in every email.</p>
</form>
<div class="box"><b>Why this exists.</b> Every uptime service wants an account, a card on file and a monthly plan, and the free tiers shrink every year. This is the opposite: give it a URL and an email, get alerts. That's it.</div>
<div class="box"><b>Free public status page.</b> From your private page, pick a slug and your monitor gets a public page at <code>/s/your-slug</code> — current state plus 24 hours of hourly history, auto-refreshing. Group several monitors under one slug. Example: <a href="/s/watch-demo">/s/watch-demo</a>.</div>
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
${m.demo ? `<div class="box">This is the public demo view of a real monitor. <a href="/">Start your own</a> — free, no account.</div>` : m.paid ? "" : `<div class="box"><b>Keep it running for a year — $5, once.</b>
<p class="small">Send <b>exactly 5 USDC</b> on <b>Base</b> or <b>Polygon</b> to this address, then click the button. Any exchange or wallet that can send USDC works (Coinbase, Binance, MetaMask, Phantom, Rabby…). No account is created here.</p>
<p><code id="addr" style="font-size:13px;word-break:break-all">${env.PAY_TO_BASE}</code> <button type="button" onclick="navigator.clipboard.writeText('${env.PAY_TO_BASE}');this.textContent='copied'" style="padding:4px 10px;font-size:13px">copy</button></p>
<form method="post" action="/w/${m.token}/claim"><button type="submit">I've sent 5 USDC — activate my year</button></form>
<p class="small" id="claimnote"></p>
<details class="small"><summary>Using an x402 wallet or an agent instead?</summary><code>GET ${esc(env.PUBLIC_ORIGIN)}/w/${m.token}/upgrade</code> returns x402 v2 payment terms; pay with the header and it activates instantly.</details>
<p class="small">No wallet, no crypto? Just let the trial end. You'll get exactly one email saying it stopped — nothing else, ever.</p></div>`}
${m.demo ? "" : `<div class="box"><b>Public status page</b> ${m.slug ? `— live at <a href="/s/${esc(m.slug)}">/s/${esc(m.slug)}</a>` : "(free)"}<br>
<form method="post" action="/w/${m.token}/publish" style="display:flex;gap:8px;align-items:center;margin-top:8px;flex-wrap:wrap">
<input name="slug" placeholder="your-slug" value="${esc(m.slug || "")}" pattern="[a-z0-9-]{3,32}" required style="width:160px;margin:0">
<input name="label" placeholder="label shown (e.g. API)" value="${esc(m.label || "")}" style="width:180px;margin:0">
<button type="submit">${m.slug ? "Update" : "Publish"}</button></form>
<p class="small">Public page shows UP/DOWN and 24h of hourly history for every monitor you publish under the same slug. Nothing private is shown. Publish other monitors of yours under the same slug to group them.</p></div>`}
${m.demo ? "" : `<form method="post" action="/w/${m.token}/cancel" onsubmit="return confirm('Stop monitoring and delete this?')"><button type="submit" style="background:#fff;color:#b3261e;border-color:#b3261e">Cancel &amp; delete</button></form>
<p class="small">This page is private to whoever holds the link. <a href="/">watch</a></p>`}</body></html>`);
}

const API_DOC = (o) => `watch API

POST ${o}/watch            form or JSON {url, email}  -> 201 {token, status_url}
GET  ${o}/w/<token>        HTML status page
GET  ${o}/w/<token>.json   JSON status
POST ${o}/w/<token>/cancel delete
POST ${o}/w/<token>/publish form {slug,label} -> public status page at /s/<slug>
GET  ${o}/s/<slug>          public status page (HTML) · ${o}/s/<slug>.json
GET  ${o}/w/<token>/upgrade
     no payment header -> 402 with x402 v2 terms ($5 USDC, eip155:8453 or eip155:137)
     with X-PAYMENT    -> verifies + settles via Coinbase facilitator, extends 365 days
GET  ${o}/stats           public counters
`;

// ---------- availability study (always-on; host PC sleeps) ----------
// Hourly, at :30, probe ~95 agent-infra sites and append one compact row per
// site to KV under study:<ISO-hour>. Read back with /study.json. Base64 so
// no JSON is inlined into a template literal (Workers escape bug).
const STUDY_B64 = "WyJodHRwOi8vZHVja2R1Y2tnby5jb20vZHVja2R1Y2tib3QuaHRtbCIsICJodHRwOi8vd3d3LnNlbXJ1c2guY29tL2JvdC5odG1sIiwgImh0dHBzOi8vMTB4NDAyLmNvbS9tb25pdG9yIiwgImh0dHBzOi8vNDAyc2NvcGUub3JnIiwgImh0dHBzOi8vYWdlbnN0cnkuY29tL2JvdCIsICJodHRwczovL2FnZW50LXRvLWFnZW50Lnh5ei9sbG1zLnR4dCIsICJodHRwczovL2FnZW50LXRvb2xzLmNsb3VkIiwgImh0dHBzOi8vYWdlbnQ0MDIuYXBwL2JvdCIsICJodHRwczovL2FnZW50YWxtYW5hYy5vcmciLCAiaHR0cHM6Ly9hZ2VudGNvdW50LmFpL21ldGhvZG9sb2d5IiwgImh0dHBzOi8vYWdlbnRkYXRhLWFwaS5jb20iLCAiaHR0cHM6Ly9hZ2VudGVjb25vbXkucmUiLCAiaHR0cHM6Ly9hZ2VudGVjb25vbXkucmVwb3J0L3MvIiwgImh0dHBzOi8vYWdlbnRwcm9iZS5vcmcvbWV0aG9kb2xvZ3kiLCAiaHR0cHM6Ly9hZ2VudHJlcHV0YXRpb24uZGV2IiwgImh0dHBzOi8vYWdlbnRzLnRyYWRlcnN6b25lLm5ldCIsICJodHRwczovL2FnZW50c3VyZS50ZWNoIiwgImh0dHBzOi8vYWl2ZS5nbG9iYWwvbWNwLXRydXN0L2NlbnN1cyIsICJodHRwczovL2FuaW1pY2EuZGV2L3g0MDIiLCAiaHR0cHM6Ly9hbnBheS5kZXYvYm90IiwgImh0dHBzOi8vYXBpLm5pdHJvZ3JhcGguY29tL2JvdCIsICJodHRwczovL2FwaS50ZW1zb3IuY29tL21jcC9pbmRleCIsICJodHRwczovL2FwaXN0cnVzdC5jb20iLCAiaHR0cHM6Ly9hdmlzcmFkYXItcHJvZHVjdGlvbi51cC5yYWlsd2F5LmFwcC9tYWlucyIsICJodHRwczovL2F2aXNyYWRhci5hcHAiLCAiaHR0cHM6Ly9ib3RhbmFyeS54eXoiLCAiaHR0cHM6Ly9jYXJib24tY2FzaG1lcmUuZGUiLCAiaHR0cHM6Ly9jb3VuY2lsb2YuYWkvYXBpL3g0MDIiLCAiaHR0cHM6Ly9jcm9zc3BlZWwuY29tIiwgImh0dHBzOi8vZGF0YWZvcnNlby5jb20vZGF0YWZvcnNlby1iIiwgImh0dHBzOi8vZGVjaXhhLmFpL2JvdCIsICJodHRwczovL2Rpc2NvdmVyLnBheWdlbnQubmV0L2Fib3V0IiwgImh0dHBzOi8vZG9ubmVlcy5odWx0cmEubGluay9zb25kZXMubWQiLCAiaHR0cHM6Ly9lbGdvby5haS9ib3QiLCAiaHR0cHM6Ly9leG9yYWlscy5uZXQiLCAiaHR0cHM6Ly9mbGFyZWNsYXcuYXBwLy53ZWxsLWtub3duL3g0MDIiLCAiaHR0cHM6Ly9mb3J1bS1sYWJzLmNvbSIsICJodHRwczovL2dsaW1pbmQuY29tL29wdC1vdXQiLCAiaHR0cHM6Ly9nb2luZGV4LnNob3AvbGVnYWwiLCAiaHR0cHM6Ly9nb2xlbXJlYWNoLmNvbS90cnVzdC9ib3QiLCAiaHR0cHM6Ly9rb3J0ZXgucm9obmVsdC5kZXYvYWJvdXQtdGhlLXByb2JlIiwgImh0dHBzOi8vbGFicy5sdWJiZWUubmV0IiwgImh0dHBzOi8vbGFzdHNlZW4uZGV2IiwgImh0dHBzOi8vbGl2ZS12cHMuc2FzYW1lLm9ubGluZS8ud2VsbC1rbm93bi9hZ2VudC1jYXJkLmpzbyIsICJodHRwczovL2xsbTRhZ2VudHMuY29tIiwgImh0dHBzOi8vbGxtbWFydC5haS9hcGkiLCAiaHR0cHM6Ly9tYXJrZXQ0MDIuY29tIiwgImh0dHBzOi8vbWNwLWNsb3VkLmFpIiwgImh0dHBzOi8vbWNwLXNjaGVtYS1hcmNoaXZlLmRlbGZyb3N0NDIud29ya2Vycy5kZXYiLCAiaHR0cHM6Ly9tY3BiZWF0LmNvbS9ib3QvIiwgImh0dHBzOi8vbWNwY2Vuc3VzLmNvbSIsICJodHRwczovL21jcGxvb2t1cC5jb20iLCAiaHR0cHM6Ly9tY3BtZXRlci5kZXYvYWJvdXQiLCAiaHR0cHM6Ly9tY3BxdWVlbi5jb20iLCAiaHR0cHM6Ly9tY3BzZXJ2ZXIubG9sL2Fib3V0L3Byb2JpbmciLCAiaHR0cHM6Ly9tY3B3aXRuZXNzLmNvbSIsICJodHRwczovL21pZGF4NDAyLmNvbS9jcmF3bGVyIiwgImh0dHBzOi8vbW9kYzIuY29tL21jcHNjYW4iLCAiaHR0cHM6Ly9tcHAzMi5vcmciLCAiaHR0cHM6Ly9ub2h1bWFucy5kaXJlY3RvcnkiLCAiaHR0cHM6Ly9ub3RzbG9wLm1lIiwgImh0dHBzOi8vcGF5YWJsZS5uc2dvb2RzLm9yZyIsICJodHRwczovL3Byb2JlNDAyLmNvbS9tZXRob2QiLCAiaHR0cHM6Ly9wcm9vZmJlbmNoLmRldi9hYm91dC9wcm9iZSIsICJodHRwczovL3B1cnNlci5pbyIsICJodHRwczovL3JlZmVyZW5jZXNvdXJjZS5vcmcvbWNwLWhlYWx0aC8iLCAiaHR0cHM6Ly9yZXZldHRyLmNvbSIsICJodHRwczovL3Jva2hhLmFpIiwgImh0dHBzOi8vcm9rbWNwLmNvbS9ib3QiLCAiaHR0cHM6Ly9yb25pbmZvcmdlLm9yZy9kYXRhL29ic2VydmF0b3J5LyIsICJodHRwczovL3Njb3V0c2NvcmUuYWkiLCAiaHR0cHM6Ly9zY3ZkLnN0b3JlIiwgImh0dHBzOi8vc2VjLnNxcnguaW8iLCAiaHR0cHM6Ly9zZXJhbmtpbmcuY29tL2JhY2tsIiwgImh0dHBzOi8vc3Bhbmx5LmNvbSIsICJodHRwczovL3RoZTQwMi5kZXYiLCAiaHR0cHM6Ly90b2xsNDAyLmNvbS9pbnNpZ2h0cy94NDAyLWRpc2NvdmVyeS1jIiwgImh0dHBzOi8vdG91Y2hzdG9uZS5uZWlsa3BhdGVsLmNvbSIsICJodHRwczovL3RyaW10YWJpc3QuY29tL3ZlcmlmaWVyIiwgImh0dHBzOi8vdHJ1c3RvdmVuLmNvbS9kb2NzL2NyYXdsZXIiLCAiaHR0cHM6Ly92ZXJhbnRpcy5haSIsICJodHRwczovL3ZlcmlmeW1jcC5pby9kb2NzL2J1aWxkL293bmVycy1qc29uIiwgImh0dHBzOi8vdmV0NDAyLmNvbS9vYnNlcnZhdG9yeS9tZXRob2RvbG9neSIsICJodHRwczovL3ZvdWNoLXByb3RvY29sLmNvbSIsICJodHRwczovL3dlbGxrbm93bi5uZXR3b3JrL2JvdCIsICJodHRwczovL3dpdG5lc3MuaG9sb3dlYXZlLm9yZyIsICJodHRwczovL3d3dy5wdWxzZWdhdGUuYWkvYm90IiwgImh0dHBzOi8vd3d3LnN1cGVyc3RhYmxlcy5jb20iLCAiaHR0cHM6Ly94NDAyLWxpc3QuY29tIiwgImh0dHBzOi8veDQwMi1saXZlbmVzcy5tYWxhY2h5c21hbGxtYW4ud29ya2Vycy5kZXYiLCAiaHR0cHM6Ly94NDAyLmZ1Y2hzcy5hcHAvdHJ1c3QiLCAiaHR0cHM6Ly94NDAybGVucy5jb20vbWV0aG9kb2xvZ3kiLCAiaHR0cHM6Ly94NDAyc3RhdHMuZGVjcmVkY29tbXVuaXR5Lm9yZyIsICJodHRwczovL3plcm8ueHl6L2JvdCIsICJodHRwczovL3pldnJ1bmEuY29tIl0=";
const STUDY_URLS = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(STUDY_B64), (c) => c.charCodeAt(0))));
async function studyTick(env) {
  const d = new Date();
  if (d.getUTCMinutes() !== 30) return;
  const hour = d.toISOString().slice(0, 13);
  if (await env.WATCH.get(`study:${hour}`)) return;
  // 50-subrequest cap: probe in two halves on consecutive minutes is complex;
  // instead cap at 45 per tick and rotate the start index by hour.
  const start = (d.getUTCHours() * 45) % STUDY_URLS.length;
  const batch = [...STUDY_URLS.slice(start), ...STUDY_URLS.slice(0, start)].slice(0, 45);
  const rows = await Promise.all(batch.map(async (u) => {
    const r = await checkOnce(u);
    return { u, c: r.status, ms: r.ms, up: r.up && r.status !== 404 && r.status !== 410 };
  }));
  await env.WATCH.put(`study:${hour}`, JSON.stringify({ hour, n: rows.length, up: rows.filter((x) => x.up).length, rows }),
    { expirationTtl: 60 * 86400 });
}

async function autoClaim(env) {
  // Every 5th minute: if someone paid by plain transfer and never clicked
  // "activate", bind the payment to the OLDEST unpaid trial monitor created
  // before the transfer. Same rule as the button, just without the button.
  if (new Date().getMinutes() % 5) return;
  let cursor; const unpaid = [];
  do {
    const page = await env.WATCH.list({ prefix: "w:", cursor, limit: 1000 });
    cursor = page.list_complete ? undefined : page.cursor;
    for (const k of page.keys) {
      const m = JSON.parse((await env.WATCH.get(k.name)) || "null");
      if (m && !m.paid && m.expiresAt > Date.now() - 7 * 86400000) unpaid.push([k.name, m]);
    }
  } while (cursor);
  if (!unpaid.length) return;
  unpaid.sort((a, b) => a[1].createdAt - b[1].createdAt);
  const hit = await findUnclaimedPayment(env, unpaid[0][1].createdAt);
  if (!hit) return;
  const [key, m] = unpaid.find(([, mm]) => mm.createdAt <= (hit.ts || Infinity)) || unpaid[0];
  await handleClaimHit(env, key, m, hit);
}

export default {
  async scheduled(event, env, ctx) {
    const n = await runAll(env);
    await bump(env, "checks", n);
    ctx.waitUntil(autoClaim(env).catch(() => {}));
    ctx.waitUntil(studyTick(env).catch(() => {}));
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const p = url.pathname;
    if (request.method === "OPTIONS")
      return new Response(null, { headers: { "access-control-allow-origin": "*",
        "access-control-allow-headers": "content-type, x-payment, payment-signature", "access-control-allow-methods": "GET,POST,OPTIONS" } });

    const statsNow = async () => {
      const s = JSON.parse((await env.WATCH.get("stats")) || "{}");
      let cursor, active = 0;
      do {
        const page = await env.WATCH.list({ prefix: "w:", cursor, limit: 1000 });
        cursor = page.list_complete ? undefined : page.cursor; active += page.keys.length;
      } while (cursor);
      s.active = active; return s;
    };
    if (p === "/" ) return landing(env, await statsNow());
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
      // `active` is derived, not counted: bump() races with itself (KV has no
      // atomic increment) and it drifted to 0 with one live monitor.
      const s = await statsNow();
      const e = await env.WATCH.get("lastMailError");
      if (e) s.lastMailError = JSON.parse(e);
      return json(s);
    }
    if (p === "/study.json") {
      let cursor; const out = [];
      do {
        const page = await env.WATCH.list({ prefix: "study:", cursor, limit: 1000 });
        cursor = page.list_complete ? undefined : page.cursor;
        for (const k of page.keys) { const v = await env.WATCH.get(k.name); if (v) out.push(JSON.parse(v)); }
      } while (cursor);
      out.sort((a, b) => a.hour.localeCompare(b.hour));
      return json({ description: "Hourly availability probe of ~95 AI-agent-infrastructure sites discovered via crawler user-agents. up = HTTP<500 and not 404/410. 45 sites per hour, rotating.", hours: out.length, samples: out });
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
        `Checked every minute for ${TRIAL_DAYS} days, free. You'll only hear from me if it goes down, comes back, or the trial ends.\n\n` +
        `Status / upgrade / cancel: ${env.PUBLIC_ORIGIN}/w/${tok}\n\n— watch, run by clankerceo (an autonomous agent). Reply to this email if anything is wrong.\n`));
      const status_url = `${env.PUBLIC_ORIGIN}/w/${tok}`;
      if (ct.includes("json")) return json({ token: tok, status_url, first_check: first }, 201);
      return Response.redirect(status_url, 303);
    }

    const sm = p.match(/^\/s\/([a-z0-9-]{1,32})(\.json)?$/);
    if (sm) {
      const slug = sm[1];
      const toks = JSON.parse((await env.WATCH.get(`slug:${slug}`)) || "[]");
      if (!toks.length) return json({ error: "no such status page" }, 404);
      const mons = (await Promise.all(toks.map((t) => env.WATCH.get(`w:${t}`)))).filter(Boolean).map((x) => JSON.parse(x));
      if (!mons.length) return json({ error: "no such status page" }, 404);
      if (sm[2]) return json({ slug, monitors: mons.map((m) => ({ label: m.label || m.host, url: m.url, state: m.state, lastCheck: m.lastCheck, lastMs: m.lastMs, hist: (m.hist || []).slice(-24) })) });
      return publicStatusPage(env, slug, mons);
    }

    const mm = p.match(/^\/w\/([a-f0-9]{32})(\.json|\/cancel|\/upgrade|\/claim|\/publish)?$/);
    if (mm) {
      const tok = mm[1], key = `w:${tok}`;
      const raw = await env.WATCH.get(key);
      if (!raw) return json({ error: "no such monitor (cancelled or never existed)" }, 404);
      const m = JSON.parse(raw);
      if (mm[2] === "/cancel" && request.method === "POST") {
        await env.WATCH.delete(key); await bump(env, "cancelled");
        if (m.slug) {
          const rest = JSON.parse((await env.WATCH.get(`slug:${m.slug}`)) || "[]").filter((t) => t !== tok);
          if (rest.length) await env.WATCH.put(`slug:${m.slug}`, JSON.stringify(rest)); else await env.WATCH.delete(`slug:${m.slug}`);
        }
        // Release the per-email slot, or three cancels lock a user out for good.
        const ek = `e:${await sha(m.email)}`;
        const cnt = parseInt((await env.WATCH.get(ek)) || "0", 10);
        await env.WATCH.put(ek, String(Math.max(0, cnt - 1)));
        return html(`<!doctype html><meta charset="utf-8"><style>${CSS}</style><h1>Deleted.</h1><p>${esc(m.url)} is no longer monitored and its record is gone.</p><p><a href="/">watch</a></p>`);
      }
      if (mm[2] === "/upgrade") return handleUpgrade(request, env, tok, m, key);
      if (mm[2] === "/claim" && request.method === "POST") return handleClaim(env, tok, m, key);
      if (mm[2] === "/publish" && request.method === "POST") {
        const f = await request.formData().catch(() => null);
        const slug = ((f && f.get("slug")) || "").toString().trim().toLowerCase();
        const label = ((f && f.get("label")) || "").toString().trim().slice(0, 40);
        if (!slugOk(slug)) return json({ error: "slug: 3-32 chars, a-z 0-9 and hyphens, not reserved" }, 400);
        const cur = JSON.parse((await env.WATCH.get(`slug:${slug}`)) || "[]");
        // a slug is owned by the email of the first monitor published under it
        if (cur.length) {
          const owner = JSON.parse((await env.WATCH.get(`w:${cur[0]}`)) || "null");
          if (owner && owner.email !== m.email) return json({ error: "that slug belongs to someone else" }, 409);
        }
        if (!cur.includes(tok)) cur.push(tok);
        await env.WATCH.put(`slug:${slug}`, JSON.stringify(cur));
        if (m.slug && m.slug !== slug) { // moved: remove from old slug
          const old = JSON.parse((await env.WATCH.get(`slug:${m.slug}`)) || "[]").filter((t) => t !== tok);
          if (old.length) await env.WATCH.put(`slug:${m.slug}`, JSON.stringify(old)); else await env.WATCH.delete(`slug:${m.slug}`);
        }
        m.slug = slug; if (label) m.label = label;
        await env.WATCH.put(key, JSON.stringify(m));
        return Response.redirect(`${env.PUBLIC_ORIGIN}/s/${slug}`, 303);
      }
      if (mm[2] === ".json") { const { email, ...pub } = m; return json({ ...pub, email: email.replace(/^(.).*(@.*)$/, "$1***$2") }); }
      return statusPage(env, m);
    }
    return json({ error: "not found", see: "/api" }, 404);
  },
};
