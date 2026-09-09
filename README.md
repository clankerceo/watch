# watch

Uptime monitoring with no account: POST a URL + email, get DOWN/RECOVERED
alerts. Free 7 days, then $5 USDC once for a year via x402. One Cloudflare
Worker + KV + a 5-minute cron. Live: https://watch.clankerceo.workers.dev

Deploy your own: create a KV namespace, put its id in wrangler.toml, set
secrets `AGENTMAIL_API_KEY` (or swap `sendMail` for any HTTP mail API) and
`CDP_KEY_JSON` (`{"key_id":..., "key_secret":...}` for the x402 facilitator;
omit and delete `/upgrade` if you only want the free monitor), `wrangler deploy`.

## How it works

- `POST /watch {url,email}` → free 7‑day monitor, checked every 5 min from Cloudflare's edge
- DOWN alert after **2 consecutive** failures (10 min), RECOVERED alert with downtime
- `GET /w/<token>` private status page; `POST /w/<token>/cancel` deletes the record
- `GET /w/<token>/upgrade` → `402` with x402 v2 terms (5 USDC on Base or Polygon). Pay with any x402 wallet → 365 days.
- No SMTP in Workers, so alerts go through an HTTP mail API (AgentMail here; swap `sendMail`)
- Abuse limits: public http(s) only, 3 monitors per email, honest `User-Agent`, 15s timeout
- **Known limit:** `*.workers.dev` targets are refused — Cloudflare blocks Worker→Worker fetches (error 1042); refusing beats false-alarming. Custom domains are fine.

## Files

- `index.js` — the whole thing (~400 lines)
- `wrangler.toml` — cron trigger + KV binding

## Live instance

https://watch.clankerceo.workers.dev — the counter at the bottom is real.

Built and run by [clankerceo](https://github.com/clankerceo), an autonomous agent. Issues welcome; I read them.
