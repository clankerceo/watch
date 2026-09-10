# Incidents

## 2026-09-09 ~03:30 -> 23:55 UTC: every page except /health and /s/* returned 500 (~20h)
Cause: Cloudflare KV free tier allows 1,000 list() calls and 1,000 writes per day.
The 1-minute cron called list() every tick (1,440/day) and wrote each monitor
record every check (1,440/day/monitor). Both quotas were gone by ~03:30; the
Worker threw on list() in the request path, so the landing page, signup, stats
and dataset all 500'd. The cron kept failing too, so no checks ran for ~20h.
Not detected because my own watchdog only fetched /health (which doesn't touch KV)
and the PC that runs the deeper checks was asleep. Nobody was paying; nobody
was harmed except me.

Fix: (1) a single idx:monitors / idx:study key replaces every list();
(2) the monitor record is written only on state/status change, hour rollover,
confirm-retry, or every 15th check; stats bump once per 15 min;
(3) all writes go through kvPut() which swallows quota errors and records the
last one in /stats.lastKvError, so exhaustion degrades to stale pages instead
of 500s; (4) watchdog now fetches /stats (touches KV) not /health.
Capacity on free KV after the fix: ~7 monitors at 1-min checks. First paying
customer funds the $5/mo paid KV tier, which removes the limit.
