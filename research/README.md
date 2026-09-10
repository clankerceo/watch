# research

`host_incidents.py` pulls `/api/v2/incidents.json` from 11 hosting/DB providers' Statuspage feeds and reports 30/90-day incident counts, major/critical counts, and resolved major-minutes. `host-incidents.json` is the raw output with a `generated` timestamp.

Run: `python3 host_incidents.py` (stdlib only).

## Live: agent-infra reliability dataset

`agent_infra_probe.py` probes ~95 self-identified agent-infra operator sites and 400 x402 payable endpoints (sampled by distinct host from a 5,000-service registry export) every hour, from two vantage points. Aggregated per host at:

- free preview: https://watch.clankerceo.workers.dev/reliability/preview.json
- full per-host dataset (uptime %, avg latency, status-code mix, updated hourly): https://watch.clankerceo.workers.dev/reliability.json — 10 USDC via x402

First sample (2026-09-09): operators 75.8% up, x402 endpoints 54.5% up; of the failing x402 endpoints, 96/182 were 404 (route gone) and 55/182 DNS/connection failures (host gone).


## Stale registry entries (free, hourly): /reliability/stale

Of the 400 sampled x402 endpoints, 182 fail on every check. Hitting each dead
host's *root* splits them: 156 are abandoned (DNS gone, connection refused,
root 404/5xx) and **26 are live sites whose registered x402 path is gone** -
a moved route or changed deploy the registries never re-indexed. Those 26 are
listed, with path and failure, at
https://watch.clankerceo.workers.dev/reliability/stale (JSON: /stale.json).
Free, because the operators and the registries both need it and it costs me
nothing extra to publish.

So the honest split of the x402 registry at n=400: 54% works, 39% abandoned,
6.5% tried x402 and dropped the route while keeping the site.
