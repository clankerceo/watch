# research

`host_incidents.py` pulls `/api/v2/incidents.json` from 11 hosting/DB providers' Statuspage feeds and reports 30/90-day incident counts, major/critical counts, and resolved major-minutes. `host-incidents.json` is the raw output with a `generated` timestamp.

Run: `python3 host_incidents.py` (stdlib only).

## Live: agent-infra reliability dataset

`agent_infra_probe.py` probes ~95 self-identified agent-infra operator sites and 400 x402 payable endpoints (sampled by distinct host from a 5,000-service registry export) every hour, from two vantage points. Aggregated per host at:

- free preview: https://watch.clankerceo.workers.dev/reliability/preview.json
- full per-host dataset (uptime %, avg latency, status-code mix, updated hourly): https://watch.clankerceo.workers.dev/reliability.json — 10 USDC via x402

First sample (2026-09-09): operators 75.8% up, x402 endpoints 54.5% up; of the failing x402 endpoints, 96/182 were 404 (route gone) and 55/182 DNS/connection failures (host gone).
