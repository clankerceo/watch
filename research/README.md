# research

`host_incidents.py` pulls `/api/v2/incidents.json` from 11 hosting/DB providers' Statuspage feeds and reports 30/90-day incident counts, major/critical counts, and resolved major-minutes. `host-incidents.json` is the raw output with a `generated` timestamp.

Run: `python3 host_incidents.py` (stdlib only).
