"""Honest version: paginate past the 50-incident cap, count only RESOLVED
incidents for duration, and separate 'component-degraded' from 'major' so a
17-day 'metrics delayed' ticket doesn't outweigh a 20-minute full outage."""
import json
import time
import urllib.request
from datetime import datetime, timedelta, timezone

HOSTS = {
    "Vercel": "https://www.vercel-status.com", "Fly.io": "https://status.flyio.net",
    "Render": "https://status.render.com", "Netlify": "https://www.netlifystatus.com",
    "Cloudflare": "https://www.cloudflarestatus.com", "Supabase": "https://status.supabase.com",
    "DigitalOcean": "https://status.digitalocean.com", "GitHub": "https://www.githubstatus.com",
    "PlanetScale": "https://www.planetscalestatus.com", "Upstash": "https://status.upstash.com",
    "Linode": "https://status.linode.com",
}
UA = {"user-agent": "clankerceo-research/1.0 (+https://github.com/clankerceo; public status history)"}
now = datetime.now(timezone.utc)
P = lambda ts: datetime.fromisoformat(ts.replace("Z", "+00:00"))


def all_incidents(base, since):
    out, page = [], 1
    while page <= 6:
        try:
            d = json.loads(urllib.request.urlopen(urllib.request.Request(f"{base}/api/v2/incidents.json?page={page}", headers=UA), timeout=25).read())
        except Exception:
            break
        inc = d.get("incidents", [])
        if not inc:
            break
        out += inc
        if P(inc[-1]["created_at"]) < since or len(inc) < 50:
            break
        page += 1; time.sleep(0.4)
    seen = set(); uniq = []
    for i in out:
        if i["id"] not in seen:
            seen.add(i["id"]); uniq.append(i)
    return uniq, page


rows = []
since90 = now - timedelta(days=90)
for name, base in HOSTS.items():
    inc, pages = all_incidents(base, since90)
    r = {"host": name, "source": base + "/api/v2/incidents.json", "pages": pages}
    for days in (30, 90):
        cutoff = now - timedelta(days=days)
        sel = [i for i in inc if P(i["created_at"]) >= cutoff]
        resolved = [i for i in sel if i.get("resolved_at")]
        major = [i for i in sel if i.get("impact") in ("major", "critical")]
        major_min = sum((P(i["resolved_at"]) - P(i["created_at"])).total_seconds() / 60 for i in major if i.get("resolved_at"))
        worst = max(((P(i["resolved_at"]) - P(i["created_at"])).total_seconds() / 60, i["name"], i["created_at"][:10]) for i in major if i.get("resolved_at")) if any(i.get("resolved_at") for i in major) else None
        r[f"d{days}"] = {"incidents": len(sel), "resolved": len(resolved), "major_or_critical": len(major),
                         "major_minutes_resolved": round(major_min), "worst_major": worst, "truncated": len(sel) >= 50 * pages}
    rows.append(r)
    a, b = r["d30"], r["d90"]
    print(f"{name:13} 30d: {a['incidents']:>3} inc, {a['major_or_critical']:>2} major = {a['major_minutes_resolved']:>5} min | 90d: {b['incidents']:>3} inc, {b['major_or_critical']:>2} major = {b['major_minutes_resolved']:>6} min | worst: {(b['worst_major'][1][:40]+' '+str(round(b['worst_major'][0]))+'m') if b['worst_major'] else '-'}{'  [TRUNC]' if b['truncated'] else ''}")

json.dump({"generated": now.isoformat(), "method": "statuspage.io /api/v2/incidents.json, paginated; durations only for resolved incidents; 'major' = impact in {major,critical}", "rows": rows},
          open("/home/hexatron/ceo/logs/host-incidents.json", "w"), indent=1)
