#!/usr/bin/env python3
"""Realtime inbox feed demo.

Drops email into the watcher inbox on a short timer and scans it, simulating a
live tenant intake. After the sample set arrives it registers a confirmed
gateway click on a credential-phish case so the dashboard can show a live
escalation to Critical with the Emergency Creds Reset panel enabled.
"""
import json
import pathlib
import re
import sys
import time
import uuid
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phishpipe import config  # noqa: E402

API = "http://127.0.0.1:8000"
SAMPLES = ROOT / "samples"
INBOX = ROOT / "data" / "inbox"

SCENARIOS = [
    "phish_m365_credential_harvest.eml",
    "phish_dhl_redelivery.eml",
    "phish_invoice_attachment.eml",
    "legit_it_maintenance_notice.eml",
]


def http(method: str, path: str, payload: dict | None = None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        API + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read()
            return resp.status, (json.loads(body) if body else {})
    except Exception as exc:  # noqa: BLE001
        return None, {"error": str(exc)}


def fresh_message_id(body: str) -> str:
    rid = uuid.uuid4().hex[:10]
    if re.search(r"(?im)^Message-ID:", body):
        return re.sub(
            r"(?im)^Message-ID:.*$",
            f"Message-ID: <{rid}@intake.local>",
            body,
            count=1,
        )
    return re.sub(
        r"(?im)^(Subject:.*)$",
        r"\1\nMessage-ID: <%s@intake.local>" % rid,
        body,
        count=1,
    )


def main() -> int:
    INBOX.mkdir(parents=True, exist_ok=True)

    pool: list[dict] = []
    for name in SCENARIOS:
        body = (SAMPLES / name).read_text(encoding="utf-8", errors="replace")
        pool.append({"body": body, "label": name, "case_id": None, "cls": ""})

    # Two forwarded variants so the same message shows up through more than one
    # path -- enough distinct cases for a meaningful queue.
    for name in (SCENARIOS[0], SCENARIOS[3]):
        body = (SAMPLES / name).read_text(encoding="utf-8", errors="replace")
        body = body.replace("Subject:", "Subject: [FWD]", 1)
        pool.append({"body": body, "label": "fwd_" + name, "case_id": None, "cls": ""})

    for i, item in enumerate(pool):
        item["body"] = fresh_message_id(item["body"])
        dest = INBOX / f"incoming_{i:02d}.eml"
        dest.write_text(item["body"], encoding="utf-8")
        print(f"[{time.strftime('%H:%M:%S')}] inbox += incoming_{i:02d}.eml ({item['label']})")
        _, res = http("POST", "/api/watch/scan", {"inbox_path": str(INBOX)})
        for r in (res or {}).get("results") or []:
            if r.get("status") == "success":
                item["case_id"] = r["case_id"]
                item["cls"] = r.get("classification", "")
            print(
                f"    -> {r.get('status')}: {r.get('case_id', '')} | {r.get('classification', '')} | conf={r.get('confidence', '')} {r.get('error', '')}"
            )
        time.sleep(6)

    # Simulate gateway telemetry: a recipient engaged with the phish landing page.
    targets = [it for it in pool if it["case_id"] and "m365" in it["label"]]
    if targets:
        cid = targets[0]["case_id"]
        payload = {
            "url": "http://malicious.example/login",
            "user_email": "jane.doe@yourcompany.com",
            "client_ip": "203.0.113.44",
            "source": "web_proxy",
            "outcome": "credentials_submitted",
            "credentials_submitted": True,
            "details": "Demo feed: gateway logged a credentials submission",
        }
        _, res = http("POST", f"/api/cases/{cid}/click-event", payload)
        print(f"[{time.strftime('%H:%M:%S')}] click confirmed on {cid}: {res}")

    print("[demo_feed] done. Cases persisted; dashboard will poll live.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
