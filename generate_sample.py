#!/usr/bin/env python3
"""
Generate a synthetic DeviceLogonEvents CSV for demoing hunt.py.

All data is fictional. IPs come from the documentation ranges reserved by RFC 5737
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so nothing here points at a real host.
"""

import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(42)
START = datetime(2026, 8, 14, 2, 0, tzinfo=timezone.utc)
rows = []


def add(offset_seconds, device, action, account, ip):
    when = START + timedelta(seconds=offset_seconds)
    rows.append({
        "Timestamp": when.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "DeviceName": device,
        "ActionType": action,
        "AccountName": account,
        "LogonType": "Network" if action == "LogonFailed" else "RemoteInteractive",
        "RemoteIP": ip,
    })


# 1. Brute force that SUCCEEDS -> High (weak password on an exposed lab VM)
t = 0
for _ in range(34):
    t += random.randint(3, 9)
    add(t, "win-vm-honeypot-01", "LogonFailed", random.choice(["administrator", "admin", "labuser"]), "203.0.113.45")
add(t + 40, "win-vm-honeypot-01", "LogonSuccess", "labuser", "203.0.113.45")

# 2. Password spraying -> Medium (slow, many accounts, few tries each)
t = 1800
for account in ["administrator", "admin", "user", "test", "guest", "backup", "sql", "support", "scanner"]:
    for _ in range(2):
        t += random.randint(60, 180)
        add(t, "win-vm-honeypot-02", "LogonFailed", account, "198.51.100.23")

# 3. Fast brute force that FAILS -> Medium
t = 4000
for _ in range(18):
    t += random.randint(5, 12)
    add(t, "linux-vm-honeypot-01", "LogonFailed", "root", "192.0.2.77")

# 4. Background noise below thresholds -> no finding
for ip in ["198.51.100.140", "203.0.113.9", "192.0.2.201"]:
    for _ in range(random.randint(2, 4)):
        add(random.randint(0, 7000), random.choice(["win-vm-honeypot-01", "linux-vm-honeypot-01"]),
            "LogonFailed", random.choice(["admin", "root"]), ip)

# 5. Normal admin logons -> no finding
for offset in (600, 3600, 6900):
    add(offset, "win-vm-honeypot-01", "LogonSuccess", "analyst", "192.0.2.10")

rows.sort(key=lambda r: r["Timestamp"])
out = Path(__file__).parent / "sample_data" / "DeviceLogonEvents_sample.csv"
out.parent.mkdir(exist_ok=True)
with out.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
print(f"Wrote {len(rows)} events to {out}")
