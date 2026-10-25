# Logon Threat Hunt Report

- **Source:** `DeviceLogonEvents_sample.csv`
- **Events analysed:** 85 (81 failed logons)
- **Period:** 2026-08-14 02:00:08 UTC to 2026-08-14 03:55:00 UTC
- **Rules:** brute force >= 10 failures in 5 min; spraying >= 5 accounts per IP

## Summary

3 suspicious source IPs: **1 High**, 2 Medium.

> **Action needed:** at least one IP logged in successfully after repeated failures. Handle the High findings first.

| Severity | Detection | Remote IP | Failed | Accounts | MITRE ATT&CK |
|---|---|---|---|---|---|
| High | Possible compromise: success after brute force | `203.0.113.45` | 34 | 1 | T1110 -> T1078 Valid Accounts |
| Medium | Password spraying | `198.51.100.23` | 18 | 9 | T1110.003 Password Spraying |
| Medium | Brute force | `192.0.2.77` | 18 | 1 | T1110.001 Password Guessing |

## Findings

### 1. [High] Possible compromise: success after brute force from `203.0.113.45`

- **What happened:** 34 failed logons, then a successful logon as 'labuser' on win-vm-honeypot-01 at 2026-08-14 02:04:16 UTC.
- **When:** 2026-08-14 02:00:08 UTC to 2026-08-14 02:04:16 UTC
- **Devices:** win-vm-honeypot-01
- **Accounts:** labuser
- **MITRE ATT&CK:** T1110 -> T1078 Valid Accounts
- **Recommended response:** Treat as a live incident: isolate the device in Defender, reset the account's password and revoke sessions, review activity after the successful logon, and block the IP.

### 2. [Medium] Password spraying from `198.51.100.23`

- **What happened:** Failed logons against 9 different accounts.
- **When:** 2026-08-14 02:32:13 UTC to 2026-08-14 03:03:40 UTC
- **Devices:** win-vm-honeypot-02
- **Accounts:** admin, administrator, backup, guest, scanner, sql, support, test, user
- **MITRE ATT&CK:** T1110.003 Password Spraying
- **Recommended response:** Block the IP, confirm MFA and lockout policy cover the targeted accounts, and check whether the targeted usernames are real.

### 3. [Medium] Brute force from `192.0.2.77`

- **What happened:** Peak of 18 failed logons within 5 min.
- **When:** 2026-08-14 03:06:50 UTC to 2026-08-14 03:09:10 UTC
- **Devices:** linux-vm-honeypot-01
- **Accounts:** root
- **MITRE ATT&CK:** T1110.001 Password Guessing
- **Recommended response:** Block the IP at the NSG/firewall, and reduce exposure: remove public RDP/SSH or restrict it to known source ranges.
