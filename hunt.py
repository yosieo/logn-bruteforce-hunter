#!/usr/bin/env python3
"""
Brute-force & password-spray hunter for Microsoft Defender for Endpoint logon events.

Reads a CSV export of DeviceLogonEvents (from the KQL query in kql/), then flags:
  1. Brute force        - many failed logons from one remote IP in a short window
                          (MITRE ATT&CK T1110.001 Password Guessing)
  2. Password spraying  - one remote IP failing against many different accounts
                          (MITRE ATT&CK T1110.003 Password Spraying)
  3. Possible compromise - a SUCCESSFUL logon from an IP that was brute-forcing
                          (MITRE ATT&CK T1078 Valid Accounts) -> highest priority

Outputs a console summary, a Markdown incident report and a CSV of findings.
Standard library only, so it runs anywhere Python 3.10+ is installed.

Usage:
    python hunt.py sample_data/DeviceLogonEvents_sample.csv
    python hunt.py export.csv --threshold 10 --window 5 --spray-accounts 5 --out reports/
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Column names as they appear in a Defender / Sentinel CSV export.
COL_TIME = "Timestamp"
COL_DEVICE = "DeviceName"
COL_ACTION = "ActionType"
COL_ACCOUNT = "AccountName"
COL_IP = "RemoteIP"
REQUIRED_COLUMNS = {COL_TIME, COL_DEVICE, COL_ACTION, COL_ACCOUNT, COL_IP}

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}

# Timestamp formats seen in Defender portal and Sentinel exports.
TIME_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y, %I:%M:%S.%f %p",
    "%m/%d/%Y, %I:%M:%S %p",
)


@dataclass
class LogonEvent:
    time: datetime
    device: str
    action: str  # "LogonSuccess" or "LogonFailed"
    account: str
    remote_ip: str


@dataclass
class Finding:
    severity: str
    detection: str
    mitre: str
    remote_ip: str
    devices: set[str] = field(default_factory=set)
    accounts: set[str] = field(default_factory=set)
    failed_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    detail: str = ""
    recommendation: str = ""


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def parse_time(value: str) -> datetime:
    value = value.strip()
    try:
        # Handles ISO 8601 incl. "Z" suffix on Python 3.11+.
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in TIME_FORMATS:
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise ValueError(f"Unrecognised timestamp format: {value!r}")


def load_events(path: Path) -> tuple[list[LogonEvent], int]:
    """Return parsed events and the number of rows skipped as unusable."""
    events: list[LogonEvent] = []
    skipped = 0
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
        if missing:
            raise ValueError(
                f"CSV is missing required columns: {', '.join(sorted(missing))}. "
                "Use the query in kql/export_logon_events.kql to export."
            )
        for row in reader:
            ip = (row[COL_IP] or "").strip()
            action = (row[COL_ACTION] or "").strip()
            # Local / console logons have no remote IP and are out of scope.
            if not ip or ip in {"-", "::1", "127.0.0.1"} or action not in {"LogonSuccess", "LogonFailed"}:
                skipped += 1
                continue
            try:
                when = parse_time(row[COL_TIME])
            except ValueError:
                skipped += 1
                continue
            events.append(
                LogonEvent(
                    time=when,
                    device=(row[COL_DEVICE] or "").strip(),
                    action=action,
                    account=(row[COL_ACCOUNT] or "").strip().lower(),
                    remote_ip=ip,
                )
            )
    events.sort(key=lambda e: e.time)
    return events, skipped


# --------------------------------------------------------------------------- #
# Detection logic
# --------------------------------------------------------------------------- #
def peak_failures_in_window(times: list[datetime], window: timedelta) -> tuple[int, datetime, datetime]:
    """Sliding window: the largest number of failures inside any `window`-long period."""
    best, best_start, best_end = 0, times[0], times[0]
    left = 0
    for right, current in enumerate(times):
        while current - times[left] > window:
            left += 1
        count = right - left + 1
        if count > best:
            best, best_start, best_end = count, times[left], current
    return best, best_start, best_end


def hunt(
    events: list[LogonEvent],
    threshold: int = 10,
    window_minutes: int = 5,
    spray_accounts: int = 5,
) -> list[Finding]:
    window = timedelta(minutes=window_minutes)
    failures_by_ip: dict[str, list[LogonEvent]] = defaultdict(list)
    successes_by_ip: dict[str, list[LogonEvent]] = defaultdict(list)
    for event in events:
        target = failures_by_ip if event.action == "LogonFailed" else successes_by_ip
        target[event.remote_ip].append(event)

    findings: list[Finding] = []
    for ip, failures in failures_by_ip.items():
        times = [f.time for f in failures]
        peak, start, end = peak_failures_in_window(times, window)
        accounts = {f.account for f in failures}
        devices = {f.device for f in failures}
        is_bruteforce = peak >= threshold
        is_spray = len(accounts) >= spray_accounts
        if not (is_bruteforce or is_spray):
            continue

        # Any successful logon from the same IP after its first failure?
        later_successes = [s for s in successes_by_ip.get(ip, []) if s.time >= failures[0].time]

        if later_successes:
            hit = later_successes[0]
            findings.append(
                Finding(
                    severity="High",
                    detection="Possible compromise: success after brute force",
                    mitre="T1110 -> T1078 Valid Accounts",
                    remote_ip=ip,
                    devices=devices | {s.device for s in later_successes},
                    accounts={s.account for s in later_successes},
                    failed_count=len(failures),
                    first_seen=failures[0].time,
                    last_seen=hit.time,
                    detail=(
                        f"{len(failures)} failed logons, then a successful logon as "
                        f"'{hit.account}' on {hit.device} at {fmt(hit.time)}."
                    ),
                    recommendation=(
                        "Treat as a live incident: isolate the device in Defender, reset the "
                        "account's password and revoke sessions, review activity after the "
                        "successful logon, and block the IP."
                    ),
                )
            )
        elif is_spray:
            findings.append(
                Finding(
                    severity="Medium",
                    detection="Password spraying",
                    mitre="T1110.003 Password Spraying",
                    remote_ip=ip,
                    devices=devices,
                    accounts=accounts,
                    failed_count=len(failures),
                    first_seen=failures[0].time,
                    last_seen=failures[-1].time,
                    detail=f"Failed logons against {len(accounts)} different accounts.",
                    recommendation=(
                        "Block the IP, confirm MFA and lockout policy cover the targeted "
                        "accounts, and check whether the targeted usernames are real."
                    ),
                )
            )
        else:
            findings.append(
                Finding(
                    severity="Medium",
                    detection="Brute force",
                    mitre="T1110.001 Password Guessing",
                    remote_ip=ip,
                    devices=devices,
                    accounts=accounts,
                    failed_count=len(failures),
                    first_seen=start,
                    last_seen=end,
                    detail=f"Peak of {peak} failed logons within {window_minutes} min.",
                    recommendation=(
                        "Block the IP at the NSG/firewall, and reduce exposure: remove public "
                        "RDP/SSH or restrict it to known source ranges."
                    ),
                )
            )

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], -f.failed_count))
    return findings


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def fmt(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S UTC") if value else "-"


def write_csv(findings: list[Finding], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["severity", "detection", "mitre", "remote_ip", "failed_count",
             "accounts", "devices", "first_seen", "last_seen", "detail"]
        )
        for f in findings:
            writer.writerow(
                [f.severity, f.detection, f.mitre, f.remote_ip, f.failed_count,
                 ";".join(sorted(f.accounts)), ";".join(sorted(f.devices)),
                 fmt(f.first_seen), fmt(f.last_seen), f.detail]
            )


def write_markdown(findings: list[Finding], events: list[LogonEvent], source: Path,
                   args: argparse.Namespace, path: Path) -> None:
    high = sum(f.severity == "High" for f in findings)
    medium = sum(f.severity == "Medium" for f in findings)
    failed = sum(e.action == "LogonFailed" for e in events)
    lines = [
        "# Logon Threat Hunt Report",
        "",
        f"- **Source:** `{source.name}`",
        f"- **Events analysed:** {len(events)} ({failed} failed logons)",
        f"- **Period:** {fmt(events[0].time) if events else '-'} to {fmt(events[-1].time) if events else '-'}",
        f"- **Rules:** brute force >= {args.threshold} failures in {args.window} min; "
        f"spraying >= {args.spray_accounts} accounts per IP",
        "",
        "## Summary",
        "",
        f"{len(findings)} suspicious source IPs: **{high} High**, {medium} Medium.",
        "",
    ]
    if high:
        lines += [
            "> **Action needed:** at least one IP logged in successfully after repeated "
            "failures. Handle the High findings first.",
            "",
        ]
    lines += [
        "| Severity | Detection | Remote IP | Failed | Accounts | MITRE ATT&CK |",
        "|---|---|---|---|---|---|",
    ]
    for f in findings:
        lines.append(
            f"| {f.severity} | {f.detection} | `{f.remote_ip}` | {f.failed_count} | "
            f"{len(f.accounts)} | {f.mitre} |"
        )
    lines += ["", "## Findings", ""]
    for number, f in enumerate(findings, start=1):
        lines += [
            f"### {number}. [{f.severity}] {f.detection} from `{f.remote_ip}`",
            "",
            f"- **What happened:** {f.detail}",
            f"- **When:** {fmt(f.first_seen)} to {fmt(f.last_seen)}",
            f"- **Devices:** {', '.join(sorted(f.devices))}",
            f"- **Accounts:** {', '.join(sorted(f.accounts))}",
            f"- **MITRE ATT&CK:** {f.mitre}",
            f"- **Recommended response:** {f.recommendation}",
            "",
        ]
    if not findings:
        lines.append("No activity met the detection thresholds.")
    path.write_text("\n".join(lines), encoding="utf-8")


def print_summary(findings: list[Finding], events: list[LogonEvent], skipped: int) -> None:
    print(f"Analysed {len(events)} remote logon events ({skipped} rows skipped).")
    if not findings:
        print("No suspicious activity found.")
        return
    print(f"\n{'SEV':<7}{'DETECTION':<48}{'REMOTE IP':<17}{'FAILED':>7}")
    print("-" * 79)
    for f in findings:
        print(f"{f.severity:<7}{f.detection:<48}{f.remote_ip:<17}{f.failed_count:>7}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Hunt for brute force and password spraying in Defender logon events.")
    parser.add_argument("csv_file", type=Path, help="CSV export of DeviceLogonEvents")
    parser.add_argument("--threshold", type=int, default=10, help="failed logons in the window that count as brute force (default 10)")
    parser.add_argument("--window", type=int, default=5, help="sliding window in minutes (default 5)")
    parser.add_argument("--spray-accounts", type=int, default=5, help="distinct accounts per IP that count as spraying (default 5)")
    parser.add_argument("--out", type=Path, default=Path("reports"), help="output folder (default reports/)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        events, skipped = load_events(args.csv_file)
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    findings = hunt(events, args.threshold, args.window, args.spray_accounts)
    print_summary(findings, events, skipped)

    args.out.mkdir(parents=True, exist_ok=True)
    report_md = args.out / "hunt_report.md"
    report_csv = args.out / "findings.csv"
    write_markdown(findings, events, args.csv_file, args, report_md)
    write_csv(findings, report_csv)
    print(f"\nReport:   {report_md}\nFindings: {report_csv}")

    # Non-zero exit when High findings exist, so the script can gate automation.
    return 1 if any(f.severity == "High" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
