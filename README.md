# Logon Brute-Force \& Password-Spray Hunter



A small Python tool that turns a Microsoft Defender for Endpoint logon export into a prioritized, developer- and manager-readable incident report.

Built from my SOC work during the LOG(N) Pacific cybersecurity internship, where I investigated alerts on internet-exposed Azure VMs with Microsoft Sentinel, Defender for Endpoint and KQL. This repo uses **synthetic sample data only**; no real logs, IPs or tenant details.





## What it detects

|Detection|Rule (default)|Severity|MITRE ATT\&CK|
|-|-|-|-|
|Brute force|≥ 10 failed logons from one IP within 5 minutes (sliding window)|Medium|T1110.001 Password Guessing|
|Password spraying|One IP failing against ≥ 5 different accounts|Medium|T1110.003 Password Spraying|
|**Possible compromise**|A **successful** logon from an IP that was brute-forcing or spraying|**High**|T1110 → T1078 Valid Accounts|



The High rule is the point: failed logons on an exposed VM are constant background noise. What an analyst actually needs to know is whether one of them *worked*.





## How it works

1. **Export** logon events with the KQL query in [`kql/export\\\_logon\\\_events.kql`](kql/export_logon_events.kql) (Defender Advanced Hunting or Sentinel), and save as CSV.
2. **Run** the hunter:

```bash
   python hunt.py sample\\\_data/DeviceLogonEvents\\\_sample.csv
   ```

3. **Read** the output:

   * `reports/hunt\\\_report.md`: incident report with what happened, when, affected accounts and devices, MITRE mapping and a recommended response
   * `reports/findings.csv`: one row per suspicious IP, for ticketing or a spreadsheet

The script exits with code `1` when a High finding exists, so it can gate a scheduled job or pipeline.





### Options

```bash
python hunt.py export.csv --threshold 10 --window 5 --spray-accounts 5 --out reports/
```





## Example output (sample data)

```
SEV    DETECTION                                       REMOTE IP         FAILED
-------------------------------------------------------------------------------
High   Possible compromise: success after brute force  203.0.113.45          34
Medium Password spraying                               198.51.100.23         18
Medium Brute force                                     192.0.2.77            18
```

See the [full sample report](reports_example/hunt_report.md).





## Design choices

* **Sliding window, not fixed time buckets:** a burst of failures that straddles two 5-minute buckets is still caught.
* **Spraying is checked separately from volume:** slow sprays stay under brute-force thresholds on purpose.
* **Local and console logons are skipped:** the focus is remote exposure.
* **Standard library only:** runs on any machine with Python 3.10+, no installs needed.





## Run the tests

```bash
python -m unittest discover -s tests -v
```





## Regenerate the sample data

```bash
python generate\\\_sample.py
```

All IPs come from the RFC 5737 documentation ranges, so none of them belong to real hosts.





## Ideas for next steps

* Enrich IPs with geolocation and threat-intel reputation
* Pull events directly from the Microsoft Graph Security / Log Analytics API instead of a CSV export
* Add an allow-list for known admin source IPs

