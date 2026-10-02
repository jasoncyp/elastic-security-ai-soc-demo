# Detection Rules

Nine custom ES|QL detection rules that cover the attack story end to end, across all
three log sources (Palo Alto PAN-OS, Windows Security/Sysmon, Linux).

They are the **baseline coverage** for the demo. Deliberately, they do *not* cover
everything in the data. The Quiet Insider's DNS lookups to personal cloud storage, the
sensitive file-share browsing, off-hours VPN, and the Linux server compromise are left
uncovered, so the AI threat-hunting step has real gaps to find and close. See
[Step 9 in the README](../README.md#9-ai-soc-walkthrough).

## How to create them

**Option A: Kibana UI (about 1 minute per rule)**

1. **Security → Rules → Detection rules (SIEM) → Create new rule**.
2. Choose **ES|QL** as the rule type and paste the query.
3. Set the name, severity, risk score, schedule (**Runs every** / **Additional look-back
   time**) from the table below, and save it **enabled**.

**Option B: let the AI agent do it.** On the Detection rules page, choose
**Create a rule → AI rule creation**. Paste the query and ask the agent to fill in the
name, severity, risk score, MITRE mapping and investigation guide, then click
**Apply to creation**. This is a good warm-up for Step 9.4 of the walkthrough.

## ⚠ Backfill: the rules must run over the past, not just "now"

The demo data spans the **last 14 days**, but a scheduled rule only looks at its own
look-back window, e.g. the last 6 minutes. Enabled on their own, rules 1, 3, 4, 6 and 7
will see almost none of the attack, so you get almost no alerts — and Attack Discovery
then has nothing to analyse.

After creating the rules, **run each one manually over the last 14 days**:

1. **Security → Rules → Detection rules (SIEM)**, then select the nine `[Demo]` rules.
2. **Bulk actions → Manual run** (or open a rule → ⋯ → **Manual run**).
3. Pick a time range that starts **15 days ago** and ends **now**, then confirm.

Manual runs can cover up to 90 days in the past. Progress shows on each rule's
**Execution results** tab, and alerts appear on **Security → Alerts** within a few
minutes.

Every query filters on `tags == "elastic-security-demo-data"`, so the rules only fire
on data from this project, never on your real telemetry or on the simulator's
`elastic-security-sample-data` events.

---

Rule numbers follow the original 19-rule reference set, which is why they skip.

| # | Rule | Severity | Risk | Interval | Lookback | Source |
|---|---|---|---|---|---|---|
| 1 | VPN Brute-Force Followed by Successful Auth | Critical | 91 | 5m | now-10m | PA PAN-OS |
| 3 | Explicit Credential Logon to Domain Controller | High | 73 | 5m | now-6m | Windows Security |
| 4 | Suspicious User Account Created | High | 73 | 5m | now-6m | Windows Security |
| 6 | Encoded PowerShell Execution | Critical | 91 | 5m | now-6m | Windows Security + Sysmon |
| 7 | Scheduled Task Created for Persistence | High | 73 | 5m | now-6m | Windows Security |
| 9 | Periodic C2 Beaconing Detected | Critical | 91 | 4h | now-25h | Windows Sysmon |
| 10 | Large Volume Data Exfiltration to External Host | Critical | 99 | 4h | now-25h | PA PAN-OS |
| 14 | Insider Data Upload to Personal Cloud Storage | High | 73 | 12h | now-14d | PA PAN-OS |
| 16 | Impossible Travel — VPN Login from Multiple Countries | High | 73 | 4h | now-25h | PA PAN-OS |

Scenario context: attacker IP `45.155.205.233`, compromised user `rjohnson`,
C2 `91.234.56.78`, exfil destination `218.92.0.190`, insider `kpatel`.

---

### Rule 1 — [Demo] VPN Brute-Force Followed by Successful Auth · CRITICAL · Risk 91

Detects 10+ firewall authentication failures concentrated within a 5-minute burst from a
single source IP, followed by a successful authentication — a rapid credential spray that
gained valid credentials. Per-aggregation `WHERE` filters with `MIN`/`MAX` timestamps
enforce temporal ordering (failures **before** success) and burst concentration.

```esql
FROM logs-panw.panos-default
| WHERE tags == "elastic-security-demo-data"
  AND event.action == "firewall-authentication"
| STATS
    failures      = COUNT(*) WHERE event.outcome == "failure",
    successes     = COUNT(*) WHERE event.outcome == "success",
    first_failure = MIN(@timestamp) WHERE event.outcome == "failure",
    last_failure  = MAX(@timestamp) WHERE event.outcome == "failure",
    first_success = MIN(@timestamp) WHERE event.outcome == "success",
    users         = VALUES(user.name)
  BY source.ip
| WHERE failures >= 10
  AND successes >= 1
  AND first_success > last_failure
  AND DATE_DIFF("minute", first_failure, last_failure) <= 5
| SORT failures DESC
```

**Investigation guide**

1. Check `source.ip` geo-location — Tor exit node or known malicious ASN?
2. Check the targeted `users` — verify with HR that these are legitimate accounts.
3. The rule confirms both failures **and** successes — the attacker got in.
4. Check PA GlobalProtect logs for a VPN tunnel established from that IP.
5. Cross-reference the timeline: attacker IP `45.155.205.233` targets `rjohnson`.

---

### Rule 3 — [Demo] Explicit Credential Logon to Domain Controller · HIGH · Risk 73

Detects Event ID 4648 (logon using explicit credentials) targeting a Domain Controller —
credential theft techniques such as `runas`, pass-the-hash, or pass-the-ticket being used
for lateral movement.

```esql
FROM logs-windows.security-default METADATA _id, _version, _index
| WHERE tags == "elastic-security-demo-data"
  AND winlog.event_id == "4648"
  AND host.name IN ("SRV-DC01", "SRV-DC02")
| KEEP _id, _version, _index, @timestamp, user.name, host.name, message
```

**Investigation guide**

1. Compare `SubjectUserName` vs `TargetUserName` in the message — are they different?
2. A standard user targeting a privileged account is highly suspicious.
3. Check the source IP — does it match the user's normal workstation?
4. Look for subsequent 4672 (special privileges assigned) events for the target user.

---

### Rule 4 — [Demo] Suspicious User Account Created · HIGH · Risk 73

Detects new user account creation (Event ID 4720) — an attacker establishing persistence
via a backdoor account. Particularly suspicious when the creator is not a known admin.

```esql
FROM logs-windows.security-default METADATA _id, _version, _index
| WHERE tags == "elastic-security-demo-data"
  AND winlog.event_id == "4720"
| KEEP _id, _version, _index, @timestamp, user.name, host.name, message
```

**Investigation guide**

1. Check `SubjectUserName` (creator) — is this an authorized admin?
2. Check `TargetUserName` (new account) — does it follow naming conventions?
3. Accounts named `svc_*` created outside change windows are suspicious.
4. Cross-reference with HR — was a new employee expected?

---

### Rule 6 — [Demo] Encoded PowerShell Execution · CRITICAL · Risk 91

Detects PowerShell execution with encoded command arguments (`-enc`, `-EncodedCommand`,
`-e`, `-ec`) — a defense-evasion technique that base64-encodes malicious scripts to bypass
command-line logging and signature detection.

```esql
FROM logs-windows.security-default, logs-windows.sysmon_operational-default METADATA _id, _version, _index
| WHERE tags == "elastic-security-demo-data"
  AND message LIKE "%powershell%"
  AND (message LIKE "%-enc %" OR message LIKE "%-EncodedCommand %" OR message LIKE "%-e %" OR message LIKE "%-ec %")
| KEEP _id, _version, _index, @timestamp, user.name, host.name, message, process.name, process.command_line
```

**Investigation guide**

1. Decode the base64 payload: `echo '<encoded>' | base64 -d`
2. Look for download cradles in the decoded command (`IEX`, `Net.WebClient`, `Invoke-Expression`).
3. Identify the parent process — `mshta.exe` spawning PowerShell is highly suspicious.
4. Check whether the user normally runs PowerShell scripts.

---

### Rule 7 — [Demo] Scheduled Task Created for Persistence · HIGH · Risk 73

Detects creation of Windows scheduled tasks (Event ID 4698) used to maintain persistence,
especially when the task executes binaries from user-writable directories.

```esql
FROM logs-windows.security-default METADATA _id, _version, _index
| WHERE tags == "elastic-security-demo-data"
  AND winlog.event_id == "4698"
| KEEP _id, _version, _index, @timestamp, user.name, host.name, message
```

**Investigation guide**

1. Examine `TaskContent` in the message — what binary does the task execute?
2. Binaries in `C:\Users\Public` or `C:\Temp` are highly suspicious.
3. A task running as SYSTEM indicates privilege-escalation intent.
4. Look for a corresponding Sysmon Event 11 (file creation) of that binary.
5. Cross-reference the user against the investigation timeline.

---

### Rule 9 — [Demo] Periodic C2 Beaconing Detected · CRITICAL · Risk 91

Detects periodic outbound connections from a single process to an external IP spanning at
least 2 hours across 3+ distinct hours. `beacons_per_hour` highlights regularity — true
beacons are consistent, normal browsing is bursty.

```esql
FROM logs-windows.sysmon_operational-default
| WHERE tags == "elastic-security-demo-data"
  AND winlog.event_id == "3"
  AND NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| STATS beacon_count = COUNT(*),
        unique_hours = COUNT_DISTINCT(DATE_EXTRACT("HOUR", @timestamp)),
        first_seen = MIN(@timestamp),
        last_seen = MAX(@timestamp)
  BY host.name, destination.ip, process.executable
| WHERE beacon_count >= 10
  AND unique_hours >= 3
  AND DATE_DIFF("hour", first_seen, last_seen) >= 2
| EVAL beacons_per_hour = beacon_count / DATE_DIFF("hour", first_seen, last_seen)
| SORT beacons_per_hour DESC
```

**Investigation guide**

1. Check `destination.ip` — `91.234.56.78` is the scenario C2.
2. Check `process.executable` — `update.exe` from `C:\Users\Public` is the implant.
3. Average interval between connections — consistent ~30-minute gaps indicate beaconing.
4. Look for PA firewall threat logs flagging the destination.
5. Check SSL/TLS certificate details for the destination.

---

### Rule 10 — [Demo] Large Volume Data Exfiltration to External Host · CRITICAL · Risk 99

Detects aggregate transfers over 50 MB to a single external IP, enriched with transfer
window duration and average bytes per session to separate bulk exfiltration (short window,
large sessions) from normal business traffic.

```esql
FROM logs-panw.panos-default
| WHERE tags == "elastic-security-demo-data"
  AND event.action == "allow"
  AND NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
  AND source.bytes > 1000000
| STATS total_bytes = SUM(source.bytes),
        sessions = COUNT(*),
        first_transfer = MIN(@timestamp),
        last_transfer = MAX(@timestamp),
        users = VALUES(user.name)
  BY source.ip, destination.ip
| WHERE total_bytes > 50000000
| EVAL transfer_window_min = DATE_DIFF("minute", first_transfer, last_transfer),
       avg_bytes_per_session = total_bytes / sessions
| SORT total_bytes DESC
```

**Investigation guide**

1. Identify the user via PA User-ID mapping for the source IP.
2. Check destination geo — transfers to `218.92.0.190` (China) are part of the attack.
3. Is the destination a known file-sharing or sanctioned business cloud service?
4. Look for data staging (file creation events) preceding the transfer.
5. Hundreds of MB in a short period is abnormal for most users.

> **Optional — pair with ML:** a custom multi-metric anomaly detection job (for example `Outbound_traffic_anomaly`, high `sum(source.bytes)` partitioned by `user.name`) learns each user's own
> baseline for outbound bytes, catching low-and-slow exfiltration that never crosses the
> static 50 MB threshold. Run both — Rule 10 for explainable high-confidence alerts, the
> ML job as a behavioural safety net.

---

### Rule 14 — [Demo] Insider Data Upload to Personal Cloud Storage · HIGH · Risk 73

Detects outbound transfers from VPN-connected users to known personal cloud storage IPs
(mega.nz, pcloud.com). Even small volumes matter when combined with off-hours access and
sensitive file share browsing — the hallmark of low-and-slow insider exfiltration.

```esql
FROM logs-panw.panos-default
| WHERE tags == "elastic-security-demo-data"
  AND event.action == "allow"
  AND destination.port == 443
  AND (
    CIDR_MATCH(destination.ip, "66.203.125.0/24")
    OR CIDR_MATCH(destination.ip, "74.120.8.0/24")
  )
  AND source.bytes > 500000
| STATS total_uploaded = SUM(source.bytes),
        sessions = COUNT(*),
        unique_days = COUNT_DISTINCT(DATE_EXTRACT("DAY_OF_YEAR", @timestamp))
  BY user.name, source.ip
| WHERE sessions >= 3
| SORT total_uploaded DESC
```

**Investigation guide**

1. Map `source.ip` back to a user via PA User-ID or GlobalProtect session logs.
2. Check the acceptable-use policy. In this scenario, mega.nz and pcloud.com are prohibited for corporate data.
3. Total the volume across sessions — 2–15 MB × 7 sessions adds up.
4. Correlate with file share access — what was the user reading beforehand?
5. Check whether the user has resigned or is on a performance improvement plan.

---

### Rule 16 — [Demo] Impossible Travel — VPN Login from Multiple Countries · HIGH · Risk 73

Detects a single user logging into VPN from 2+ distinct source IPs (geolocations) within a
12-hour window — credential sharing or physically impossible travel.
`time_between_logins_hr` helps analysts judge geographic plausibility.

```esql
FROM logs-panw.panos-default
| WHERE tags == "elastic-security-demo-data"
  AND event.action == "globalprotect-login"
| STATS locations = COUNT_DISTINCT(source.ip),
        countries = VALUES(source.geo.country_iso_code),
        sessions = COUNT(*),
        first_login = MIN(@timestamp),
        last_login = MAX(@timestamp)
  BY user.name
| WHERE locations >= 2
| EVAL time_between_logins_hr = DATE_DIFF("hour", first_login, last_login)
| WHERE time_between_logins_hr <= 12
| SORT time_between_logins_hr ASC
```

**Investigation guide**

1. Check the geo-locations — San Francisco to Seoul in 2 hours is impossible.
2. Check GlobalProtect device details — different hostname/OS means different devices.
3. Verify with the user whether they shared VPN credentials.
4. Look for abnormal activity during the foreign session (data access, uploads).
5. May indicate credential theft or deliberate credential sharing.
