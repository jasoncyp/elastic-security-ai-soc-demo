# Shared Entity Model

Both data sets now describe **one organisation and one attack story**.

Before alignment they described two unrelated companies — 0 of 15 host names shared,
0 IPs shared, and only 3 coincidental user names (`admin`, `root`, `svc_backup`).
A pivot from a simulator alert into the demo firewall logs found nothing, so the two
halves of the demo could not be narrated as one incident.

The **demo walkthrough logs (`demo-logs/`) are the anchor**; the Elastic sample-data
simulator (`simulator/`) was moved onto their entity model. That direction keeps every
ES|QL detection rule in [DETECTION_RULES.md](DETECTION_RULES.md) working untouched.

---

## 1. The organisation

**Network topology**

| Segment | Range | Notes |
|---|---|---|
| Corporate LAN | `10.1.10.x`, `10.1.20.x`, `10.1.30.x` | Workstations and core servers |
| Secondary site | `10.2.10.x` | Linux application servers |
| GlobalProtect VPN pool | `10.5.0.x` | `10.5.0.99` attacker, `10.5.0.42` insider |
| DMZ | `10.100.1.x` | Demo logs only |
| Perimeter NAT | `203.0.113.1` | PA-3260-01 outbound NAT address |

**Hosts**

| Host | Role | Simulator | Demo logs |
|---|---|:--:|:--:|
| `SRV-DC01` | Domain controller | ✓ | ✓ |
| `SRV-FILE01` | File server | ✓ | ✓ |
| `SRV-WEB01` | Web server | ✓ | ✓ |
| `SRV-DB01` | Database server | ✓ | ✓ |
| `WS-PC001` … `WS-PC003` | Workstations | ✓ | ✓ |
| `WS-PC004` … `WS-PC007` | Workstations | — | ✓ |
| `SRV-LINUX01` | Linux server (target of chapter 13) | — | ✓ |
| `SRV-APP01` | Application server | — | ✓ |
| `SRV-MAIL01` | Mail server | — | ✓ |
| `PA-3260-01` | Palo Alto firewall (`observer.hostname`) | — | ✓ |

**Identities**

| User | Role in the story | Simulator | Demo logs |
|---|---|:--:|:--:|
| `rjohnson` | Compromised contractor — the way in | ✓ | ✓ |
| `admin.ops` | Privilege-escalation target | ✓ | ✓ |
| `kpatel` | The Quiet Insider | ✓ | ✓ |
| `jsmith`, `mwilson`, `alee`, `dgarcia` | Background noise | ✓ | ✓ |
| `tchen`, `bkim`, `lnguyen`, `svc_monitoring` | Background noise | — | ✓ |
| `svc_backup` | Service account, brute-force target | ✓ | ✓ |
| `root`, `admin`, `Administrator` | Built-in accounts | ✓ | ✓ (`administrator`) |

**External infrastructure**

| IP | Role | Geo | Simulator | Demo logs |
|---|---|---|:--:|:--:|
| `45.155.205.233` | Attacker source | Bucharest, RO | ✓ | ✓ |
| `10.5.0.99` | Attacker's VPN-assigned IP | — | ✓ | ✓ |
| `91.234.56.78` | C2 server | Moscow, RU | ✓ | ✓ |
| `218.92.0.190` | Exfiltration destination | Jiangsu, CN | — | ✓ |
| `66.203.125.12` / `74.120.8.90` | mega.nz / pcloud.com | — | — | ✓ |
| `185.220.101.35` | Tor exit node | Frankfurt, DE | — | ✓ |

---

## 2. The story, and which data set tells each chapter

| # | Chapter | Data set | Entities | Detects as |
|---|---|---|---|---|
| 1 | Okta account takeover — MFA fatigue, then session hijack | Simulator | `rjohnson` ← `45.155.205.233` | Synthetic alert |
| 2 | VPN credential spray, then successful auth | Demo logs | `rjohnson` ← `45.155.205.233`, VPN `10.5.0.99` | **Rule 1** |
| 3 | Internal reconnaissance from the VPN foothold | Demo logs | `rjohnson` on `WS-PC00x` | 🔍 Hunt target |
| 4 | Lateral movement to the domain controller | Both | `rjohnson` → `SRV-DC01` from `10.5.0.99` | **Rule 3** + synthetic alerts |
| 5 | Credential dumping on the DC (procdump / reg save SAM) | Simulator | `rjohnson` on `SRV-DC01` | Synthetic alerts |
| 6 | Persistence — backdoor account, scheduled task, run key | Demo logs | `SRV-DC01`, `WS-PC00x` | **Rules 4, 7** · run key = 🔍 hunt target |
| 7 | Encoded PowerShell + LOLBin execution | Demo logs | `WS-PC00x` | **Rule 6** · certutil / mshta = 🔍 hunt target |
| 8 | Cloud privilege escalation | Simulator | `admin.ops` ← `45.155.205.233` | Synthetic alert |
| 9 | C2 beaconing every ~30 min | Both | `→ 91.234.56.78` | **Rule 9** |
| 10 | Bulk data exfiltration | Demo logs | `→ 218.92.0.190` | **Rule 10** |
| 11 | Ransomware on the file server | Simulator | `admin.ops` on `SRV-FILE01`, C2 `91.234.56.78` | Synthetic alerts |
| 12 | The Quiet Insider — off-hours VPN, finance/HR share browsing, DNS to mega.nz / pcloud.com, uploads, impossible travel | Demo logs | `kpatel`, VPN `10.5.0.42` | **Rules 14, 16** · off-hours VPN, share access, cloud DNS = 🔍 hunt targets |
| 13 | Linux server compromise — recon, `chmod +s`, cron persistence, MySQL file dump, `tar` staging, `curl` exfil, `history -c` | Demo logs | `rjohnson` on `SRV-LINUX01` from `10.5.0.99` | 🔍 Hunt target (no baseline rule) |

**Rule N** = covered by the nine baseline rules in [DETECTION_RULES.md](DETECTION_RULES.md).
🔍 **Hunt target** = present in the data but deliberately left without a rule, so the AI
threat-hunting step (README, Step 9) has something real to discover and close.

Chapters 4, 9 and 11 are the join points — the same host, user, or C2 address appears
in both data sets, so a pivot from a simulator alert lands in real firewall and Sysmon
evidence, and vice versa.

**Suggested demo pivot:** open the Okta takeover alert (chapter 1) → note `rjohnson` →
pivot to Discover on `logs-panw.panos-default` filtered by `user.name: rjohnson` →
Rule 1's brute-force burst is right there → pivot to `SRV-DC01` → Rule 3 fires on the
same host the simulator's credential-dumping alerts point at.

---

## 3. What changed, exactly

Only `simulator/sample-data.js` was edited, and only **literal identity values** —
no function, branch, loop, or output field was touched. Apart from a modification
notice added to the file header, every changed line is a `const` assignment or a
string literal.

To review every change, compare against the upstream file in
[elastic/agent-skills](https://github.com/elastic/agent-skills)
— the `security-generate-security-sample-data` skill's `scripts/sample-data.js`:

```bash
diff <agent-skills checkout>/<skill folder>/scripts/sample-data.js simulator/sample-data.js
```

### Mapping table

| Line | Was | Now | Why |
|---|---|---|---|
| 23 | `FAKE_USERS = ["alice","bob","charlie","dave","eve","frank"]` | `["jsmith","mwilson","rjohnson","alee","kpatel","dgarcia"]` | Corporate directory |
| 24 | `FAKE_HOSTS = ["web-prod-01","db-prod-02",…]` | `["WS-PC001","WS-PC002","WS-PC003","SRV-WEB01","SRV-DB01"]` | AD naming convention |
| 25 | `FAKE_IPS = ["192.0.2.10",…]` | `["10.1.10.11","10.1.10.25","10.1.20.15","10.1.20.42","10.1.30.7","10.2.10.19"]` | Corporate subnets |
| 125 | brute-force target `"test"` | `"svc_backup"` | Real service account |
| 188 | `"10.0.0." + randomInt(1,254)` | `"10.1.10." + randomInt(1,254)` | Corporate LAN |
| 506–508 | `198.51.100.77` / `db-prod-02` / `svc_backup` | `10.5.0.99` / `SRV-DC01` / `rjohnson` | Ch. 4–5: lateral movement to the DC over VPN |
| 637, 639 | `203.0.113.99` / `compromised-dev` | `45.155.205.233` / `admin.ops` | Ch. 8: cloud escalation |
| 787–788 | `198.51.100.88` / `charlie` | `45.155.205.233` / `rjohnson` | Ch. 1: initial identity compromise |
| 910–914 | `app-staging-03` / `dave` / `203.0.113.42` | `SRV-FILE01` / `admin.ops` / `91.234.56.78` | Ch. 11: ransomware, same C2 |
| 989 | `"10.0.0.50"` | `"10.1.10.50"` | Corporate LAN |
| 1373–1375, 1528–1529, 1653–1654, 1763–1766, 1826–1828 | as above | as above | Alert documents mirroring each scenario |

---

## 4. Verified

Measured by generating both data sets and comparing the resulting documents:

| Field | Shared before | Shared after |
|---|---|---|
| `host.name` | 0 % | **100 %** (7/7) |
| `user.name` | 25 % | **91 %** (10/11) |
| `source.ip` | 0 % | **92 %** (23/25) |

The remaining unshared values are intentional, not drift:

- `Administrator` — Windows built-in account used in failed-logon noise. The demo set
  spells it `administrator` (lowercase, from Linux logs); both are realistic.
- A handful of `10.1.10.x` / `10.1.30.x` / `10.2.10.x` addresses — random host octets
  inside the *correct* subnets. Real networks have unused addresses; the topology matches,
  which is what a pivot depends on.

**Tag isolation is intact.** Simulator documents carry `elastic-security-sample-data`,
demo documents carry `elastic-security-demo-data`, with zero overlap. Every one of the
19 ES|QL rules filters on `tags == "elastic-security-demo-data"`, so aligning the entity
names does **not** cause simulator events to fire the demo rules. Cleanup still removes
each set independently.

---

## 5. Caveat — real routable IPs

`45.155.205.233`, `91.234.56.78` and `218.92.0.190` are real, routable addresses (this
was already true of the demo logs; the simulator has now adopted them for narrative
continuity, replacing its RFC 5737 documentation ranges).

Nothing connects to them — they only appear as field values — but be deliberate about
which clusters receive this data, and never ingest it into a production SIEM where it
could be mistaken for live telemetry or picked up by threat-intel enrichment.
