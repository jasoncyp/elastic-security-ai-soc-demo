# Elastic Security AI SOC Demo — Data Generator

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%E2%89%A522-339933.svg)](https://nodejs.org)
[![Elastic](https://img.shields.io/badge/Elastic%20Security-9.x%20%7C%20Serverless-005571.svg)](https://www.elastic.co/security)

Turn an empty Elastic Security cluster into a realistic SOC in about ten minutes. You get
14 days of firewall, Windows and Linux telemetry, a multi-stage intrusion, a hidden insider
threat, and synthetic alerts. Then you can show what **Elastic's AI SOC capabilities** do
with it: **Attack Discovery** and the **Elastic AI Agent**.

> ⚠ **Demo and lab clusters only.** Everything here is synthetic. Never ingest it into a
> production SIEM, where it would mix with real alerts. See [Disclaimer](#disclaimer).

---

## Contents

1. [Background — what this project does](#1-background--what-this-project-does)
2. [Prerequisites](#2-prerequisites)
3. [Get the code and install Node.js](#3-get-the-code-and-install-nodejs)
4. [Configure credentials](#4-configure-credentials)
5. [Prepare the cluster](#5-prepare-the-cluster)
6. [Generate and ingest the data](#6-generate-and-ingest-the-data)
7. [Verify the data landed](#7-verify-the-data-landed)
8. [Create the baseline detection rules](#8-create-the-baseline-detection-rules)
9. [AI SOC walkthrough](#9-ai-soc-walkthrough)
10. [Clean up](#10-clean-up)
11. [Troubleshooting](#11-troubleshooting)
12. [Project layout and advanced usage](#12-project-layout-and-advanced-usage)
13. [Credits, license and disclaimer](#13-credits-license-and-disclaimer)

---

## 1. Background — what this project does

### The problem

AI-driven SOC features are only as convincing as the data underneath them. Attack
Discovery needs alerts that actually relate to each other. An AI agent asked to "hunt for
hidden threats" needs a threat that is really hidden in realistic noise. A fresh POC or
demo cluster has neither, and real customer data is rarely available on day one.

### The solution — two data sources, one story

This project combines two generators and aligns them so they describe **one company and
one attack**:

| Source | What it adds | Where it lands |
|---|---|---|
| **Elastic security sample-data generator**<br>(from [elastic/agent-skills](https://github.com/elastic/agent-skills), `security-generate-security-sample-data`) | Generic ECS events across system, endpoint, Windows, Okta and AWS; four attack scenarios; about 19 **synthetic alerts** with MITRE ATT&CK mappings; and an investigation **case** | `logs-system.*`, `logs-endpoint.*`, `logs-okta.*`, `logs-aws.*`, `.alerts-security.alerts-*` |
| **Demo walkthrough logs** (this project) | ~8,600 **Palo Alto PAN-OS firewall**, **Windows Security / Sysmon** and **Linux auth** events: 14 days of background noise with three attack stories woven in | `logs-panw.panos-*`, `logs-windows.*`, `logs-system.auth-*` |

The sample-data generator gives you alerts, rules-ready events and identity/cloud
coverage out of the box. On their own, though, they are thin and generic. The PA,
Windows and Linux logs add network and host evidence underneath. So when you pivot from
an alert, you land in real-looking firewall sessions, Sysmon beacons and shell history,
not an empty search.

Both sources share the same host names, users, subnets and attacker infrastructure (see
[docs/ENTITY_MODEL.md](docs/ENTITY_MODEL.md)). An Okta alert for `rjohnson` therefore
leads straight to `rjohnson`'s VPN brute-force in the firewall logs, then to the domain
controller `SRV-DC01`, where the credential-dumping alerts sit.

### The story in the data

| Thread | Who / what | What happens |
|---|---|---|
| **Operation Silent Pivot** — external attacker | `rjohnson` (contractor) from `45.155.205.233` | Okta takeover → VPN credential spray → recon → lateral movement to `SRV-DC01` → credential dumping → persistence → C2 beaconing to `91.234.56.78` → exfiltration to `218.92.0.190` → ransomware on `SRV-FILE01` |
| **The Quiet Insider** — hidden | `kpatel` (engineer) on VPN `10.5.0.42` | Off-hours VPN sessions, browsing HR/Finance shares, DNS lookups to mega.nz / pcloud.com, small steady uploads, impossible travel (San Francisco → Seoul) |
| **Linux server compromise** — hidden | `rjohnson` on `SRV-LINUX01` | Recon, SUID change, cron persistence, MySQL file dump, staging, `curl` exfil, `history -c` cleanup |

The first thread is loud and produces alerts. The other two are **deliberately left
without detection rules**, so the AI threat-hunting step has something real to find.

### How it works

```
                       ┌──────────────┐
  credentials.txt ───▶ │   run.js     │  1. pick: Serverless | Cloud Hosted | Self-managed
                       │  (launcher)  │  2. test the Elasticsearch + Kibana connection
                       └──────┬───────┘  3. pick: simulator | demo logs | both | cleanup
              ┌───────────────┴────────────────┐
              ▼                                ▼
  simulator/demo-walkthrough.js     demo-logs/generate_all_demo_logs.cjs
   └ generates in memory and          └ writes fresh NDJSON (timestamps relative to now)
     bulk-indexes events, alerts,     demo-logs/ingest_all_demo_logs.cjs
     and a case via Kibana API          └ routes each doc to its data stream, bulk-indexes
              │                                │
              └──────────────┬─────────────────┘
                             ▼
                  Elasticsearch / Kibana  →  Detection rules  →  Alerts
                                          →  Attack Discovery →  Elastic AI Agent
```

---

## 2. Prerequisites

### Elastic

| Requirement | Details |
|---|---|
| **Deployment** | Elastic Cloud Serverless (**Security** project), Elastic Cloud Hosted, or self-managed |
| **Version** | **9.4+** or Serverless recommended. The walkthrough uses the Elastic AI Agent with skills, the 9.4 model. On 9.3 the same steps work with the opt-in Agent Builder experience and the *Threat Hunting Agent*. On 8.x, use the AI Assistant. |
| **Subscription** | Attack Discovery and the AI features need an **Enterprise** subscription (Cloud Hosted or self-managed) or the **Security Analytics Complete** / **Elastic AI SOC Engine (EASE)** tier on Serverless. A free trial works. |
| **LLM connector** | Any supported connector, or the Elastic Managed LLM where available. Pick a model rated well in the [LLM performance matrix](https://www.elastic.co/docs/solutions/security/ai/large-language-model-performance-matrix). |
| **API key** | Needs write access to `logs-*` and `.alerts-security.alerts-*`, plus Kibana access for the case. On a throwaway demo cluster, an API key that inherits the owner's privileges is simplest. |

### Your machine

| Tool | Version | Check |
|---|---|---|
| Node.js | **22 or newer** | `node --version` |
| npm | comes with Node | `npm --version` |
| git | any recent | `git --version` |

No Python and no Docker. The only npm dependency is the official `@elastic/elasticsearch`
client.

---

## 3. Get the code and install Node.js

### Option A — macOS Terminal

**3.1 Install Node.js 22 with nvm** (recommended — keeps this project's Node version
separate from anything else on your Mac, similar to a Python virtual environment):

```bash
brew install nvm
mkdir -p ~/.nvm
echo 'export NVM_DIR="$HOME/.nvm"' >> ~/.zshrc
echo '[ -s "$(brew --prefix nvm)/nvm.sh" ] && . "$(brew --prefix nvm)/nvm.sh"' >> ~/.zshrc
source ~/.zshrc

nvm install 22
nvm use 22
node --version            # → v22.x.x
```

No Homebrew? Install it from <https://brew.sh>, or download Node 22 LTS from
<https://nodejs.org>.

**3.2 Clone the repository and install the dependency:**

```bash
git clone https://github.com/YOUR-GITHUB-USER/elastic-security-ai-soc-demo.git
cd elastic-security-ai-soc-demo
npm install
```

`npm install` creates a project-local `node_modules/` folder. Nothing is installed
globally, and deleting the folder removes everything.

### Option B — VS Code

1. **Clone**: `Cmd+Shift+P` → **Git: Clone** → paste the repository URL → choose a folder
   → **Open**.
2. **Open the integrated terminal**: `` Ctrl+` ``. It starts in the project folder.
3. **Select Node 22**: run `nvm use 22` (or `node --version` to confirm the version).
4. **Install**: `npm install`.
5. **Optional — debug the launcher**: create `.vscode/launch.json`:

   ```json
   {
     "version": "0.2.0",
     "configurations": [
       {
         "type": "node",
         "request": "launch",
         "name": "Run AI SOC demo ingest",
         "program": "${workspaceFolder}/run.js",
         "console": "integratedTerminal"
       }
     ]
   }
   ```

   `integratedTerminal` matters: the launcher asks questions, so it needs a real terminal.

### Option C — Linux or Windows

Same steps. On Linux, install Node 22 with nvm or your package manager. On Windows, use the
Node 22 installer from nodejs.org, and use `copy` instead of `cp` in the next step.

---

## 4. Configure credentials

**Why a text file?** The launcher supports three deployment types, which each need
different settings. Keeping them in one sectioned file lets you switch targets from the
menu, with no environment variables to export and no `.env` to manage.

```bash
cp credentials.example.txt credentials.txt
```

Open `credentials.txt` and fill in **only the section for your deployment**.
`credentials.txt` is git-ignored, so your keys are never committed.

| Menu option | Section | What you need | Where to find it |
|---|---|---|---|
| **1** Serverless | `[serverless]` | `ELASTICSEARCH_URL`, `KIBANA_URL`, `ELASTICSEARCH_API_KEY` | Cloud console → your project → **Manage** → *Application endpoints* |
| **2** Cloud Hosted | `[cloud_hosted]` | `ELASTICSEARCH_CLOUD_ID`, `ELASTICSEARCH_API_KEY` | Deployment overview page (Cloud ID). Endpoints are decoded from it automatically. |
| **3** Self-managed | `[self_managed]` | `ELASTICSEARCH_URL`, `KIBANA_URL`, `ELASTICSEARCH_API_KEY`, and `CA_CERT` or `VERIFY_SSL` | Your cluster |

**Creating the API key:** Kibana → **Stack Management → API Keys → Create API key**.
Copy the **Encoded** value (a single base64 string).

> **Self-managed note:** the demo-log ingest step authenticates with an API key only.
> Username and password work for the simulator, but not for the PA/Windows/Linux logs.

Example (`[cloud_hosted]`):

```ini
[cloud_hosted]
ELASTICSEARCH_CLOUD_ID = my-demo:<long base64 string from the deployment page>
ELASTICSEARCH_API_KEY  = <encoded API key>
```

---

## 5. Prepare the cluster

Do this **once per cluster, before ingesting**.

### 5.1 Install the three integrations

**Why:** each integration installs the index templates and field mappings for its data
stream. Without them, fields such as `source.ip` or `winlog.event_id` may get the wrong
type, and the ES|QL detection rules will not match.

Kibana → **Integrations** → install each of these. You only need the assets, so when it
offers to add Elastic Agent, choose to add the integration *without* an agent, or simply
install the assets.

| Integration | Creates |
|---|---|
| **Palo Alto Next-Gen Firewall** | `logs-panw.panos-default` |
| **Windows** | `logs-windows.security-default`, `logs-windows.sysmon_operational-default` |
| **System** | `logs-system.auth-default`, `logs-system.syslog-default` |

The simulator's Okta, AWS and endpoint events work without their integrations, but
installing **Okta**, **AWS CloudTrail** and **Elastic Defend** gives them proper mappings
and dashboards too.

### 5.2 Configure an LLM connector

**Why:** Attack Discovery and the AI Agent both call an LLM. Without a connector the
data still loads, but Section 9 will not work.

Kibana → **Stack Management → Connectors** (or **GenAI Settings**) → create a connector for
your model provider, or confirm the Elastic Managed LLM is available.

---

## 6. Generate and ingest the data

```bash
node run.js
```

Here is what each prompt does, and what happens behind the scenes.

### 6.1 Choose the destination

```
  Select Elasticsearch destination
    1. Elastic Cloud Serverless
    2. Elastic Cloud Hosted
    3. Elastic Self-Managed (on-premise / Docker / local)
```

The launcher reads the matching section of `credentials.txt`, resolves the endpoints
(decoding the Cloud ID if needed), masks the API key on screen, and **tests both the
Elasticsearch and Kibana connections before writing anything**. If Elasticsearch is
unreachable, it stops here with the reason.

### 6.2 Choose what to ingest

```
  What would you like to ingest?
    1. POC Simulator only — synthetic events, attack scenarios, alerts, case
    2. Demo walkthrough logs only — PA PAN-OS + Windows + Linux NDJSON
    3. Both (recommended for a full demo environment)
    4. Cleanup — remove all previously ingested demo & sample data
```

**Choose 3 the first time.**

**Simulator step** (about 30 seconds): generates about 320 events in memory and indexes them
straight into Elasticsearch, with about 19 synthetic alerts. Then, through the Kibana API, it
creates an investigation case and opens **Security → Alerts** in your browser. Its
timestamps fall within the last few hours.

**Demo-log step** (about 1–2 minutes):

1. **Generate.** It writes fresh NDJSON files into `demo-logs/`. Every timestamp is
   relative to *now*: 14 days of background noise, with the attack unfolding over the
   last 3 days. If files already exist, you're asked whether to regenerate. **Say yes
   before every demo**, because stale timestamps fall outside the detection rules'
   windows.
2. **Ingest.** It reads the combined file, routes each document to its data stream by
   `data_stream.dataset`, and bulk-indexes it in batches of 500 with `pipeline=_none`.
   The events are already ECS-shaped, so the integrations' parsing pipelines are skipped.

Every document is tagged, `elastic-security-sample-data` (simulator) or
`elastic-security-demo-data` (demo logs), so each set can be found and removed cleanly.

> **Run it once.** Ingest uses `create` on data streams, which has no de-duplication. If
> you run *both* again, you double the demo logs. To refresh, clean up first (Section 10).

At the end you get a summary, Kibana links and a few ES|QL checks.

---

## 7. Verify the data landed

**Why:** catching a mapping or routing problem now is far cheaper than discovering it
halfway through a live demo.

Kibana → **Discover** → switch to **ES|QL** and run:

```esql
FROM logs-panw.panos-default, logs-windows.*, logs-system.auth-default
| WHERE tags == "elastic-security-demo-data"
| STATS events = COUNT(*) BY data_stream.dataset
| SORT events DESC
```

You should see roughly **5,200** `panw.panos`, **1,600** `windows.security`,
**1,200** `windows.sysmon_operational` and **600** `system.auth` events.

```esql
FROM logs-*
| WHERE user.name == "rjohnson"
| STATS events = COUNT(*) BY data_stream.dataset
```

This confirms the alignment: `rjohnson` appears in the firewall, Windows and Linux logs
**and** in the simulator's events.

Also check **Security → Alerts**, which should show the simulator's synthetic alerts, and
**Security → Cases**, which should show one case.

---

## 8. Create the baseline detection rules

**Why:** the synthetic alerts cover the simulator's scenarios, but the PA/Windows/Linux
logs only become alerts once rules run over them. These nine ES|QL rules turn the loud
part of the attack into alerts, which Attack Discovery can then correlate. They
**deliberately leave gaps**, and closing those gaps is part of the AI walkthrough.

| # | Rule | Severity | Source |
|---|---|---|---|
| 1 | VPN Brute-Force Followed by Successful Auth | Critical | PA PAN-OS |
| 3 | Explicit Credential Logon to Domain Controller | High | Windows |
| 4 | Suspicious User Account Created | High | Windows |
| 6 | Encoded PowerShell Execution | Critical | Windows + Sysmon |
| 7 | Scheduled Task Created for Persistence | High | Windows |
| 9 | Periodic C2 Beaconing Detected | Critical | Sysmon |
| 10 | Large Volume Data Exfiltration to External Host | Critical | PA PAN-OS |
| 14 | Insider Data Upload to Personal Cloud Storage | High | PA PAN-OS |
| 16 | Impossible Travel — VPN Login from Multiple Countries | High | PA PAN-OS |

Queries, schedules, MITRE context and investigation guides for each rule are in
**[docs/DETECTION_RULES.md](docs/DETECTION_RULES.md)**.

### 8.1 Create the rules

**Security → Rules → Detection rules (SIEM) → Create new rule → ES|QL**, then paste each
query. Or use **Create a rule → AI rule creation**: paste the query, let the agent fill
in the metadata, and click **Apply to creation**.

### 8.2 Backfill — don't skip this

A scheduled rule only looks at its own window, for example *the last 6 minutes*. The
attack happened over the last 3 days, so on their own the rules see almost nothing.

Select the nine `[Demo]` rules → **Bulk actions → Manual run** → time range **15 days ago
→ now**. Manual runs can cover up to 90 days back. Within a few minutes,
**Security → Alerts** fills up with real detections alongside the synthetic ones.

---

## 9. AI SOC walkthrough

This is the payoff: a six-step flow that takes the AI from *"what happened?"* to
*"we're now protected against it."* Each step says why it matters, where to click, what to
ask, and what you should see.

```
 9.1 Attack Discovery ─▶ 9.2 Correlate ─▶ 9.3 Hunt hidden threats ─▶ 9.4 Open a case
                                                                          │
                              9.6 Dashboard ◀── 9.5 Rules for the gaps ◀──┘
```

### 9.0 Before you start

- **Chat experience:** on **9.4+ / Serverless**, the Elastic AI Agent is the default chat
  in Elastic Security. Open it from the AI chat button in the Kibana header. On **9.3**,
  first [opt in to Agent Builder](https://www.elastic.co/docs/explore-analyze/ai-features/ai-chat-experiences/ai-agent-or-ai-assistant#switch-between-chat-experiences).
- **Skills used:** `threat-hunting`, `alert-analysis`, `cases-management`,
  `detection-rule-edit` and `dashboard-management`. The agent picks the right skill from
  your prompt, or you can force one with a slash command such as `/threat-hunting`.
- **Optional:** to *run* Attack Discovery from chat (not just discuss results), turn on
  the advanced setting `securitySolution:enableAttackDiscoveryWorkflows`.
- **Tip:** start a **new conversation** for each demo run, so earlier context doesn't
  leak into the answers.

> AI output is non-deterministic. Treat the prompts below as a script, the expected
> results as what a good answer covers, and always verify before acting on it.

---

### 9.1 Run Attack Discovery — let AI find the attacks in the alerts

**Why:** a SOC analyst facing 50+ alerts across firewall, Windows, Okta and AWS has to
work out which ones belong together. Attack Discovery does that grouping with an LLM. It
turns the alert pile into a few attack narratives, each mapped to MITRE ATT&CK.

**Do this:**

1. Open **Attack Discovery** from the Security navigation.
2. In its settings, select your **LLM connector**. Set the alert window to cover your
   backfill. Alert timestamps are when the alert was *created*, so **Last 24 hours** is
   usually enough right after Section 8.2. Raise the alert count limit, for example to
   200, so nothing is cut off.
3. Click **Generate** (or **Run**). It takes one to a few minutes.
4. **Optional:** create a **schedule** (for example daily) to show continuous, unattended
   analysis.

**What you should see:** several discoveries. Typical ones:

- **Credential access and lateral movement on `SRV-DC01`** by `rjohnson`: explicit
  credential logon, procdump against LSASS, SAM hive export
- **Identity takeover**: `rjohnson`'s Okta account taken over from `45.155.205.233`
- **Cloud privilege escalation** by `admin.ops`
- **Ransomware on `SRV-FILE01`**, with C2 to `91.234.56.78`
- **VPN intrusion → C2 → exfiltration**: brute-force from `45.155.205.233`, beaconing to
  `91.234.56.78`, large transfer to `218.92.0.190`

Point out that the *same* user, host and IP thread through several discoveries. That
continuity is what the entity alignment buys you.

---

### 9.2 Correlate with the AI Agent — one incident or several?

**Why:** Attack Discovery groups alerts *within* a discovery. An analyst still needs to
know whether the discoveries are one campaign, what the full timeline is, and which
assets are at risk. This step shows the agent reasoning *across* discoveries and back
into raw logs.

**Do this:** open the AI chat. Attach a discovery where your version offers it (for
example **Add to chat** on the discovery), or simply describe it in your prompt.

**Ask:**

```text
Review the attack discoveries from the last 24 hours. Are any of them part of the same
campaign? Correlate them by shared users, hosts and IP addresses, and give me one
consolidated timeline from initial access to impact.
```

```text
Focus on rjohnson and 45.155.205.233. Using the firewall, Windows and Linux logs as well
as the alerts, reconstruct every step this attacker took. Map each step to a MITRE ATT&CK
tactic.
```

```text
Which hosts and accounts should we treat as compromised right now, and what should we
contain first?
```

**What a good answer covers:** one campaign, in order. Okta takeover → VPN credential
spray on `firewall-authentication` → successful login from VPN IP `10.5.0.99` → recon →
`SRV-DC01` → credential dumping and persistence → beaconing to `91.234.56.78` → exfil to
`218.92.0.190` → ransomware on `SRV-FILE01`. It names `rjohnson` and `admin.ops` as
compromised identities and `SRV-DC01` / `SRV-FILE01` as priority assets.

---

### 9.3 Threat hunt — find what no rule caught

**Why:** detection rules only find what someone anticipated. The most damaging threats,
insiders and quiet persistence, usually fire nothing. This step shows the agent forming
hypotheses and running iterative ES|QL against raw logs to find activity with **no alert
at all**.

**Ask** (the `/threat-hunting` prefix forces the hunting skill):

```text
/threat-hunting Over the last 14 days, are there any users with unusual remote-access
patterns? Compare VPN login hours and source locations against each user's own baseline
in logs-panw.panos-default.
```

```text
/threat-hunting Look for possible insider data theft: DNS lookups to personal cloud
storage in Sysmon (event 22), outbound HTTPS uploads to those destinations in the
firewall logs, and access to HR or Finance file shares by users outside those
departments. Correlate the results by user.
```

```text
/threat-hunting The external attacker used VPN IP 10.5.0.99. Did that IP reach any Linux
servers? If so, show the full command history on that host and flag privilege
escalation, staging, exfiltration and anti-forensics.
```

**What a good answer covers:**

| Hidden threat | Evidence the agent should surface |
|---|---|
| **The Quiet Insider: `kpatel`** | VPN logins around 02:00–04:00 from `10.5.0.42`. `explorer.exe \\SRV-FILE01\Finance-Reports` and HR-Confidential share access. DNS to `mega.nz`, `pcloud.com`, `upload.pcloud.com`. Repeated 2–15 MB HTTPS uploads to `66.203.125.x` / `74.120.8.x`. Impossible travel, San Francisco → Seoul. |
| **Linux compromise: `rjohnson` on `SRV-LINUX01`** | SSH from `10.5.0.99`, then `whoami`, `cat /etc/passwd`, `find / -perm -4000`, `sudo chmod +s`, `crontab -e`, a `dd` of `/var/lib/mysql/customer_data.ibd`, `tar czf /tmp/.data_archive…`, repeated `curl -X POST`, and finally `history -c` with `rm -rf /tmp/.data_*`. |

Neither thread has a baseline rule. Rules 14 and 16 catch fragments of the insider
story, but nothing ties it together. That is exactly the gap the next steps close.

---

### 9.4 Open a case for the new findings

**Why:** a hunt finding is worthless if it lives only in a chat window. Cases are where
evidence, ownership and status are tracked for an incident. Here the agent turns its
own findings into a documented case without copy-paste. This uses the
`cases-management` skill.

**Ask:**

```text
Create a new Security case titled "Insider data exfiltration — kpatel" with severity
high. Summarize the evidence from the hunt, list the affected hosts, destination IPs and
domains as observables, and add the recommended next steps: preserve evidence, notify HR
and Legal, and restrict kpatel's VPN access.
```

```text
Create a second case, "Linux server compromise — SRV-LINUX01", linked to the rjohnson
campaign, with the command timeline as a comment.
```

**What you should see:** the agent confirms before writing, then reports the case it
created. Open **Security → Cases** to show the case with its description, observables and
comments. If you want an alert in the case too, ask the agent to attach the related Rule
14 / Rule 16 alerts.

---

### 9.5 Create detection rules for the uncovered threats

**Why:** a hunt that ends in a case fixes this incident. Turning the hunt into a rule
fixes **every future one**. This is the detection-engineering loop: hunt → codify →
detect. It uses the `detection-rule-edit` skill, which builds ES|QL rules and saves
them only when you click.

**Ask (one rule per prompt works best):**

```text
Create an ES|QL detection rule that alerts when a Windows host makes DNS queries to
personal cloud storage domains such as mega.nz or pcloud.com (Sysmon event 22,
dns.question.name), filtered to tags == "elastic-security-demo-data". Severity medium,
map it to MITRE T1567.002.
```

```text
Create an ES|QL rule that detects a user accessing HR-Confidential or Finance-Reports
shares on SRV-FILE01 when they don't normally do so.
```

```text
Create an ES|QL rule for Linux anti-forensics: history clearing (history -c) or deletion
of files in /tmp shortly after archive creation, from logs-system.auth-default.
```

**Then:**

1. On each rule the agent proposes, click **Apply to creation**. Review the form and
   save it.
2. Validate the rule against history. Ask *"How many alerts would this rule have
   generated in the last 14 days?"*, or **Manual run** the new rule over the last 15
   days, as in Section 8.2.
3. Re-run Attack Discovery. The insider and Linux threads now produce alerts, and they
   show up as new discoveries.

---

### 9.6 Build a dashboard to track it going forward

**Why:** leadership and the SOC lead want a view to watch, not a chat log. This step
shows the agent composing a Kibana dashboard from the investigation's context, using
the `dashboard-management` skill.

**Ask:**

```text
Create a dashboard called "AI SOC — Insider & Intrusion Watch" with:
- alerts over time by rule name for the [Demo] rules
- top users and top hosts by alert count
- VPN logins by hour of day per user from logs-panw.panos-default
- outbound bytes to external IPs by user
- DNS queries to cloud storage domains over time
```

**What you should see:** the agent builds the dashboard in the conversation. Save it and
open it from **Analytics → Dashboards**. `kpatel`'s off-hours VPN spike and the exfil
volume to `218.92.0.190` should stand out at a glance.

---

### Presenter answer key

<details>
<summary>Key entities and facts (expand)</summary>

| Fact | Value |
|---|---|
| Attacker source IP | `45.155.205.233` (Bucharest, RO) |
| Attacker VPN-assigned IP | `10.5.0.99` |
| Compromised user | `rjohnson` (contractor) |
| Escalation target | `admin.ops` |
| C2 server | `91.234.56.78` (Moscow, RU), about 30-minute beacon interval |
| Exfil destination | `218.92.0.190` (Jiangsu, CN) |
| Domain controller | `SRV-DC01` (`10.1.10.5`) |
| Ransomware target | `SRV-FILE01` |
| Insider | `kpatel`, VPN `10.5.0.42` |
| Insider cloud targets | mega.nz `66.203.125.12`, pcloud.com `74.120.8.90` |
| Linux victim | `SRV-LINUX01` (`10.2.10.50`) |
| Attack window | last 3 days. Background noise: last 14 days. |

Full chapter-by-chapter story: [docs/ENTITY_MODEL.md](docs/ENTITY_MODEL.md).

</details>

---

## 10. Clean up

```bash
node run.js --cleanup
```

This deletes every document tagged `elastic-security-sample-data` or
`elastic-security-demo-data` from the target data streams, plus the simulator's sample
cases. The rules, cases, dashboards and any AI-created objects from Section 9 are
**not** removed. Delete them in Kibana if you want a fully clean cluster.

To refresh a demo: clean up, then `node run.js` → **3 (Both)** → regenerate **yes**. Then
**Manual run** the rules again.

---

## 11. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `credentials.txt not found` | Run `cp credentials.example.txt credentials.txt` and fill in your section. |
| `No Elasticsearch endpoint for [section]` | That section is empty or misspelled. Valid names: `[serverless]`, `[cloud_hosted]`, `[self_managed]`. |
| `HTTP 401` / `403` | API key expired, revoked or under-privileged. Create a new one (Section 4). |
| `fetch failed` / unreachable | Wrong URL, a network filter, or TLS. For self-signed certificates set `CA_CERT`, or `VERIFY_SSL = false` in a lab. |
| Simulator step fails, demo logs succeed | Usually `npm install` was skipped: only the simulator needs `@elastic/elasticsearch`. The launcher checks for this and prints the fix. |
| `demo-log ingest script supports API key auth only` | Add `ELASTICSEARCH_API_KEY`. Username and password are not enough for that step. |
| `Data stream … not found` | Install the PAN-OS, Windows and System integrations first (Section 5.1). |
| Data is in, but almost no rule alerts | You skipped the **Manual run** backfill (Section 8.2), or the NDJSON was generated days ago. Regenerate and re-ingest. |
| Duplicate / doubled counts | Ingest ran twice. Run `node run.js --cleanup`, then ingest once. |
| Attack Discovery shows nothing | Check there's an LLM connector, that alerts fall in the selected window, and the subscription tier (Section 2). |
| AI agent says it can't find the data | Name the index explicitly (for example `logs-panw.panos-default`) and the time range, *last 14 days*. |
| `⚠ A .env file exists` | A stray `.env` can override `credentials.txt`. Rename or delete it. |
| `SyntaxError` / Node errors | `node --version` must be 22 or newer. Run `nvm use 22`. |

---

## 12. Project layout and advanced usage

```
.
├── run.js                       interactive launcher (start here)
├── credentials.example.txt      credential template, copied to credentials.txt (git-ignored)
├── package.json
├── simulator/                   Elastic security sample-data generator
│   ├── demo-walkthrough.js        one-shot runner: events → scenarios → alerts → case
│   ├── sample-data.js             generators (identity constants aligned, see notice in header)
│   ├── es-client.js               Elasticsearch client factory
│   └── kibana-client.js           Kibana REST helper
├── demo-logs/                   PA / Windows / Linux demo logs
│   ├── generate_all_demo_logs.cjs writes demo_logs_*.ndjson (git-ignored)
│   └── ingest_all_demo_logs.cjs   routes and bulk-indexes NDJSON
└── docs/
    ├── DETECTION_RULES.md         the nine baseline ES|QL rules
    └── ENTITY_MODEL.md            shared hosts/users/IPs and the story chapter by chapter
```

### Non-interactive runs (CI, scripts)

```bash
node run.js --target cloud_hosted --task both --yes
node run.js --target serverless   --task demo-logs --regenerate --yes
node run.js --target self_managed --task simulator --count 100 --yes
node run.js --cleanup --target cloud_hosted --yes
node run.js --help
```

| Flag | Meaning |
|---|---|
| `--target` | `serverless`, `cloud_hosted` or `self_managed` |
| `--task` | `simulator`, `demo-logs`, `both` or `cleanup` |
| `--count n` | Simulator events per package (default 50) |
| `--regenerate` / `--no-regenerate` | Force or skip NDJSON regeneration |
| `--yes`, `-y` | Skip confirmation prompts (also means regenerate) |

### Calling the underlying scripts directly

The launcher just sets environment variables and runs these, so you can too:

```bash
export ELASTICSEARCH_URL=https://… ELASTICSEARCH_API_KEY=… KIBANA_URL=https://…

node simulator/sample-data.js windows okta aws --scenarios --alerts --yes

node demo-logs/generate_all_demo_logs.cjs
node demo-logs/ingest_all_demo_logs.cjs demo-logs/demo_logs_combined_<timestamp>.ndjson
```

Always pass the **combined** file to the ingest script. With no argument, it
auto-discovers every `demo_logs_*.ndjson`, which double-ingests the per-category files.

---

## 13. Credits, license and disclaimer

### Credits

- `simulator/` is adapted from the **`security-generate-security-sample-data`** skill in
  [elastic/agent-skills](https://github.com/elastic/agent-skills) (Apache License 2.0).
  The only change is identity constants in `sample-data.js`, so its entities match the
  demo logs. The file header carries a modification notice, and see [NOTICE](NOTICE).
- `demo-logs/`, `run.js` and the documentation are original to this project.

### License

[Apache License 2.0](LICENSE).

### Disclaimer

This is a community demo project. It is **not an official Elastic product** and is not
supported by Elastic. All data is synthetic. Some IP addresses in the attack story
(`45.155.205.233`, `91.234.56.78`, `218.92.0.190` and others) are real, routable
addresses used as field values for realism. Nothing connects to them. Use only on
demo, lab or trial clusters you control. AI features produce non-deterministic output,
so review everything an agent proposes before you rely on it.
