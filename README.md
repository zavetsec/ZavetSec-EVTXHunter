<div align="center">

# ZavetSec-EVTXHunter

### Advanced Windows Event Log Threat Hunter

**Sigma-subset detection · correlation engine · entity risk scoring · self-contained HTML reports.**
**Pure PowerShell. Zero dependencies. Air-gap ready.**

<!-- Version is driven by $script:VERSION in the script; keep this badge in sync. -->
[![Version](https://img.shields.io/badge/Version-1.2.0-ff6b00)](CHANGELOG.md)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE)](#requirements)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6)](#requirements)
[![Dependencies](https://img.shields.io/badge/Dependencies-none-00ff88)](#why-evtxhunter)
[![MITRE ATT&CK](https://img.shields.io/badge/Mapped_to-MITRE_ATT%26CK-c01818)](#detection-coverage)

</div>

---

Point it at a folder of `.evtx` files — or run it live on the host. Minutes later you have one self-contained HTML report: findings ranked by severity, multi-event attack chains reconstructed, every user / IP / host / process scored by risk, all mapped to MITRE ATT&CK. No agent, no server, no internet, no binaries to trust. It runs anywhere PowerShell 5.1 exists — which is every Windows box since Server 2012 R2.

It is built for the analyst working an incident under time pressure, on an isolated host, who needs answers from the logs *now* — not after standing up a pipeline.

Most EVTX hunters answer one question: *which events matched a rule?* EVTXHunter is built to answer the questions that come next — *which user is most suspicious, which host accumulated the most risk, which events form a complete attack chain, and what should be investigated first.* The correlation engine, per-entity risk scoring, and hand-off-ready HTML report exist to turn a wall of matches into a triaged investigation. The point is not just detection — it is triage.

> **EVTXHunter trades breadth for zero-friction deployment plus the analysis the others leave to you** — correlation, scoring, and a report you can hand to someone without a SIEM.

*Bring the analysis to the logs, not the logs to the platform.*

---

## Example report

The entire output is a single self-contained HTML file — no server, no internet, no external assets. The screenshots below show the report structure: the severity-ranked findings dashboard, the MITRE ATT&CK mapping, entity risk scoring, and reconstructed correlation chains.

<!-- Replace these with real screenshots committed under docs/.
     Suggested captures: full overview, MITRE matrix, top-risk entities, a correlation chain expanded. -->
<div align="center">

<img width="1738" height="868" alt="evtxhunter" src="https://github.com/user-attachments/assets/2b1dfa6d-5c5f-455a-ad27-c6ccf2284002" />

</div>

---

## Why EVTXHunter

There are excellent EVTX hunters already — [Hayabusa](https://github.com/Yamato-Security/hayabusa) and [Chainsaw](https://github.com/WithSecureLabs/chainsaw) chief among them. EVTXHunter is not trying to replace a full Sigma engine. It fills a specific gap: **a single PowerShell file you can drop on any Windows host and run, with analysis built in.**

| | EVTXHunter | Typical binary hunters |
|---|---|---|
| Dependencies | **None** — pure PowerShell 5.1 | Binary + Sigma rule repo |
| Deploy to a locked-down host | Copy one `.ps1` | Stage executable, may trip allowlisting |
| Multi-event attack chains | **Built-in correlation engine** | Usually single-event rules |
| Risk scoring | **Per-entity (user / IP / host / process)** | Per-detection |
| Temporal anomalies | **Off-hours / burst / dormant** | Rarely |
| Output | **Interactive self-contained HTML** | CSV / JSONL, bring your own viewer |
| Air-gap | **Yes** | Yes (once staged) |

The trade-off is honest: a binary engine with the full public Sigma corpus has far more raw rule coverage. EVTXHunter does not compete on rule count — it competes on getting you from raw logs to a triaged, scored, hand-off-ready report with nothing to install.

---

## Features

- **10 correlation chains** — multi-event attack sequences reconstructed across time, e.g. *Brute Force -> Successful Logon*, *Reconnaissance -> Lateral Movement*, *Service Install -> Log Clearing*, *Account Creation -> Admin Group Addition*. This is the part single-event rules miss.
- **Entity risk scoring** — every user, IP, host, and process accumulates a normalized risk score across all findings and anomalies, so the report tells you *who* and *what* to look at first, not just *what fired*.
- **Temporal anomaly engine** — off-hours and weekend authentication, burst activity, and dormant-account wakeups (an account inactive for `-DormantDays` that suddenly authenticates), with machine/service accounts (SYSTEM, DWM-*, UMFD-*, machine `$`, well-known SIDs, AV service accounts) filtered out so the signal isn't drowned in noise.
- **Interactive HTML report** — self-contained, opens in any browser with no internet. Severity-ranked findings, click any row for full event detail, MITRE ATT&CK tactic matrix, top-risk entity board, reconstructed chains.
- **Noise control that doesn't go blind** — Windows-managed driver installs (the `DriverStore\FileRepository` class) are suppressed automatically, and a built-in vendor whitelist plus an external JSON whitelist (which *extends* the defaults, never replaces them) handle the rest. Plain `System32\drivers\*.sys` installs are deliberately *kept* as low-severity findings, because that path is the Bring-Your-Own-Vulnerable-Driver (BYOVD) attack surface — suppressing it would hide exactly what an attacker exploits.
- **54 built-in detection rules** — a curated Sigma-subset covering the techniques that actually show up in Windows IR, written directly against event fields (no external rule files to ship or update).
- **File or live** — analyze a directory of collected `.evtx`, or scan the live logs on the host you're triaging.

---

## Quick start

```powershell
# Analyze a directory of EVTX files (recursive)
.\Invoke-ZavetSecEVTXHunter.ps1 -Path C:\Evidence\evtx

# Analyze a single file
.\Invoke-ZavetSecEVTXHunter.ps1 -Path C:\Evidence\Security.evtx

# Scan the live host
.\Invoke-ZavetSecEVTXHunter.ps1 -LiveScan

# Only surface High and Critical, output all formats
.\Invoke-ZavetSecEVTXHunter.ps1 -Path .\evtx -MinSeverity High -OutputFormat All

# Tune business hours (in the monitored site's UTC+5 zone) and apply your own whitelist
.\Invoke-ZavetSecEVTXHunter.ps1 -Path .\evtx -WorkHoursStart 8 -WorkHoursEnd 19 -WorkHoursTimeZoneOffset 5 -Whitelist .\zavetsec-whitelist.example.json
```

Output is written to the output directory as `ZavetSec-EVTXHunter_<timestamp>.html` (and `.json` / `.csv` when requested).

---

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-Path <path>` | *(required, File mode)* | Single `.evtx` file or directory of them (recursive) |
| `-LiveScan` | *(required, Live mode)* | Scan live Windows Event Logs on the local host |
| `-LogNames <string[]>` | Security, System, Application, PowerShell/Operational, Sysmon/Operational | Which live logs to scan (Live mode) |
| `-OutputPath <path>` | current directory | Where reports are written |
| `-OutputFormat <HTML\|JSON\|CSV\|All>` | `HTML` | Report format(s) to generate |
| `-MinSeverity <Info\|Low\|Medium\|High\|Critical>` | `Low` | Minimum severity to report |
| `-DisableCorrelation` | off | Skip the correlation engine (faster on huge datasets) |
| `-WorkHoursStart <0-23>` | `9` | Start of business hours for off-hours detection |
| `-WorkHoursEnd <1-23>` | `18` | End of business hours for off-hours detection |
| `-WorkHoursTimeZoneOffset <-14..14>` | `0` (UTC) | UTC offset of the *monitored* environment, so business hours are judged in the site's local time, not the analyst workstation's |
| `-DormantDays <int>` | `30` | Days of inactivity after which an account's next logon is flagged as a dormant-account wakeup (`0` disables) |
| `-MaxEvents <int>` | `1000000` | Cap on events parsed |
| `-TimeRangeHours <int>` | `0` (all) | Only analyze events within the last N hours |
| `-Whitelist <path>` | none | JSON file of additional whitelist rules (extends built-in defaults) |

---

## Detection coverage

54 rules and 10 correlation chains spanning **9 MITRE ATT&CK tactics**:

| Tactic | Focus |
|---|---|
| Credential Access | Brute force, credential dumping indicators, Kerberoasting, explicit-credential abuse |
| Defense Evasion | Log clearing, audit policy tampering, obfuscated/encoded execution |
| Persistence | Service install, scheduled tasks, run keys, account creation |
| Lateral Movement | Remote logons, pass-the-hash indicators, remote service creation |
| Execution | PowerShell/script abuse, suspicious process creation, LOLBins |
| Privilege Escalation | Admin group changes, token/privilege abuse |
| Discovery | Account and network reconnaissance |
| Impact | Destructive actions |
| Command and Control | Suspicious outbound indicators |

Detection logic is tuned to suppress the highest-volume real-world false positives — Windows-managed driver installs, and machine/service accounts authenticating around the clock — without blunting the categories that matter. See [False-positive control](#false-positive-control) for how this is balanced against the BYOVD attack surface.

### Example detections

A representative sample of the built-in rules (exact titles as they appear in the report):

| Tactic | Detection |
|---|---|
| Credential Access | Kerberoasting (RC4 service-ticket requests), AS-REP Roasting, DCSync (Directory Replication access), Pass-the-Hash (network NTLM logon), Password Spray |
| Defense Evasion | Security/System event log cleared, `wevtutil` log clearing, AMSI bypass, Windows Defender tampering |
| Execution | PowerShell encoded command, download cradle, LOLBin execution, Office spawning a shell |
| Persistence | New service installed, WMI event subscription, suspicious scheduled task (temp/shell path) |
| Privilege Escalation | User added to Administrators / Domain Admins, SID-History injection, token-privilege manipulation |
| Credential Dumping | LSASS memory access, LSASS dump via `comsvcs.dll` MiniDump, SAM database access |
| Lateral Movement | RDP brute force, remote thread injection, executable written to an admin share |
| Impact | Inhibit system recovery (shadow-copy / backup deletion) |

And multi-event **correlation chains** that single-event rules miss:

- Brute Force Leading to Successful Logon
- Reconnaissance Followed by Lateral Movement
- Persistence via Service Followed by Log Clearing
- Account Creation Followed by Admin Group Addition
- DCSync Preparation: Recon then Replication Access
- PowerShell Encoded Execution Followed by Persistence



---

## False-positive control

Log hunting lives or dies on signal-to-noise. EVTXHunter handles it in two layers:

**1. Automatic, generalizable suppression.** Service installs from the Windows-managed `DriverStore\FileRepository` path (signed device drivers — GPU, audio, chipset, AV filter drivers) are suppressed by rule logic, on any host, without naming a single vendor. What is *not* suppressed: plain `System32\drivers\*.sys` installs, because that is where Bring-Your-Own-Vulnerable-Driver attacks stage their payloads — a loud low-severity finding there is correct.

**2. Your environment's whitelist.** Host- or estate-specific noise (your AV's driver family, your management agent, named service accounts) belongs in an external JSON file that *extends* the built-in defaults rather than replacing them. A working example for a Kaspersky-protected host ships as [`zavetsec-whitelist.example.json`](zavetsec-whitelist.example.json):

```json
[
  { "RuleID": "ZVS-PE-001", "Fields": { "ImagePath": "*\\DRIVERS\\K4W-*\\*.sys" } },
  { "RuleID": "ZVS-PE-001", "Fields": { "ServiceName": "Kaspersky*" } }
]
```

```powershell
.\Invoke-ZavetSecEVTXHunter.ps1 -Path .\evtx -Whitelist .\zavetsec-whitelist.example.json
```

Fields are matched with wildcards (`-like`). A rule with no `RuleID` applies to all rules. Your entries are **added** to the built-in defaults, never replace them.

> The built-in default whitelist is intentionally minimal and not tuned to any one environment. Expect to add your own AV/EDR and management-agent entries on first run — that is the design, not a gap.

---

## Requirements

| | |
|---|---|
| PowerShell | 5.1+ (built into Windows 8.1 / Server 2012 R2 and later) |
| Privileges | Standard user for file analysis; Administrator for `-LiveScan` of the Security log |
| Internet | Not required — fully air-gap capable |
| Install | None — single script file |

---

## Verify before running

In regulated or high-sensitivity environments, download to an offline staging machine, verify the SHA256 against the published checksum, then deploy from an internal share.

```powershell
Get-FileHash .\Invoke-ZavetSecEVTXHunter.ps1 -Algorithm SHA256
```

> EVTXHunter is read-only against your evidence and generates observable telemetry when run (ScriptBlock logging, AMSI, process creation). It is an authorized-IR tool, not a covert one.

---

## Performance

<!-- TODO: fill in with real numbers from a benchmark run. Do NOT ship placeholder
     figures - measure on a representative dataset and a stated test system, e.g.:

     | Dataset       | Events  | Time    |
     |---------------|---------|---------|
     | Single host   | ~100k   | _ s     |
     | Small estate  | ~500k   | _ s     |
     | Large pull    | ~1M     | _ s     |

     Test system: <CPU> / <RAM> / PowerShell <version>

     Until measured, this section is intentionally omitted rather than guessed. -->

_Benchmarks pending — will be published from a representative dataset on a stated test system._

---

## How it works

```text
   EVTX files  ──or──  live channels
        │
        ▼
   ┌──────────┐   normalize fields, index by Event ID + account
   │  Parser  │
   └──────────┘
        │
        ▼
   ┌────────────────────┐   54 Sigma-subset rules + whitelist
   │  Detection engine  │
   └────────────────────┘
        │
        ▼
   ┌──────────────────────┐   10 multi-event attack chains
   │  Correlation engine  │
   └──────────────────────┘
        │
        ▼
   ┌─────────────────┐   per-entity risk: users / IPs / hosts / procs
   │  Risk scoring   │   + temporal anomalies (off-hours / burst / dormant)
   └─────────────────┘
        │
        ▼
   Self-contained HTML report  (+ optional JSON / CSV)
```

1. **Parse** — reads `.evtx` (file mode) or live channels (live mode), normalizing each event's fields into a queryable structure and indexing by Event ID and account.
2. **Detect** — runs the 54-rule engine over the indexed events, applying the whitelist to suppress known-good noise.
3. **Correlate** — the chain engine looks for multi-event attack sequences within time windows.
4. **Score** — every finding feeds a per-entity risk score for users, IPs, hosts, and processes; temporal anomalies add weighted context.
5. **Report** — emits a self-contained interactive HTML report (and optional JSON/CSV) ready to read or hand off. Event timestamps in the report are shown in **UTC** (the EVTX native time base), so findings line up across hosts in different time zones.

---

## Roadmap

- [ ] Amcache / ShimCache enrichment
- [ ] Sigma rule import (map external Sigma YAML onto the engine)
- [x] Timeline view in the HTML report
- [ ] Pluggable rule packs per environment profile

---

## License

See [LICENSE](LICENSE).

---

<div align="center">

**Part of the ZavetSec DFIR toolkit** — zero dependencies, zero setup, immediate output.

Built for incident responders, DFIR analysts, and threat hunters who need answers from Windows logs without deploying additional infrastructure.

[github.com/zavetsec](https://github.com/zavetsec)

*Discipline over marketing.*

</div>
