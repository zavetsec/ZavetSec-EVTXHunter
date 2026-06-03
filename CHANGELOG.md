# Changelog

All notable changes to ZavetSec-EVTXHunter are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0]

### Added
- **7 new detection rules** across five additional channels (54 → 61 rules):
  scheduled task registered/deleted (TaskScheduler/Operational), WMI permanent
  event consumer (WMI-Activity/Operational), Defender real-time protection
  disabled and malware detected (Windows Defender/Operational), and RDP
  session/auth tracking (TerminalServices Local/RemoteConnection Manager). All are
  channel-scoped so generic Event IDs do not cross-fire from other providers.
- **Five channels added to the default `-LogNames`** so live scans cover the new
  rules out of the box (TaskScheduler, WMI-Activity, Windows Defender, and both
  TerminalServices Operational channels).
- **Directory mode now skips uncovered channels.** When `-Path` is a folder
  (e.g. `C:\Windows\System32\winevt\Logs`), only `.evtx` files from channels the
  rules cover are parsed; the rest are skipped to save time. New `-AllFiles`
  switch forces an exhaustive pass.

## [1.2.3]

### Fixed
- **Live mode now handles missing or empty channels cleanly.** A channel that is
  not present (e.g. `Microsoft-Windows-Sysmon/Operational` when Sysmon is not
  installed) or empty previously surfaced as Get-WinEvent's cryptic "The parameter
  is incorrect". Channels are now resolved with `Get-WinEvent -ListLog` first and
  skipped with a clear message; reads also fall back to the `-LogName` form to work
  around a known Get-WinEvent `-FilterHashtable` quirk on edge channels.

## [1.2.2]

### Changed
- Running the script with no arguments now prints a short usage summary with
  examples instead of prompting for a path (`-Path` is no longer a mandatory
  prompt). `-Path` or `-LiveScan` is still required to actually run an analysis.

## [1.2.1]

### Fixed
- **Live mode (`-LiveScan`) ignored a smaller `-MaxEvents`.** The channel read
  forced a minimum of 100,000 events per log regardless of the requested cap. The
  cap is now honored and applied as a global budget across all live channels
  (`0` = unlimited).

### Added
- Live mode now warns up front when the **Security** channel is requested without
  Administrator rights (it would otherwise return empty), and reports clearer
  per-channel status (no events vs. inaccessible).

## [1.2.0]

### Added
- **Dormant-account wakeup detection** — an account inactive for `-DormantDays`
  (default 30) that authenticates again is flagged as a temporal anomaly, via gap
  analysis of each account's logon timeline. Set `-DormantDays 0` to disable.
- **`-WorkHoursTimeZoneOffset`** — UTC offset of the monitored environment, so
  off-hours analysis is judged in the site's local time rather than the analyst
  workstation's.
- **`FieldExists` rule condition** is now evaluated by the detection engine (it was
  documented in the rule schema but never applied).
- **Parse-error visibility** — events that fail to parse (corrupt XML / malformed
  Event ID) are counted and reported in the run summary instead of being dropped
  silently.
- Business-hours sanity guard: an end hour not greater than the start hour now warns
  and falls back to 9–18 instead of flagging all activity as off-hours.

### Fixed
- **External JSON whitelist was non-functional and could suppress real findings.**
  Rules loaded via `-Whitelist` arrived as objects whose fields could not be
  enumerated, so a matching rule silently whitelisted *everything* for that rule ID.
  JSON rules are now converted to a proper match structure, rules with no field
  conditions are rejected at load time, and an empty condition set can never mean
  "match all".
- **Report JSON corrupted on locales with a comma decimal separator (e.g. ru-RU).**
  Entity risk scores serialized as `33,3` instead of `33.3`, breaking the interactive
  report. The script now runs under invariant culture.
- **Event timestamps are now parsed and reported deterministically in UTC** (the EVTX
  native time base), instead of being silently converted to the analyst machine's
  local time. Report time columns are labelled `(UTC)`.
- Version string is consistent across the banner, HTML report, and JSON export
  (driven by a single `$script:VERSION`).

### Changed
- **Burst detection rewritten as a true sliding window** (monotonic two-pointer,
  O(n)), matching the threshold engine. The previous tumbling-window reset could
  under-count bursts that straddled a reset boundary.
- Removed dead bookkeeping in the multi-step correlation matcher.

## [1.0.0]

### Added
- Initial release: EVTX file and live-log analysis in pure PowerShell 5.1.
- 54 built-in detection rules across 9 MITRE ATT&CK tactics.
- 10 correlation chains for multi-event attack sequences.
- Per-entity risk scoring (users, IPs, hosts, processes).
- Temporal anomaly analysis (off-hours / weekend / burst).
- Self-contained interactive HTML report, plus optional JSON / CSV output.
- Built-in vendor whitelist and external JSON whitelist support.

[1.3.0]: https://github.com/zavetsec/ZavetSec-EVTXHunter/releases/tag/v1.3.0
[1.2.3]: https://github.com/zavetsec/ZavetSec-EVTXHunter/releases/tag/v1.2.3
[1.2.2]: https://github.com/zavetsec/ZavetSec-EVTXHunter/releases/tag/v1.2.2
[1.2.1]: https://github.com/zavetsec/ZavetSec-EVTXHunter/releases/tag/v1.2.1
[1.2.0]: https://github.com/zavetsec/ZavetSec-EVTXHunter/releases/tag/v1.2.0
[1.0.0]: https://github.com/zavetsec/ZavetSec-EVTXHunter/releases/tag/v1.0.0
