#Requires -Version 5.1
<#
.SYNOPSIS
    ZavetSec-EVTXHunter v1.1.0 - Advanced Windows Event Log Threat Hunter

.DESCRIPTION
    Threat hunting and DFIR analysis tool for Windows Event Logs (EVTX).
    Features built-in Sigma-subset detection rules, correlation engine,
    temporal anomaly analysis, entity scoring, and interactive HTML reports.

    Advantages over Hayabusa and Chainsaw:
      - Zero external dependencies (pure PowerShell 5.1, no binaries)
      - Correlation engine for multi-event attack chain detection
      - Temporal anomaly analysis (off-hours, burst, dormant account activity)
      - Entity-based risk scoring (users, IPs, hosts, processes)
      - Fully interactive self-contained HTML report (no internet required)
      - Air-gap ready

.PARAMETER Path
    Path to a single EVTX file or directory containing EVTX files (recursive).

.PARAMETER LiveScan
    Scan live Windows Event Logs on the local system.

.PARAMETER LogNames
    When using -LiveScan, specify which logs to scan.
    Default: Security, System, Application, Microsoft-Windows-PowerShell/Operational

.PARAMETER OutputPath
    Directory for output files. Default: current directory.

.PARAMETER OutputFormat
    HTML | JSON | CSV | All   (default: HTML)

.PARAMETER MinSeverity
    Info | Low | Medium | High | Critical   (default: Low)

.PARAMETER DisableCorrelation
    Skip correlation engine (faster for quick triage).

.PARAMETER WorkHoursStart
    Business hours start in 24h format for temporal analysis. Default: 9

.PARAMETER WorkHoursEnd
    Business hours end in 24h format for temporal analysis. Default: 18

.PARAMETER MaxEvents
    Maximum events to process per log/file. 0 = unlimited. Default: 1000000

.PARAMETER TimeRangeHours
    Process only events from the last N hours. 0 = all events. Default: 0

.PARAMETER WorkHoursTimeZoneOffset
    UTC offset (in hours) of the MONITORED environment, used to interpret
    business hours during temporal off-hours analysis. Default: 0 (UTC).
    Example: for a host in UTC+5 (e.g. Almaty), pass 5 so that 09:00-18:00
    local is evaluated correctly regardless of the analyst workstation's
    own time zone. Display timestamps elsewhere are unaffected.

.PARAMETER Whitelist
    Path to JSON whitelist file with conditions to suppress false positives.
    Expected shape (array of objects):
      [ { "RuleID": "ZVS-PE-001", "Fields": { "ImagePath": "*\\MyApp\\*" } } ]
    RuleID is optional (omit to apply to all rules). Fields is required and
    must contain at least one field/wildcard pair.

.EXAMPLE
    .\Invoke-ZavetSecEVTXHunter.ps1 -Path C:\Forensics\Security.evtx
    Analyse a single EVTX file and output HTML report.

.EXAMPLE
    .\Invoke-ZavetSecEVTXHunter.ps1 -Path C:\Forensics\ -OutputFormat All
    Analyse all EVTX files recursively, output HTML + JSON + CSV.

.EXAMPLE
    .\Invoke-ZavetSecEVTXHunter.ps1 -LiveScan -MinSeverity High
    Scan live logs, report only High and Critical findings.

.EXAMPLE
    .\Invoke-ZavetSecEVTXHunter.ps1 -Path C:\Logs\ -TimeRangeHours 72
    Analyse events from the last 72 hours only.

.NOTES
    Author  : ZavetSec Research
    Version : 1.1.0
    Tags    : DFIR, Threat Hunting, EVTX, Sigma, Windows Event Logs
    License : MIT
#>

[CmdletBinding(DefaultParameterSetName = 'File')]
param(
    [Parameter(ParameterSetName = 'File', Mandatory = $true, Position = 0)]
    [string]$Path,

    [Parameter(ParameterSetName = 'Live', Mandatory = $true)]
    [switch]$LiveScan,

    [Parameter(ParameterSetName = 'Live')]
    [string[]]$LogNames = @(
        'Security',
        'System',
        'Application',
        'Microsoft-Windows-PowerShell/Operational',
        'Microsoft-Windows-Sysmon/Operational'
    ),

    [string]$OutputPath = (Get-Location).Path,

    [ValidateSet('HTML','JSON','CSV','All')]
    [string]$OutputFormat = 'HTML',

    [ValidateSet('Info','Low','Medium','High','Critical')]
    [string]$MinSeverity = 'Low',

    [switch]$DisableCorrelation,

    [ValidateRange(0,23)]
    [int]$WorkHoursStart = 9,

    [ValidateRange(1,23)]
    [int]$WorkHoursEnd = 18,

    [ValidateRange(-14,14)]
    [int]$WorkHoursTimeZoneOffset = 0,

    [ValidateRange(0,[int]::MaxValue)]
    [int]$MaxEvents = 1000000,

    [ValidateRange(0,[int]::MaxValue)]
    [int]$TimeRangeHours = 0,

    [string]$Whitelist = ''
)

Set-StrictMode -Version 1.0
$ErrorActionPreference = 'SilentlyContinue'

# Force InvariantCulture so all numeric -> string conversions use '.' as the
# decimal separator. Without this, on locales like ru-RU (comma separator) the
# entity scores embedded into the report JSON serialize as e.g. "score":33,3 -
# invalid JSON that breaks JSON.parse and the interactive report. Date output
# uses explicit format strings and is unaffected.
[System.Threading.Thread]::CurrentThread.CurrentCulture =
    [System.Globalization.CultureInfo]::InvariantCulture

# ================================================================
# SECTION 1: CONSTANTS & GLOBAL STATE
# ================================================================

$script:VERSION        = '1.0.0'
$script:TOOL_NAME      = 'ZavetSec-EVTXHunter'
$script:StartTime      = Get-Date
$script:TotalParsed    = 0
$script:TotalHits      = 0
$script:ParseErrors    = 0   # events that failed to parse (corrupt XML / bad EventID)

$script:SeverityWeight = @{
    'Info'     = 0
    'Low'      = 1
    'Medium'   = 2
    'High'     = 3
    'Critical' = 4
}

# Score added to entity per finding severity
$script:SeverityScore = @{
    'Info'     = 2
    'Low'      = 8
    'Medium'   = 20
    'High'     = 35
    'Critical' = 55
}

$script:SeverityColor = @{
    'Info'     = '#6b7280'
    'Low'      = '#3b82f6'
    'Medium'   = '#f59e0b'
    'High'     = '#ef4444'
    'Critical' = '#ff2d55'
}

# Global event store used by correlation engine
$script:AllEvents   = [System.Collections.Generic.List[object]]::new()

# Indexed stores for O(1) correlation lookups
$script:IdxByEventID = [System.Collections.Hashtable]::new()
$script:IdxByUser    = [System.Collections.Hashtable]::new()
$script:IdxByIP      = [System.Collections.Hashtable]::new()
$script:IdxByHost    = [System.Collections.Hashtable]::new()

# Findings accumulator
$script:Findings     = [System.Collections.Generic.List[object]]::new()

# Deduplication map: composite key -> finding object. Identical findings
# (same rule, host, principals, target object) are collapsed into one entry
# whose GroupCount is incremented, instead of flooding the report with
# hundreds of identical rows (e.g. boot-time audit-policy or service installs).
$script:DedupeMap    = [System.Collections.Hashtable]::new()

# Entity score accumulator  [entity_key] -> score_object
$script:EntityScores = [System.Collections.Hashtable]::new()

# External whitelist rules loaded from JSON (via -Whitelist). These are ADDED to the
# built-in defaults below, not replaced, so a user file extends rather than overrides.
$script:WhitelistRules = @()

# Built-in vendor whitelist. Test-WhitelistMatch compares each RawFields[field] with
# -like (wildcards), scoped to RuleID when set. These suppress common AV/EDR false
# positives where vendors reinstall signed services on update. A genuinely malicious
# service still fires PE-002 (obfuscation) or surfaces via correlation; this only
# silences known-good vendor ImagePaths on the path-context rules (PE-001 / PE-002b).
#
# Scope note: this built-in list is intentionally CONSERVATIVE. Host-specific AV driver
# paths (e.g. Kaspersky's "\DRIVERS\K4W-xx-xx\kl*.sys" family, which can be dozens of
# entries per host) are deliberately NOT baked in here - they vary by product/version
# and belong in YOUR environment's -Whitelist JSON, not in a tool others will run on
# different stacks. Windows-managed DriverStore installs are handled separately by
# PE-001's FieldNotRegex, not here. Override or extend with -Whitelist <json>.
$script:DefaultWhitelist = @(
    # Windows Defender platform service
    @{ RuleID='ZVS-PE-001';  Fields=@{ 'ImagePath'='*\Windows Defender\*' } }
    @{ RuleID='ZVS-PE-002b'; Fields=@{ 'ImagePath'='*\Windows Defender\*' } }
    @{ RuleID='ZVS-PE-001';  Fields=@{ 'ImagePath'='*MpKslDrv.sys*' } }
    @{ RuleID='ZVS-PE-002b'; Fields=@{ 'ImagePath'='*MpKslDrv.sys*' } }
    # Kaspersky removal/deployment wrapper staged in TEMP (KAVREM) - the PE-002b case
    @{ RuleID='ZVS-PE-002b'; Fields=@{ 'ImagePath'='*\KAVREM~1\*' } }
    # Kaspersky standard install layouts (KES/KSC). These cover Program Files-style
    # paths; the per-host \DRIVERS\K4W-* driver family is intentionally left to user JSON.
    @{ RuleID='ZVS-PE-001';  Fields=@{ 'ImagePath'='*\Kaspersky Lab\*' } }
    @{ RuleID='ZVS-PE-002b'; Fields=@{ 'ImagePath'='*\Kaspersky Lab\*' } }
    @{ RuleID='ZVS-PE-001';  Fields=@{ 'ImagePath'='*\Kaspersky*\Bases\*' } }
    @{ RuleID='ZVS-PE-002b'; Fields=@{ 'ImagePath'='*\Kaspersky*\Bases\*' } }
)



# ================================================================
# SECTION 2: HELPER UTILITIES
# ================================================================

function Write-Banner {
    $banner = @"

 ______                    _    _____            
|___  /                   | |  / ____|           
   / /  __ ___   _____  _| |_| (___   ___  ___  
  / /  / _' \ \ / / _ \| __\___ \ / _ \/ __|
 / /__| (_| |\ V /  __/| |_ ____) |  __/ (__  
/_____|\__,_| \_/ \___| \__|_____/ \___|\___|
                                               
  EVTX Hunter v$($script:VERSION) | Advanced Threat Hunting Engine
  Zero Dependencies | Correlation Engine | Entity Scoring
================================================================
"@
    Write-Host $banner -ForegroundColor Green
}

function Write-Status {
    param(
        [string]$Message,
        [string]$Type = 'INFO'
    )
    $ts = (Get-Date).ToString('HH:mm:ss')
    $color = switch ($Type) {
        'INFO'    { 'Cyan'    }
        'OK'      { 'Green'   }
        'WARN'    { 'Yellow'  }
        'ERROR'   { 'Red'     }
        'SECTION' { 'Magenta' }
        default   { 'White'   }
    }
    Write-Host "[$ts] " -NoNewline -ForegroundColor DarkGray
    Write-Host "[$Type] " -NoNewline -ForegroundColor $color
    Write-Host $Message -ForegroundColor White
}

function ConvertTo-JsonString {
    <#
    .SYNOPSIS
        Escape a string for safe embedding inside a JSON string value.
        Handles backslash, double-quote, and control characters.
        NOTE: PowerShell -replace uses .NET Regex.Replace where the REPLACEMENT
        string treats '\' as literal (only '$' is special). So to emit one JSON
        backslash-escape (\\) the replacement is '\\' (two chars), NOT '\\\\'.
        Using the .Replace() string method instead of -replace avoids regex
        replacement-token ambiguity entirely.
    #>
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $s = $Text
    $s = $s.Replace('\', '\\')      # backslash first - one becomes two
    $s = $s.Replace('"', '\"')      # double quote
    $s = $s.Replace("`r`n", '\n')   # CRLF
    $s = $s.Replace("`n", '\n')     # LF
    $s = $s.Replace("`r", '\n')     # CR
    $s = $s.Replace("`t", '\t')     # tab
    return $s
}


function ConvertTo-HtmlEncoded {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $Text `
        -replace '&', '&amp;' `
        -replace '<', '&lt;'  `
        -replace '>', '&gt;'  `
        -replace '"', '&quot;' `
        -replace "'", '&#39;'
}

function Get-SafeString {
    param($Value, [string]$Default = '-')
    if ($null -eq $Value) { return $Default }
    $s = "$Value".Trim()
    if ([string]::IsNullOrWhiteSpace($s) -or $s -eq '-') { return $Default }
    return $s
}

function ConvertTo-UnixTimestamp {
    param([datetime]$Date)
    [int64](($Date.ToUniversalTime() - [datetime]'1970-01-01T00:00:00Z').TotalMilliseconds)
}

function Add-EntityScore {
    param(
        [string]$EntityType,   # User | IP | Host | Process
        [string]$EntityKey,
        [string]$Severity,
        [decimal]$Multiplier = 1.0,
        [string]$Reason = ''
    )
    if ([string]::IsNullOrWhiteSpace($EntityKey) -or $EntityKey -eq '-') { return }

    $key = "${EntityType}::${EntityKey}"
    if (-not $script:EntityScores.ContainsKey($key)) {
        $script:EntityScores[$key] = [PSCustomObject]@{
            EntityType = $EntityType
            EntityKey  = $EntityKey
            RawScore   = [decimal]0
            HitCount   = 0
            MaxSeverity = 'Info'
            Reasons    = [System.Collections.Generic.List[string]]::new()
        }
    }
    $obj   = $script:EntityScores[$key]
    $delta = [decimal]($script:SeverityScore[$Severity]) * $Multiplier
    $obj.RawScore  += $delta
    $obj.HitCount  += 1

    if ($script:SeverityWeight[$Severity] -gt $script:SeverityWeight[$obj.MaxSeverity]) {
        $obj.MaxSeverity = $Severity
    }
    if (-not [string]::IsNullOrEmpty($Reason)) {
        $obj.Reasons.Add($Reason)
    }
}

function Get-NormalizedScore {
    param([decimal]$Raw)
    # Soft cap at 100 using logarithmic normalization
    $capped = [Math]::Min($Raw, 300)
    return [Math]::Round(($capped / 300) * 100, 1)
}

function Get-RiskLevel {
    param([decimal]$Score)
    if ($Score -ge 80) { return 'Critical' }
    if ($Score -ge 60) { return 'High' }
    if ($Score -ge 40) { return 'Medium' }
    if ($Score -ge 20) { return 'Low' }
    return 'Info'
}

function Test-MinSeverity {
    param([string]$Severity)
    return $script:SeverityWeight[$Severity] -ge $script:SeverityWeight[$MinSeverity]
}

function Test-WhitelistMatch {
    param($Event, $Rule)
    # Check built-in vendor defaults first, then any user-supplied rules.
    foreach ($wlRule in @($script:DefaultWhitelist) + @($script:WhitelistRules)) {
        # Check RuleID match
        if ($wlRule.RuleID -and $wlRule.RuleID -ne $Rule.RuleID) { continue }
        # A whitelist rule with no field conditions must NOT silently match everything.
        # (This previously suppressed all findings when a JSON rule had an empty Fields.)
        if ($null -eq $wlRule.Fields -or $wlRule.Fields.Keys.Count -eq 0) { continue }
        $matched = $true
        foreach ($field in $wlRule.Fields.Keys) {
            $val = $Event.RawFields[$field]
            if ($val -notlike $wlRule.Fields[$field]) { $matched = $false; break }
        }
        if ($matched) { return $true }
    }
    return $false
}

function Add-EventToIndex {
    param($ParsedEvent)
    # By EventID
    $eid = $ParsedEvent.EventID
    if (-not $script:IdxByEventID.ContainsKey($eid)) {
        $script:IdxByEventID[$eid] = [System.Collections.Generic.List[object]]::new()
    }
    $script:IdxByEventID[$eid].Add($ParsedEvent)

    # By User (SubjectUserName or TargetUserName)
    foreach ($uField in @('SubjectUserName','TargetUserName','UserName')) {
        $u = Get-SafeString $ParsedEvent.RawFields[$uField]
        if ($u -ne '-' -and -not (Test-IsMachineOrServiceAccount $u)) {
            if (-not $script:IdxByUser.ContainsKey($u)) {
                $script:IdxByUser[$u] = [System.Collections.Generic.List[object]]::new()
            }
            $script:IdxByUser[$u].Add($ParsedEvent)
        }
    }

    # By IP
    foreach ($ipField in @('IpAddress','SourceNetworkAddress','ClientAddress')) {
        $ip = Get-SafeString $ParsedEvent.RawFields[$ipField]
        if ($ip -ne '-' -and $ip -ne '::1' -and $ip -ne '127.0.0.1' -and $ip -notmatch '^-') {
            if (-not $script:IdxByIP.ContainsKey($ip)) {
                $script:IdxByIP[$ip] = [System.Collections.Generic.List[object]]::new()
            }
            $script:IdxByIP[$ip].Add($ParsedEvent)
        }
    }

    # By Host
    $h = Get-SafeString $ParsedEvent.Computer
    if ($h -ne '-') {
        if (-not $script:IdxByHost.ContainsKey($h)) {
            $script:IdxByHost[$h] = [System.Collections.Generic.List[object]]::new()
        }
        $script:IdxByHost[$h].Add($ParsedEvent)
    }
}

# ================================================================
# SECTION 3: EVTX PARSER
# ================================================================

function ConvertFrom-EventXml {
    <#
    .SYNOPSIS
        Parse a raw EventLogRecord into a normalized hashtable.
        Returns $null if the event cannot be parsed.
    #>
    param($RawEvent)

    try {
        $xmlStr = $RawEvent.ToXml()
        if ([string]::IsNullOrEmpty($xmlStr)) { $script:ParseErrors++; return $null }
        [xml]$xml = $xmlStr
    }
    catch { $script:ParseErrors++; return $null }

    $sys = $xml.Event.System

    # Parse EventID (may be nested: <EventID Qualifiers="...">4624</EventID>)
    $eid = 0
    try {
        $eidNode = $sys.EventID
        if ($eidNode -is [System.Xml.XmlElement]) {
            $eid = [int]$eidNode.'#text'
        } else {
            $eid = [int]$eidNode
        }
    } catch { $script:ParseErrors++; return $null }

    # Parse TimeCreated. EVTX SystemTime is ISO-8601 UTC (suffix 'Z'). Parse with
    # RoundtripKind so the resulting DateTime keeps Kind=Utc deterministically,
    # instead of being silently converted to the analyst machine's local time.
    $tc = $null
    try {
        $tcStr = $sys.TimeCreated.SystemTime
        if (-not [datetime]::TryParse(
                $tcStr, [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$tc)) {
            $tc = [datetime]::UtcNow
        }
    } catch { $tc = [datetime]::UtcNow }

    # Apply TimeRange filter early to save memory
    if ($TimeRangeHours -gt 0) {
        $cutoff = (Get-Date).AddHours(-$TimeRangeHours).ToUniversalTime()
        if ($tc.ToUniversalTime() -lt $cutoff) { return $null }
    }

    # Parse all EventData / UserData fields into a hashtable
    $fields = [System.Collections.Hashtable]::new()

    # Standard EventData - two formats exist in Windows EVTX:
    #   Format A (modern): <Data Name="SubjectUserName">value</Data>
    #   Format B (legacy): <SubjectUserName>value</SubjectUserName>
    if ($xml.Event.EventData) {
        $posIndex = 0
        foreach ($node in $xml.Event.EventData.ChildNodes) {
            if ($null -eq $node) { continue }
            $lname = $node.LocalName
            if ($null -eq $lname -or $lname -eq '#text' -or $lname -eq '#comment') { continue }

            if ($lname -eq 'Data') {
                # Format A: <Data Name="FieldName">value</Data>
                try {
                    if ($node.HasAttribute('Name')) {
                        $fname = $node.GetAttribute('Name')
                        if (-not [string]::IsNullOrEmpty($fname)) {
                            $fields[$fname] = $node.InnerText
                        } else {
                            # Unnamed positional Data node
                            $fields["_Data$posIndex"] = $node.InnerText
                            $posIndex++
                        }
                    } else {
                        # No Name attribute - store positionally
                        $fields["_Data$posIndex"] = $node.InnerText
                        $posIndex++
                    }
                } catch {}
            } else {
                # Format B: <FieldName>value</FieldName>
                try { $fields[$lname] = $node.InnerText } catch {}
            }
        }
    }

    # UserData fallback (some event types use a wrapper element)
    if ($xml.Event.UserData) {
        foreach ($child in $xml.Event.UserData.ChildNodes) {
            if ($null -eq $child) { continue }
            foreach ($subChild in $child.ChildNodes) {
                if ($null -eq $subChild) { continue }
                $sl = $subChild.LocalName
                if (-not [string]::IsNullOrEmpty($sl) -and $sl -ne '#text' -and $sl -ne '#comment') {
                    try { $fields[$sl] = $subChild.InnerText } catch {}
                }
            }
        }
    }

    # ---- FIELD NORMALIZATION ----
    # Different providers name equivalent fields differently. Sysmon EID 1
    # uses Image/ParentImage/User; Security EID 4688 uses NewProcessName/
    # ParentProcessName/SubjectUserName. We create aliases so a single rule
    # can match both sources without duplication. Only fill an alias if the
    # canonical field is absent, never overwrite a present value.
    $aliasMap = @{
        # canonical (Security 4688 style) = source (Sysmon style)
        'NewProcessName'    = 'Image'
        'ParentProcessName' = 'ParentImage'
        'ProcessCommandLine'= 'CommandLine'   # keep CommandLine canonical both ways
    }
    foreach ($canonical in $aliasMap.Keys) {
        $source = $aliasMap[$canonical]
        if ((-not $fields.ContainsKey($canonical)) -and $fields.ContainsKey($source)) {
            $fields[$canonical] = $fields[$source]
        }
        # And the reverse: if only the canonical exists, expose the Sysmon name too
        if ((-not $fields.ContainsKey($source)) -and $fields.ContainsKey($canonical)) {
            $fields[$source] = $fields[$canonical]
        }
    }
    # Sysmon stores the acting user in "User" (DOMAIN\user); map to SubjectUserName
    # when the Security-style field is absent. Strip domain prefix for matching.
    if ((-not $fields.ContainsKey('SubjectUserName')) -and $fields.ContainsKey('User')) {
        $uval = "$($fields['User'])"
        if ($uval -match '\\') { $uval = ($uval -split '\\')[-1] }
        $fields['SubjectUserName'] = $uval
    }
    # Expose PowerShell ScriptBlockText (EID 4104) under CommandLine too, so a single
    # command-line rule matches process-creation (4688/Sysmon1) AND script-block
    # (4104) evidence of the same technique without needing two rules. Dedicated
    # ScriptBlockText rules still work because that field is left intact.
    if ((-not $fields.ContainsKey('CommandLine')) -and $fields.ContainsKey('ScriptBlockText')) {
        $fields['CommandLine'] = $fields['ScriptBlockText']
    }

    # Determine Channel
    $channel = ''
    try {
        $channel = $sys.Channel
    } catch {}
    if ([string]::IsNullOrEmpty($channel)) {
        try { $channel = $RawEvent.LogName } catch {}
    }

    # Build normalized event object
    $parsed = [PSCustomObject]@{
        TimeCreated     = $tc
        EventID         = $eid
        Channel         = $channel
        Computer        = (Get-SafeString $sys.Computer)
        EventRecordID   = 0
        ProviderName    = ''
        RawFields       = $fields
        # Convenience shortcuts populated below
        SubjectUserName = ''
        TargetUserName  = ''
        IpAddress       = ''
        CommandLine     = ''
        ProcessName     = ''
    }

    try { $parsed.EventRecordID   = [long]$sys.EventRecordID }      catch {}
    try { $parsed.ProviderName    = $sys.Provider.Name }             catch {}
    try { $parsed.SubjectUserName = Get-SafeString $fields['SubjectUserName'] } catch {}
    try { $parsed.TargetUserName  = Get-SafeString $fields['TargetUserName']  } catch {}
    try {
        $ipVal = $fields['IpAddress']
        if ([string]::IsNullOrEmpty($ipVal)) { $ipVal = $fields['SourceNetworkAddress'] }
        if ([string]::IsNullOrEmpty($ipVal)) { $ipVal = $fields['ClientAddress'] }
        $parsed.IpAddress = Get-SafeString $ipVal
    } catch {}
    try {
        $clVal = $fields['CommandLine']
        if ([string]::IsNullOrEmpty($clVal)) { $clVal = $fields['ScriptBlockText'] }
        $parsed.CommandLine = Get-SafeString $clVal
    } catch {}
    try {
        $pnVal = $fields['NewProcessName']
        if ([string]::IsNullOrEmpty($pnVal)) { $pnVal = $fields['Image'] }
        if ([string]::IsNullOrEmpty($pnVal)) { $pnVal = $fields['ProcessName'] }
        $parsed.ProcessName = Get-SafeString $pnVal
    } catch {}

    return $parsed
}

function Read-EVTXFile {
    param([string]$FilePath)

    Write-Status "Parsing: $FilePath" 'INFO'
    $count = 0

    try {
        $query  = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new(
            $FilePath,
            [System.Diagnostics.Eventing.Reader.PathType]::FilePath
        )
        $reader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new($query)

        while ($true) {
            if ($MaxEvents -gt 0 -and $count -ge $MaxEvents) { break }

            $rawEvent = $reader.ReadEvent()
            if ($null -eq $rawEvent) { break }

            $parsed = ConvertFrom-EventXml -RawEvent $rawEvent
            $rawEvent.Dispose()

            if ($null -eq $parsed) { continue }

            $script:AllEvents.Add($parsed)
            Add-EventToIndex -ParsedEvent $parsed
            $count++
        }
        $reader.Dispose()
    }
    catch {
        Write-Status "Error reading $FilePath`: $_" 'WARN'
    }

    Write-Status "  -> $count events loaded" 'OK'
    $script:TotalParsed += $count
}

function Read-LiveLogs {
    param([string[]]$Logs)

    foreach ($logName in $Logs) {
        Write-Status "Live scan: $logName" 'INFO'
        $count = 0

        try {
            $filterHash = @{ LogName = $logName }
            if ($TimeRangeHours -gt 0) {
                $filterHash['StartTime'] = (Get-Date).AddHours(-$TimeRangeHours)
            }

            $events = Get-WinEvent -FilterHashtable $filterHash -MaxEvents ([Math]::Max($MaxEvents, 100000)) -Oldest -ErrorAction SilentlyContinue
            if ($null -eq $events) { continue }

            foreach ($rawEvent in $events) {
                $parsed = ConvertFrom-EventXml -RawEvent $rawEvent
                if ($null -eq $parsed) { continue }
                $script:AllEvents.Add($parsed)
                Add-EventToIndex -ParsedEvent $parsed
                $count++
            }
        }
        catch {
            Write-Status "  Cannot access '$logName' (may not exist or no permission)" 'WARN'
        }

        if ($count -gt 0) {
            Write-Status "  -> $count events loaded" 'OK'
            $script:TotalParsed += $count
        }
    }
}

# ================================================================
# SECTION 4: DETECTION RULES
# ================================================================
# Rule schema:
#   RuleID          : string          - unique identifier ZVS-XX-NNN
#   Title           : string
#   Description     : string
#   EventIDs        : int[]           - match any of these
#   Channels        : string[]        - null = any channel
#   FieldMatches    : hashtable       - [fieldName] -> string[]  (ANY value matches)
#   FieldNotMatch   : hashtable       - [fieldName] -> string[]  (none must match)
#   FieldContains   : hashtable       - [fieldName] -> string[]  (case-insensitive contains)
#   FieldNotContain : hashtable       - [fieldName] -> string[]  (must not contain)
#   FieldRegex      : hashtable       - [fieldName] -> string    (regex match)
#   FieldNotRegex   : hashtable       - [fieldName] -> string    (regex must NOT match)
#   FieldExists     : string[]        - field must be present and non-empty
#   Threshold       : hashtable       - { Count; TimeWindowSeconds; GroupBy }
#   Severity        : string
#   MitreTactic     : string
#   MitreTechniqueID: string
#   MitreTechnique  : string
#   TacticName      : string
#   Recommendation  : string
#   FalsePositives  : string[]
# ================================================================

$script:DetectionRules = @(

    # ================================================================
    # CREDENTIAL ACCESS
    # ================================================================

    [PSCustomObject]@{
        RuleID           = 'ZVS-CA-001'
        Title            = 'Brute Force: Multiple Failed Logon Attempts'
        Description      = 'Multiple consecutive failed authentications from a single source IP within a short time window. Indicative of password guessing or credential stuffing.'
        EventIDs         = @(4625)
        Channels         = @('Security')
        FieldNotMatch    = @{ 'TargetUserName' = @('-','','ANONYMOUS LOGON') }
        Threshold        = @{ Count = 5; TimeWindowSeconds = 300; GroupBy = 'IpAddress' }
        Severity         = 'Medium'
        MitreTactic      = 'TA0006'
        MitreTechniqueID = 'T1110.001'
        MitreTechnique   = 'Brute Force: Password Guessing'
        TacticName       = 'Credential Access'
        Recommendation   = 'Investigate source IP. Verify whether a successful logon followed. Consider blocking source IP and enabling account lockout policy.'
        FalsePositives   = @('Misconfigured services re-using stale credentials','Password expiry sync','Backup software with cached credentials')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-CA-002'
        Title            = 'Password Spray: Same Password Across Multiple Accounts'
        Description      = 'Single source IP attempting authentication against many different accounts - classic password spray pattern avoiding lockout thresholds.'
        EventIDs         = @(4625)
        Channels         = @('Security')
        FieldNotMatch    = @{ 'TargetUserName' = @('-','','ANONYMOUS LOGON') }
        Threshold        = @{ Count = 10; TimeWindowSeconds = 600; GroupBy = 'IpAddress'; UniqueField = 'TargetUserName'; UniqueMin = 5 }
        Severity         = 'High'
        MitreTactic      = 'TA0006'
        MitreTechniqueID = 'T1110.003'
        MitreTechnique   = 'Brute Force: Password Spraying'
        TacticName       = 'Credential Access'
        Recommendation   = 'Block source IP. Audit all targeted accounts for compromise. Review MFA status.'
        FalsePositives   = @('Misconfigured service accounts','Network scanner with auth')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-CA-003'
        Title            = 'Account Lockout'
        Description      = 'A user account has been locked out, suggesting brute-force or automated credential attacks.'
        EventIDs         = @(4740)
        Channels         = @('Security')
        FieldNotMatch    = @{ 'TargetUserName' = @('-','','SYSTEM') }
        Threshold        = $null
        Severity         = 'Medium'
        MitreTactic      = 'TA0006'
        MitreTechniqueID = 'T1110'
        MitreTechnique   = 'Brute Force'
        TacticName       = 'Credential Access'
        Recommendation   = 'Identify the source (CallerComputerName), unlock the account if legitimate, investigate if repeated.'
        FalsePositives   = @('User forgot password','Password change not propagated')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-CA-004'
        Title            = 'Kerberoasting: RC4 Service Ticket Requested'
        Description      = 'Kerberos service ticket requested with RC4 (0x17) encryption for a non-machine account SPN - classic Kerberoasting indicator.'
        EventIDs         = @(4769)
        Channels         = @('Security')
        FieldMatches     = @{ 'TicketEncryptionType' = @('0x17','23') }
        FieldNotRegex    = @{ 'ServiceName' = '\$$' }
        FieldNotMatch    = @{ 'ServiceName' = @('krbtgt','kadmin/changepw') }
        Threshold        = $null
        Severity         = 'High'
        MitreTactic      = 'TA0006'
        MitreTechniqueID = 'T1558.003'
        MitreTechnique   = 'Steal or Forge Kerberos Tickets: Kerberoasting'
        TacticName       = 'Credential Access'
        Recommendation   = 'Identify the requesting account, check if it has a weak password, rotate service account passwords, use AES-only ticket encryption.'
        FalsePositives   = @('Legacy applications requiring RC4','Older domain controllers')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-CA-005'
        Title            = 'Kerberoasting: Mass Service Ticket Requests (RC4)'
        Description      = 'High volume of RC4 Kerberos service ticket requests in a short window - automated Kerberoasting tool activity.'
        EventIDs         = @(4769)
        Channels         = @('Security')
        FieldMatches     = @{ 'TicketEncryptionType' = @('0x17','23') }
        FieldNotRegex    = @{ 'ServiceName' = '\$$' }
        Threshold        = @{ Count = 10; TimeWindowSeconds = 60; GroupBy = 'IpAddress' }
        Severity         = 'Critical'
        MitreTactic      = 'TA0006'
        MitreTechniqueID = 'T1558.003'
        MitreTechnique   = 'Steal or Forge Kerberos Tickets: Kerberoasting'
        TacticName       = 'Credential Access'
        Recommendation   = 'Immediately investigate requesting host. Likely use of Rubeus, Invoke-Kerberoast or similar. Isolate if confirmed.'
        FalsePositives   = @('Application scanning all SPNs (rare)')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-CA-006'
        Title            = 'AS-REP Roasting: Kerberos Pre-Authentication Not Required'
        Description      = 'Kerberos TGT requested without pre-authentication (PreAuthType=0). Account may have "Do not require Kerberos preauthentication" enabled, enabling offline hash cracking.'
        EventIDs         = @(4768)
        Channels         = @('Security')
        FieldMatches     = @{ 'PreAuthType' = @('0') }
        FieldNotMatch    = @{ 'TargetUserName' = @('-','') }
        Threshold        = $null
        Severity         = 'High'
        MitreTactic      = 'TA0006'
        MitreTechniqueID = 'T1558.004'
        MitreTechnique   = 'Steal or Forge Kerberos Tickets: AS-REP Roasting'
        TacticName       = 'Credential Access'
        Recommendation   = 'Enable Kerberos pre-authentication on the affected account. Use a strong, unique password for the account.'
        FalsePositives   = @('Deliberately disabled pre-auth for legacy compatibility')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-CA-007'
        Title            = 'Golden Ticket: krbtgt Service Ticket Requested'
        Description      = 'A Kerberos service ticket was requested for the krbtgt service - possible Golden Ticket usage or forged ticket attack.'
        EventIDs         = @(4769)
        Channels         = @('Security')
        FieldMatches     = @{ 'ServiceName' = @('krbtgt') }
        Threshold        = $null
        Severity         = 'Critical'
        MitreTactic      = 'TA0006'
        MitreTechniqueID = 'T1558.001'
        MitreTechnique   = 'Steal or Forge Kerberos Tickets: Golden Ticket'
        TacticName       = 'Credential Access'
        Recommendation   = 'Investigate immediately. Correlate with unusual admin activity. If confirmed, reset krbtgt password twice and investigate DC compromise.'
        FalsePositives   = @('Extremely rare legitimate case')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-CA-008'
        Title            = 'DCSync: Directory Replication Services Access'
        Description      = 'An account requested DS-Replication permissions on the domain object - DCSync attack pattern used to dump domain credentials.'
        EventIDs         = @(4662)
        Channels         = @('Security')
        FieldRegex       = @{ 'Properties' = '(?i)(1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c|1131f6aa|1131f6ad|89e95b76)' }
        FieldNotRegex    = @{ 'SubjectUserName' = '.*\$$' }
        FieldNotMatch    = @{ 'SubjectUserName' = @('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','-','MSOL_','ANONYMOUS LOGON') }
        Threshold        = $null
        Severity         = 'Critical'
        MitreTactic      = 'TA0006'
        MitreTechniqueID = 'T1003.006'
        MitreTechnique   = 'OS Credential Dumping: DCSync'
        TacticName       = 'Credential Access'
        Recommendation   = 'Immediately investigate account. DCSync allows full domain credential dump. Treat as full domain compromise if confirmed.'
        FalsePositives   = @('Domain controllers replicating (filter machine accounts)','Azure AD Connect sync account')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-CA-009'
        Title            = 'SAM Database Access Attempt'
        Description      = 'Direct access to the SAM object via Security Account Manager - may indicate local credential extraction.'
        EventIDs         = @(4661)
        Channels         = @('Security')
        FieldContains    = @{ 'ObjectName' = @('SAM_DOMAIN','SAM_USER') }
        FieldNotMatch    = @{ 'SubjectUserName' = @('SYSTEM','-') }
        Threshold        = $null
        Severity         = 'High'
        MitreTactic      = 'TA0006'
        MitreTechniqueID = 'T1003.002'
        MitreTechnique   = 'OS Credential Dumping: Security Account Manager'
        TacticName       = 'Credential Access'
        Recommendation   = 'Investigate the process that triggered the access. Check for LSASS dumps or credential extraction tools.'
        FalsePositives   = @('Legitimate AD management tools','Group Policy processing')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-CA-010'
        Title            = 'Pass-the-Hash Indicator: Network NTLM Logon'
        Description      = 'Network logon using NTLM authentication - common Pass-the-Hash indicator, especially when the source machine does not match the user domain.'
        EventIDs         = @(4624)
        Channels         = @('Security')
        FieldMatches     = @{ 'LogonType' = @('3'); 'AuthenticationPackageName' = @('NTLM','NtLmSsp') }
        FieldNotMatch    = @{ 'TargetUserName' = @('ANONYMOUS LOGON','-','') }
        FieldNotRegex    = @{ 'TargetUserName' = '.*\$$' }
        Threshold        = $null
        Severity         = 'Low'
        MitreTactic      = 'TA0008'
        MitreTechniqueID = 'T1550.002'
        MitreTechnique   = 'Use Alternate Authentication Material: Pass the Hash'
        TacticName       = 'Lateral Movement'
        Recommendation   = 'Correlate with other suspicious activity. Single occurrences may be legitimate. Multiple targets from same source is suspicious.'
        FalsePositives   = @('Legacy Windows applications','Workgroup environments','File share access')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-CA-011'
        Title            = 'Kerberos Pre-Authentication Failure'
        Description      = 'Kerberos pre-authentication failed, possible online password guessing against Kerberos.'
        EventIDs         = @(4771)
        Channels         = @('Security')
        FieldNotMatch    = @{ 'TargetUserName' = @('-','') }
        Threshold        = @{ Count = 5; TimeWindowSeconds = 300; GroupBy = 'ClientAddress' }
        Severity         = 'Medium'
        MitreTactic      = 'TA0006'
        MitreTechniqueID = 'T1110.001'
        MitreTechnique   = 'Brute Force: Password Guessing'
        TacticName       = 'Credential Access'
        Recommendation   = 'Investigate the client address. Correlate with successful TGT requests.'
        FalsePositives   = @('Misconfigured clock skew','Service with wrong credentials')
    }

    # ================================================================
    # DEFENSE EVASION
    # ================================================================

    [PSCustomObject]@{
        RuleID           = 'ZVS-DE-001'
        Title            = 'Security Event Log Cleared'
        Description      = 'The Windows Security audit log was cleared. Attackers clear logs to remove evidence of their activity.'
        EventIDs         = @(1102)
        Channels         = @('Security')
        Threshold        = $null
        Severity         = 'High'
        MitreTactic      = 'TA0005'
        MitreTechniqueID = 'T1070.001'
        MitreTechnique   = 'Indicator Removal: Clear Windows Event Logs'
        TacticName       = 'Defense Evasion'
        Recommendation   = 'Investigate who cleared the log (SubjectUserName), correlate with other suspicious activity, consider forwarding logs to SIEM in real-time.'
        FalsePositives   = @('Scheduled maintenance (if documented)','Disk space management')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-DE-002'
        Title            = 'System Event Log Cleared'
        Description      = 'The Windows System log was cleared.'
        EventIDs         = @(104)
        Channels         = @('System')
        Threshold        = $null
        Severity         = 'High'
        MitreTactic      = 'TA0005'
        MitreTechniqueID = 'T1070.001'
        MitreTechnique   = 'Indicator Removal: Clear Windows Event Logs'
        TacticName       = 'Defense Evasion'
        Recommendation   = 'Correlate with Security log clearing (EID 1102). Investigate the user account that performed this action.'
        FalsePositives   = @('Scheduled maintenance')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-DE-003'
        Title            = 'Audit Policy Modified'
        Description      = 'Windows audit policy was changed. Attackers modify audit settings to avoid generating logs - but Windows also re-applies audit subcategories in bulk at boot/logon, so this is medium-severity and best assessed after deduplication and by context (off-hours, unexpected account).'
        EventIDs         = @(4719)
        Channels         = @('Security')
        FieldNotMatch    = @{ 'SubjectUserName' = @('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','-') }
        FieldNotRegex    = @{ 'SubjectUserName' = '.*\$$' }
        Threshold        = $null
        Severity         = 'Medium'
        MitreTactic      = 'TA0005'
        MitreTechniqueID = 'T1562.002'
        MitreTechnique   = 'Impair Defenses: Disable Windows Event Logging'
        TacticName       = 'Defense Evasion'
        Recommendation   = 'Review the change, verify it was authorized. Check audit policy baseline.'
        FalsePositives   = @('Authorized GPO changes','Security tool deployment')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-DE-004'
        Title            = 'System Time Changed'
        Description      = 'System time was modified by a non-SYSTEM process - possible timestomping or log manipulation.'
        EventIDs         = @(4616)
        Channels         = @('Security')
        FieldNotMatch    = @{ 'SubjectUserName' = @('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','-') }
        Threshold        = $null
        Severity         = 'Medium'
        MitreTactic      = 'TA0005'
        MitreTechniqueID = 'T1070.006'
        MitreTechnique   = 'Indicator Removal: Timestomp'
        TacticName       = 'Defense Evasion'
        Recommendation   = 'Verify if this was an authorized NTP adjustment. Investigate who changed the time and why.'
        FalsePositives   = @('NTP synchronization','VM clock adjustment','Daylight saving adjustment')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-DE-005'
        Title            = 'Windows Firewall Disabled or Rule Added'
        Description      = 'Windows Firewall was turned off or a new inbound rule was added - may indicate attacker bypassing perimeter controls.'
        EventIDs         = @(4946, 4950, 4947, 4948)
        Channels         = @('Security')
        Threshold        = $null
        Severity         = 'Low'
        MitreTactic      = 'TA0005'
        MitreTechniqueID = 'T1562.004'
        MitreTechnique   = 'Impair Defenses: Disable or Modify System Firewall'
        TacticName       = 'Defense Evasion'
        Recommendation   = 'Review the firewall rule (see RuleName/ProfileChanged in raw fields) or setting change. Verify it was authorized. Note: these events do not record the acting user - correlate by time with process-creation events.'
        FalsePositives   = @('Software installation','GPO-driven firewall policy changes','Authorized administration')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-DE-006'
        Title            = 'PowerShell AMSI Bypass Detected'
        Description      = 'Script block logging captured code attempting to disable or bypass AMSI (Antimalware Scan Interface).'
        EventIDs         = @(4104)
        Channels         = @('Microsoft-Windows-PowerShell/Operational')
        FieldRegex       = @{ 'ScriptBlockText' = '(?i)(amsiInitFailed|AmsiScanBuffer|AmsiUtils|amsiContext|amsiSession|Disable-Amsi|bypass.{0,15}amsi|amsi.{0,15}bypass|System\.Management\.Automation\.Amsi|\[Ref\]\.Assembly\.GetType.*Amsi|amsi\.dll)' }
        Threshold        = $null
        Severity         = 'Critical'
        MitreTactic      = 'TA0005'
        MitreTechniqueID = 'T1562.001'
        MitreTechnique   = 'Impair Defenses: Disable or Modify Tools'
        TacticName       = 'Defense Evasion'
        Recommendation   = 'Investigate the full script block. This is a strong indicator of malicious intent. Check process lineage.'
        FalsePositives   = @('Security research tools (unlikely in production)')
    }

    # ================================================================
    # EXECUTION
    # ================================================================

    [PSCustomObject]@{
        RuleID           = 'ZVS-EX-001'
        Title            = 'PowerShell Encoded Command Execution'
        Description      = 'PowerShell launched with encoded command parameter - common technique to obfuscate malicious code.'
        EventIDs         = @(4688, 1)
        Channels         = $null
        FieldRegex       = @{ 'CommandLine' = '(?i)(powershell|pwsh).{0,40}\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+[A-Za-z0-9+/=]{20,}' }
        Threshold        = $null
        Severity         = 'High'
        MitreTactic      = 'TA0002'
        MitreTechniqueID = 'T1059.001'
        MitreTechnique   = 'Command and Scripting Interpreter: PowerShell'
        TacticName       = 'Execution'
        Recommendation   = 'Decode the base64 payload and analyse the script. Review the parent process and user context.'
        FalsePositives   = @('Legitimate automation scripts using encoded parameters','SCCM/Intune deployments')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-EX-002'
        Title            = 'PowerShell Download Cradle'
        Description      = 'PowerShell script downloading and executing code from the internet - classic dropper pattern.'
        EventIDs         = @(4104)
        Channels         = @('Microsoft-Windows-PowerShell/Operational')
        FieldRegex       = @{ 'ScriptBlockText' = '(?i)(IEX|Invoke-Expression|Invoke-WebRequest|WebClient|DownloadString|DownloadFile|New-Object.*Net\.WebClient|Start-BitsTransfer|bitsadmin.*transfer)' }
        Threshold        = $null
        Severity         = 'High'
        MitreTactic      = 'TA0002'
        MitreTechniqueID = 'T1059.001'
        MitreTechnique   = 'Command and Scripting Interpreter: PowerShell'
        TacticName       = 'Execution'
        Recommendation   = 'Analyse the full script block. Identify the remote URL. Check for staged payload delivery.'
        FalsePositives   = @('Legitimate update scripts','Security tools','Package managers')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-EX-003'
        Title            = 'PowerShell Credential Theft Signatures'
        Description      = 'Script block contains known credential theft tool signatures (Mimikatz, Invoke-Kerberoast, etc.).'
        EventIDs         = @(4104)
        Channels         = @('Microsoft-Windows-PowerShell/Operational')
        FieldRegex       = @{ 'ScriptBlockText' = '(?i)(Invoke-Mimikatz|mimikatz|sekurlsa|kerberos::list|lsadump|Invoke-Kerberoast|Get-NetSession|Invoke-BloodHound|SharpHound|PowerSploit|PowerView|Get-DomainUser|Get-DomainGroup|Invoke-ShareFinder|Find-LocalAdminAccess)' }
        Threshold        = $null
        Severity         = 'Critical'
        MitreTactic      = 'TA0006'
        MitreTechniqueID = 'T1003'
        MitreTechnique   = 'OS Credential Dumping'
        TacticName       = 'Credential Access'
        Recommendation   = 'Treat as confirmed hostile. Isolate affected host immediately. Initiate IR process.'
        FalsePositives   = @('Red team engagements (documented)','Security testing (documented)')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-EX-004'
        Title            = 'LOLBin: Living-Off-the-Land Binary Execution'
        Description      = 'Execution of native Windows binaries commonly abused for code execution, bypass, or lateral movement.'
        EventIDs         = @(4688, 1)
        Channels         = $null
        FieldRegex       = @{ 'CommandLine' = '(?i)(certutil.*(-decode|-urlcache|-split|-encode)|mshta\.exe|mshta.*(javascript|vbscript|http)|wmic.*process.*call.*create|regsvr32.*(http|scrobj|/i:|/s)|rundll32.*(javascript:|vbscript:|http|comsvcs\.dll.*minidump)|cmstp\.(exe|com)|xwizard\.exe|pcalua\.exe|syncappvpublishingserver|msiexec.*(http|https|/q.*\.msi)|forfiles.*\/p.*\/c.*\/m|appsyncpublishingserver|xwizard.*loadlib|odbcconf.*(/a|regsvr)|replace\.exe.*\\\\|msdeploy.*(-verb|-allowuntrusted)|msbuild.*\.(xml|csproj|targets)|installutil.*/logfile|regasm.*\.dll|regsvcs.*\.dll|mavinject.*\/injectrunning|fodhelper\.exe|computerdefaults\.exe|sdclt\.exe|eventvwr\.exe|wevtutil.*\b(cl|clear-log)\b|bitsadmin.*(/transfer|/addfile)|presentationhost\.exe.*http|wsreset\.exe)' }
        Threshold        = $null
        Severity         = 'High'
        MitreTactic      = 'TA0002'
        MitreTechniqueID = 'T1218'
        MitreTechnique   = 'System Binary Proxy Execution'
        TacticName       = 'Execution'
        Recommendation   = 'Investigate the command line arguments and parent process. Block unnecessary LOLBins via AppLocker/WDAC.'
        FalsePositives   = @('Legitimate admin tasks using certutil','Software deployment')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-EX-005'
        Title            = 'Suspicious Process: Office Spawning Shell'
        Description      = 'Microsoft Office application spawning a command interpreter - strong indicator of macro-based malware or exploit.'
        EventIDs         = @(4688, 1)
        Channels         = $null
        FieldRegex       = @{ 'ParentProcessName' = '(?i)(winword|excel|powerpnt|outlook|onenote|msaccess|mspub)\.exe' }
        FieldRegex2      = @{ 'NewProcessName' = '(?i)(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe|rundll32\.exe|regsvr32\.exe|certutil\.exe|bitsadmin\.exe|wmic\.exe)' }
        Threshold        = $null
        Severity         = 'Critical'
        MitreTactic      = 'TA0002'
        MitreTechniqueID = 'T1204.002'
        MitreTechnique   = 'User Execution: Malicious File'
        TacticName       = 'Execution'
        Recommendation   = 'Isolate the affected host. Identify the Office document that triggered this. Check email gateway logs.'
        FalsePositives   = @('Specific trusted macros in controlled environments')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-EX-006'
        Title            = 'WMI Process Creation'
        Description      = 'Process created via WMI (parent is WmiPrvSE.exe) - common lateral movement and execution technique.'
        EventIDs         = @(4688, 1)
        Channels         = $null
        FieldRegex       = @{ 'ParentProcessName' = '(?i)WmiPrvSE\.exe' }
        Threshold        = $null
        Severity         = 'Medium'
        MitreTactic      = 'TA0002'
        MitreTechniqueID = 'T1047'
        MitreTechnique   = 'Windows Management Instrumentation'
        TacticName       = 'Execution'
        Recommendation   = 'Review the spawned process and command line. Correlate with remote WMI calls (EID 4624 type 3 from remote host).'
        FalsePositives   = @('Management software using WMI','SCCM','Monitoring agents')
    }

    # ================================================================
    # PERSISTENCE
    # ================================================================

    [PSCustomObject]@{
        RuleID           = 'ZVS-PE-001'
        Title            = 'New Service Installed'
        Description      = 'A new Windows service was installed. Service creation is a common persistence mechanism but is also extremely common for legitimate software/driver installs, so this is low-severity context on its own - escalate via ZVS-PE-002 (suspicious path) or correlation. Drivers installed through the Windows-managed DriverStore (DriverStore\FileRepository) are suppressed: that path is INF-staged and signature-gated by Windows and is overwhelmingly device drivers (GPU/audio/chipset/AV filter drivers), not attacker persistence. Note: plain System32\drivers\*.sys is intentionally NOT suppressed, because Bring-Your-Own-Vulnerable-Driver (BYOVD) attacks stage signed drivers there.'
        EventIDs         = @(7045)
        Channels         = @('System')
        # Suppress only the Windows-managed driver store. This is a path *class*, not a
        # vendor list - it generalizes to any host (Intel/NVIDIA/Realtek/Kaspersky/VBox
        # all install device drivers through FileRepository) without chasing publishers.
        FieldNotRegex    = @{ 'ImagePath' = '(?i)DriverStore[\\/]+FileRepository[\\/]+' }
        Threshold        = $null
        Severity         = 'Low'
        MitreTactic      = 'TA0003'
        MitreTechniqueID = 'T1543.003'
        MitreTechnique   = 'Create or Modify System Process: Windows Service'
        TacticName       = 'Persistence'
        Recommendation   = 'Verify the service is authorized. Check ServiceName and ImagePath for suspicious paths or names.'
        FalsePositives   = @('Software installation','IT agent deployment','Windows updates','Signed device drivers via DriverStore')
    }

    # PE-002 (was a single noisy Critical) is split into two rules:
    #  - PE-002 Critical: genuine obfuscation / shell interpreter / inline-encoded payload
    #    in a service ImagePath. These are rarely legitimate.
    #  - PE-002b Medium: service running from a temp/AppData/user directory. This is
    #    suspicious *context*, not proof: legitimate installers (Kaspersky removal tool,
    #    Defender platform updates, vendor MSI wrappers) routinely stage binaries there.
    #    Both rules respect the built-in vendor whitelist (see $script:WhitelistRules
    #    seeding below) so signed vendor service paths (Defender, Kaspersky, Group-IB,
    #    etc.) are suppressed.
    [PSCustomObject]@{
        RuleID           = 'ZVS-PE-002'
        Title            = 'Suspicious Service: Obfuscated or Shell Payload in Path'
        Description      = 'Newly installed service whose ImagePath invokes a shell interpreter or carries an inline-encoded/obfuscated payload - a strong indicator of malicious persistence.'
        EventIDs         = @(7045)
        Channels         = @('System')
        # Tightened: only real interpreters + encoding/obfuscation markers. Bare temp/
        # programdata paths moved to PE-002b. cmd/powershell still require an argument-ish
        # context so a service literally named after a shell isn't enough on its own.
        FieldRegex       = @{ 'ImagePath' = '(?i)((cmd\.exe|powershell|pwsh)\b.*(/c|/k|-c\s|-enc|-e\s|-w\s|hidden|bypass|iex|downloadstring|frombase64)|encodedcommand|-enc\s|/e:|frombase64string|[A-Za-z0-9+/]{60,}={0,2})' }
        Threshold        = $null
        Severity         = 'Critical'
        MitreTactic      = 'TA0003'
        MitreTechniqueID = 'T1543.003'
        MitreTechnique   = 'Create or Modify System Process: Windows Service'
        TacticName       = 'Persistence'
        Recommendation   = 'Stop and disable the service immediately. Investigate the ImagePath payload. Treat as active intrusion.'
        FalsePositives   = @('Rarely legitimate')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-PE-002b'
        Title            = 'Service Running From Temp/User Directory'
        Description      = 'Newly installed service whose ImagePath executes from a temp, AppData, ProgramData or user profile directory. Common for legitimate installers and AV/EDR update wrappers, so this is context for triage, not proof of compromise - escalate by correlation or unsigned/unknown publisher.'
        EventIDs         = @(7045)
        Channels         = @('System')
        FieldRegex       = @{ 'ImagePath' = '(?i)(%temp%|\\temp\\|\\appdata\\|\\users\\[^\\]+\\(downloads|desktop|documents)\\)' }
        Threshold        = $null
        Severity         = 'Medium'
        MitreTactic      = 'TA0003'
        MitreTechniqueID = 'T1543.003'
        MitreTechnique   = 'Create or Modify System Process: Windows Service'
        TacticName       = 'Persistence'
        Recommendation   = 'Verify the publisher and signature of the ImagePath binary. Correlate with the installing user/process. Legitimate AV/EDR/MSI installers commonly use these paths.'
        FalsePositives   = @('Kaspersky removal/deployment wrappers (KAVREM)','Windows Defender platform/definition updates','MSI installer wrappers','Vendor EDR agents staged from ProgramData')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-PE-003'
        Title            = 'Scheduled Task Created'
        Description      = 'A new scheduled task was created - commonly used for persistence, execution, and lateral movement.'
        EventIDs         = @(4698)
        Channels         = @('Security')
        FieldNotMatch    = @{ 'SubjectUserName' = @('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','-') }
        Threshold        = $null
        Severity         = 'Medium'
        MitreTactic      = 'TA0003'
        MitreTechniqueID = 'T1053.005'
        MitreTechnique   = 'Scheduled Task/Job: Scheduled Task'
        TacticName       = 'Persistence'
        Recommendation   = 'Review the task definition in TaskContent. Verify the task action is authorized.'
        FalsePositives   = @('Software installation','Backup jobs','IT automation')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-PE-004'
        Title            = 'Suspicious Scheduled Task: Shell or Temp Path'
        Description      = 'Scheduled task created with suspicious action - executing PowerShell, cmd, or scripts from temp/user directories.'
        EventIDs         = @(4698)
        Channels         = @('Security')
        FieldRegex       = @{ 'TaskContent' = '(?i)(powershell|cmd\.exe|wscript|cscript|%temp%|\\temp\\|\\appdata\\|\\users\\.*\\(downloads|desktop)|mshta|rundll32|regsvr32|base64)' }
        Threshold        = $null
        Severity         = 'Critical'
        MitreTactic      = 'TA0003'
        MitreTechniqueID = 'T1053.005'
        MitreTechnique   = 'Scheduled Task/Job: Scheduled Task'
        TacticName       = 'Persistence'
        Recommendation   = 'Delete the suspicious task. Investigate the payload. Review who created it.'
        FalsePositives   = @('Limited legitimate use cases')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-PE-005'
        Title            = 'WMI Event Subscription Created (Sysmon)'
        Description      = 'WMI event subscription created - stealthy persistence mechanism that survives reboots.'
        EventIDs         = @(19, 20, 21)
        Channels         = @('Microsoft-Windows-Sysmon/Operational')
        Threshold        = $null
        Severity         = 'High'
        MitreTactic      = 'TA0003'
        MitreTechniqueID = 'T1546.003'
        MitreTechnique   = 'Event Triggered Execution: Windows Management Instrumentation Event Subscription'
        TacticName       = 'Persistence'
        Recommendation   = 'Enumerate and audit all WMI subscriptions. Remove unauthorized ones.'
        FalsePositives   = @('Management software using WMI subscriptions (rare)')
    }

    # ================================================================
    # PRIVILEGE ESCALATION
    # ================================================================

    [PSCustomObject]@{
        RuleID           = 'ZVS-PA-001'
        Title            = 'Special Privileges Assigned at Logon'
        Description      = 'Sensitive privileges were assigned at logon - may indicate privilege escalation or privileged account abuse.'
        EventIDs         = @(4672)
        Channels         = @('Security')
        FieldNotMatch    = @{ 'SubjectUserName' = @('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','-','ANONYMOUS LOGON') }
        FieldNotRegex    = @{ 'SubjectUserName' = '.*\$$' }
        Threshold        = $null
        Severity         = 'Info'
        MitreTactic      = 'TA0004'
        MitreTechniqueID = 'T1078.002'
        MitreTechnique   = 'Valid Accounts: Domain Accounts'
        TacticName       = 'Privilege Escalation'
        Recommendation   = 'Context event - fires on every privileged logon. Valuable for correlation (who held admin rights when), not as a standalone alert. Investigate only unusual accounts receiving SeDebugPrivilege/SeTcbPrivilege.'
        FalsePositives   = @('Authorized admin accounts','Service accounts with required privileges')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-PA-002'
        Title            = 'SID History Added to Account'
        Description      = 'SID history was added to a user account - can grant access to resources of the original domain and may indicate domain privilege escalation.'
        EventIDs         = @(4765, 4766)
        Channels         = @('Security')
        Threshold        = $null
        Severity         = 'Critical'
        MitreTactic      = 'TA0004'
        MitreTechniqueID = 'T1134.005'
        MitreTechnique   = 'Access Token Manipulation: SID-History Injection'
        TacticName       = 'Privilege Escalation'
        Recommendation   = 'Investigate immediately. SID history modification is rarely legitimate post-migration.'
        FalsePositives   = @('Active domain migration (documented)')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-PA-003'
        Title            = 'Token Privilege Manipulation'
        Description      = 'A process attempted to use or adjust sensitive token privileges - possible privilege escalation.'
        EventIDs         = @(4703)
        Channels         = @('Security')
        FieldRegex       = @{ 'EnabledPrivileges' = '(?i)(SeDebugPrivilege|SeTcbPrivilege|SeLoadDriverPrivilege|SeRestorePrivilege|SeTakeOwnershipPrivilege|SeCreateTokenPrivilege)' }
        FieldNotMatch    = @{ 'SubjectUserName' = @('SYSTEM','-') }
        Threshold        = $null
        Severity         = 'High'
        MitreTactic      = 'TA0004'
        MitreTechniqueID = 'T1134.001'
        MitreTechnique   = 'Access Token Manipulation: Token Impersonation/Theft'
        TacticName       = 'Privilege Escalation'
        Recommendation   = 'Investigate the process and account. SeDebugPrivilege is particularly sensitive.'
        FalsePositives   = @('System processes','Privileged admin tools')
    }

    # ================================================================
    # LATERAL MOVEMENT
    # ================================================================

    [PSCustomObject]@{
        RuleID           = 'ZVS-LM-001'
        Title            = 'Remote Desktop Logon'
        Description      = 'Successful RemoteInteractive (RDP) logon from a remote source.'
        EventIDs         = @(4624)
        Channels         = @('Security')
        FieldMatches     = @{ 'LogonType' = @('10') }
        FieldNotMatch    = @{ 'IpAddress' = @('-','','::1','127.0.0.1') }
        FieldNotRegex    = @{ 'TargetUserName' = '.*\$$' }
        Threshold        = $null
        Severity         = 'Low'
        MitreTactic      = 'TA0008'
        MitreTechniqueID = 'T1021.001'
        MitreTechnique   = 'Remote Services: Remote Desktop Protocol'
        TacticName       = 'Lateral Movement'
        Recommendation   = 'Verify the source IP and user are authorized for RDP. Watch for unusual hours or unexpected accounts.'
        FalsePositives   = @('Authorized remote administration','Helpdesk access')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-LM-002'
        Title            = 'RDP Brute Force'
        Description      = 'Multiple failed remote desktop (RDP) logon attempts from the same source - RDP brute force attack.'
        EventIDs         = @(4625)
        Channels         = @('Security')
        FieldMatches     = @{ 'LogonType' = @('10','3') }
        FieldNotMatch    = @{ 'IpAddress' = @('-','','::1','127.0.0.1') }
        Threshold        = @{ Count = 8; TimeWindowSeconds = 300; GroupBy = 'IpAddress' }
        Severity         = 'High'
        MitreTactic      = 'TA0008'
        MitreTechniqueID = 'T1110.001'
        MitreTechnique   = 'Brute Force: Password Guessing'
        TacticName       = 'Lateral Movement'
        Recommendation   = 'Block the source IP. Enable account lockout. Consider deploying RDP gateway.'
        FalsePositives   = @('Misconfigured remote access client')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-LM-003'
        Title            = 'Explicit Credential Logon (runas / network)'
        Description      = 'Logon using explicitly provided credentials (runas, network logon with alternate credentials) - possible lateral movement or privilege escalation attempt.'
        EventIDs         = @(4648)
        Channels         = @('Security')
        FieldNotMatch    = @{ 'SubjectUserName' = @('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','-') }
        FieldNotRegex    = @{ 'SubjectUserName' = '.*\$$' }
        Threshold        = $null
        Severity         = 'Medium'
        MitreTactic      = 'TA0008'
        MitreTechniqueID = 'T1550'
        MitreTechnique   = 'Use Alternate Authentication Material'
        TacticName       = 'Lateral Movement'
        Recommendation   = 'Review the target account and server. Frequency and pattern analysis helps distinguish legitimate use from lateral movement.'
        FalsePositives   = @('Authorized runas usage','Scripted admin tasks')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-LM-004'
        Title            = 'Remote Thread Injection (Sysmon)'
        Description      = 'A process created a remote thread in another process - classic process injection technique used in many malware families.'
        EventIDs         = @(8)
        Channels         = @('Microsoft-Windows-Sysmon/Operational')
        FieldNotRegex    = @{
            'SourceImage'  = '(?i)(csrss\.exe|lsass\.exe|svchost\.exe)'
            'TargetImage'  = '(?i)(csrss\.exe)'
        }
        Threshold        = $null
        Severity         = 'High'
        MitreTactic      = 'TA0005'
        MitreTechniqueID = 'T1055.003'
        MitreTechnique   = 'Process Injection: Thread Execution Hijacking'
        TacticName       = 'Defense Evasion'
        Recommendation   = 'Investigate source and target processes. Check for in-memory malware.'
        FalsePositives   = @('AV/EDR products','Debugging tools')
    }

    # ================================================================
    # DISCOVERY
    # ================================================================

    [PSCustomObject]@{
        RuleID           = 'ZVS-DI-001'
        Title            = 'Local Group Membership Enumeration'
        Description      = 'A process or user enumerated local group membership - reconnaissance for privilege escalation or lateral movement.'
        EventIDs         = @(4798, 4799)
        Channels         = @('Security')
        FieldNotMatch    = @{ 'SubjectUserName' = @('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','-') }
        FieldNotRegex    = @{ 'SubjectUserName' = '.*\$$' }
        Threshold        = @{ Count = 5; TimeWindowSeconds = 120; GroupBy = 'SubjectUserName' }
        Severity         = 'Medium'
        MitreTactic      = 'TA0007'
        MitreTechniqueID = 'T1087.001'
        MitreTechnique   = 'Account Discovery: Local Account'
        TacticName       = 'Discovery'
        Recommendation   = 'Correlate with other reconnaissance activity. Volume or pattern (hitting admin groups) is the key indicator.'
        FalsePositives   = @('Security auditing tools','IT inventory software','Group Policy processing')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-DI-002'
        Title            = 'Administrators Group Membership Enumeration'
        Description      = 'The local Administrators group membership was specifically enumerated - targeted privilege reconnaissance.'
        EventIDs         = @(4799)
        Channels         = @('Security')
        FieldRegex       = @{ 'TargetUserName' = '(?i)(administrators|domain admins|enterprise admins)' }
        FieldNotMatch    = @{ 'SubjectUserName' = @('SYSTEM','-') }
        Threshold        = $null
        Severity         = 'High'
        MitreTactic      = 'TA0007'
        MitreTechniqueID = 'T1087.002'
        MitreTechnique   = 'Account Discovery: Domain Account'
        TacticName       = 'Discovery'
        Recommendation   = 'Investigate why this account is querying admin group membership. Correlate with BloodHound/SharpHound activity.'
        FalsePositives   = @('Security tools','Domain controllers')
    }

    # ================================================================
    # PERSISTENCE - ACCOUNT MANIPULATION
    # ================================================================

    [PSCustomObject]@{
        RuleID           = 'ZVS-AM-001'
        Title            = 'New User Account Created'
        Description      = 'A new user account was created - may indicate persistence via backdoor account creation.'
        EventIDs         = @(4720)
        Channels         = @('Security')
        FieldNotMatch    = @{ 'SubjectUserName' = @('SYSTEM','-') }
        Threshold        = $null
        Severity         = 'Medium'
        MitreTactic      = 'TA0003'
        MitreTechniqueID = 'T1136.001'
        MitreTechnique   = 'Create Account: Local Account'
        TacticName       = 'Persistence'
        Recommendation   = 'Verify the account creation was authorized. Check if the account was immediately added to privileged groups.'
        FalsePositives   = @('Authorized IT provisioning','Service account creation')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-AM-002'
        Title            = 'User Added to Administrators or Domain Admins Group'
        Description      = 'A user was added to a high-privilege group - direct privilege escalation or persistence mechanism.'
        EventIDs         = @(4732, 4728, 4756)
        Channels         = @('Security')
        FieldRegex       = @{ 'TargetUserName' = '(?i)(administrators|domain admins|enterprise admins|schema admins|group policy creator owners|backup operators|account operators|print operators|server operators)' }
        FieldNotMatch    = @{ 'SubjectUserName' = @('SYSTEM','-') }
        Threshold        = $null
        Severity         = 'High'
        MitreTactic      = 'TA0004'
        MitreTechniqueID = 'T1098.007'
        MitreTechnique   = 'Account Manipulation: Additional Group Membership'
        TacticName       = 'Privilege Escalation'
        Recommendation   = 'Immediately verify authorization. If unauthorized, remove the account from the group and investigate.'
        FalsePositives   = @('Authorized admin provisioning')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-AM-003'
        Title            = 'Computer Account Created'
        Description      = 'A new computer account was created in the domain - may indicate unauthorized domain join or machine account attack setup.'
        EventIDs         = @(4741)
        Channels         = @('Security')
        FieldNotMatch    = @{ 'SubjectUserName' = @('SYSTEM','-') }
        Threshold        = $null
        Severity         = 'Medium'
        MitreTactic      = 'TA0003'
        MitreTechniqueID = 'T1136.002'
        MitreTechnique   = 'Create Account: Domain Account'
        TacticName       = 'Persistence'
        Recommendation   = 'Verify the machine account was created through authorized channels.'
        FalsePositives   = @('Domain join during imaging','Authorized server provisioning')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-AM-004'
        Title            = 'User Account Kerberos Pre-Auth Disabled'
        Description      = 'A user account was modified to disable Kerberos pre-authentication - enables AS-REP Roasting attacks.'
        EventIDs         = @(4738)
        Channels         = @('Security')
        FieldRegex       = @{ 'UserAccountControl' = '(?i)(DONT_REQ_PREAUTH|Don.t Require Preauth|2097152|%%2050)' }
        Threshold        = $null
        Severity         = 'High'
        MitreTactic      = 'TA0006'
        MitreTechniqueID = 'T1558.004'
        MitreTechnique   = 'Steal or Forge Kerberos Tickets: AS-REP Roasting'
        TacticName       = 'Credential Access'
        Recommendation   = 'Re-enable pre-authentication on the account. Investigate who made the change.'
        FalsePositives   = @('Rarely legitimate')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-AM-005'
        Title            = 'Domain Policy or Trust Modified'
        Description      = 'Domain policy or trust settings were modified - may enable new attack paths or weaken security posture.'
        EventIDs         = @(4739, 4706, 4707)
        Channels         = @('Security')
        Threshold        = $null
        Severity         = 'High'
        MitreTactic      = 'TA0005'
        MitreTechniqueID = 'T1484.001'
        MitreTechnique   = 'Domain Policy Modification'
        TacticName       = 'Defense Evasion'
        Recommendation   = 'Review the policy change. Verify it was authorized and follows change management.'
        FalsePositives   = @('Authorized domain configuration changes')
    }

    # ================================================================
    # LSASS / PROCESS ACCESS (Sysmon)
    # ================================================================

    [PSCustomObject]@{
        RuleID           = 'ZVS-CR-001'
        Title            = 'LSASS Memory Access (Sysmon)'
        Description      = 'A process opened lsass.exe with elevated access rights - classic credential dumping via LSASS memory access.'
        EventIDs         = @(10)
        Channels         = @('Microsoft-Windows-Sysmon/Operational')
        FieldRegex       = @{ 'TargetImage' = '(?i)lsass\.exe' }
        FieldRegex2      = @{ 'GrantedAccess' = '(?i)^0x(1010|1410|143a|1438|147a|1f0fff|1f1fff|1fffff)$' }
        FieldNotRegex    = @{ 'SourceImage' = '(?i)(MsMpEng|csrss\.exe|wininit\.exe|lsass\.exe|antimalware|MpDefenderCoreService|SenseIR|SenseNdr|CSFalcon|carbon|cb\.exe|protect)' }
        Threshold        = $null
        Severity         = 'Critical'
        MitreTactic      = 'TA0006'
        MitreTechniqueID = 'T1003.001'
        MitreTechnique   = 'OS Credential Dumping: LSASS Memory'
        TacticName       = 'Credential Access'
        Recommendation   = 'Treat as confirmed credential theft attempt. Isolate host. Rotate all credentials. Check for Mimikatz, ProcDump, or similar.'
        FalsePositives   = @('AV/EDR solutions accessing LSASS','Windows Defender Credential Guard (reduce false positives by filtering known security processes)')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-CR-002'
        Title            = 'Suspicious Named Pipe Access (Sysmon)'
        Description      = 'Connection to a suspicious named pipe - used by Cobalt Strike, Metasploit, and other C2 frameworks for lateral movement.'
        EventIDs         = @(17, 18)
        Channels         = @('Microsoft-Windows-Sysmon/Operational')
        FieldRegex       = @{ 'PipeName' = '(?i)(\\msagent_[0-9a-f]{2}|\\DserNamePipe[0-9]|\\mojo\.[0-9]+\.[0-9]+|\\wkssvc_[0-9a-z]{10}|\\ntsvcs[0-9a-f]{5,10}|\\scerpc_[0-9a-f]{4,10}|\\win_svc[0-9a-f]{5}|\\UIA_PIPE|\\ShellBroadcast|\\kerberos_[0-9a-z]+|\\lsarpc[0-9a-z]+|\\samr[0-9a-z]{5,10}|\\spoolss|\\srvsvc[0-9a-z]+)' }
        Threshold        = $null
        Severity         = 'High'
        MitreTactic      = 'TA0008'
        MitreTechniqueID = 'T1134.001'
        MitreTechnique   = 'Access Token Manipulation: Token Impersonation/Theft'
        TacticName       = 'Defense Evasion'
        Recommendation   = 'Investigate the process creating the named pipe. This is a strong C2 beacon indicator.'
        FalsePositives   = @('Some legitimate Windows services use similar patterns')
    }

    # ================================================================
    # NETWORK / C2
    # ================================================================

    [PSCustomObject]@{
        RuleID           = 'ZVS-NT-001'
        Title            = 'Session Reconnect to Window Station'
        Description      = 'A disconnected session was reconnected - may indicate session hijacking.'
        EventIDs         = @(4778)
        Channels         = @('Security')
        FieldNotMatch    = @{ 'AccountName' = @('SYSTEM','-') }
        Threshold        = $null
        Severity         = 'Low'
        MitreTactic      = 'TA0008'
        MitreTechniqueID = 'T1563.002'
        MitreTechnique   = 'Remote Service Session Hijacking: RDP Hijacking'
        TacticName       = 'Lateral Movement'
        Recommendation   = 'Verify the reconnecting account and source IP were expected.'
        FalsePositives   = @('Normal reconnect after network drop','Remote work')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-NT-002'
        Title            = 'DNS Query to Suspicious TLD (Sysmon)'
        Description      = 'DNS query to a suspicious top-level domain often associated with C2 infrastructure.'
        EventIDs         = @(22)
        Channels         = @('Microsoft-Windows-Sysmon/Operational')
        FieldRegex       = @{ 'QueryName' = '(?i)\.(top|xyz|pw|cc|tk|ml|ga|cf|gq|bit|onion|dyn\.dns|ddns\.|no-ip\.|hopto\.|myftp\.|servebeer\.)' }
        Threshold        = $null
        Severity         = 'Medium'
        MitreTactic      = 'TA0011'
        MitreTechniqueID = 'T1071.004'
        MitreTechnique   = 'Application Layer Protocol: DNS'
        TacticName       = 'Command and Control'
        Recommendation   = 'Investigate the querying process and full DNS name. Block at DNS level if confirmed malicious.'
        FalsePositives   = @('Some legitimate services using non-standard TLDs')
    }

    # ================================================================
    # IMPACT / RANSOMWARE
    # ================================================================

    [PSCustomObject]@{
        RuleID           = 'ZVS-IM-001'
        Title            = 'Inhibit System Recovery: Shadow Copy / Backup Deletion'
        Description      = 'Deletion or resizing of Volume Shadow Copies, backup catalogs, or disabling of Windows recovery - one of the strongest pre-encryption ransomware indicators. Attackers destroy recovery options before deploying ransomware.'
        EventIDs         = @(4688, 1, 4104)
        Channels         = $null
        FieldRegex       = @{ 'CommandLine' = '(?i)(vssadmin.*(delete|resize).*shadow|wmic.*shadowcopy.*delete|wbadmin.*delete.*(catalog|systemstatebackup|backup)|bcdedit.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|Delete-VolumeShadowCopy|Get-WmiObject.*Win32_Shadowcopy.*Delete|vssadmin.*resize.*shadowstorage.*/maxsize)' }
        Threshold        = $null
        Severity         = 'Critical'
        MitreTactic      = 'TA0040'
        MitreTechniqueID = 'T1490'
        MitreTechnique   = 'Inhibit System Recovery'
        TacticName       = 'Impact'
        Recommendation   = 'Treat as imminent ransomware. Isolate the host IMMEDIATELY - encryption may be in progress or imminent. Identify the parent process and initiate emergency IR. Preserve backups offline.'
        FalsePositives   = @('Rare authorized backup maintenance (should be documented and scheduled)')
    }

    # ================================================================
    # CREDENTIAL ACCESS (additional)
    # ================================================================

    [PSCustomObject]@{
        RuleID           = 'ZVS-CR-003'
        Title            = 'LSASS Credential Dump via comsvcs.dll MiniDump'
        Description      = 'rundll32 invoking comsvcs.dll MiniDump to dump LSASS process memory - a fileless living-off-the-land credential theft technique that bypasses tools dropping mimikatz.exe.'
        EventIDs         = @(4688, 1, 4104)
        Channels         = $null
        FieldRegex       = @{ 'CommandLine' = '(?i)(comsvcs\.dll.{0,40}minidump|rundll32.{0,60}comsvcs.{0,40}#?\s*24|rundll32.{0,80}(MiniDump|MiniDumpW))' }
        Threshold        = $null
        Severity         = 'Critical'
        MitreTactic      = 'TA0006'
        MitreTechniqueID = 'T1003.001'
        MitreTechnique   = 'OS Credential Dumping: LSASS Memory'
        TacticName       = 'Credential Access'
        Recommendation   = 'Treat as confirmed credential theft. Isolate host, rotate all credentials that authenticated to it, hunt for the dump output file. Initiate IR.'
        FalsePositives   = @('Extremely rare - comsvcs MiniDump has no legitimate admin use')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-CA-012'
        Title            = 'WDigest Cleartext Credential Caching Enabled'
        Description      = 'Registry modification enabling WDigest UseLogonCredential, which forces Windows to cache plaintext passwords in LSASS memory - a common precursor to credential theft on modern (post-2014) systems where this is disabled by default.'
        EventIDs         = @(4688, 1, 4104)
        Channels         = $null
        FieldRegex       = @{ 'CommandLine' = '(?i)(reg.*add.*WDigest.*UseLogonCredential.*(/d\s*1|0x1)|Set-ItemProperty.*WDigest.*UseLogonCredential.*1|New-ItemProperty.*WDigest.*UseLogonCredential)' }
        Threshold        = $null
        Severity         = 'High'
        MitreTactic      = 'TA0006'
        MitreTechniqueID = 'T1112'
        MitreTechnique   = 'Modify Registry (WDigest downgrade)'
        TacticName       = 'Credential Access'
        Recommendation   = 'Revert the registry change. This is preparation for plaintext credential harvesting - hunt for subsequent LSASS access. Investigate the account and parent process.'
        FalsePositives   = @('Legacy application compatibility requirements (rare, should be documented)')
    }

    # ================================================================
    # DEFENSE EVASION (additional)
    # ================================================================

    [PSCustomObject]@{
        RuleID           = 'ZVS-DE-007'
        Title            = 'Event Log Cleared via Command Line'
        Description      = 'Event logs cleared using wevtutil, Clear-EventLog, or Remove-EventLog - command-line log destruction that complements EID 1102/104 and may catch clearing of non-Security channels.'
        EventIDs         = @(4688, 1, 4104)
        Channels         = $null
        FieldRegex       = @{ 'CommandLine' = '(?i)(wevtutil\s+(cl|clear-log)\s|Clear-EventLog|Remove-EventLog|Limit-EventLog.*-MaximumSize|fsutil\s+usn\s+deletejournal|Get-EventLog.*-LogName.*\|.*Clear-EventLog)' }
        Threshold        = $null
        Severity         = 'High'
        MitreTactic      = 'TA0005'
        MitreTechniqueID = 'T1070.001'
        MitreTechnique   = 'Indicator Removal: Clear Windows Event Logs'
        TacticName       = 'Defense Evasion'
        Recommendation   = 'Investigate which logs were cleared and by whom. Correlate with other suspicious activity around the same time. Treat as active intrusion.'
        FalsePositives   = @('Documented log maintenance scripts')
    }

    [PSCustomObject]@{
        RuleID           = 'ZVS-DE-008'
        Title            = 'Windows Defender Tampering'
        Description      = 'Disabling Windows Defender real-time protection, adding broad exclusions, or removing definitions via Set-MpPreference/Add-MpPreference/MpCmdRun - common defense evasion before payload execution.'
        EventIDs         = @(4688, 1, 4104)
        Channels         = $null
        FieldRegex       = @{ 'CommandLine' = '(?i)(Set-MpPreference.*-Disable(RealtimeMonitoring|BehaviorMonitoring|IOAVProtection|ScriptScanning|BlockAtFirstSeen).*\$?true|Add-MpPreference.*-ExclusionPath|Add-MpPreference.*-ExclusionProcess|Add-MpPreference.*-ExclusionExtension|MpCmdRun.*-RemoveDefinitions|Set-MpPreference.*-MAPSReporting\s*0|Set-MpPreference.*-SubmitSamplesConsent\s*2|sc.*(stop|delete).*(WinDefend|Sense|WdNisSvc))' }
        Threshold        = $null
        Severity         = 'High'
        MitreTactic      = 'TA0005'
        MitreTechniqueID = 'T1562.001'
        MitreTechnique   = 'Impair Defenses: Disable or Modify Tools'
        TacticName       = 'Defense Evasion'
        Recommendation   = 'Re-enable protection and review exclusions for abuse. Disabling AV or adding exclusions for temp/user paths immediately before execution is a strong attack indicator.'
        FalsePositives   = @('Authorized AV migration or sanctioned exclusions (verify against change records)')
    }

    # ================================================================
    # LATERAL MOVEMENT (additional)
    # ================================================================

    [PSCustomObject]@{
        RuleID           = 'ZVS-LM-005'
        Title            = 'Executable Written to Administrative Share'
        Description      = 'An executable, DLL, or script written to a remote ADMIN$ or C$ share - the signature of PsExec, SMBExec, and similar lateral movement / tool transfer techniques (a service binary dropped into ADMIN$).'
        EventIDs         = @(5145)
        Channels         = @('Security')
        FieldRegex       = @{ 'ShareName' = '(?i)\\\\\*\\(ADMIN\$|C\$)' }
        FieldRegex2      = @{ 'RelativeTargetName' = '(?i)\.(exe|dll|bat|cmd|ps1|vbs|scr|sys|jsp|aspx)$' }
        FieldNotRegex    = @{ 'SubjectUserName' = '.*\$$' }
        Threshold        = $null
        Severity         = 'High'
        MitreTactic      = 'TA0008'
        MitreTechniqueID = 'T1021.002'
        MitreTechnique   = 'Remote Services: SMB/Windows Admin Shares'
        TacticName       = 'Lateral Movement'
        Recommendation   = 'Identify the source IP and account. Correlate with new service creation (7045) or remote logon (4624 type 3) on this host. Strong PsExec-style lateral movement signal.'
        FalsePositives   = @('Legitimate remote software deployment (SCCM, GPO startup scripts)')
    }

    # ================================================================
    # DISCOVERY (additional)
    # ================================================================

    [PSCustomObject]@{
        RuleID           = 'ZVS-DI-003'
        Title            = 'Native Reconnaissance Commands'
        Description      = 'Execution of built-in domain/host discovery commands frequently chained by attackers post-compromise (nltest domain trusts, net group Domain Admins, whoami /all, AdFind-style queries).'
        EventIDs         = @(4688, 1)
        Channels         = $null
        FieldRegex       = @{ 'CommandLine' = '(?i)(nltest.*(/domain_trusts|/dclist|/all_trusts)|net\s+group\s+.{0,5}(domain admins|enterprise admins|domain controllers)|net\s+localgroup\s+administrators|whoami\s+/(all|groups|priv)|net\s+user\s+/domain|dsquery\s+(group|user|computer)|adfind\.exe|wmic\s+/node:|quser\b|qwinsta\b|tasklist\s+/svc.*\\\\|arp\s+-a|route\s+print|nltest\.exe)' }
        Threshold        = @{ Count = 3; TimeWindowSeconds = 300; GroupBy = 'Computer' }
        Severity         = 'Medium'
        MitreTactic      = 'TA0007'
        MitreTechniqueID = 'T1087.002'
        MitreTechnique   = 'Account Discovery: Domain Account'
        TacticName       = 'Discovery'
        Recommendation   = 'A burst of these commands from one host indicates hands-on-keyboard reconnaissance. Identify the user/process and correlate with the preceding initial access event.'
        FalsePositives   = @('Administrators and inventory/monitoring tools running discovery; tune threshold per environment')
    }

) # end $script:DetectionRules

# ================================================================
# SECTION 5: CORRELATION CHAINS
# ================================================================
# Chain schema:
#   ChainID          : string
#   Title            : string
#   Description      : string
#   Severity         : string
#   MitreTactics     : string[]
#   MitreTechniques  : string[]
#   TacticNames      : string[]
#   Steps            : array of step objects
#   GroupBy          : string  - field used to link steps together
#   MaxWindowSeconds : int     - total time window for the chain
#   Recommendation   : string
#
# Step schema:
#   StepNum          : int
#   EventIDs         : int[]
#   MinCount         : int   (default 1)
#   FieldMatches     : hashtable
#   FieldRegex       : hashtable
#   FieldNotMatch    : hashtable
# ================================================================

$script:CorrelationChains = @(

    [PSCustomObject]@{
        ChainID          = 'CHAIN-001'
        Title            = 'Brute Force Leading to Successful Logon'
        Description      = 'Multiple failed logon attempts from the same source followed by a successful authentication - indicates successful brute force.'
        Severity         = 'Critical'
        MitreTactics     = @('TA0006','TA0001')
        MitreTechniques  = @('T1110','T1078')
        TacticNames      = @('Credential Access','Initial Access')
        GroupBy          = 'IpAddress'
        MaxWindowSeconds = 900
        Steps            = @(
            [PSCustomObject]@{ StepNum=1; EventIDs=@(4625); MinCount=5; FieldNotMatch=@{ 'TargetUserName'=@('-','','ANONYMOUS LOGON') } }
            [PSCustomObject]@{ StepNum=2; EventIDs=@(4624); MinCount=1; FieldNotMatch=@{ 'TargetUserName'=@('-','','ANONYMOUS LOGON') } }
        )
        Recommendation   = 'Investigate the successfully authenticated account. Check if the IP originated the failed attempts and the successful logon. Revoke session if unauthorized.'
    }

    [PSCustomObject]@{
        ChainID          = 'CHAIN-002'
        Title            = 'Reconnaissance Followed by Lateral Movement'
        Description      = 'Group/user enumeration followed by explicit credential or network logon - reconnaissance leading to lateral movement.'
        Severity         = 'High'
        MitreTactics     = @('TA0007','TA0008')
        MitreTechniques  = @('T1087','T1021')
        TacticNames      = @('Discovery','Lateral Movement')
        GroupBy          = 'SubjectUserName'
        MaxWindowSeconds = 1800
        Steps            = @(
            [PSCustomObject]@{ StepNum=1; EventIDs=@(4798,4799); MinCount=3; FieldNotMatch=@{ 'SubjectUserName'=@('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','-') }; FieldNotRegex=@{ 'SubjectUserName'='.*\$$' } }
            [PSCustomObject]@{ StepNum=2; EventIDs=@(4648); MinCount=1; FieldNotMatch=@{ 'SubjectUserName'=@('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','-') }; FieldNotRegex=@{ 'SubjectUserName'='.*\$$' } }
        )
        Recommendation   = 'Investigate the account that performed enumeration and then logged on remotely. This is a classic attacker workflow.'
    }

    [PSCustomObject]@{
        ChainID          = 'CHAIN-003'
        Title            = 'Persistence via Service Followed by Log Clearing'
        Description      = 'Service installation followed by log clearing - attacker installs backdoor then attempts to destroy evidence.'
        Severity         = 'Critical'
        MitreTactics     = @('TA0003','TA0005')
        MitreTechniques  = @('T1543.003','T1070.001')
        TacticNames      = @('Persistence','Defense Evasion')
        GroupBy          = 'Computer'
        MaxWindowSeconds = 3600
        Steps            = @(
            [PSCustomObject]@{ StepNum=1; EventIDs=@(7045); MinCount=1 }
            [PSCustomObject]@{ StepNum=2; EventIDs=@(1102,104); MinCount=1 }
        )
        Recommendation   = 'Treat as active intrusion. Investigate the installed service. Preserve any remaining evidence. Initiate IR.'
    }

    [PSCustomObject]@{
        ChainID          = 'CHAIN-004'
        Title            = 'Account Creation Followed by Admin Group Addition'
        Description      = 'New user account created and immediately added to a privileged group - backdoor account creation pattern.'
        Severity         = 'Critical'
        MitreTactics     = @('TA0003','TA0004')
        MitreTechniques  = @('T1136.001','T1098')
        TacticNames      = @('Persistence','Privilege Escalation')
        GroupBy          = 'Computer'
        MaxWindowSeconds = 600
        Steps            = @(
            [PSCustomObject]@{ StepNum=1; EventIDs=@(4720); MinCount=1 }
            [PSCustomObject]@{ StepNum=2; EventIDs=@(4732,4728,4756); MinCount=1 }
        )
        Recommendation   = 'Disable and investigate the newly created account. Identify who created it and from which host.'
    }

    [PSCustomObject]@{
        ChainID          = 'CHAIN-005'
        Title            = 'Scheduled Task Persistence with Subsequent Execution'
        Description      = 'Scheduled task created followed by process execution - confirms the persistence mechanism is active.'
        Severity         = 'High'
        MitreTactics     = @('TA0003','TA0002')
        MitreTechniques  = @('T1053.005','T1059')
        TacticNames      = @('Persistence','Execution')
        GroupBy          = 'Computer'
        MaxWindowSeconds = 3600
        Steps            = @(
            [PSCustomObject]@{ StepNum=1; EventIDs=@(4698); MinCount=1; FieldRegex=@{ 'TaskContent'='(?i)(powershell|cmd\.exe|wscript|cscript|%temp%|\\temp\\|\\appdata\\|\\users\\.*\\(downloads|desktop)|mshta|rundll32|regsvr32|base64|-enc\s|bitsadmin|certutil)' } }
            [PSCustomObject]@{ StepNum=2; EventIDs=@(4688,1); MinCount=1; FieldRegex=@{ 'NewProcessName'='(?i)(powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)\.exe' } }
        )
        Recommendation   = 'Review the task definition and identify the process it executes. Remove if unauthorized.'
    }

    [PSCustomObject]@{
        ChainID          = 'CHAIN-006'
        Title            = 'DCSync Preparation: Recon then Replication Access'
        Description      = 'Group membership enumeration followed by directory replication access - DCSync attack preparation and execution.'
        Severity         = 'Critical'
        MitreTactics     = @('TA0007','TA0006')
        MitreTechniques  = @('T1087','T1003.006')
        TacticNames      = @('Discovery','Credential Access')
        GroupBy          = 'SubjectUserName'
        MaxWindowSeconds = 3600
        Steps            = @(
            [PSCustomObject]@{ StepNum=1; EventIDs=@(4798,4799); MinCount=2; FieldNotMatch=@{ 'SubjectUserName'=@('SYSTEM','-') } }
            [PSCustomObject]@{ StepNum=2; EventIDs=@(4662); MinCount=1; FieldRegex=@{ 'Properties'='(?i)(1131f6aa|1131f6ad|89e95b76)' } }
        )
        Recommendation   = 'Full domain compromise likely. Reset krbtgt password twice. Audit all privileged accounts. Initiate IR.'
    }

    [PSCustomObject]@{
        ChainID          = 'CHAIN-007'
        Title            = 'Kerberoasting Sweep'
        Description      = 'Multiple RC4 service ticket requests in a short window - automated Kerberoasting tool scanning all SPNs.'
        Severity         = 'Critical'
        MitreTactics     = @('TA0006')
        MitreTechniques  = @('T1558.003')
        TacticNames      = @('Credential Access')
        GroupBy          = 'IpAddress'
        MaxWindowSeconds = 120
        Steps            = @(
            [PSCustomObject]@{ StepNum=1; EventIDs=@(4769); MinCount=10; FieldMatches=@{ 'TicketEncryptionType'=@('0x17','23') }; FieldNotRegex=@{ 'ServiceName'='\$$' } }
        )
        Recommendation   = 'Isolate the requesting host. Rotate all service account passwords. Convert SPNs to use AES encryption.'
    }

    [PSCustomObject]@{
        ChainID          = 'CHAIN-008'
        Title            = 'RDP Brute Force Followed by Successful RDP Logon'
        Description      = 'Multiple failed RDP logon attempts from same source followed by a successful RDP session.'
        Severity         = 'Critical'
        MitreTactics     = @('TA0006','TA0008')
        MitreTechniques  = @('T1110','T1021.001')
        TacticNames      = @('Credential Access','Lateral Movement')
        GroupBy          = 'IpAddress'
        MaxWindowSeconds = 900
        Steps            = @(
            [PSCustomObject]@{ StepNum=1; EventIDs=@(4625); MinCount=5; FieldMatches=@{ 'LogonType'=@('10','3') }; FieldNotMatch=@{ 'IpAddress'=@('-','','::1','127.0.0.1') } }
            [PSCustomObject]@{ StepNum=2; EventIDs=@(4624); MinCount=1; FieldMatches=@{ 'LogonType'=@('10') }; FieldNotMatch=@{ 'IpAddress'=@('-','','::1','127.0.0.1') } }
        )
        Recommendation   = 'Immediately terminate the RDP session. Block source IP. Investigate target account for further compromise.'
    }

    [PSCustomObject]@{
        ChainID          = 'CHAIN-009'
        Title            = 'Log Clearing After Lateral Movement'
        Description      = 'Successful network logon followed by event log clearing on the same host - cover tracks after lateral movement.'
        Severity         = 'Critical'
        MitreTactics     = @('TA0008','TA0005')
        MitreTechniques  = @('T1021','T1070.001')
        TacticNames      = @('Lateral Movement','Defense Evasion')
        GroupBy          = 'Computer'
        MaxWindowSeconds = 7200
        Steps            = @(
            [PSCustomObject]@{ StepNum=1; EventIDs=@(4624); MinCount=1; FieldMatches=@{ 'LogonType'=@('3','10') }; FieldNotMatch=@{ 'IpAddress'=@('-','','::1','127.0.0.1') } }
            [PSCustomObject]@{ StepNum=2; EventIDs=@(1102,104); MinCount=1 }
        )
        Recommendation   = 'Treat as active intrusion. Correlate with source host activities. Preserve all remaining evidence.'
    }

    [PSCustomObject]@{
        ChainID          = 'CHAIN-010'
        Title            = 'PowerShell Encoded Execution Followed by Persistence'
        Description      = 'Obfuscated PowerShell execution followed by scheduled task or service creation - staged dropper establishing persistence.'
        Severity         = 'Critical'
        MitreTactics     = @('TA0002','TA0003')
        MitreTechniques  = @('T1059.001','T1053.005')
        TacticNames      = @('Execution','Persistence')
        GroupBy          = 'Computer'
        MaxWindowSeconds = 1800
        Steps            = @(
            [PSCustomObject]@{ StepNum=1; EventIDs=@(4104); MinCount=1; FieldRegex=@{ 'ScriptBlockText'='(?i)(-enc\s|-encodedcommand|IEX|DownloadString|WebClient)' } }
            [PSCustomObject]@{ StepNum=2; EventIDs=@(4698,7045); MinCount=1 }
        )
        Recommendation   = 'Full investigation required. Decode the PowerShell payload. Identify and remove persistence mechanisms.'
    }

) # end $script:CorrelationChains

# ================================================================
# SECTION 6: DETECTION ENGINE
# ================================================================

function Test-FieldCondition {
    <#
    .SYNOPSIS
        Evaluate a single field condition against the event's RawFields hashtable.
        Returns $true if the event matches the condition.
    #>
    param(
        [hashtable]$Fields,
        [string]$FieldName,
        [string]$ConditionType,  # Matches | NotMatch | Contains | NotContain | Regex | NotRegex
        $ConditionValue           # string[] or string
    )
    $val = if ($Fields.ContainsKey($FieldName)) { "$($Fields[$FieldName])" } else { '' }

    switch ($ConditionType) {
        'Matches' {
            foreach ($v in $ConditionValue) {
                if ($val -ieq $v) { return $true }
            }
            return $false
        }
        'NotMatch' {
            foreach ($v in $ConditionValue) {
                if ($val -ieq $v) { return $false }
            }
            return $true
        }
        'Contains' {
            foreach ($v in $ConditionValue) {
                if ($val -like "*$v*") { return $true }
            }
            return $false
        }
        'NotContain' {
            foreach ($v in $ConditionValue) {
                if ($val -like "*$v*") { return $false }
            }
            return $true
        }
        'Regex' {
            return ($val -match $ConditionValue)
        }
        'NotRegex' {
            return ($val -notmatch $ConditionValue)
        }
        'Exists' {
            return (-not [string]::IsNullOrWhiteSpace($val))
        }
    }
    return $true
}

function Test-RuleMatch {
    <#
    .SYNOPSIS
        Test whether a parsed event matches a detection rule's conditions.
        Returns $true if the event passes all conditions (AND logic).
    #>
    param($Event, $Rule)

    # 1. EventID filter
    if ($Rule.EventIDs -and ($Event.EventID -notin $Rule.EventIDs)) { return $false }

    # 2. Channel filter
    if ($Rule.Channels) {
        $channelMatch = $false
        foreach ($ch in $Rule.Channels) {
            if ($Event.Channel -like "*$ch*") { $channelMatch = $true; break }
        }
        if (-not $channelMatch) { return $false }
    }

    $rf = $Event.RawFields

    # 3. FieldMatches (AND between fields, OR between values)
    if ($Rule.FieldMatches) {
        foreach ($fname in $Rule.FieldMatches.Keys) {
            if (-not (Test-FieldCondition -Fields $rf -FieldName $fname -ConditionType 'Matches' -ConditionValue $Rule.FieldMatches[$fname])) {
                return $false
            }
        }
    }

    # 4. FieldNotMatch
    if ($Rule.FieldNotMatch) {
        foreach ($fname in $Rule.FieldNotMatch.Keys) {
            if (-not (Test-FieldCondition -Fields $rf -FieldName $fname -ConditionType 'NotMatch' -ConditionValue $Rule.FieldNotMatch[$fname])) {
                return $false
            }
        }
    }

    # 5. FieldContains
    if ($Rule.FieldContains) {
        foreach ($fname in $Rule.FieldContains.Keys) {
            if (-not (Test-FieldCondition -Fields $rf -FieldName $fname -ConditionType 'Contains' -ConditionValue $Rule.FieldContains[$fname])) {
                return $false
            }
        }
    }

    # 6. FieldNotContain
    if ($Rule.FieldNotContain) {
        foreach ($fname in $Rule.FieldNotContain.Keys) {
            if (-not (Test-FieldCondition -Fields $rf -FieldName $fname -ConditionType 'NotContain' -ConditionValue $Rule.FieldNotContain[$fname])) {
                return $false
            }
        }
    }

    # 7. FieldRegex (primary)
    if ($Rule.FieldRegex) {
        foreach ($fname in $Rule.FieldRegex.Keys) {
            if (-not (Test-FieldCondition -Fields $rf -FieldName $fname -ConditionType 'Regex' -ConditionValue $Rule.FieldRegex[$fname])) {
                return $false
            }
        }
    }

    # 8. FieldRegex2 (secondary - used when rule needs two independent regex checks)
    if ($null -ne $Rule.FieldRegex2) {
        foreach ($fname in $Rule.FieldRegex2.Keys) {
            if (-not (Test-FieldCondition -Fields $rf -FieldName $fname -ConditionType 'Regex' -ConditionValue $Rule.FieldRegex2[$fname])) {
                return $false
            }
        }
    }

    # 9. FieldNotRegex
    if ($Rule.FieldNotRegex) {
        foreach ($fname in $Rule.FieldNotRegex.Keys) {
            if (-not (Test-FieldCondition -Fields $rf -FieldName $fname -ConditionType 'NotRegex' -ConditionValue $Rule.FieldNotRegex[$fname])) {
                return $false
            }
        }
    }

    # 10. FieldExists - every listed field must be present and non-empty
    if ($Rule.FieldExists) {
        foreach ($fname in $Rule.FieldExists) {
            if (-not (Test-FieldCondition -Fields $rf -FieldName $fname -ConditionType 'Exists' -ConditionValue $null)) {
                return $false
            }
        }
    }

    return $true
}

function Invoke-DetectionEngine {
    Write-Status 'Running detection engine...' 'SECTION'

    # Pre-collect matches (before threshold filtering)
    $rawMatches = [System.Collections.Generic.List[object]]::new()

    $ruleCount = $script:DetectionRules.Count
    $processed = 0

    foreach ($rule in $script:DetectionRules) {
        $processed++
        if ($processed % 10 -eq 0) {
            Write-Status "  Rules: $processed / $ruleCount" 'INFO'
        }

        if (-not (Test-MinSeverity $rule.Severity)) { continue }

        # Get candidate events (fast path: filter by EventID if possible)
        $candidates = if ($rule.EventIDs) {
            $clist = [System.Collections.Generic.List[object]]::new()
            foreach ($eid in $rule.EventIDs) {
                if ($script:IdxByEventID.ContainsKey($eid)) {
                    foreach ($e in $script:IdxByEventID[$eid]) { $clist.Add($e) }
                }
            }
            $clist
        } else {
            $script:AllEvents
        }

        foreach ($event in $candidates) {
            if (-not (Test-RuleMatch -Event $event -Rule $rule)) { continue }
            if (Test-WhitelistMatch -Event $event -Rule $rule) { continue }
            $rawMatches.Add([PSCustomObject]@{ Event = $event; Rule = $rule })
        }
    }

    Write-Status "  Raw matches: $($rawMatches.Count)" 'INFO'

    # Apply threshold logic
    $thresholdGroups = [System.Collections.Hashtable]::new()

    foreach ($match in $rawMatches) {
        $rule = $match.Rule

        if ($null -eq $rule.Threshold) {
            # No threshold - emit finding directly
            Add-Finding -Event $match.Event -Rule $rule -IsChain $false
        } else {
            # Group for threshold processing
            $ruleID = $rule.RuleID
            if (-not $thresholdGroups.ContainsKey($ruleID)) {
                $thresholdGroups[$ruleID] = [System.Collections.Generic.List[object]]::new()
            }
            $thresholdGroups[$ruleID].Add($match)
        }
    }

    # Process threshold rules
    foreach ($ruleID in $thresholdGroups.Keys) {
        $matches    = $thresholdGroups[$ruleID]
        $rule       = $matches[0].Rule
        $threshold  = $rule.Threshold
        $groupBy    = $threshold['GroupBy']
        $minCount   = $threshold['Count']
        $windowSec  = $threshold['TimeWindowSeconds']
        $uniqueField = if ($threshold.ContainsKey('UniqueField')) { $threshold['UniqueField'] } else { $null }
        $uniqueMin   = if ($threshold.ContainsKey('UniqueMin'))   { $threshold['UniqueMin']   } else { 0 }

        # Group events by the GroupBy field value.
        # 'Computer' and 'Channel' are top-level event properties, not in RawFields.
        $grouped = [System.Collections.Hashtable]::new()
        foreach ($m in $matches) {
            if ($groupBy -eq 'Computer') {
                $gval = Get-SafeString $m.Event.Computer
            } elseif ($groupBy -eq 'Channel') {
                $gval = Get-SafeString $m.Event.Channel
            } else {
                $gval = Get-SafeString $m.Event.RawFields[$groupBy]
            }
            if ($gval -eq '-') { $gval = 'unknown' }
            if (-not $grouped.ContainsKey($gval)) {
                $grouped[$gval] = [System.Collections.Generic.List[object]]::new()
            }
            $grouped[$gval].Add($m.Event)
        }

        foreach ($gval in $grouped.Keys) {
            $eventsForGroup = @($grouped[$gval] | Sort-Object TimeCreated)
            if ($eventsForGroup.Count -lt $minCount) { continue }

            # Correct sliding window: for each event as the right edge, expand the
            # left edge until the window fits within $windowSec. If at any point the
            # number of events in the window meets the threshold, it's a detection.
            # We use a left pointer that only moves forward (monotonic) - O(n).
            $left = 0
            $fired = $false

            for ($right = 0; $right -lt $eventsForGroup.Count; $right++) {
                # Shrink window from the left until it fits the time window
                while ((($eventsForGroup[$right].TimeCreated - $eventsForGroup[$left].TimeCreated).TotalSeconds) -gt $windowSec) {
                    $left++
                }

                $windowSize = $right - $left + 1
                if ($windowSize -lt $minCount) { continue }

                # Window currently holds >= minCount events within the time window.
                # Build the window slice for unique-field validation.
                $windowHits = [System.Collections.Generic.List[object]]::new()
                for ($k = $left; $k -le $right; $k++) {
                    $windowHits.Add($eventsForGroup[$k])
                }

                # Check unique-field constraint (e.g. password spray: many distinct accounts)
                $passUnique = $true
                if ($uniqueField -and $uniqueMin -gt 0) {
                    $uniqueVals = ($windowHits | ForEach-Object { Get-SafeString $_.RawFields[$uniqueField] } |
                                   Where-Object { $_ -ne '-' } | Sort-Object -Unique).Count
                    $passUnique = ($uniqueVals -ge $uniqueMin)
                }

                if ($passUnique) {
                    # Fire ONCE per group per contiguous burst to avoid flooding findings.
                    # Use the earliest event in the window as representative.
                    Add-Finding -Event $windowHits[0] -Rule $rule -IsChain $false `
                        -GroupCount $windowHits.Count -GroupKey $gval
                    $fired = $true
                    break  # one finding per group is enough; entity scoring captures volume
                }
            }
        }
    }

    Write-Status "  Findings after threshold: $($script:Findings.Count)" 'OK'
}

function Add-Finding {
    param(
        $Event,
        $Rule,
        [bool]$IsChain,
        [int]$GroupCount = 1,
        [string]$GroupKey = '',
        [string]$ChainID = ''
    )

    $finding = [PSCustomObject]@{
        FindingID        = [System.Guid]::NewGuid().ToString('N').Substring(0,12)
        TimeCreated      = $Event.TimeCreated
        Computer         = $Event.Computer
        EventID          = $Event.EventID
        Channel          = $Event.Channel
        IsChain          = $IsChain
        ChainID          = $ChainID
        RuleID           = $Rule.RuleID
        Title            = $Rule.Title
        Severity         = $Rule.Severity
        MitreTactic      = $Rule.MitreTactic
        MitreTechniqueID = $Rule.MitreTechniqueID
        MitreTechnique   = $Rule.MitreTechnique
        TacticName       = if ($Rule.TacticName) { $Rule.TacticName } elseif ($Rule.TacticNames) { $Rule.TacticNames -join ', ' } else { '-' }
        GroupCount       = $GroupCount
        GroupKey         = $GroupKey
        SubjectUser      = Get-SafeString $Event.RawFields['SubjectUserName']
        TargetUser       = Get-SafeString $Event.RawFields['TargetUserName']
        IpAddress        = (& {
            $v = Get-SafeString $Event.RawFields['IpAddress']
            if ($v -eq '-') { $v = Get-SafeString $Event.RawFields['SourceNetworkAddress'] }
            if ($v -eq '-') { $v = Get-SafeString $Event.RawFields['ClientAddress'] }
            $v
        })
        ProcessName      = (& {
            $v = Get-SafeString $Event.RawFields['NewProcessName']
            if ($v -eq '-') { $v = Get-SafeString $Event.RawFields['Image'] }
            if ($v -eq '-') { $v = Get-SafeString $Event.RawFields['ProcessName'] }
            # For service-install events (7045) the binary path lives in ImagePath -
            # surface it here so the analyst sees what the service runs.
            if ($v -eq '-') { $v = Get-SafeString $Event.RawFields['ImagePath'] }
            $v
        })
        CommandLine      = (& {
            $v = Get-SafeString $Event.RawFields['CommandLine']
            if ($v -eq '-') { $v = Get-SafeString $Event.RawFields['ScriptBlockText'] }
            # Service install: show the full ImagePath as the command context too.
            if ($v -eq '-') { $v = Get-SafeString $Event.RawFields['ImagePath'] }
            $v
        })
        ServiceName      = (& {
            $v = Get-SafeString $Event.RawFields['ServiceName']
            # Firewall events (4946/4950/etc) carry no service or user; show the
            # rule name / changed profile so the row isn't all dashes.
            if ($v -eq '-') { $v = Get-SafeString $Event.RawFields['RuleName'] }
            if ($v -eq '-') {
                $prof = Get-SafeString $Event.RawFields['ProfileChanged']
                $sv   = Get-SafeString $Event.RawFields['SettingType']
                if ($prof -ne '-' -or $sv -ne '-') {
                    $v = (@($prof, $sv) | Where-Object { $_ -ne '-' }) -join ' / '
                }
            }
            $v
        })
        TaskName         = Get-SafeString $Event.RawFields['TaskName']
        Description      = $Rule.Description
        Recommendation   = $Rule.Recommendation
        EventRecordID    = $Event.EventRecordID
    }

    # Trim CommandLine/ScriptBlock for display (keep full for details)
    if ($finding.CommandLine.Length -gt 300) {
        $finding.CommandLine = $finding.CommandLine.Substring(0, 300) + '...'
    }

    # ---- DEDUPLICATION ----
    # Collapse identical findings into one row with a running count. Without this,
    # high-frequency benign events (boot-time audit-policy changes, service
    # installs, repeated logons) produce hundreds of identical rows that bury the
    # real signal. The key includes the distinguishing object fields so genuinely
    # different events (different service, task, IP, user) stay separate.
    # Threshold findings and chains carry their own aggregation; we still key them
    # by GroupKey/ChainID so distinct windows remain distinct.
    $dedupeKey = (@(
        $finding.RuleID, $finding.Computer, $finding.SubjectUser, $finding.TargetUser,
        $finding.IpAddress, $finding.ServiceName, $finding.TaskName, $finding.ProcessName,
        $ChainID, $GroupKey
    ) -join '|')

    if ($script:DedupeMap.ContainsKey($dedupeKey)) {
        $existing = $script:DedupeMap[$dedupeKey]
        $existing.GroupCount += $GroupCount
        # Keep the earliest occurrence as the representative timestamp, and record
        # the latest so the analyst sees the span.
        if ($Event.TimeCreated -lt $existing.TimeCreated) { $existing.TimeCreated = $Event.TimeCreated }
        if ($Event.TimeCreated -gt $existing.LastSeen)    { $existing.LastSeen    = $Event.TimeCreated }
        return   # do NOT add a duplicate row or re-score the entity
    }

    # First occurrence of this key
    $finding | Add-Member -NotePropertyName 'LastSeen' -NotePropertyValue $Event.TimeCreated
    $script:DedupeMap[$dedupeKey] = $finding
    $script:Findings.Add($finding)
    $script:TotalHits++

    # Update entity scores (once per unique finding, not per duplicate)
    $multiplier = if ($IsChain) { [decimal]2.0 } else { [decimal]1.0 }

    if ($finding.SubjectUser -ne '-') {
        Add-EntityScore -EntityType 'User' -EntityKey $finding.SubjectUser -Severity $finding.Severity -Multiplier $multiplier -Reason $finding.Title
    }
    if ($finding.TargetUser -ne '-') {
        Add-EntityScore -EntityType 'User' -EntityKey $finding.TargetUser -Severity $finding.Severity -Multiplier ($multiplier * [decimal]0.8) -Reason $finding.Title
    }
    if ($finding.IpAddress -ne '-') {
        Add-EntityScore -EntityType 'IP' -EntityKey $finding.IpAddress -Severity $finding.Severity -Multiplier $multiplier -Reason $finding.Title
    }
    if ($finding.Computer -ne '-') {
        Add-EntityScore -EntityType 'Host' -EntityKey $finding.Computer -Severity $finding.Severity -Multiplier ($multiplier * [decimal]0.7) -Reason $finding.Title
    }
}

# ================================================================
# SECTION 7: CORRELATION ENGINE
# ================================================================

function Get-LinkValue {
    <#
    .SYNOPSIS
        Resolve the "linking" value used to correlate events across a chain.
        Different event types place the same logical entity in different fields
        (e.g. a user is SubjectUserName in 4798 but TargetUserName in 4624).
        This returns the best available value for the requested link type,
        normalised (lower-case, domain stripped for users) for comparison.
    #>
    param($Event, [string]$LinkType)

    switch ($LinkType) {
        'IpAddress' {
            foreach ($f in @('IpAddress','SourceNetworkAddress','ClientAddress')) {
                $v = Get-SafeString $Event.RawFields[$f]
                if ($v -ne '-' -and $v -ne '::1' -and $v -ne '127.0.0.1') { return $v.ToLower() }
            }
            return $null
        }
        'SubjectUserName' {
            # A user may be the subject (actor) in one event and the target in another.
            # Collect every plausible user field and return them as a set string.
            $users = @()
            foreach ($f in @('SubjectUserName','TargetUserName')) {
                $v = Get-SafeString $Event.RawFields[$f]
                if ($v -ne '-' -and $v -notmatch '\$$' -and
                    $v -notmatch '(?i)^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|DWM-\d+|UMFD-\d+)$') {
                    if ($v -match '\\') { $v = ($v -split '\\')[-1] }
                    if ($v -match '@')  { $v = ($v -split '@')[0]  }
                    if ($v -match '\$$') { continue }   # machine account after domain strip
                    $users += $v.ToLower()
                }
            }
            if ($users.Count -eq 0) { return $null }
            return ($users | Sort-Object -Unique)   # array - caller does set-intersection
        }
        'Computer' {
            $v = Get-SafeString $Event.Computer
            if ($v -eq '-') { return $null }
            return $v.ToLower()
        }
        default {
            $v = Get-SafeString $Event.RawFields[$LinkType]
            if ($v -eq '-') { return $null }
            return $v.ToLower()
        }
    }
}

function Test-LinkMatch {
    <#
    .SYNOPSIS
        Compare two link values (from Get-LinkValue). Handles the user case where
        either side may be an array of candidate usernames - match on intersection.
    #>
    param($A, $B)
    if ($null -eq $A -or $null -eq $B) { return $false }

    $aArr = @($A); $bArr = @($B)
    foreach ($x in $aArr) {
        foreach ($y in $bArr) {
            if ($x -eq $y) { return $true }
        }
    }
    return $false
}

function Invoke-CorrelationEngine {
    if ($DisableCorrelation) { return }
    Write-Status 'Running correlation engine...' 'SECTION'

    $chainHits = 0

    foreach ($chain in $script:CorrelationChains) {
        if (-not (Test-MinSeverity $chain.Severity)) { continue }

        $groupBy     = $chain.GroupBy
        $maxWindow   = $chain.MaxWindowSeconds
        $firstStep   = $chain.Steps[0]

        # Get candidate events for step 1
        $step1Events = [System.Collections.Generic.List[object]]::new()
        foreach ($eid in $firstStep.EventIDs) {
            if ($script:IdxByEventID.ContainsKey($eid)) {
                foreach ($e in $script:IdxByEventID[$eid]) {
                    if (Test-StepMatch -Event $e -Step $firstStep) {
                        $step1Events.Add($e)
                    }
                }
            }
        }

        if ($step1Events.Count -eq 0) { continue }

        # Group step1 events by their resolved link value (handles user-in-different-fields)
        $grouped = [System.Collections.Hashtable]::new()
        foreach ($e in $step1Events) {
            $linkVal = Get-LinkValue -Event $e -LinkType $groupBy
            if ($null -eq $linkVal) { continue }
            # For user link type, linkVal may be an array; index by each candidate
            foreach ($lv in @($linkVal)) {
                if (-not $grouped.ContainsKey($lv)) {
                    $grouped[$lv] = [System.Collections.Generic.List[object]]::new()
                }
                $grouped[$lv].Add($e)
            }
        }

        foreach ($gval in $grouped.Keys) {
            $step1Group = $grouped[$gval]

            # Check step1 MinCount
            if ($step1Group.Count -lt $firstStep.MinCount) { continue }

            # Attempt to match remaining steps
            if ($chain.Steps.Count -eq 1) {
                # Single-step chain = pure burst threshold. Use a proper sliding
                # window: does MinCount events fall within maxWindow at any point?
                $sorted = @($step1Group | Sort-Object TimeCreated)
                $minNeeded = $firstStep.MinCount
                $left = 0
                $burstFound = $false
                $burstAnchor = $null
                for ($right = 0; $right -lt $sorted.Count; $right++) {
                    while ((($sorted[$right].TimeCreated - $sorted[$left].TimeCreated).TotalSeconds) -gt $maxWindow) {
                        $left++
                    }
                    if (($right - $left + 1) -ge $minNeeded) {
                        $burstFound = $true
                        $burstAnchor = $sorted[$left]
                        break
                    }
                }

                if ($burstFound) {
                    $chainHits++
                    $chainRule = [PSCustomObject]@{
                        RuleID           = $chain.ChainID
                        Title            = $chain.Title
                        Description      = $chain.Description
                        Severity         = $chain.Severity
                        MitreTactic      = $chain.MitreTactics[0]
                        MitreTechniqueID = $chain.MitreTechniques[0]
                        MitreTechnique   = $chain.MitreTechniques[0]
                        TacticName       = $chain.TacticNames[0]
                        Recommendation   = $chain.Recommendation
                        FieldMatches     = $null
                        FieldNotMatch    = $null
                        FieldContains    = $null
                        FieldNotContain  = $null
                        FieldRegex       = $null
                        FieldRegex2      = $null
                        FieldNotRegex    = $null
                        Threshold        = $null
                    }
                    Add-Finding -Event $burstAnchor -Rule $chainRule -IsChain $true -GroupCount $step1Group.Count -GroupKey $gval -ChainID $chain.ChainID
                }
                continue
            }

            # Multi-step chain matching.
            # Anchor on the EARLIEST step-1 event for this entity; subsequent steps
            # must occur at or after that anchor and within MaxWindowSeconds.
            $step1Sorted = @($step1Group | Sort-Object TimeCreated)
            $anchorTime  = $step1Sorted[0].TimeCreated
            $windowEnd   = $anchorTime.AddSeconds($maxWindow)

            $allStepsMatched = $true

            for ($si = 1; $si -lt $chain.Steps.Count; $si++) {
                $step = $chain.Steps[$si]
                $stepMatches = [System.Collections.Generic.List[object]]::new()

                foreach ($eid in $step.EventIDs) {
                    if ($script:IdxByEventID.ContainsKey($eid)) {
                        foreach ($e in $script:IdxByEventID[$eid]) {
                            # Temporal window: at/after anchor, before window end.
                            if ($e.TimeCreated -lt $anchorTime) { continue }
                            if ($e.TimeCreated -gt $windowEnd)  { continue }

                            # Entity linkage: resolved link value must match the group.
                            $eLink = Get-LinkValue -Event $e -LinkType $groupBy
                            if (-not (Test-LinkMatch -A $eLink -B $gval)) { continue }

                            if (Test-StepMatch -Event $e -Step $step) {
                                $stepMatches.Add($e)
                            }
                        }
                    }
                }

                if ($stepMatches.Count -lt $step.MinCount) {
                    $allStepsMatched = $false
                    break
                }
            }

            if ($allStepsMatched) {
                $chainHits++
                $chainRule = [PSCustomObject]@{
                    RuleID           = $chain.ChainID
                    Title            = $chain.Title
                    Description      = $chain.Description
                    Severity         = $chain.Severity
                    MitreTactic      = $chain.MitreTactics[0]
                    MitreTechniqueID = $chain.MitreTechniques[0]
                    MitreTechnique   = $chain.MitreTechniques -join ', '
                    TacticName       = $chain.TacticNames -join ' -> '
                    Recommendation   = $chain.Recommendation
                    FieldMatches     = $null
                    FieldNotMatch    = $null
                    FieldContains    = $null
                    FieldNotContain  = $null
                    FieldRegex       = $null
                    FieldRegex2      = $null
                    FieldNotRegex    = $null
                    Threshold        = $null
                }
                Add-Finding -Event $step1Sorted[0] -Rule $chainRule -IsChain $true -GroupCount ($step1Group.Count) -GroupKey $gval -ChainID $chain.ChainID
            }
        }
    }

    Write-Status "  Chain findings: $chainHits" 'OK'
}

function Test-StepMatch {
    param($Event, $Step)

    foreach ($ctype in @('FieldMatches','FieldNotMatch','FieldContains','FieldNotContain','FieldRegex','FieldNotRegex')) {
        $cond = $Step.$ctype
        if ($null -eq $cond) { continue }
        foreach ($fname in $cond.Keys) {
            $ctype2 = $ctype -replace 'Field',''
            $pass = Test-FieldCondition -Fields $Event.RawFields -FieldName $fname -ConditionType $ctype2 -ConditionValue $cond[$fname]
            if (-not $pass) { return $false }
        }
    }
    return $true
}

# ================================================================
# SECTION 8: TEMPORAL ANOMALY ENGINE
# ================================================================

# Accounts that authenticate continuously and at all hours by design. Flagging their
# off-hours or burst activity is pure noise - it dominated early reports with Critical
# scores on SYSTEM/DWM/UMFD/service accounts. We exclude:
#   - machine accounts (trailing $)
#   - well-known service identities (EN + RU localized names)
#   - session/desktop pseudo-accounts (DWM-*, UMFD-*)
#   - raw SIDs (S-1-5-*) which are unresolved well-known principals
#   - common AV/EDR service accounts
# A real attacker using one of these would surface via the detection RULES (logon type,
# explicit-cred, lateral movement), not via this heuristic temporal scoring.
function Test-IsMachineOrServiceAccount {
    param([string]$User)
    if ([string]::IsNullOrEmpty($User) -or $User -eq '-') { return $true }
    if ($User -match '\$$')          { return $true }   # machine account
    if ($User -match '^S-1-5-')      { return $true }   # raw SID
    if ($User -match '^(DWM|UMFD)-\d+$') { return $true }   # session/desktop accounts
    # Well-known service identities. Russian localized names are written as \uXXXX escapes
    # so this file stays pure ASCII - embedding literal Cyrillic breaks under PowerShell
    # 5.1 when the .ps1 is read as the system ANSI codepage (Windows-1251) instead of UTF-8.
    # \u0421\u0418\u0421\u0422\u0415\u041C\u0410 = SYSTEM
    # \u041B\u041E\u041A\u0410\u041B\u042C\u041D\u0410\u042F \u0421\u041B\u0423\u0416\u0411\u0410 = LOCAL SERVICE
    # \u0421\u0415\u0422\u0415\u0412\u0410\u042F \u0421\u041B\u0423\u0416\u0411\u0410 = NETWORK SERVICE
    if ($User -match '(?i)^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS( LOGON)?|\u0421\u0418\u0421\u0422\u0415\u041C\u0410|\u041B\u041E\u041A\u0410\u041B\u042C\u041D\u0410\u042F \u0421\u041B\u0423\u0416\u0411\u0410|\u0421\u0415\u0422\u0415\u0412\u0410\u042F \u0421\u041B\u0423\u0416\u0411\u0410)$') { return $true }
    # Common AV/EDR proxy/service accounts
    if ($User -match '(?i)^(ksnproxy|mssql\$|sophos|mcafee)') { return $true }
    return $false
}

function Invoke-TemporalAnalysis {
    Write-Status 'Running temporal anomaly analysis...' 'SECTION'

    $anomalies = 0

    # 1. Off-hours activity: logons outside business hours.
    # TimeCreated is UTC (Kind=Utc); shift by the monitored environment's UTC
    # offset so business hours are evaluated in THAT site's local time, not the
    # analyst workstation's. Default offset 0 = treat business hours as UTC.
    $authEvents = @(4624, 4625, 4648)
    foreach ($eid in $authEvents) {
        if (-not $script:IdxByEventID.ContainsKey($eid)) { continue }
        foreach ($e in $script:IdxByEventID[$eid]) {
            $localTime = $e.TimeCreated.ToUniversalTime().AddHours($WorkHoursTimeZoneOffset)
            $hour = $localTime.Hour
            $dow  = $localTime.DayOfWeek

            $isOffHours = ($hour -lt $WorkHoursStart -or $hour -ge $WorkHoursEnd)
            $isWeekend  = ($dow -eq [DayOfWeek]::Saturday -or $dow -eq [DayOfWeek]::Sunday)

            if (-not ($isOffHours -or $isWeekend)) { continue }

            $user = Get-SafeString $e.RawFields['TargetUserName']
            if (Test-IsMachineOrServiceAccount $user) { continue }

            $timeLabel = if ($isWeekend) { 'weekend' } else { 'off-hours' }
            $multiplier = if ($isWeekend) { [decimal]1.8 } else { [decimal]1.5 }

            Add-EntityScore -EntityType 'User' -EntityKey $user `
                -Severity 'Low' -Multiplier $multiplier `
                -Reason "Authentication event ($eid) at $timeLabel [$($localTime.ToString('yyyy-MM-dd HH:mm'))]"
            $anomalies++
        }
    }

    # 2. Burst detection: high event rate for a specific entity.
    # Proper sliding window (monotonic two-pointer, O(n)) - mirrors the threshold
    # engine. The previous tumbling-window reset could under-count bursts that
    # straddle a reset boundary.
    foreach ($user in $script:IdxByUser.Keys) {
        if (Test-IsMachineOrServiceAccount $user) { continue }
        $userEvents = @($script:IdxByUser[$user] | Sort-Object TimeCreated)
        if ($userEvents.Count -lt 20) { continue }

        # Largest number of events falling inside any 60-second sliding window.
        $left     = 0
        $maxBurst = 1
        for ($right = 0; $right -lt $userEvents.Count; $right++) {
            while ((($userEvents[$right].TimeCreated - $userEvents[$left].TimeCreated).TotalSeconds) -gt 60) {
                $left++
            }
            $windowSize = $right - $left + 1
            if ($windowSize -gt $maxBurst) { $maxBurst = $windowSize }
        }

        if ($maxBurst -ge 20) {
            Add-EntityScore -EntityType 'User' -EntityKey $user `
                -Severity 'Medium' -Multiplier ([decimal]1.5) `
                -Reason "Burst activity: $maxBurst events in 60 seconds"
            $anomalies++
        }
    }

    Write-Status "  Temporal anomalies: $anomalies" 'OK'
}

# ================================================================
# SECTION 9: HTML REPORT GENERATOR
# ================================================================

function New-HtmlReport {
    param([string]$OutFile)

    Write-Status 'Generating HTML report...' 'SECTION'

    # Pre-process data
    $findings   = $script:Findings | Sort-Object { $script:SeverityWeight[$_.Severity] } -Descending
    $totalFindings = $findings.Count

    # Severity counts
    $sevCounts = @{ 'Critical'=0; 'High'=0; 'Medium'=0; 'Low'=0; 'Info'=0 }
    foreach ($f in $findings) {
        if ($sevCounts.ContainsKey($f.Severity)) { $sevCounts[$f.Severity]++ }
    }

    # Top entities (top 15 by score)
    $topEntities = @()
    foreach ($key in $script:EntityScores.Keys) {
        $obj   = $script:EntityScores[$key]
        $score = Get-NormalizedScore -Raw $obj.RawScore
        $topEntities += [PSCustomObject]@{
            EntityType  = $obj.EntityType
            EntityKey   = $obj.EntityKey
            Score       = $score
            RiskLevel   = Get-RiskLevel -Score $score
            HitCount    = $obj.HitCount
            MaxSeverity = $obj.MaxSeverity
            Reasons     = ($obj.Reasons | Sort-Object -Unique | Select-Object -First 5) -join '; '
        }
    }
    $topEntities = $topEntities | Sort-Object Score -Descending | Select-Object -First 20

    # MITRE tactic hit counts
    $tacticHits = @{}
    foreach ($f in $findings) {
        if ([string]::IsNullOrEmpty($f.MitreTactic)) { continue }
        $ta = $f.MitreTactic
        if (-not $tacticHits.ContainsKey($ta)) { $tacticHits[$ta] = 0 }
        $tacticHits[$ta]++
    }

    # Chain findings
    $chainFindings = $findings | Where-Object { $_.IsChain -eq $true }

    # Scan metadata
    $scanDuration = [Math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 1)
    $scanTime     = $script:StartTime.ToString('yyyy-MM-dd HH:mm:ss')

    # Build findings JSON for JS
    $findingsJson = ConvertTo-FindingsJson -Findings $findings

    # Build entities JSON
    $entitiesJson = ConvertTo-EntitiesJson -Entities $topEntities

    # Overall risk score
    $overallScore = if ($topEntities.Count -gt 0) {
        [Math]::Round(($topEntities | Measure-Object -Property Score -Maximum).Maximum, 1)
    } else { 0 }
    $overallRisk = Get-RiskLevel -Score $overallScore

    # HTML generation
    $html = Get-HtmlTemplate `
        -SevCounts         $sevCounts `
        -TotalFindings     $totalFindings `
        -TopEntities       $topEntities `
        -TacticHits        $tacticHits `
        -ChainFindings     $chainFindings `
        -ScanDuration      $scanDuration `
        -ScanTime          $scanTime `
        -TotalParsed       $script:TotalParsed `
        -FindingsJson      $findingsJson `
        -EntitiesJson      $entitiesJson `
        -OverallScore      $overallScore `
        -OverallRisk       $overallRisk

    [System.IO.File]::WriteAllText($OutFile, $html, [System.Text.Encoding]::UTF8)
    Write-Status "HTML report saved: $OutFile" 'OK'
}

function ConvertTo-FindingsJson {
    param($Findings)
    # These values are rendered into the report via innerHTML in buildFindingsRow/openFinding.
    # HTML-encode FIRST (so <, >, & in command lines/paths can't break or inject markup),
    # THEN JSON-encode (to safely embed inside the JS string literals). Order matters:
    # HtmlEncoded output contains only &..; entities with no quotes/backslashes, so the
    # JSON step won't double-escape it.
    $arr = foreach ($f in $Findings) {
        $title   = ConvertTo-JsonString (ConvertTo-HtmlEncoded $f.Title)
        $desc    = ConvertTo-JsonString (ConvertTo-HtmlEncoded $f.Description)
        $rec     = ConvertTo-JsonString (ConvertTo-HtmlEncoded $f.Recommendation)
        $subj    = ConvertTo-JsonString (ConvertTo-HtmlEncoded $f.SubjectUser)
        $tgt     = ConvertTo-JsonString (ConvertTo-HtmlEncoded $f.TargetUser)
        $ip      = ConvertTo-JsonString (ConvertTo-HtmlEncoded $f.IpAddress)
        $proc    = ConvertTo-JsonString (ConvertTo-HtmlEncoded $f.ProcessName)
        $cmdl    = ConvertTo-JsonString (ConvertTo-HtmlEncoded $f.CommandLine)
        $svc     = ConvertTo-JsonString (ConvertTo-HtmlEncoded $f.ServiceName)
        $task    = ConvertTo-JsonString (ConvertTo-HtmlEncoded $f.TaskName)
        $comp    = ConvertTo-JsonString (ConvertTo-HtmlEncoded $f.Computer)
        $tactic  = ConvertTo-JsonString (ConvertTo-HtmlEncoded $f.TacticName)
        $tech    = ConvertTo-JsonString (ConvertTo-HtmlEncoded $f.MitreTechniqueID)
        $chain   = if ($f.IsChain) { 'true' } else { 'false' }

        $ts      = $f.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')

        "{`"id`":`"$($f.FindingID)`",`"ts`":`"$ts`",`"sev`":`"$($f.Severity)`",`"title`":`"$title`",`"rule`":`"$($f.RuleID)`",`"computer`":`"$comp`",`"eid`":$($f.EventID),`"tactic`":`"$tactic`",`"technique`":`"$tech`",`"subj`":`"$subj`",`"tgt`":`"$tgt`",`"ip`":`"$ip`",`"proc`":`"$proc`",`"cmd`":`"$cmdl`",`"svc`":`"$svc`",`"task`":`"$task`",`"cnt`":$($f.GroupCount),`"chain`":$chain,`"desc`":`"$desc`",`"rec`":`"$rec`"}"
    }
    '[' + ($arr -join ',') + ']'
}

function ConvertTo-EntitiesJson {
    param($Entities)
    # Same HTML-then-JSON encoding rationale as ConvertTo-FindingsJson - entity keys can
    # contain usernames/paths and are rendered via innerHTML.
    $arr = foreach ($e in $Entities) {
        $key  = ConvertTo-JsonString (ConvertTo-HtmlEncoded $e.EntityKey)
        $rsns = ConvertTo-JsonString (ConvertTo-HtmlEncoded $e.Reasons)
        "{`"type`":`"$($e.EntityType)`",`"key`":`"$key`",`"score`":$($e.Score),`"risk`":`"$($e.RiskLevel)`",`"hits`":$($e.HitCount),`"maxsev`":`"$($e.MaxSeverity)`",`"reasons`":`"$rsns`"}"
    }
    '[' + ($arr -join ',') + ']'
}

function Get-HtmlTemplate {
    param(
        $SevCounts, $TotalFindings, $TopEntities,
        $TacticHits, $ChainFindings, $ScanDuration,
        $ScanTime, $TotalParsed, $FindingsJson,
        $EntitiesJson, $OverallScore, $OverallRisk
    )

    $riskColor = $script:SeverityColor[$OverallRisk]

    $tacticMatrix = Get-MitreMatrixHtml -TacticHits $TacticHits

    $chainRows = if ($ChainFindings) {
        ($ChainFindings | ForEach-Object {
            $sev  = $_.Severity
            $col  = $script:SeverityColor[$sev]
            $t    = ConvertTo-HtmlEncoded $_.Title
            $id   = ConvertTo-HtmlEncoded $_.ChainID
            $tc   = ConvertTo-HtmlEncoded $_.TacticName
            $rec  = ConvertTo-HtmlEncoded $_.Recommendation
            $ts   = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
            $comp = ConvertTo-HtmlEncoded $_.Computer
            "<tr><td><span class='badge' style='background:$col'>$sev</span></td><td class='mono'>$id</td><td>$t</td><td class='mono'>$comp</td><td class='muted'>$ts</td><td>$tc</td><td class='rec-cell'>$rec</td></tr>"
        }) -join "`n"
    } else { '<tr><td colspan="7" class="muted" style="text-align:center;padding:20px">No correlation chains triggered</td></tr>' }

    $sevBarsCritical = [Math]::Round(($SevCounts['Critical'] / [Math]::Max($TotalFindings,1)) * 100, 1)
    $sevBarsHigh     = [Math]::Round(($SevCounts['High']     / [Math]::Max($TotalFindings,1)) * 100, 1)
    $sevBarsMedium   = [Math]::Round(($SevCounts['Medium']   / [Math]::Max($TotalFindings,1)) * 100, 1)
    $sevBarsLow      = [Math]::Round(($SevCounts['Low']      / [Math]::Max($TotalFindings,1)) * 100, 1)

    return @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ZavetSec-EVTXHunter Report | $ScanTime</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');
  *{margin:0;padding:0;box-sizing:border-box}
  :root{
    --bg:#0a0d10;--bg2:#0d1117;--bg3:#111820;--bg4:#151c26;
    --border:#1e2d3d;--border2:#243447;
    --green:#00ff88;--green2:#00cc6a;--green3:#004d28;
    --red:#ff2d55;--orange:#f59e0b;--blue:#3b82f6;--purple:#a855f7;
    --cyan:#06b6d4;--white:#e2e8f0;--muted:#64748b;--muted2:#475569;
    --critical:#ff2d55;--high:#ef4444;--medium:#f59e0b;--low:#3b82f6;--info:#6b7280;
    --font-mono:'JetBrains Mono',monospace;
    --font-ui:'Rajdhani','JetBrains Mono',monospace;
  }
  html{scroll-behavior:smooth}
  body{background:var(--bg);color:var(--white);font-family:var(--font-ui);font-size:14px;line-height:1.6;min-height:100vh;overflow-x:hidden}
  body::before{content:'';position:fixed;top:0;left:0;width:100%;height:100%;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,136,.01) 2px,rgba(0,255,136,.01) 4px);pointer-events:none;z-index:0}
  body::after{content:'';position:fixed;top:0;left:0;width:100%;height:100%;background:radial-gradient(ellipse 80% 60% at 50% -20%,rgba(0,255,136,.08) 0%,transparent 70%);pointer-events:none;z-index:0}

  /* LAYOUT */
  .wrapper{position:relative;z-index:1;max-width:1600px;margin:0 auto;padding:0 24px 60px}

  /* HEADER */
  .header{padding:32px 0 24px;border-bottom:1px solid var(--border);margin-bottom:32px;display:flex;align-items:center;justify-content:space-between}
  .logo-block{display:flex;align-items:center;gap:16px}
  .logo-dot{width:12px;height:12px;border-radius:50%;background:var(--green);box-shadow:0 0 12px var(--green);animation:pulse 2s infinite}
  @keyframes pulse{0%,100%{box-shadow:0 0 8px var(--green)}50%{box-shadow:0 0 20px var(--green),0 0 40px rgba(0,255,136,.3)}}
  .logo-title{font-size:22px;font-weight:700;color:var(--green);letter-spacing:2px;text-transform:uppercase}
  .logo-sub{font-size:11px;color:var(--muted);letter-spacing:1px;font-family:var(--font-mono)}
  .header-meta{text-align:right;font-family:var(--font-mono);font-size:11px;color:var(--muted)}
  .header-meta span{display:block;margin-bottom:2px}
  .header-meta .val{color:var(--white)}

  /* SECTIONS */
  .section-title{font-size:11px;font-weight:700;color:var(--green);letter-spacing:3px;text-transform:uppercase;margin-bottom:16px;display:flex;align-items:center;gap:10px}
  .section-title::after{content:'';flex:1;height:1px;background:linear-gradient(90deg,var(--border),transparent)}
  .section{margin-bottom:40px}

  /* CARDS */
  .card{background:var(--bg2);border:1px solid var(--border);border-radius:4px;padding:20px;position:relative;overflow:hidden}
  .card::before{content:'';position:absolute;top:0;left:0;width:3px;height:100%;background:var(--green)}
  .card-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}

  /* STAT CARDS */
  .stat-card{background:var(--bg2);border:1px solid var(--border);border-radius:4px;padding:20px;text-align:center;position:relative;overflow:hidden;transition:.2s}
  .stat-card:hover{border-color:var(--border2);background:var(--bg3)}
  .stat-val{font-size:36px;font-weight:700;font-family:var(--font-mono);line-height:1.1;margin-bottom:4px}
  .stat-label{font-size:11px;color:var(--muted);letter-spacing:1px;text-transform:uppercase}
  .stat-card.critical .stat-val{color:var(--critical)}
  .stat-card.high .stat-val{color:var(--high)}
  .stat-card.medium .stat-val{color:var(--medium)}
  .stat-card.low .stat-val{color:var(--low)}
  .stat-card.green .stat-val{color:var(--green)}

  /* RISK SCORE */
  .risk-panel{background:var(--bg2);border:1px solid var(--border);border-radius:4px;padding:32px;display:flex;align-items:center;gap:40px}
  .risk-dial{width:120px;height:120px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-direction:column;border:3px solid;position:relative}
  .risk-score{font-size:32px;font-weight:700;font-family:var(--font-mono)}
  .risk-label{font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--muted)}
  .risk-info{flex:1}
  .risk-info h2{font-size:20px;font-weight:700;margin-bottom:8px}
  .risk-info p{color:var(--muted);font-size:13px}

  /* SEV BARS */
  .sev-bar-row{display:flex;align-items:center;gap:12px;margin-bottom:8px}
  .sev-bar-label{width:70px;font-size:12px;font-family:var(--font-mono)}
  .sev-bar-track{flex:1;height:8px;background:var(--bg3);border-radius:4px;overflow:hidden}
  .sev-bar-fill{height:100%;border-radius:4px;transition:.6s ease}
  .sev-bar-count{width:50px;text-align:right;font-family:var(--font-mono);font-size:12px;color:var(--muted)}

  /* TABLES */
  .tbl{width:100%;border-collapse:collapse}
  .tbl th{background:var(--bg3);color:var(--green);font-size:10px;letter-spacing:2px;text-transform:uppercase;padding:10px 14px;text-align:left;border-bottom:1px solid var(--border);font-weight:600;cursor:pointer;user-select:none;white-space:nowrap}
  .tbl th:hover{background:var(--bg4);color:#fff}
  .tbl td{padding:10px 14px;border-bottom:1px solid rgba(30,45,61,.5);vertical-align:middle;font-size:13px}
  .tbl tr:hover td{background:rgba(255,255,255,.02)}
  .tbl tr:last-child td{border-bottom:none}
  .mono{font-family:var(--font-mono);font-size:12px}
  .muted{color:var(--muted);font-size:12px}
  .rec-cell{font-size:12px;color:var(--muted);max-width:280px}

  /* BADGES */
  .badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:10px;font-weight:700;letter-spacing:1px;text-transform:uppercase;font-family:var(--font-mono)}
  .badge-chain{background:rgba(168,85,247,.15);color:#a855f7;border:1px solid rgba(168,85,247,.3)}
  .tag{display:inline-block;padding:1px 6px;border-radius:2px;font-size:10px;font-family:var(--font-mono);background:var(--bg3);color:var(--muted);border:1px solid var(--border)}

  /* FILTERS */
  .filter-bar{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
  .filter-input{background:var(--bg3);border:1px solid var(--border);color:var(--white);padding:7px 12px;border-radius:3px;font-size:13px;font-family:var(--font-mono);outline:none;min-width:240px}
  .filter-input:focus{border-color:var(--green);box-shadow:0 0 0 2px rgba(0,255,136,.1)}
  .filter-btn{background:var(--bg3);border:1px solid var(--border);color:var(--muted);padding:7px 14px;border-radius:3px;font-size:11px;font-family:var(--font-mono);cursor:pointer;letter-spacing:1px;text-transform:uppercase;transition:.15s}
  .filter-btn:hover{border-color:var(--green);color:var(--green)}
  .filter-btn.active{border-color:var(--green);color:var(--green);background:rgba(0,255,136,.08)}
  .filter-count{font-family:var(--font-mono);font-size:11px;color:var(--muted);margin-left:auto}

  /* MITRE MATRIX */
  .mitre-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px}
  .mitre-cell{background:var(--bg3);border:1px solid var(--border);border-radius:3px;padding:10px;text-align:center;transition:.2s}
  .mitre-cell.hit{border-color:var(--green);background:rgba(0,255,136,.06)}
  .mitre-cell.hit-high{border-color:var(--red);background:rgba(255,45,85,.08)}
  .mitre-cell .tactic-id{font-size:9px;color:var(--muted);font-family:var(--font-mono);letter-spacing:1px}
  .mitre-cell .tactic-name{font-size:11px;font-weight:600;margin:4px 0}
  .mitre-cell .tactic-count{font-family:var(--font-mono);font-size:20px;font-weight:700}
  .mitre-cell.hit .tactic-count{color:var(--green)}
  .mitre-cell.hit-high .tactic-count{color:var(--red)}

  /* DETAIL MODAL */
  .modal-overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.7);z-index:1000;align-items:center;justify-content:center}
  .modal-overlay.open{display:flex}
  .modal{background:var(--bg2);border:1px solid var(--border);border-radius:4px;max-width:760px;width:90%;max-height:80vh;overflow-y:auto;padding:28px;position:relative}
  .modal::before{content:'';position:absolute;top:0;left:0;width:100%;height:3px}
  .modal-close{position:absolute;top:16px;right:16px;background:none;border:none;color:var(--muted);font-size:20px;cursor:pointer;font-family:var(--font-mono)}
  .modal-close:hover{color:var(--white)}
  .modal-title{font-size:17px;font-weight:700;margin-bottom:16px;padding-right:32px}
  .modal-row{display:flex;gap:8px;margin-bottom:8px;align-items:flex-start}
  .modal-key{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;min-width:120px;padding-top:1px;font-family:var(--font-mono)}
  .modal-val{font-size:13px;font-family:var(--font-mono);word-break:break-all;color:var(--white)}
  .modal-val.cmd{background:var(--bg3);border:1px solid var(--border);padding:8px 12px;border-radius:3px;border-left:3px solid var(--orange);font-size:11px;white-space:pre-wrap;max-height:150px;overflow-y:auto;width:100%}
  .modal-desc{background:var(--bg3);border-left:3px solid var(--cyan);padding:12px;border-radius:0 3px 3px 0;font-size:13px;color:var(--muted);margin:12px 0}
  .modal-rec{background:var(--bg3);border-left:3px solid var(--green);padding:12px;border-radius:0 3px 3px 0;font-size:13px;color:var(--white);margin-top:12px}
  .modal-rec-label{font-size:10px;color:var(--green);letter-spacing:2px;text-transform:uppercase;margin-bottom:6px;font-family:var(--font-mono)}

  /* SCROLLBAR */
  ::-webkit-scrollbar{width:6px;height:6px}
  ::-webkit-scrollbar-track{background:var(--bg)}
  ::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
  ::-webkit-scrollbar-thumb:hover{background:var(--border2)}

  /* NAV */
  .nav{display:flex;gap:24px;margin-bottom:32px;border-bottom:1px solid var(--border);padding-bottom:0}
  .nav-item{padding:10px 0;font-size:12px;letter-spacing:2px;text-transform:uppercase;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px;transition:.15s}
  .nav-item:hover{color:var(--white)}
  .nav-item.active{color:var(--green);border-bottom-color:var(--green)}

  /* ENTITY TABLE */
  .score-bar{width:80px;height:6px;background:var(--bg3);border-radius:3px;overflow:hidden;display:inline-block;vertical-align:middle;margin-right:6px}
  .score-bar-fill{height:100%;border-radius:3px}

  /* TOP FINDINGS TIMELINE */
  .timeline{position:relative;padding-left:24px}
  .timeline::before{content:'';position:absolute;left:8px;top:0;bottom:0;width:1px;background:var(--border)}
  .tl-item{position:relative;margin-bottom:16px;padding:12px 16px;background:var(--bg3);border:1px solid var(--border);border-radius:3px}
  .tl-item::before{content:'';position:absolute;left:-20px;top:18px;width:8px;height:8px;border-radius:50%;background:var(--bg);border:2px solid var(--border)}
  .tl-item.sev-Critical::before{border-color:var(--critical);background:var(--critical)}
  .tl-item.sev-High::before{border-color:var(--high)}
  .tl-item.sev-Medium::before{border-color:var(--medium)}
  .tl-item.sev-Low::before{border-color:var(--low)}
  .tl-time{font-size:10px;color:var(--muted);font-family:var(--font-mono);margin-bottom:4px}
  .tl-title{font-size:13px;font-weight:600;margin-bottom:4px}
  .tl-meta{font-size:11px;color:var(--muted);font-family:var(--font-mono)}

  /* RESPONSIVE */
  @media(max-width:900px){
    .risk-panel{flex-direction:column;align-items:flex-start}
    .header{flex-direction:column;gap:12px;align-items:flex-start}
  }
</style>
</head>
<body>
<div class="wrapper">

  <!-- HEADER -->
  <div class="header">
    <div class="logo-block">
      <div class="logo-dot"></div>
      <div>
        <div class="logo-title">ZavetSec &middot; EVTXHunter</div>
        <div class="logo-sub">v$($script:VERSION) &middot; Advanced Threat Hunting Engine &middot; $($script:DetectionRules.Count) Rules &middot; $($script:CorrelationChains.Count) Correlation Chains</div>
      </div>
    </div>
    <div class="header-meta">
      <span>SCAN TIME <span class="val">$ScanTime</span></span>
      <span>DURATION <span class="val">${ScanDuration}s</span></span>
      <span>EVENTS PARSED <span class="val">$($TotalParsed.ToString('N0'))</span></span>
      <span>TOTAL FINDINGS <span class="val">$TotalFindings</span></span>
    </div>
  </div>

  <!-- NAV -->
  <div class="nav">
    <div class="nav-item active" onclick="showTab('overview')">Overview</div>
    <div class="nav-item" onclick="showTab('findings')">Findings ($TotalFindings)</div>
    <div class="nav-item" onclick="showTab('chains')">Attack Chains ($($ChainFindings.Count))</div>
    <div class="nav-item" onclick="showTab('entities')">Entities ($($TopEntities.Count))</div>
    <div class="nav-item" onclick="showTab('mitre')">MITRE ATT&amp;CK</div>
  </div>

  <!-- ==================== TAB: OVERVIEW ==================== -->
  <div id="tab-overview">

    <!-- RISK PANEL -->
    <div class="section">
      <div class="risk-panel">
        <div class="risk-dial" style="border-color:$riskColor;box-shadow:0 0 20px rgba($(if($OverallRisk -eq 'Critical'){'255,45,85'}elseif($OverallRisk -eq 'High'){'239,68,68'}elseif($OverallRisk -eq 'Medium'){'245,158,11'}else{'59,130,246'}),.25)">
          <div class="risk-score" style="color:$riskColor">$OverallScore</div>
          <div class="risk-label">/ 100</div>
        </div>
        <div class="risk-info">
          <h2>Overall Risk: <span style="color:$riskColor">$OverallRisk</span></h2>
          <p>Based on $TotalFindings findings across $($script:TotalParsed.ToString('N0')) events. Entity scoring, severity weighting, and correlation chain multipliers applied.</p>
        </div>
        <div style="min-width:200px">
          <div class="sev-bar-row">
            <span class="sev-bar-label" style="color:var(--critical)">Critical</span>
            <div class="sev-bar-track"><div class="sev-bar-fill" style="width:${sevBarsCritical}%;background:var(--critical)"></div></div>
            <span class="sev-bar-count" style="color:var(--critical)">$($SevCounts['Critical'])</span>
          </div>
          <div class="sev-bar-row">
            <span class="sev-bar-label" style="color:var(--high)">High</span>
            <div class="sev-bar-track"><div class="sev-bar-fill" style="width:${sevBarsHigh}%;background:var(--high)"></div></div>
            <span class="sev-bar-count" style="color:var(--high)">$($SevCounts['High'])</span>
          </div>
          <div class="sev-bar-row">
            <span class="sev-bar-label" style="color:var(--medium)">Medium</span>
            <div class="sev-bar-track"><div class="sev-bar-fill" style="width:${sevBarsMedium}%;background:var(--medium)"></div></div>
            <span class="sev-bar-count" style="color:var(--medium)">$($SevCounts['Medium'])</span>
          </div>
          <div class="sev-bar-row">
            <span class="sev-bar-label" style="color:var(--low)">Low</span>
            <div class="sev-bar-track"><div class="sev-bar-fill" style="width:${sevBarsLow}%;background:var(--low)"></div></div>
            <span class="sev-bar-count" style="color:var(--low)">$($SevCounts['Low'])</span>
          </div>
        </div>
      </div>
    </div>

    <!-- STAT CARDS -->
    <div class="section">
      <div class="section-title">Summary</div>
      <div class="card-grid">
        <div class="stat-card green"><div class="stat-val">$($script:TotalParsed.ToString('N0'))</div><div class="stat-label">Events Parsed</div></div>
        <div class="stat-card critical"><div class="stat-val">$($SevCounts['Critical'])</div><div class="stat-label">Critical Findings</div></div>
        <div class="stat-card high"><div class="stat-val">$($SevCounts['High'])</div><div class="stat-label">High Findings</div></div>
        <div class="stat-card medium"><div class="stat-val">$($SevCounts['Medium'])</div><div class="stat-label">Medium Findings</div></div>
        <div class="stat-card low"><div class="stat-val">$($ChainFindings.Count)</div><div class="stat-label">Attack Chains</div></div>
        <div class="stat-card green"><div class="stat-val">$($TopEntities.Count)</div><div class="stat-label">At-Risk Entities</div></div>
      </div>
    </div>

    <!-- TOP FINDINGS TIMELINE -->
    <div class="section">
      <div class="section-title">Critical &amp; High Findings &mdash; Timeline</div>
      <div id="top-timeline" class="timeline"></div>
    </div>

    <!-- TOP ENTITIES PREVIEW -->
    <div class="section">
      <div class="section-title">Top At-Risk Entities</div>
      <div class="card" style="padding:0;overflow:hidden">
        <table class="tbl">
          <thead><tr>
            <th>Type</th><th>Entity</th><th>Risk Score</th>
            <th>Risk Level</th><th>Hits</th><th>Max Severity</th>
          </tr></thead>
          <tbody id="overview-entities"></tbody>
        </table>
      </div>
    </div>

  </div><!-- /tab-overview -->

  <!-- ==================== TAB: FINDINGS ==================== -->
  <div id="tab-findings" style="display:none">
    <div class="section">
      <div class="section-title">All Findings</div>
      <div class="filter-bar">
        <input class="filter-input" id="find-search" placeholder="Search title, user, IP, process..." oninput="filterFindings()">
        <button class="filter-btn active" id="btn-all" onclick="setSevFilter('')">All</button>
        <button class="filter-btn" id="btn-Critical" onclick="setSevFilter('Critical')" style="color:var(--critical)">Critical</button>
        <button class="filter-btn" id="btn-High" onclick="setSevFilter('High')" style="color:var(--high)">High</button>
        <button class="filter-btn" id="btn-Medium" onclick="setSevFilter('Medium')" style="color:var(--medium)">Medium</button>
        <button class="filter-btn" id="btn-Low" onclick="setSevFilter('Low')" style="color:var(--low)">Low</button>
        <button class="filter-btn" id="btn-Chain" onclick="setSevFilter('Chain')" style="color:#a855f7">Chains</button>
        <span class="filter-count" id="find-count">$TotalFindings findings</span>
      </div>
      <div class="card" style="padding:0;overflow:hidden">
        <table class="tbl" id="findings-table">
          <thead><tr>
            <th onclick="sortTable(0)">Time (UTC) &#8597;</th>
            <th onclick="sortTable(1)">Severity &#8597;</th>
            <th onclick="sortTable(2)">Rule</th>
            <th onclick="sortTable(3)">Title</th>
            <th>Computer</th>
            <th>Subject User</th>
            <th>Target User</th>
            <th>Source IP</th>
            <th>Technique</th>
            <th>Type</th>
          </tr></thead>
          <tbody id="findings-tbody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ==================== TAB: CHAINS ==================== -->
  <div id="tab-chains" style="display:none">
    <div class="section">
      <div class="section-title">Attack Chain Correlation Results</div>
      <div class="card" style="padding:14px;margin-bottom:16px;background:rgba(168,85,247,.06);border-color:rgba(168,85,247,.3)">
        <span style="color:#a855f7;font-size:12px">&#11041; CORRELATION ENGINE</span>
        <span style="color:var(--muted);font-size:12px;margin-left:12px">The following entries represent multi-event attack sequences detected by temporal correlation across the event timeline. Each chain multiplies entity risk score by &times;2.</span>
      </div>
      <div class="card" style="padding:0;overflow:hidden">
        <table class="tbl">
          <thead><tr>
            <th>Severity</th><th>Chain ID</th><th>Title</th>
            <th>Host</th><th>First Seen (UTC)</th><th>Tactics</th><th>Recommendation</th>
          </tr></thead>
          <tbody>$chainRows</tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ==================== TAB: ENTITIES ==================== -->
  <div id="tab-entities" style="display:none">
    <div class="section">
      <div class="section-title">Entity Risk Scores</div>
      <div class="card" style="padding:0;overflow:hidden">
        <table class="tbl">
          <thead><tr>
            <th>Type</th><th>Entity</th><th>Risk Score</th>
            <th>Risk Level</th><th>Hits</th><th>Max Severity</th><th>Activity Summary</th>
          </tr></thead>
          <tbody id="entities-tbody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ==================== TAB: MITRE ==================== -->
  <div id="tab-mitre" style="display:none">
    <div class="section">
      <div class="section-title">MITRE ATT&amp;CK Coverage Matrix</div>
      $tacticMatrix
    </div>
  </div>

</div><!-- /wrapper -->

<!-- DETAIL MODAL -->
<div class="modal-overlay" id="modal-overlay" onclick="if(event.target===this)closeModal()">
  <div class="modal" id="modal-content">
    <button class="modal-close" onclick="closeModal()">&#10005;</button>
    <div id="modal-inner"></div>
  </div>
</div>

<script>
// ================================================================
// DATA
// ================================================================
const FINDINGS  = $FindingsJson;
const ENTITIES  = $EntitiesJson;
"@ + @'
const SEVCOLOR  = {Critical:'#ff2d55',High:'#ef4444',Medium:'#f59e0b',Low:'#3b82f6',Info:'#6b7280'};
let currentSevFilter = '';
let sortCol = 0, sortAsc = false;

// ================================================================
// TABS
// ================================================================
function showTab(id) {
  document.querySelectorAll('[id^="tab-"]').forEach(t => t.style.display='none');
  document.getElementById('tab-'+id).style.display='block';
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  event.target.classList.add('active');
}

// ================================================================
// FINDINGS TABLE
// ================================================================
function buildFindingsRow(f) {
  const sc = SEVCOLOR[f.sev]||'#6b7280';
  const chain = f.chain ? '<span class="badge badge-chain">CHAIN</span>' : '';
  const cnt = (f.cnt && f.cnt > 1) ? ` <span class="badge" style="background:#6366f122;color:#818cf8;border:1px solid #6366f144" title="${f.cnt} identical events collapsed">&times;${f.cnt}</span>` : '';
  return `<tr onclick="openFinding('${f.id}')" style="cursor:pointer" data-sev="${f.sev}" data-chain="${f.chain}" data-search="${(f.title+f.subj+f.tgt+f.ip+f.proc+f.rule).toLowerCase()}">
    <td class="mono muted">${f.ts}</td>
    <td><span class="badge" style="background:${sc}22;color:${sc};border:1px solid ${sc}44">${f.sev}</span></td>
    <td class="mono" style="color:var(--muted);font-size:11px">${f.rule}</td>
    <td style="font-weight:600;max-width:280px">${f.title}${cnt}</td>
    <td class="mono">${f.computer||'-'}</td>
    <td class="mono">${f.subj||'-'}</td>
    <td class="mono">${f.tgt||'-'}</td>
    <td class="mono">${f.ip||'-'}</td>
    <td><span class="tag">${f.technique||'-'}</span></td>
    <td>${chain}</td>
  </tr>`;
}

function renderFindings() {
  const tbody = document.getElementById('findings-tbody');
  tbody.innerHTML = FINDINGS.map(buildFindingsRow).join('');
  updateFindingCount();
}

function filterFindings() {
  const q   = document.getElementById('find-search').value.toLowerCase();
  const rows = document.querySelectorAll('#findings-tbody tr');
  let visible = 0;
  rows.forEach(r => {
    const sevMatch   = !currentSevFilter
      || (currentSevFilter==='Chain' ? r.dataset.chain==='true' : r.dataset.sev===currentSevFilter);
    const searchMatch = !q || r.dataset.search.includes(q);
    const show = sevMatch && searchMatch;
    r.style.display = show ? '' : 'none';
    if (show) visible++;
  });
  document.getElementById('find-count').textContent = visible + ' findings';
}

function setSevFilter(sev) {
  currentSevFilter = sev;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  const id = sev ? 'btn-'+sev : 'btn-all';
  document.getElementById(id).classList.add('active');
  filterFindings();
}

function updateFindingCount() {
  document.getElementById('find-count').textContent = FINDINGS.length + ' findings';
}

function sortTable(col) {
  if (sortCol === col) sortAsc = !sortAsc; else { sortCol = col; sortAsc = true; }
  const tbody = document.getElementById('findings-tbody');
  const rows  = Array.from(tbody.querySelectorAll('tr'));
  rows.sort((a,b) => {
    const va = a.cells[col]?.textContent.trim() || '';
    const vb = b.cells[col]?.textContent.trim() || '';
    return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
  });
  rows.forEach(r => tbody.appendChild(r));
}

// ================================================================
// MODAL
// ================================================================
function openFinding(id) {
  const f = FINDINGS.find(x => x.id === id);
  if (!f) return;
  const sc = SEVCOLOR[f.sev]||'#6b7280';
  const chainBadge = f.chain ? '<span class="badge badge-chain" style="margin-left:8px">CORRELATION CHAIN</span>' : '';
  const cmdBlock = f.cmd ? `<div class="modal-row"><span class="modal-key">Command</span><div class="modal-val cmd">${f.cmd}</div></div>` : '';

  document.getElementById('modal-inner').innerHTML = `
    <div style="margin-bottom:6px"><span class="badge" style="background:${sc}22;color:${sc};border:1px solid ${sc}44">${f.sev}</span>${chainBadge}</div>
    <div class="modal-title">${f.title}</div>
    <div class="modal-desc">${f.desc}</div>
    <div class="modal-row"><span class="modal-key">Rule ID</span><span class="modal-val">${f.rule}</span></div>
    <div class="modal-row"><span class="modal-key">Time (UTC)</span><span class="modal-val">${f.ts}</span></div>
    <div class="modal-row"><span class="modal-key">Computer</span><span class="modal-val">${f.computer||'-'}</span></div>
    <div class="modal-row"><span class="modal-key">Event ID</span><span class="modal-val">${f.eid}</span></div>
    <div class="modal-row"><span class="modal-key">Subject User</span><span class="modal-val">${f.subj||'-'}</span></div>
    <div class="modal-row"><span class="modal-key">Target User</span><span class="modal-val">${f.tgt||'-'}</span></div>
    <div class="modal-row"><span class="modal-key">Source IP</span><span class="modal-val">${f.ip||'-'}</span></div>
    <div class="modal-row"><span class="modal-key">Process</span><span class="modal-val">${f.proc||'-'}</span></div>
    <div class="modal-row"><span class="modal-key">Service</span><span class="modal-val">${f.svc||'-'}</span></div>
    <div class="modal-row"><span class="modal-key">Task</span><span class="modal-val">${f.task||'-'}</span></div>
    ${cmdBlock}
    <div class="modal-row"><span class="modal-key">MITRE Tactic</span><span class="modal-val">${f.tactic||'-'}</span></div>
    <div class="modal-row"><span class="modal-key">Technique</span><span class="modal-val">${f.technique||'-'}</span></div>
    <div class="modal-rec"><div class="modal-rec-label">Recommendation</div>${f.rec}</div>
  `;
  const modal = document.getElementById('modal-content');
  modal.style.borderTop = '3px solid '+sc;
  document.getElementById('modal-overlay').classList.add('open');
}

function closeModal() {
  document.getElementById('modal-overlay').classList.remove('open');
}

document.addEventListener('keydown', e => { if (e.key==='Escape') closeModal(); });

// ================================================================
// ENTITIES TABLE
// ================================================================
function renderEntities() {
  const tbody = document.getElementById('entities-tbody');
  tbody.innerHTML = ENTITIES.map(e => {
    const sc = SEVCOLOR[e.risk]||'#6b7280';
    const bar = `<div class="score-bar"><div class="score-bar-fill" style="width:${e.score}%;background:${sc}"></div></div>`;
    const msc = SEVCOLOR[e.maxsev]||'#6b7280';
    return `<tr>
      <td><span class="tag">${e.type}</span></td>
      <td class="mono" style="font-weight:600">${e.key}</td>
      <td>${bar}<span class="mono" style="color:${sc}">${e.score}</span></td>
      <td><span class="badge" style="background:${sc}22;color:${sc};border:1px solid ${sc}44">${e.risk}</span></td>
      <td class="mono">${e.hits}</td>
      <td><span class="badge" style="background:${msc}22;color:${msc};border:1px solid ${msc}44">${e.maxsev}</span></td>
      <td class="rec-cell">${e.reasons}</td>
    </tr>`;
  }).join('');

  // Overview entities (top 5)
  const ov = document.getElementById('overview-entities');
  ov.innerHTML = ENTITIES.slice(0,8).map(e => {
    const sc = SEVCOLOR[e.risk]||'#6b7280';
    const bar = `<div class="score-bar"><div class="score-bar-fill" style="width:${e.score}%;background:${sc}"></div></div>`;
    const msc = SEVCOLOR[e.maxsev]||'#6b7280';
    return `<tr>
      <td><span class="tag">${e.type}</span></td>
      <td class="mono" style="font-weight:600">${e.key}</td>
      <td>${bar}<span class="mono" style="color:${sc}">${e.score}</span></td>
      <td><span class="badge" style="background:${sc}22;color:${sc};border:1px solid ${sc}44">${e.risk}</span></td>
      <td class="mono">${e.hits}</td>
      <td><span class="badge" style="background:${msc}22;color:${msc};border:1px solid ${msc}44">${e.maxsev}</span></td>
    </tr>`;
  }).join('');
}

// ================================================================
// TIMELINE (overview)
// ================================================================
function renderTimeline() {
  const el = document.getElementById('top-timeline');
  const top = FINDINGS.filter(f => f.sev==='Critical'||f.sev==='High').slice(0,15);
  if (top.length===0) { el.innerHTML='<div class="muted" style="padding:16px">No Critical or High findings.</div>'; return; }
  el.innerHTML = top.map(f => {
    const sc = SEVCOLOR[f.sev];
    const chain = f.chain ? '<span class="badge badge-chain" style="margin-left:8px">CHAIN</span>' : '';
    return `<div class="tl-item sev-${f.sev}" onclick="showTab('findings');openFinding('${f.id}')" style="cursor:pointer;border-left:3px solid ${sc}">
      <div class="tl-time">${f.ts} &middot; ${f.rule}</div>
      <div class="tl-title">${f.title}${chain}</div>
      <div class="tl-meta">${[f.computer,f.subj,f.tgt,f.ip].filter(x=>x&&x!=='-').join(' &middot; ')}</div>
    </div>`;
  }).join('');
}

// ================================================================
// INIT
// ================================================================
window.addEventListener('DOMContentLoaded', () => {
  renderFindings();
  renderEntities();
  renderTimeline();
});
</script>
</body>
</html>
'@
}

function Get-MitreMatrixHtml {
    param([hashtable]$TacticHits)

    $tactics = @(
        @{ ID='TA0001'; Name='Initial Access';          Desc='Gain initial access to a network' }
        @{ ID='TA0002'; Name='Execution';               Desc='Run malicious code' }
        @{ ID='TA0003'; Name='Persistence';             Desc='Maintain their foothold' }
        @{ ID='TA0004'; Name='Privilege Escalation';    Desc='Gain higher-level permissions' }
        @{ ID='TA0005'; Name='Defense Evasion';         Desc='Avoid being detected' }
        @{ ID='TA0006'; Name='Credential Access';       Desc='Steal credentials like passwords' }
        @{ ID='TA0007'; Name='Discovery';               Desc='Figure out the environment' }
        @{ ID='TA0008'; Name='Lateral Movement';        Desc='Move through the environment' }
        @{ ID='TA0009'; Name='Collection';              Desc='Gather data of interest' }
        @{ ID='TA0010'; Name='Exfiltration';            Desc='Steal data' }
        @{ ID='TA0011'; Name='Command and Control';     Desc='Communicate with compromised systems' }
        @{ ID='TA0040'; Name='Impact';                  Desc='Manipulate, interrupt, or destroy' }
    )

    $cells = foreach ($t in $tactics) {
        $count = if ($TacticHits.ContainsKey($t.ID)) { $TacticHits[$t.ID] } else { 0 }
        $css   = if ($count -gt 5) { 'mitre-cell hit-high' }
                 elseif ($count -gt 0) { 'mitre-cell hit' }
                 else { 'mitre-cell' }
        $col   = if ($count -gt 5) { 'var(--red)' }
                 elseif ($count -gt 0) { 'var(--green)' }
                 else { 'var(--muted)' }
        "<div class='$css' title='$($t.Desc)'><div class='tactic-id'>$($t.ID)</div><div class='tactic-name'>$($t.Name)</div><div class='tactic-count' style='color:$col'>$count</div></div>"
    }

    '<div class="mitre-grid">' + ($cells -join '') + '</div>'
}

# ================================================================
# SECTION 10: OUTPUT FUNCTIONS
# ================================================================

function Export-JsonReport {
    param([string]$OutFile)
    $report = [PSCustomObject]@{
        Meta     = @{
            Tool       = $script:TOOL_NAME
            Version    = $script:VERSION
            ScanTime   = $script:StartTime.ToString('o')
            Duration   = [Math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 1)
            EventCount = $script:TotalParsed
        }
        Summary  = @{
            Critical = ($script:Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
            High     = ($script:Findings | Where-Object { $_.Severity -eq 'High' }).Count
            Medium   = ($script:Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
            Low      = ($script:Findings | Where-Object { $_.Severity -eq 'Low' }).Count
            Chains   = ($script:Findings | Where-Object { $_.IsChain -eq $true }).Count
        }
        Findings = $script:Findings
        Entities = @(
            foreach ($key in $script:EntityScores.Keys) {
                $obj   = $script:EntityScores[$key]
                $score = Get-NormalizedScore -Raw $obj.RawScore
                [PSCustomObject]@{
                    EntityType  = $obj.EntityType
                    EntityKey   = $obj.EntityKey
                    Score       = $score
                    RiskLevel   = Get-RiskLevel -Score $score
                    HitCount    = $obj.HitCount
                    MaxSeverity = $obj.MaxSeverity
                }
            }
        )
    }

    $json = $report | ConvertTo-Json -Depth 8 -Compress:$false
    [System.IO.File]::WriteAllText($OutFile, $json, [System.Text.Encoding]::UTF8)
    Write-Status "JSON report saved: $OutFile" 'OK'
}

function Export-CsvReport {
    param([string]$OutFile)
    $script:Findings | Select-Object TimeCreated, Severity, RuleID, Title, Computer,
        EventID, MitreTactic, MitreTechniqueID, MitreTechnique, TacticName,
        SubjectUser, TargetUser, IpAddress, ProcessName, ServiceName, TaskName,
        CommandLine, IsChain, ChainID, GroupCount, GroupKey, Recommendation |
        Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
    Write-Status "CSV report saved: $OutFile" 'OK'
}

# ================================================================
# SECTION 11: MAIN EXECUTION
# ================================================================

function Main {
    Write-Banner

    # Validate Path
    if ($PSCmdlet.ParameterSetName -eq 'File') {
        if (-not (Test-Path $Path)) {
            Write-Status "Path not found: $Path" 'ERROR'
            exit 1
        }
    }

    # Validate OutputPath
    if (-not (Test-Path $OutputPath)) {
        try { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
        catch {
            Write-Status "Cannot create output directory: $OutputPath" 'ERROR'
            exit 1
        }
    }

    # Sanity-check business hours (overnight ranges are not supported by the
    # off-hours logic; warn and fall back to defaults instead of flagging 100%).
    if ($WorkHoursEnd -le $WorkHoursStart) {
        Write-Status "WorkHoursEnd ($WorkHoursEnd) must be greater than WorkHoursStart ($WorkHoursStart). Falling back to 9-18." 'WARN'
        $script:WorkHoursStart = 9
        $script:WorkHoursEnd   = 18
    }

    # Load external whitelist. ConvertFrom-Json yields PSCustomObjects whose
    # nested .Fields has no .Keys; convert each rule's Fields to a real hashtable
    # so Test-WhitelistMatch can enumerate it like the built-in defaults.
    if (-not [string]::IsNullOrEmpty($Whitelist) -and (Test-Path $Whitelist)) {
        try {
            $rawRules = Get-Content $Whitelist -Raw | ConvertFrom-Json
            $converted = foreach ($r in @($rawRules)) {
                $fields = @{}
                if ($r.PSObject.Properties['Fields'] -and $null -ne $r.Fields) {
                    foreach ($p in $r.Fields.PSObject.Properties) { $fields[$p.Name] = $p.Value }
                }
                @{ RuleID = $r.RuleID; Fields = $fields }
            }
            # Drop rules with no field conditions - they would suppress everything.
            $script:WhitelistRules = @($converted | Where-Object { $_.Fields.Keys.Count -gt 0 })
            $skipped = @($converted).Count - $script:WhitelistRules.Count
            Write-Status "Whitelist loaded: $($script:WhitelistRules.Count) rules$(if($skipped){" ($skipped skipped: empty Fields)"})" 'OK'
        }
        catch {
            Write-Status "Failed to load whitelist: $_" 'WARN'
        }
    }

    # ---- PHASE 1: PARSE ----
    Write-Status '=== PHASE 1: EVENT PARSING ===' 'SECTION'

    if ($PSCmdlet.ParameterSetName -eq 'File') {
        $item = Get-Item $Path

        if ($item.PSIsContainer) {
            $evtxFiles = Get-ChildItem -Path $Path -Filter '*.evtx' -Recurse
            Write-Status "Found $($evtxFiles.Count) EVTX files in $Path" 'INFO'
            foreach ($f in $evtxFiles) {
                Read-EVTXFile -FilePath $f.FullName
            }
        }
        elseif ($item.Extension -ieq '.evtx') {
            Read-EVTXFile -FilePath $item.FullName
        }
        else {
            Write-Status "Unsupported file type: $($item.Extension). Expected .evtx" 'ERROR'
            exit 1
        }
    }
    else {
        Read-LiveLogs -Logs $LogNames
    }

    if ($script:TotalParsed -eq 0) {
        Write-Status 'No events parsed. Check path and permissions.' 'WARN'
        exit 0
    }

    Write-Status "Total events in memory: $($script:AllEvents.Count)" 'OK'

    # ---- PHASE 2: DETECT ----
    Write-Status '=== PHASE 2: DETECTION ===' 'SECTION'
    Invoke-DetectionEngine

    # ---- PHASE 3: CORRELATE ----
    Write-Status '=== PHASE 3: CORRELATION ===' 'SECTION'
    Invoke-CorrelationEngine

    # ---- PHASE 4: TEMPORAL ----
    Write-Status '=== PHASE 4: TEMPORAL ANALYSIS ===' 'SECTION'
    Invoke-TemporalAnalysis

    # ---- PHASE 5: OUTPUT ----
    Write-Status '=== PHASE 5: REPORT GENERATION ===' 'SECTION'

    $ts        = $script:StartTime.ToString('yyyyMMdd_HHmmss')
    $baseName  = "ZavetSec-EVTXHunter_$ts"

    if ($OutputFormat -eq 'HTML' -or $OutputFormat -eq 'All') {
        $htmlFile = Join-Path $OutputPath "$baseName.html"
        New-HtmlReport -OutFile $htmlFile
    }
    if ($OutputFormat -eq 'JSON' -or $OutputFormat -eq 'All') {
        $jsonFile = Join-Path $OutputPath "$baseName.json"
        Export-JsonReport -OutFile $jsonFile
    }
    if ($OutputFormat -eq 'CSV' -or $OutputFormat -eq 'All') {
        $csvFile = Join-Path $OutputPath "$baseName.csv"
        Export-CsvReport -OutFile $csvFile
    }

    # ---- SUMMARY ----
    $duration = [Math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 1)
    Write-Host ''
    Write-Host '================================================================' -ForegroundColor DarkGray
    Write-Host " SCAN COMPLETE - ${duration}s" -ForegroundColor Green
    Write-Host "  Events Parsed : $($script:TotalParsed.ToString('N0'))" -ForegroundColor White
    if ($script:ParseErrors -gt 0) {
        Write-Host "  Parse Errors  : $($script:ParseErrors.ToString('N0')) (events skipped - corrupt XML/EventID)" -ForegroundColor Yellow
    }
    Write-Host "  Total Findings: $($script:Findings.Count)" -ForegroundColor White
    Write-Host "  Critical      : $( ($script:Findings | Where-Object Severity -eq 'Critical').Count )" -ForegroundColor Red
    Write-Host "  High          : $( ($script:Findings | Where-Object Severity -eq 'High').Count )" -ForegroundColor Yellow
    Write-Host "  Attack Chains : $( ($script:Findings | Where-Object IsChain -eq $true).Count )" -ForegroundColor Magenta
    Write-Host "  Entities Scored: $($script:EntityScores.Count)" -ForegroundColor White
    Write-Host '================================================================' -ForegroundColor DarkGray
}

# Entry point
Main
