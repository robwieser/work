<#
.SYNOPSIS
    Ermittelt auf allen Terminalservern einer AD-OU, ob Benutzer ein temporäres FSLogix-Profil erhalten haben.

.DESCRIPTION
    Prüft je Server MEHRERE Quellen, weil der Text "temporary profile" in den FSLogix-Profile-Logs
    in vielen Umgebungen gar nicht vorkommt:

      1) Registry  HKLM\SOFTWARE\FSLogix\Profiles\Sessions\<SID>
         -> Wert "Temporary" = 1 ist der eindeutigste FSLogix-Nachweis (gilt für aktive Sessions).
      2) Eventlog  Microsoft-FSLogix-Apps/Operational + /Admin
         -> FSLogix-eigene Fehler beim Attach/Load des Profils.
      3) Eventlog  Application, Microsoft-Windows-User Profiles Service, ID 1511/1515
         -> Windows-Nachweis "Sie wurden mit einem temporären Profil angemeldet".
      4) Textsuche in C:\ProgramData\FSLogix\Logs\Profile\*.log
         -> Muster für Temp-Profil UND für die typischen Ursachen (VHD in use, attach failed, ...).

    Mit -Diagnose wird zusätzlich ausgegeben, WAS überhaupt gefunden wurde (Anzahl Logdateien,
    Zeitraum, Zeilenzahl, häufigste ERROR/WARN-Meldungen). Damit lässt sich erkennen, ob die
    Suchmuster zur Umgebung passen - eine stille Null ist so nicht mehr möglich.

.PARAMETER SearchBase
    DN der OU mit den Terminalservern.

.PARAMETER DaysBack
    Zeitraum rückwirkend in Tagen (Default: 7).

.PARAMETER Diagnose
    Zusätzlich Bestandsaufnahme der Logs + Top-Fehlermeldungen je Server ausgeben.

.PARAMETER Sources
    Welche Quellen geprüft werden. Default: alle.

.EXAMPLE
    # Erster Lauf: immer mit -Diagnose, um zu sehen was in der Umgebung tatsächlich geloggt wird
    .\Find-FslogixTempProfiles.ps1 -SearchBase "OU=FARMP10,OU=WTS 10.25,OU=Servers,OU=AHP Infrastructure Objects,DC=contoso,DC=local" -DaysBack 7 -Diagnose

.EXAMPLE
    .\Find-FslogixTempProfiles.ps1 -SearchBase "OU=FARMP10,...,DC=contoso,DC=local" -DaysBack 7 -OutputCsv C:\temp\rwi\TempProfiles.csv
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SearchBase,

    [int]$DaysBack = 7,

    [ValidateSet('Registry', 'FslogixEvents', 'UpsEvents', 'LogFiles')]
    [string[]]$Sources = @('Registry', 'FslogixEvents', 'UpsEvents', 'LogFiles'),

    [string]$LogPath = 'C:\ProgramData\FSLogix\Logs\Profile',

    # Muster, die direkt auf ein Temp-Profil hindeuten
    [string[]]$TempPattern = @(
        'temporary profile',
        'temp profile',
        'tempor[aä]r',
        'as a temp',
        'TEMP_PROFILE',
        'ProfileType.*[Tt]emp'
    ),

    # Fehlerzeilen-Marker. FSLogix schreibt die Stufe als [ERROR:0000007b] / [ERR] in den Zeilenkopf.
    # Das ist sprach- und versionsunabhaengig und damit der verlaesslichste Anker.
    [string]$ErrorPattern = '\[ERR',

    # Bekanntes Rauschen, das NICHT gemeldet wird.
    # - MSTeams/AppX/AppLocker: FSLogix versucht bei jedem Logon die Teams-MSIX zu registrieren,
    #   AppLocker blockt das mit 0x800704EC. Gewollt, wenn Teams nicht per AppX verteilt wird.
    # - "Failed to query username/domain name/connection state for session": Abfragen auf bereits
    #   beendete Sessions, ohne Aussagekraft.
    [string[]]$ExcludePattern = @(
        'MSTeams',
        'AppLocker',
        '_8wekyb3d8bbwe',
        '0x800704EC',
        'Failed to query (username|domain name|connection state) for session',
        'getUserToken'
    ),

    # Meldungen, die eine fehlgeschlagene Profilladung belegen (Logon blockiert ODER Temp-Profil)
    [string[]]$FailPattern = @(
        'LoadProfile failed',
        'profile disk is in use',
        'Logon failed',
        'Failed to open virtual disk',
        "is using .*'s .*disk",
        'file is locked',
        'Failed to remove corrupt',
        "registry hive was missing"
    ),

    # Optionale Eingrenzung: nur Fehlerzeilen, die sich thematisch auf das Profil beziehen.
    # Nur wirksam mit -OnlyProfileRelevant.
    [string[]]$CausePattern = @(
        'profile', 'vhd', 'disk', 'attach', 'mount', 'container',
        'in use', 'sharing', 'denied', 'corrupt', 'redirect'
    ),

    # Nur profilbezogene Fehlerzeilen melden statt aller [ERR...]-Zeilen
    [switch]$OnlyProfileRelevant,

    [switch]$Diagnose,
    [string]$ComputerFilter = '*',
    [string]$OutputCsv,

    [int]$BatchSize = 20,
    [int]$ThrottleLimit = 10,
    [switch]$SkipPing
)

#region --- Analyse-Scriptblock ---------------------------------------------------------
# Nimmt GENAU EINEN Parameter (Hashtable) entgegen.
# Grund: Invoke-Command -ArgumentList flacht Arrays auf und verschiebt dadurch alle Folgeparameter.

$AnalyzeBlock = {
    param([hashtable]$Cfg)

    $Path        = $Cfg.Path
    $Cutoff      = $Cfg.Cutoff
    $TempRegex   = $Cfg.TempRegex
    $ErrorRegex  = $Cfg.ErrorRegex
    $CauseRegex  = $Cfg.CauseRegex
    $ExclRegex   = $Cfg.ExcludeRegex
    $FailRegex   = $Cfg.FailRegex
    $OnlyRel     = $Cfg.OnlyProfileRelevant
    $Sources     = $Cfg.Sources
    $Diagnose    = $Cfg.Diagnose
    $Label       = if ($Cfg.ComputerLabel) { $Cfg.ComputerLabel } else { $env:COMPUTERNAME }

    $out = New-Object System.Collections.Generic.List[object]

    function Add-Row {
        param($Severity, $Source, $User, $When, $Message, $Detail)
        $out.Add([pscustomobject]@{
            Computer = $Label
            Severity = $Severity        # HIT | CAUSE | INFO | WARN
            Source   = $Source
            User     = $User
            When     = $When
            Message  = $Message
            Detail   = $Detail
        })
    }

    function Resolve-Sid {
        param([string]$Sid)
        try { (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value }
        catch { $Sid }
    }

    # ---------- 1) Registry: FSLogix Session-Status ----------
    if ($Sources -contains 'Registry') {
        $sessRoot = 'HKLM:\SOFTWARE\FSLogix\Profiles\Sessions'
        if (Test-Path $sessRoot) {
            $sessions = @(Get-ChildItem $sessRoot -ErrorAction SilentlyContinue)
            if ($Diagnose) { Add-Row 'INFO' 'Registry' $null $null ("Aktive FSLogix-Sessions: {0}" -f $sessions.Count) $sessRoot }
            foreach ($s in $sessions) {
                $p = Get-ItemProperty $s.PSPath -ErrorAction SilentlyContinue
                $sid  = Split-Path $s.PSPath -Leaf
                $user = Resolve-Sid $sid
                if ($p.Temporary -eq 1) {
                    Add-Row 'HIT' 'Registry-Temporary' $user $null 'FSLogix: Session laeuft mit TEMPORAEREM Profil (Temporary=1)' "$sid"
                }
                # Status/Reason sind im Normalbetrieb ungleich 0 (aktive Session) und daher
                # KEIN Fehlerindikator - nur in der Diagnose ausgeben.
                if ($Diagnose) {
                    Add-Row 'INFO' 'Registry-Session' $user $null `
                        ("Status={0} Reason={1} Temporary={2}" -f $p.Status, $p.Reason, $p.Temporary) "$sid"
                }
            }
        } elseif ($Diagnose) {
            Add-Row 'INFO' 'Registry' $null $null 'Kein FSLogix-Sessions-Key vorhanden (keine aktive Session)' $sessRoot
        }

        # Konfiguration: bekommt der Benutzer bei Fehler ein Temp-Profil oder wird der Logon verweigert?
        $prof = Get-ItemProperty 'HKLM:\SOFTWARE\FSLogix\Profiles' -ErrorAction SilentlyContinue
        if ($prof) {
            $pl  = [int]($prof.PreventLoginWithFailure)
            $plt = [int]($prof.PreventLoginWithTempProfile)
            $mode = if ($pl -eq 1 -or $plt -eq 1) { 'Logon wird VERWEIGERT (kein Temp-Profil)' }
                    else { 'Benutzer erhaelt bei Fehler ein TEMP-PROFIL' }
            Add-Row 'INFO' 'Registry-Config' $null $null `
                ("PreventLoginWithFailure={0} PreventLoginWithTempProfile={1} -> {2}" -f $pl, $plt, $mode) $null
        }
    }

    # ---------- 2) FSLogix-eigene Eventlogs ----------
    if ($Sources -contains 'FslogixEvents') {
        foreach ($ln in 'Microsoft-FSLogix-Apps/Operational', 'Microsoft-FSLogix-Apps/Admin') {
            try {
                $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $ln; StartTime = $Cutoff; Level = 1, 2, 3 } -ErrorAction Stop)
                if ($Diagnose) { Add-Row 'INFO' 'FslogixEvents' $null $null ("$ln : {0} Events (Level 1-3)" -f $ev.Count) $null }
                $skipped = 0
                foreach ($e in $ev) {
                    $first = ($e.Message -split "`r?`n")[0]
                    if ($ExclRegex -and $first -match $ExclRegex) { $skipped++; continue }
                    $sev = if ($first -match $TempRegex) { 'HIT' }
                           elseif ($first -match $FailRegex) { 'FAIL' } else { 'CAUSE' }
                    $u = $null
                    if ($e.UserId) { $u = Resolve-Sid $e.UserId.Value }
                    if ($first -match '(?i)\bUser:\s*(?<u>[^\s.,;]+)') { $u = $Matches.u }
                    Add-Row $sev "FSLogixEvent-$($e.Id)" $u $e.TimeCreated $first $ln
                }
                if ($Diagnose -and $skipped) { Add-Row 'INFO' 'FslogixEvents' $null $null ("$ln : $skipped Events als Rauschen ignoriert") $null }
            } catch {
                if ($_.Exception.Message -notmatch 'No events were found|Es wurden keine Ereignisse|kein Ereignisprotokoll|does not exist') {
                    Add-Row 'WARN' 'FslogixEvents' $null $null "$ln nicht lesbar: $($_.Exception.Message)" $null
                } elseif ($Diagnose) {
                    Add-Row 'INFO' 'FslogixEvents' $null $null "$ln : keine Events im Zeitraum" $null
                }
            }
        }
    }

    # ---------- 3) User Profile Service 1511/1515 ----------
    if ($Sources -contains 'UpsEvents') {
        try {
            $ev = @(Get-WinEvent -FilterHashtable @{
                LogName = 'Application'; ProviderName = 'Microsoft-Windows-User Profiles Service'
                Id = 1511, 1515; StartTime = $Cutoff } -ErrorAction Stop)
            if ($Diagnose) { Add-Row 'INFO' 'UpsEvents' $null $null ("UPS 1511/1515: {0} Events" -f $ev.Count) $null }
            foreach ($e in $ev) {
                $u = $null
                if ($e.UserId) { $u = Resolve-Sid $e.UserId.Value }
                Add-Row 'HIT' "UPS-$($e.Id)" $u $e.TimeCreated (($e.Message -split "`r?`n")[0]) 'Application'
            }
        } catch {
            if ($_.Exception.Message -notmatch 'No events were found|Es wurden keine Ereignisse') {
                Add-Row 'WARN' 'UpsEvents' $null $null "UPS-Events nicht lesbar: $($_.Exception.Message)" $null
            } elseif ($Diagnose) {
                Add-Row 'INFO' 'UpsEvents' $null $null 'UPS 1511/1515: keine Events im Zeitraum' $null
            }
        }
    }

    # ---------- 4) FSLogix Profile-Logdateien ----------
    if ($Sources -contains 'LogFiles') {
        if (-not (Test-Path -LiteralPath $Path)) {
            Add-Row 'WARN' 'LogFiles' $null $null "Logpfad existiert nicht: $Path" $null
        }
        else {
            # bewusst *.log (nicht nur Profile-*.log), damit keine Datei durchrutscht
            $allFiles = @(Get-ChildItem -LiteralPath $Path -Filter '*.log' -File -ErrorAction SilentlyContinue)
            $files    = @($allFiles | Where-Object { $_.LastWriteTime -ge $Cutoff } | Sort-Object Name)

            if ($allFiles.Count -eq 0) {
                Add-Row 'WARN' 'LogFiles' $null $null "Keine *.log-Dateien in $Path gefunden (Logging deaktiviert?)" $null
            }
            elseif ($files.Count -eq 0) {
                Add-Row 'WARN' 'LogFiles' $null $null ("Keine Logdatei im Zeitraum. Neueste: {0} ({1:yyyy-MM-dd})" -f `
                    $allFiles[-1].Name, ($allFiles | Sort-Object LastWriteTime)[-1].LastWriteTime) $null
            }

            $totalLines = 0; $errLines = 0; $warnLines = 0; $noise = 0

            foreach ($file in $files) {
                $lines = $null
                try { $lines = [System.IO.File]::ReadAllLines($file.FullName) }
                catch {
                    try {
                        $fs = [System.IO.File]::Open($file.FullName, 'Open', 'Read', 'ReadWrite')
                        $sr = New-Object System.IO.StreamReader($fs)
                        $lines = @(); while (-not $sr.EndOfStream) { $lines += $sr.ReadLine() }
                        $sr.Close(); $fs.Close()
                    } catch {
                        Add-Row 'WARN' 'LogFiles' $null $null "Datei nicht lesbar: $($file.Name) - $($_.Exception.Message)" $null
                        continue
                    }
                }
                $totalLines += $lines.Count

                for ($i = 0; $i -lt $lines.Count; $i++) {
                    $line = $lines[$i]

                    # Fehlerzeile? FSLogix schreibt die Stufe als [ERROR:0000007b] bzw. [ERR...]
                    $isErr = $line -match $ErrorRegex
                    if ($isErr)                    { $errLines++ }
                    elseif ($line -match '\[WARN') { $warnLines++ }

                    # Bekanntes Rauschen (MSTeams/AppLocker, Session-Abfragen) komplett ignorieren
                    if ($ExclRegex -and $line -match $ExclRegex) { $noise++; continue }

                    $isTemp = $line -match $TempRegex
                    $isFail = $line -match $FailRegex

                    # Optional: uebrige Fehlerzeilen auf profilbezogene Meldungen eingrenzen
                    if ($isErr -and $OnlyRel -and ($line -notmatch $CauseRegex)) { $isErr = $false }

                    if (-not ($isTemp -or $isFail -or $isErr)) { continue }

                    # Zeilenformat: [HH:mm:ss.fff][tid:xxxxxxxx.xxxxxxxx][ERROR:0000007b]  Meldung
                    $time = $null; $tid = $null; $msg = $line; $code = $null
                    if ($line -match '^\[(?<time>\d{2}:\d{2}:\d{2}(\.\d+)?)\]\[tid:(?<tid>[0-9a-fA-F.]+)\]\[(?<lvl>[^\]]*)\]\s*(?<msg>.*)$') {
                        $time = $Matches.time; $tid = $Matches.tid; $msg = $Matches.msg.Trim()
                        if ($Matches.lvl -match '(?i)ERR[A-Z]*\s*:\s*(?<c>[0-9a-fA-F]+)') { $code = "0x$($Matches.c)" }
                    }

                    # Benutzer aus dem Kontext desselben Threads ermitteln
                    $user = $null
                    for ($j = $i; $j -ge [Math]::Max(0, $i - 500); $j--) {
                        $ctx = $lines[$j]
                        if ($tid -and $ctx -notmatch [regex]::Escape("[tid:$tid]")) { continue }
                        if ($ctx -match '(?i)\b(Username|User|UserName|Account|SamAccountName)\s*[:=]\s*(?<u>[^\s\]]+)') { $user = $Matches.u; break }
                        if (-not $user -and $ctx -match '(?<sid>S-1-5-21-[\d-]+)') { $user = Resolve-Sid $Matches.sid }
                    }

                    $when = $null
                    if ($file.BaseName -match '(\d{4})(\d{2})(\d{2})' -and $time) {
                        $when = '{0}-{1}-{2} {3}' -f $Matches[1], $Matches[2], $Matches[3], $time
                    } elseif ($time) { $when = $time }

                    # Benutzer bevorzugt direkt aus der Meldung ziehen
                    # ("LoadProfile failed. Version: x User: u000001. SID: S-1-5-... SessionId: 101.")
                    if ($msg -match '(?i)\bUser:\s*(?<u>[^\s.,;]+)') { $user = $Matches.u }
                    elseif ($msg -match "(?i)is using (?<u>[^\s']+)'s") { $user = $Matches.u }

                    $sev = if ($isTemp) { 'HIT' } elseif ($isFail) { 'FAIL' } else { 'CAUSE' }
                    $src = if ($isTemp) { 'Log-TempProfile' }
                           elseif ($isFail) { 'Log-ProfilFehler' }
                           elseif ($code) { "Log-ERROR $code" }
                           else { 'Log-ERROR' }

                    Add-Row $sev $src $user $when $msg "$($file.Name)"
                }
            }

            if ($Diagnose) {
                $range = if ($files.Count) { "{0} .. {1}" -f $files[0].Name, $files[-1].Name } else { '-' }
                Add-Row 'INFO' 'LogFiles' $null $null `
                    ("Logdateien gesamt: {0}, im Zeitraum: {1} [{2}], Zeilen: {3}, ERROR: {4}, WARN: {5}, ignoriert (Rauschen): {6}" -f `
                        $allFiles.Count, $files.Count, $range, $totalLines, $errLines, $warnLines, $noise) $Path
            }
        }
    }

    return $out
}

#endregion

#region --- Hauptlogik ------------------------------------------------------------------

Import-Module ActiveDirectory -ErrorAction Stop

$cutoff     = (Get-Date).Date.AddDays(-$DaysBack)
$tempRegex  = ($TempPattern  -join '|')
$causeRegex = ($CausePattern -join '|')
$errRegex   = $ErrorPattern
$exclRegex  = if ($ExcludePattern) { ($ExcludePattern -join '|') } else { $null }
$failRegex  = ($FailPattern -join '|')

Write-Host "Terminalserver aus OU lesen: $SearchBase" -ForegroundColor Cyan

$computers = Get-ADComputer -SearchBase $SearchBase -Filter 'Enabled -eq $true' -Properties DNSHostName |
    Where-Object { $_.Name -like $ComputerFilter } | Sort-Object Name
if (-not $computers) { Write-Warning 'Keine aktivierten Computerobjekte in der OU gefunden.'; return }

$hostnames = @($computers | ForEach-Object { if ($_.DNSHostName) { $_.DNSHostName } else { $_.Name } })
Write-Host ("{0} Server | Zeitraum seit {1:yyyy-MM-dd} | Quellen: {2}" -f `
    $hostnames.Count, $cutoff, ($Sources -join ', ')) -ForegroundColor Cyan

# --- Erreichbarkeit (TCP 5985 statt Ping) ---
$online = New-Object System.Collections.Generic.List[string]
$offline = New-Object System.Collections.Generic.List[string]
if ($SkipPing) { $hostnames | ForEach-Object { $online.Add($_) } }
else {
    Write-Host 'Erreichbarkeit pruefen (TCP/5985)...' -ForegroundColor Cyan
    $n = 0
    foreach ($h in $hostnames) {
        $n++
        Write-Progress -Activity 'Erreichbarkeit' -Status $h -PercentComplete (($n / $hostnames.Count) * 100)
        $ok = $false
        try {
            $c = New-Object System.Net.Sockets.TcpClient
            $iar = $c.BeginConnect($h, 5985, $null, $null)
            $ok = $iar.AsyncWaitHandle.WaitOne(1500, $false) -and $c.Connected
            if ($ok) { $c.EndConnect($iar) }
            $c.Close()
        } catch { $ok = $false }
        if ($ok) { $online.Add($h) } else { $offline.Add($h) }
    }
    Write-Progress -Activity 'Erreichbarkeit' -Completed
    Write-Host ("Erreichbar: {0} | nicht erreichbar: {1}" -f $online.Count, $offline.Count) -ForegroundColor Cyan
}

$all = New-Object System.Collections.Generic.List[object]
$cfg = @{
    Path = $LogPath; Cutoff = $cutoff
    TempRegex = $tempRegex; ErrorRegex = $errRegex; CauseRegex = $causeRegex
    ExcludeRegex = $exclRegex; FailRegex = $failRegex
    OnlyProfileRelevant = [bool]$OnlyProfileRelevant
    Sources = $Sources; Diagnose = [bool]$Diagnose; ComputerLabel = $null
}

$total = $online.Count
$batches = [Math]::Max(1, [Math]::Ceiling($total / $BatchSize))
Write-Host "Analyse per WinRM in $batches Batch(es) a max. $BatchSize Server..." -ForegroundColor Cyan

for ($b = 0; $b -lt $batches; $b++) {
    $slice = $online[($b * $BatchSize)..([Math]::Min(($b + 1) * $BatchSize - 1, $total - 1))]
    Write-Progress -Activity 'FSLogix-Analyse' -Status ("Batch {0}/{1}" -f ($b + 1), $batches) `
        -PercentComplete ((($b + 1) / $batches) * 100)

    $rmErr = $null
    $res = Invoke-Command -ComputerName $slice -ThrottleLimit $ThrottleLimit `
        -ScriptBlock $AnalyzeBlock -ArgumentList $cfg -ErrorAction SilentlyContinue -ErrorVariable rmErr

    foreach ($r in $res) {
        $all.Add([pscustomobject]@{
            Computer = $r.PSComputerName; Severity = $r.Severity; Source = $r.Source
            User = $r.User; When = $r.When; Message = $r.Message; Detail = $r.Detail })
    }
    foreach ($e in $rmErr) {
        $t = $e.TargetObject; if (-not $t) { $t = $e.OriginInfo.PSComputerName }
        $all.Add([pscustomobject]@{ Computer = $t; Severity = 'WARN'; Source = 'WinRM'
            User = $null; When = $null; Message = $e.Exception.Message; Detail = $null })
    }
}
Write-Progress -Activity 'FSLogix-Analyse' -Completed

foreach ($h in $offline) {
    $all.Add([pscustomobject]@{ Computer = $h; Severity = 'WARN'; Source = 'Erreichbarkeit'
        User = $null; When = $null; Message = 'Server nicht erreichbar (TCP 5985)'; Detail = $null })
}

#endregion

#region --- Ausgabe ---------------------------------------------------------------------

$hits   = @($all | Where-Object Severity -eq 'HIT')
$fails  = @($all | Where-Object Severity -eq 'FAIL')
$causes = @($all | Where-Object Severity -eq 'CAUSE')
$infos  = @($all | Where-Object Severity -eq 'INFO')
$warns  = @($all | Where-Object Severity -eq 'WARN')

Write-Host ''
Write-Host '==================== ZUSAMMENFASSUNG ====================' -ForegroundColor Yellow
Write-Host ("Server analysiert: {0} von {1}" -f $online.Count, $hostnames.Count)
Write-Host ("TEMPORAERES PROFIL (eindeutig): {0} Treffer auf {1} Server(n)" -f `
    $hits.Count, @($hits | Select-Object -ExpandProperty Computer -Unique).Count) `
    -ForegroundColor $(if ($hits.Count) { 'Red' } else { 'Green' })
Write-Host ("Moegliche Ursachen / Profilfehler: {0} Treffer auf {1} Server(n)" -f `
    $causes.Count, @($causes | Select-Object -ExpandProperty Computer -Unique).Count) `
    -ForegroundColor $(if ($causes.Count) { 'Yellow' } else { 'Green' })
Write-Host ("Warnungen/nicht auswertbar: {0}" -f $warns.Count)

Write-Host ("FEHLGESCHLAGENE PROFILLADUNGEN: {0} Meldungen, {1} Benutzer, {2} Server" -f `
    $fails.Count, @($fails | Where-Object User | Select-Object -ExpandProperty User -Unique).Count, `
    @($fails | Select-Object -ExpandProperty Computer -Unique).Count) `
    -ForegroundColor $(if ($fails.Count) { 'Red' } else { 'Green' })

# Konfiguration: Temp-Profil oder Logon-Verweigerung?
$cfgRows = @($all | Where-Object Source -eq 'Registry-Config')
if ($cfgRows.Count) {
    Write-Host ''
    Write-Host '--- FSLOGIX-VERHALTEN BEI PROFILFEHLER ---' -ForegroundColor Cyan
    $cfgRows | Group-Object Message | Sort-Object Count -Descending | ForEach-Object {
        Write-Host ("  [{0,3} Server] {1}" -f $_.Count, $_.Name) -ForegroundColor Cyan
    }
}

if ($fails.Count) {
    Write-Host ''
    Write-Host '--- FEHLGESCHLAGENE PROFILLADUNGEN je Benutzer ---' -ForegroundColor Red
    $fails | Where-Object User | Group-Object User | Sort-Object Count -Descending | ForEach-Object {
        $srv = (@($_.Group | Select-Object -ExpandProperty Computer -Unique)) -join ', '
        Write-Host ("  {0,-14} {1,3}x  auf: {2}" -f $_.Name, $_.Count, $srv) -ForegroundColor Red
    }
    Write-Host ''
    $fails | Where-Object { $_.Message -match 'LoadProfile failed|profile disk is in use' } |
        Sort-Object When | Format-Table When, Computer, User, Message -AutoSize -Wrap
}

if ($hits.Count) {
    Write-Host ''
    Write-Host '--- BENUTZER MIT TEMPORAEREM PROFIL ---' -ForegroundColor Red
    $hits | Group-Object Computer | Sort-Object Name | ForEach-Object {
        $u = (@($_.Group | Where-Object User | Select-Object -ExpandProperty User -Unique)) -join ', '
        if (-not $u) { $u = '(Benutzer nicht ermittelbar)' }
        Write-Host ("  {0,-24} {1,3}x  ->  {2}" -f $_.Name, $_.Count, $u)
    }
    Write-Host ''
    $hits | Sort-Object Computer, When | Format-Table Computer, When, User, Source, Message -AutoSize -Wrap
}

if ($causes.Count) {
    Write-Host ''
    Write-Host '--- FEHLERZEILEN nach Fehlercode ---' -ForegroundColor Yellow
    $causes | Group-Object Source | Sort-Object Count -Descending | Select-Object -First 15 | ForEach-Object {
        $srv = @($_.Group | Select-Object -ExpandProperty Computer -Unique).Count
        Write-Host ("  [{0,5}x auf {1,3} Server] {2}" -f $_.Count, $srv, $_.Name) -ForegroundColor Yellow
        $_.Group | Select-Object -ExpandProperty Message -Unique | Select-Object -First 3 | ForEach-Object {
            Write-Host ("            $_") -ForegroundColor DarkGray }
    }

    Write-Host ''
    Write-Host '--- FEHLERZEILEN nach Meldung (normalisiert) ---' -ForegroundColor Yellow
    $causes | ForEach-Object {
        # Zahlen, Hex-Werte, SIDs und Pfade maskieren, damit gleichartige Meldungen zusammenfallen
        $norm = $_.Message -replace 'S-1-5-21-[\d-]+', '<SID>' `
                           -replace '0x[0-9a-fA-F]+', '<HEX>' `
                           -replace '[A-Za-z]:\\[^\s,;]+', '<PFAD>' `
                           -replace '\\\\[^\s,;]+', '<UNC>' `
                           -replace '\b\d{3,}\b', '<N>'
        [pscustomobject]@{ Norm = $norm; Computer = $_.Computer; User = $_.User; Original = $_.Message }
    } | Group-Object Norm | Sort-Object Count -Descending | Select-Object -First 20 | ForEach-Object {
        $srv = @($_.Group | Select-Object -ExpandProperty Computer -Unique).Count
        Write-Host ("  [{0,5}x auf {1,3} Server] {2}" -f $_.Count, $srv, $_.Name) -ForegroundColor Yellow
        Write-Host ("            z.B. " + ($_.Group[0].Original)) -ForegroundColor DarkGray
    }
}

if ($Diagnose -and $infos.Count) {
    Write-Host ''
    Write-Host '--- DIAGNOSE (was wurde ueberhaupt durchsucht) ---' -ForegroundColor Cyan
    $infos | Group-Object Message | Sort-Object Count -Descending | Select-Object -First 20 | ForEach-Object {
        Write-Host ("  [{0,4}x] {1}" -f $_.Count, $_.Name) -ForegroundColor DarkCyan
    }
    Write-Host ''
    Write-Host '  Beispiel eines einzelnen Servers:' -ForegroundColor Cyan
    $first = @($infos | Select-Object -ExpandProperty Computer -Unique)[0]
    $infos | Where-Object Computer -eq $first | Format-Table Computer, Source, Message -AutoSize -Wrap
}

if ($warns.Count) {
    Write-Host ''
    Write-Host '--- WARNUNGEN (gruppiert) ---' -ForegroundColor DarkYellow
    $warns | Group-Object Message | Sort-Object Count -Descending | ForEach-Object {
        Write-Host ("  [{0,4}x] {1}" -f $_.Count, $_.Name) -ForegroundColor DarkYellow
        Write-Host ("          " + ((@($_.Group.Computer) | Select-Object -First 8) -join ', ') +
                    $(if ($_.Count -gt 8) { " ... (+$($_.Count - 8))" })) -ForegroundColor DarkGray
    }
}

if ($OutputCsv) {
    $all | Sort-Object Severity, Computer, When | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    Write-Host ''
    Write-Host "CSV exportiert: $OutputCsv" -ForegroundColor Cyan
}

$all

#endregion