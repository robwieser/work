<#
.SYNOPSIS
    Zeigt, welche Prozesse in einer haengenden Terminalserver-Session den Logoff blockieren.

.DESCRIPTION
    Wenn eine getrennte Session ihr Disconnect-Limit ueberschreitet, hat Windows den Logoff
    angestossen, konnte ihn aber nicht abschliessen. Ursache ist fast immer ein Prozess, der
    nicht beendet werden kann: eine haengende Anwendung, ein offener Speichern-Dialog oder ein
    Prozess, der auf eine nicht mehr erreichbare Ressource wartet (Netzlaufwerk, Datenbank).

    Das Skript listet je angegebener Session alle Prozesse mit Startzeit, CPU-Zeit, dauerhafter
    CPU-Last und Speicher.

    WICHTIG zur Erkennung: Responding und MainWindowTitle sind ueber WinRM praktisch nie lesbar -
    die Abfrage laeuft in Session 0 und erhaelt fuer Prozesse fremder Sessions kein Fensterhandle.
    Das tragfaehige Signal ist deshalb die DAUERHAFTE CPU-LAST (CPU-Sekunden geteilt durch
    Lebensdauer): ein Prozess, der ueber Stunden einen nennenswerten Anteil eines Kerns verbraucht,
    dreht in einer Schleife und blockiert den Logoff. Zusaetzlich wird LogonUI markiert - laeuft es,
    war die Session beim Trennen gesperrt.

    Nur lesend. Mit -KillNonResponding werden auffaellige Prozesse gezielt beendet;
    danach laeuft der Logoff meist von selbst durch.

.PARAMETER Session
    Ein oder mehrere Ziele in der Form "Server:SessionId", z. B. "sr00045305:4".
    Diese Angaben stehen genau so in der Spalte Computer/SessionId von Find-FslogixOrphanedDisks.

.PARAMETER KillNonResponding
    Beendet in den angegebenen Sessions die Prozesse, deren Fenster nicht mehr reagieren.
    Unterstuetzt -WhatIf und -Confirm. Systemprozesse werden nie angefasst.

.EXAMPLE
    .\Get-StuckSessionProcesses.ps1 -Session sr00045305:4, sr00045270:72, sr00045273:3, sr00045273:11

.EXAMPLE
    .\Get-StuckSessionProcesses.ps1 -Session sr00045305:4 -KillNonResponding -WhatIf
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [string[]]$Session,

    [switch]$KillNonResponding,
    # Ab welcher Dauer-CPU-Last (% eines Kerns) ein Prozess als haengend gilt
    [int]$CpuThreshold = 20,
    [string]$OutputCsv
)

# Prozesse, die nie beendet werden - Beenden wuerde die Session hart abschiessen
$Protected = @(
    'System', 'Idle', 'csrss', 'wininit', 'winlogon', 'services', 'lsass', 'smss',
    'svchost', 'dwm', 'fontdrvhost', 'LogonUI', 'frxccd', 'frxccds', 'frxsvc'
)

$Block = {
    param([hashtable]$Cfg)

    $ids = @($Cfg.SessionIds)
    $res = New-Object System.Collections.Generic.List[object]

    foreach ($id in $ids) {
        $procs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $id })
        if (-not $procs.Count) {
            $res.Add([pscustomobject]@{
                Computer = $env:COMPUTERNAME; SessionId = $id; Prozess = '(keine Prozesse)'
                Pid = $null; Reagiert = $null; Start = $null; CpuSek = $null
                SpeicherMB = $null; Fenstertitel = $null; Hinweis = 'Session hat keine Prozesse mehr - Logoff haengt im Kernel' })
            continue
        }
        foreach ($p in $procs) {
            # Responding wirft bei Prozessen ohne Fenster - daher gekapselt
            $resp = $null
            try { if ($p.MainWindowHandle -ne 0) { $resp = $p.Responding } } catch { }
            $start = $null
            try { $start = $p.StartTime } catch { }
            $title = $null
            try { if ($p.MainWindowTitle) { $title = $p.MainWindowTitle } } catch { }

            # Achtung: try/catch ist in PowerShell 5.1 KEIN Ausdruck und darf nicht in einem
            # Hashtable-Literal stehen - Werte deshalb vorher einzeln ermitteln.
            $cpu = $null
            try { if ($null -ne $p.CPU) { $cpu = [math]::Round($p.CPU, 1) } } catch { }
            $memMb = $null
            try { $memMb = [math]::Round($p.WorkingSet64 / 1MB, 1) } catch { }

            # CPU-Auslastung ueber die Lebensdauer. Das ist das entscheidende Signal:
            # Responding/MainWindowTitle sind ueber WinRM NICHT lesbar (die Abfrage laeuft in
            # Session 0 und bekommt fuer fremde Sessions kein Fensterhandle) - deshalb wird
            # ein haengender Prozess hier ueber dauerhafte CPU-Last erkannt, nicht ueber sein Fenster.
            $cpuPct = $null
            if ($null -ne $cpu -and $start) {
                $wall = ((Get-Date) - $start).TotalSeconds
                if ($wall -gt 60) { $cpuPct = [math]::Round(($cpu / $wall) * 100, 1) }
            }

            $hint = ''
            if ($resp -eq $false) { $hint = 'REAGIERT NICHT - wahrscheinlicher Blockierer' }
            elseif ($cpuPct -ge $Cfg.CpuThreshold) { $hint = "DAUERLAST $cpuPct% eines Kerns - dreht vermutlich in einer Schleife" }
            elseif ($p.ProcessName -eq 'LogonUI') { $hint = 'Sperrbildschirm aktiv - Session war beim Trennen gesperrt' }
            elseif ($title -match '(?i)speichern|save|changes|aenderungen|schliessen|closing') {
                $hint = 'Dialogtitel deutet auf offene Rueckfrage hin'
            }

            $res.Add([pscustomobject]@{
                Computer = $env:COMPUTERNAME; SessionId = $id; Prozess = $p.ProcessName
                Pid = $p.Id; Reagiert = $resp; Start = $start
                CpuSek = $cpu; CpuProzent = $cpuPct; SpeicherMB = $memMb
                Fenstertitel = $title; Hinweis = $hint })
        }
    }
    return $res
}

$KillBlock = {
    param([hashtable]$Cfg)
    $res = New-Object System.Collections.Generic.List[object]
    foreach ($id in @($Cfg.SessionIds)) {
        foreach ($p in @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $id })) {
            if ($Cfg.Protected -contains $p.ProcessName) { continue }
            # Kandidat, wenn das Fenster nicht reagiert ODER der Prozess dauerhaft CPU brennt
            $resp = $null
            try { if ($p.MainWindowHandle -ne 0) { $resp = $p.Responding } } catch { }
            $burn = $false
            try {
                $st = $p.StartTime
                $wall = ((Get-Date) - $st).TotalSeconds
                if ($wall -gt 60 -and $null -ne $p.CPU) { $burn = (($p.CPU / $wall) * 100) -ge $Cfg.CpuThreshold }
            } catch { }
            if ($resp -ne $false -and -not $burn) { continue }
            try {
                Stop-Process -Id $p.Id -Force -ErrorAction Stop
                $res.Add([pscustomobject]@{ Computer = $env:COMPUTERNAME; SessionId = $id
                    Prozess = $p.ProcessName; Pid = $p.Id; Erfolg = $true; Meldung = 'beendet' })
            } catch {
                $res.Add([pscustomobject]@{ Computer = $env:COMPUTERNAME; SessionId = $id
                    Prozess = $p.ProcessName; Pid = $p.Id; Erfolg = $false; Meldung = $_.Exception.Message })
            }
        }
    }
    return $res
}

# --- Ziele gruppieren ---
$targets = @{}
foreach ($s in $Session) {
    if ($s -notmatch '^(?<c>[^:]+):(?<id>\d+)$') {
        Write-Warning "Ungueltiges Format (erwartet Server:SessionId): $s"; continue
    }
    $c = $Matches.c
    if (-not $targets[$c]) { $targets[$c] = @() }
    $targets[$c] += [int]$Matches.id
}
if (-not $targets.Keys.Count) { Write-Warning 'Keine gueltigen Ziele.'; return }

$all = New-Object System.Collections.Generic.List[object]
foreach ($srv in ($targets.Keys | Sort-Object)) {
    Write-Host ("--- {0}, Session(s) {1} ---" -f $srv, ($targets[$srv] -join ', ')) -ForegroundColor Cyan
    try {
        $r = Invoke-Command -ComputerName $srv -ScriptBlock $Block `
            -ArgumentList @{ SessionIds = $targets[$srv]; CpuThreshold = $CpuThreshold } -ErrorAction Stop
        foreach ($x in $r) {
            $all.Add([pscustomobject]@{
                Computer = $x.Computer; SessionId = $x.SessionId; Prozess = $x.Prozess; Pid = $x.Pid
                Reagiert = $x.Reagiert; Start = $x.Start; CpuSek = $x.CpuSek
                CpuProzent = $x.CpuProzent; SpeicherMB = $x.SpeicherMB
                Fenstertitel = $x.Fenstertitel; Hinweis = $x.Hinweis })
        }
    } catch {
        Write-Warning ("{0}: {1}" -f $srv, $_.Exception.Message)
    }
}

if (-not $all.Count) { Write-Warning 'Keine Prozessdaten erhalten.'; return }

# --- Auswertung ---
$blocker = @($all | Where-Object { $_.Hinweis })
Write-Host ''
Write-Host '==================== ERGEBNIS ====================' -ForegroundColor Yellow
Write-Host ("Prozesse gesamt: {0}   Auffaellig: {1}" -f $all.Count, $blocker.Count) `
    -ForegroundColor $(if ($blocker.Count) { 'Red' } else { 'Green' })

if ($blocker.Count) {
    Write-Host ''
    Write-Host '--- WAHRSCHEINLICHE BLOCKIERER ---' -ForegroundColor Red
    $blocker | Sort-Object -Property @{e={$_.CpuProzent}; Descending=$true} |
        Format-Table Computer, SessionId, Prozess, Pid, CpuSek, CpuProzent, Hinweis -AutoSize -Wrap
}

Write-Host ''
Write-Host '--- ALLE PROZESSE JE SESSION ---' -ForegroundColor Cyan
$all | Group-Object Computer, SessionId | ForEach-Object {
    Write-Host ("  {0}: {1} Prozesse -> {2}" -f $_.Name, $_.Count,
        ((@($_.Group | Select-Object -ExpandProperty Prozess -Unique) | Sort-Object) -join ', ')) -ForegroundColor DarkCyan
}

if ($OutputCsv) {
    $all | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    Write-Host ''
    Write-Host "CSV exportiert: $OutputCsv" -ForegroundColor Cyan
}

# --- Optional: Blockierer beenden ---
if (-not $KillNonResponding) {
    if ($blocker.Count) {
        Write-Host ''
        Write-Host 'Zum Beenden der auffaelligen Prozesse: -KillNonResponding (vorher -WhatIf).' -ForegroundColor Cyan
    }
    return $all
}

foreach ($srv in ($targets.Keys | Sort-Object)) {
    $desc = "Nicht reagierende Prozesse in Session(s) {0} beenden" -f ($targets[$srv] -join ', ')
    if (-not $PSCmdlet.ShouldProcess($srv, $desc)) { continue }
    try {
        $r = Invoke-Command -ComputerName $srv -ScriptBlock $KillBlock `
            -ArgumentList @{ SessionIds = $targets[$srv]; Protected = $Protected; CpuThreshold = $CpuThreshold } -ErrorAction Stop
        if ($r) { $r | Format-Table Computer, SessionId, Prozess, Pid, Erfolg, Meldung -AutoSize }
        else { Write-Host "$srv : nichts zu beenden" -ForegroundColor Green }
    } catch {
        Write-Warning ("{0}: {1}" -f $srv, $_.Exception.Message)
    }
}

Write-Host ''
Write-Host 'Danach den Sessionstatus erneut pruefen - der Logoff laeuft meist von selbst durch.' -ForegroundColor Cyan

return $all