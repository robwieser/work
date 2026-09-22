<#
.SYNOPSIS
    Prueft farmweit, ob ein bestimmter Prozess dauerhaft CPU verbraucht - getrennt nach
    aktiven und getrennten Sessions.

.DESCRIPTION
    Entstanden aus der Beobachtung, dass AHPLogon in haengenden Sessions enorme CPU-Zeit
    ansammelt (in einem Fall 170.741 CPU-Sekunden ueber 131 Stunden Laufzeit). Die offene
    Frage dabei: Tritt das generell auf oder erst, nachdem die Session getrennt wurde?

    Das Skript ermittelt je Server alle Instanzen des gesuchten Prozesses, berechnet die
    dauerhafte CPU-Last (CPU-Sekunden geteilt durch Lebensdauer, in Prozent eines Kerns) und
    ordnet jede Instanz ueber die WTS-API ihrer Session zu - inklusive Status (Aktiv/Getrennt),
    Benutzer und Trennzeitpunkt.

    Die Auswertung stellt aktive und getrennte Sessions gegenueber. Liegt die Last in beiden
    Gruppen gleich hoch, ist es ein genereller Fehler im Prozess. Steigt sie erst nach dem
    Trennen deutlich an, reagiert der Prozess auf den Sessionwechsel.

    Reines Lesen - es wird nichts veraendert.

.PARAMETER SearchBase
    DN der AD-OU mit den Terminalservern. Alternativ -ComputerName.

.PARAMETER ComputerName
    Explizite Serverliste.

.PARAMETER ProcessName
    Prozessname ohne .exe (Default: AHPLogon). Mehrere moeglich, Wildcards erlaubt.

.PARAMETER WarnPercent
    Ab welcher Dauerlast (% eines Kerns) eine Instanz als auffaellig gilt (Default: 10).

.EXAMPLE
    .\Get-ProcessBurnRate.ps1 -SearchBase "OU=FARMP10,OU=WTS 10.25,OU=Servers,OU=AHP Infrastructure Objects,DC=medi,DC=local" -OutputCsv C:\temp\rwi\ahplogon.csv

.EXAMPLE
    # Mehrere AHP-Komponenten auf einmal vergleichen
    .\Get-ProcessBurnRate.ps1 -SearchBase "OU=FARMP10,...,DC=medi,DC=local" -ProcessName AHPLogon,'AHP Session Manager'

.EXAMPLE
    # Nur die zehn Server aus der Logauswertung
    .\Get-ProcessBurnRate.ps1 -ComputerName sr00045270,sr00045273,sr00045305 -ProcessName AHPLogon
#>
[CmdletBinding(DefaultParameterSetName = 'OU')]
param(
    [Parameter(Mandatory, ParameterSetName = 'OU')]
    [string]$SearchBase,

    [Parameter(Mandatory, ParameterSetName = 'List')]
    [string[]]$ComputerName,

    [string[]]$ProcessName = @('AHPLogon'),
    [string]$ComputerFilter = '*',
    [int]$WarnPercent = 10,

    [string]$OutputCsv,
    [int]$BatchSize = 20,
    [int]$ThrottleLimit = 10,
    [switch]$SkipPing
)

#region --- Remote-Scriptblock ----------------------------------------------------------

$Block = {
    param([hashtable]$Cfg)

    $me = $env:COMPUTERNAME
    $out = New-Object System.Collections.Generic.List[object]

    # --- Sessions ueber die WTS-API (sprachunabhaengig, auch ueber WinRM nutzbar) ---
    if (-not ('Wts.Api' -as [type])) {
        Add-Type -ErrorAction SilentlyContinue -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Wts {
  [StructLayout(LayoutKind.Sequential)]
  public struct SESSION_INFO { public int SessionId; public IntPtr pWinStationName; public int State; }

  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct INFOEX1 {
    public int SessionId; public int SessionState; public int SessionFlags;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 33)] public string WinStationName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)] public string UserName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 18)] public string DomainName;
    public long LogonTime; public long ConnectTime; public long DisconnectTime;
    public long LastInputTime; public long CurrentTime;
  }

  public class Session {
    public int SessionId; public int State; public string UserName;
    public DateTime? LogonTime; public DateTime? DisconnectTime;
  }

  public static class Api {
    [DllImport("wtsapi32.dll", SetLastError = true)]
    static extern int WTSEnumerateSessionsW(IntPtr hServer, int Reserved, int Version, ref IntPtr ppSessionInfo, ref int pCount);
    [DllImport("wtsapi32.dll", SetLastError = true)]
    static extern int WTSQuerySessionInformationW(IntPtr hServer, int sessionId, int infoClass, out IntPtr ppBuffer, out int pBytesReturned);
    [DllImport("wtsapi32.dll")]
    static extern void WTSFreeMemory(IntPtr pMemory);

    public static Session[] GetSessions() {
      var list = new List<Session>();
      IntPtr pp = IntPtr.Zero; int cnt = 0;
      if (WTSEnumerateSessionsW(IntPtr.Zero, 0, 1, ref pp, ref cnt) == 0)
        throw new Exception("WTSEnumerateSessions Win32-Fehler " + Marshal.GetLastWin32Error());
      try {
        int size = Marshal.SizeOf(typeof(SESSION_INFO));
        for (int i = 0; i < cnt; i++) {
          IntPtr cur = new IntPtr(pp.ToInt64() + (long)i * size);
          SESSION_INFO si = (SESSION_INFO)Marshal.PtrToStructure(cur, typeof(SESSION_INFO));
          IntPtr buf; int n;
          if (WTSQuerySessionInformationW(IntPtr.Zero, si.SessionId, 25, out buf, out n) == 0) continue;
          try {
            INFOEX1 x = (INFOEX1)Marshal.PtrToStructure(new IntPtr(buf.ToInt64() + 8), typeof(INFOEX1));
            Session s = new Session();
            s.SessionId = si.SessionId; s.State = x.SessionState; s.UserName = x.UserName;
            if (x.LogonTime > 0) s.LogonTime = DateTime.FromFileTime(x.LogonTime);
            if (x.DisconnectTime > 0) s.DisconnectTime = DateTime.FromFileTime(x.DisconnectTime);
            list.Add(s);
          } finally { WTSFreeMemory(buf); }
        }
      } finally { WTSFreeMemory(pp); }
      return list.ToArray();
    }
  }
}
'@
    }

    $sess = @{}
    try {
        foreach ($s in [Wts.Api]::GetSessions()) { $sess[$s.SessionId] = $s }
    } catch {
        $out.Add([pscustomobject]@{
            Computer = $me; Prozess = $null; Pid = $null; SessionId = $null; Benutzer = $null
            SessionStatus = $null; GetrenntSeit = $null; LaufzeitStd = $null; CpuSek = $null
            CpuProzent = $null; SpeicherMB = $null; Hinweis = "WTS-Sessions nicht lesbar: $($_.Exception.Message)" })
    }

    $now = Get-Date
    $found = 0

    foreach ($pattern in @($Cfg.Names)) {
        foreach ($p in @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like $pattern })) {
            $found++

            $start = $null
            try { $start = $p.StartTime } catch { }
            $cpu = $null
            try { if ($null -ne $p.CPU) { $cpu = [math]::Round($p.CPU, 1) } } catch { }
            $memMb = $null
            try { $memMb = [math]::Round($p.WorkingSet64 / 1MB, 1) } catch { }

            $hours = $null; $pct = $null
            if ($start) {
                $sec = ($now - $start).TotalSeconds
                $hours = [math]::Round($sec / 3600, 1)
                if ($sec -gt 60 -and $null -ne $cpu) { $pct = [math]::Round(($cpu / $sec) * 100, 1) }
            }

            $s = $sess[$p.SessionId]
            $stateName = 'unbekannt'; $user = $null; $discSince = $null
            if ($s) {
                $user = $s.UserName
                $stateName = switch ($s.State) {
                    0 { 'Aktiv' } 1 { 'Verbunden' } 2 { 'ConnectQuery' } 3 { 'Shadow' }
                    4 { 'Getrennt' } 5 { 'Idle' } 6 { 'Listen' } 7 { 'Reset' } 8 { 'Down' } 9 { 'Init' }
                    default { "Status $($s.State)" }
                }
                if ($s.State -eq 4 -and $s.DisconnectTime) { $discSince = $s.DisconnectTime }
            }
            if ($p.SessionId -eq 0) { $stateName = 'Dienst (Session 0)' }

            $hint = ''
            if ($null -ne $pct -and $pct -ge $Cfg.WarnPercent) { $hint = 'DAUERLAST' }

            $out.Add([pscustomobject]@{
                Computer = $me; Prozess = $p.ProcessName; Pid = $p.Id; SessionId = $p.SessionId
                Benutzer = $user; SessionStatus = $stateName
                GetrenntSeit = if ($discSince) { '{0:yyyy-MM-dd HH:mm}' -f $discSince } else { $null }
                LaufzeitStd = $hours; CpuSek = $cpu; CpuProzent = $pct; SpeicherMB = $memMb
                Hinweis = $hint })
        }
    }

    if ($found -eq 0) {
        $out.Add([pscustomobject]@{
            Computer = $me; Prozess = '(nicht gefunden)'; Pid = $null; SessionId = $null; Benutzer = $null
            SessionStatus = $null; GetrenntSeit = $null; LaufzeitStd = $null; CpuSek = $null
            CpuProzent = $null; SpeicherMB = $null; Hinweis = 'Prozess laeuft auf diesem Server nicht' })
    }

    return $out
}

#endregion

#region --- Serverliste -----------------------------------------------------------------

if ($PSCmdlet.ParameterSetName -eq 'OU') {
    Import-Module ActiveDirectory -ErrorAction Stop
    $c = Get-ADComputer -SearchBase $SearchBase -Filter 'Enabled -eq $true' -Properties DNSHostName |
        Where-Object { $_.Name -like $ComputerFilter } | Sort-Object Name
    if (-not $c) { Write-Warning 'Keine Computerobjekte in der OU gefunden.'; return }
    $hosts = @($c | ForEach-Object { if ($_.DNSHostName) { $_.DNSHostName } else { $_.Name } })
} else {
    $hosts = @($ComputerName)
}

Write-Host ("{0} Server | gesuchte Prozesse: {1}" -f $hosts.Count, ($ProcessName -join ', ')) -ForegroundColor Cyan

$online = New-Object System.Collections.Generic.List[string]
$offline = New-Object System.Collections.Generic.List[string]
if ($SkipPing) { $hosts | ForEach-Object { $online.Add($_) } }
else {
    $n = 0
    foreach ($h in $hosts) {
        $n++
        Write-Progress -Activity 'Erreichbarkeit' -Status $h -PercentComplete (($n / $hosts.Count) * 100)
        $ok = $false
        try {
            $cl = New-Object System.Net.Sockets.TcpClient
            $iar = $cl.BeginConnect($h, 5985, $null, $null)
            $ok = $iar.AsyncWaitHandle.WaitOne(1500, $false) -and $cl.Connected
            if ($ok) { $cl.EndConnect($iar) }
            $cl.Close()
        } catch { $ok = $false }
        if ($ok) { $online.Add($h) } else { $offline.Add($h) }
    }
    Write-Progress -Activity 'Erreichbarkeit' -Completed
    if ($offline.Count) { Write-Warning ("Nicht erreichbar ({0}): {1}" -f $offline.Count, (($offline | Select-Object -First 8) -join ', ')) }
}

#endregion

#region --- Sammeln ---------------------------------------------------------------------

$all = New-Object System.Collections.Generic.List[object]
$cfg = @{ Names = $ProcessName; WarnPercent = $WarnPercent }
$total = $online.Count
$batches = [Math]::Max(1, [Math]::Ceiling($total / $BatchSize))

for ($b = 0; $b -lt $batches; $b++) {
    $slice = $online[($b * $BatchSize)..([Math]::Min(($b + 1) * $BatchSize - 1, $total - 1))]
    Write-Progress -Activity 'Prozesse erfassen' -Status ("Batch {0}/{1}" -f ($b + 1), $batches) `
        -PercentComplete ((($b + 1) / $batches) * 100)
    $rmErr = $null
    $r = Invoke-Command -ComputerName $slice -ThrottleLimit $ThrottleLimit `
        -ScriptBlock $Block -ArgumentList $cfg -ErrorAction SilentlyContinue -ErrorVariable rmErr
    foreach ($x in $r) {
        $all.Add([pscustomobject]@{
            Computer = $x.PSComputerName; Prozess = $x.Prozess; Pid = $x.Pid; SessionId = $x.SessionId
            Benutzer = $x.Benutzer; SessionStatus = $x.SessionStatus; GetrenntSeit = $x.GetrenntSeit
            LaufzeitStd = $x.LaufzeitStd; CpuSek = $x.CpuSek; CpuProzent = $x.CpuProzent
            SpeicherMB = $x.SpeicherMB; Hinweis = $x.Hinweis })
    }
    foreach ($e in $rmErr) {
        $t = $e.TargetObject; if (-not $t) { $t = $e.OriginInfo.PSComputerName }
        $all.Add([pscustomobject]@{
            Computer = $t; Prozess = $null; Pid = $null; SessionId = $null; Benutzer = $null
            SessionStatus = $null; GetrenntSeit = $null; LaufzeitStd = $null; CpuSek = $null
            CpuProzent = $null; SpeicherMB = $null; Hinweis = "WinRM: $($e.Exception.Message)" })
    }
}
Write-Progress -Activity 'Prozesse erfassen' -Completed

#endregion

#region --- Auswertung ------------------------------------------------------------------

function Get-Median {
    param([double[]]$Werte)
    if (-not $Werte -or $Werte.Count -eq 0) { return $null }
    $s = $Werte | Sort-Object
    $m = [int][math]::Floor($s.Count / 2)
    if ($s.Count % 2 -eq 1) { return [math]::Round($s[$m], 1) }
    return [math]::Round((($s[$m - 1] + $s[$m]) / 2), 1)
}

$inst    = @($all | Where-Object { $_.Pid -and $null -ne $_.CpuProzent })
$missing = @($all | Where-Object Hinweis -eq 'Prozess laeuft auf diesem Server nicht')
$warn    = @($all | Where-Object { $_.Hinweis -like 'WinRM*' -or $_.Hinweis -like 'WTS*' })

Write-Host ''
Write-Host '==================== ZUSAMMENFASSUNG ====================' -ForegroundColor Yellow
Write-Host ("Server geprueft: {0}   Instanzen gefunden: {1}   Server ohne Prozess: {2}" -f `
    $online.Count, $inst.Count, $missing.Count)

if (-not $inst.Count) {
    Write-Host 'Keine Instanzen mit auswertbarer CPU-Zeit gefunden.' -ForegroundColor Yellow
    if ($warn.Count) { $warn | Group-Object Hinweis | ForEach-Object { Write-Host ("  [{0}x] {1}" -f $_.Count, $_.Name) -ForegroundColor DarkYellow } }
    return $all
}

# --- Kernfrage: aktiv vs. getrennt ---
Write-Host ''
Write-Host '--- DAUERLAST NACH SESSIONSTATUS (die eigentliche Frage) ---' -ForegroundColor Cyan
$byState = $inst | Group-Object SessionStatus | Sort-Object Count -Descending
$tab = foreach ($g in $byState) {
    $vals = @($g.Group | ForEach-Object { [double]$_.CpuProzent })
    [pscustomobject]@{
        SessionStatus = $g.Name
        Instanzen     = $g.Count
        'CPU% Median' = Get-Median $vals
        'CPU% Mittel' = [math]::Round(($vals | Measure-Object -Average).Average, 1)
        'CPU% Max'    = [math]::Round(($vals | Measure-Object -Maximum).Maximum, 1)
        'Laufzeit Std Median' = Get-Median @($g.Group | Where-Object LaufzeitStd | ForEach-Object { [double]$_.LaufzeitStd })
        'davon auffaellig'    = @($g.Group | Where-Object { [double]$_.CpuProzent -ge $WarnPercent }).Count
    }
}
$tab | Format-Table -AutoSize

$akt = @($byState | Where-Object Name -eq 'Aktiv')
$get = @($byState | Where-Object Name -eq 'Getrennt')
if ($akt.Count -and $get.Count) {
    $mA = Get-Median @($akt[0].Group | ForEach-Object { [double]$_.CpuProzent })
    $mG = Get-Median @($get[0].Group | ForEach-Object { [double]$_.CpuProzent })
    Write-Host ''
    if ($null -ne $mA -and $null -ne $mG) {
        if ($mG -gt ($mA * 2) -and $mG -ge 5) {
            Write-Host ("  BEFUND: getrennte Sessions {0}% vs. aktive {1}% (Median)." -f $mG, $mA) -ForegroundColor Red
            Write-Host '  Die Last entsteht erst nach dem Trennen - der Prozess reagiert auf den Sessionwechsel.' -ForegroundColor Red
        }
        elseif ($mA -ge $WarnPercent) {
            Write-Host ("  BEFUND: auch aktive Sessions liegen bei {0}% (Median)." -f $mA) -ForegroundColor Red
            Write-Host '  Die Last ist unabhaengig vom Sessionstatus - genereller Fehler im Prozess.' -ForegroundColor Red
        }
        else {
            Write-Host ("  BEFUND: aktiv {0}%, getrennt {1}% (Median) - kein auffaelliger Unterschied." -f $mA, $mG) -ForegroundColor Green
            Write-Host '  Die hohe Last betrifft dann nur Einzelfaelle, siehe Liste unten.' -ForegroundColor Green
        }
    }
} else {
    Write-Host ''
    Write-Host '  Hinweis: Es liegen nicht beide Gruppen (Aktiv und Getrennt) vor -' -ForegroundColor DarkYellow
    Write-Host '  der Vergleich ist damit nicht aussagekraeftig. Spaeter erneut laufen lassen.' -ForegroundColor DarkYellow
}

# --- Auffaellige Instanzen ---
$hot = @($inst | Where-Object { [double]$_.CpuProzent -ge $WarnPercent } |
    Sort-Object -Property @{e={[double]$_.CpuProzent}; Descending=$true})
if ($hot.Count) {
    Write-Host ''
    Write-Host ('--- AUFFAELLIGE INSTANZEN (ab {0}% Dauerlast) ---' -f $WarnPercent) -ForegroundColor Red
    $hot | Select-Object -First 25 |
        Format-Table Computer, Prozess, Benutzer, SessionId, SessionStatus, GetrenntSeit, LaufzeitStd, CpuSek, CpuProzent -AutoSize
    if ($hot.Count -gt 25) { Write-Host ("  ... und {0} weitere (siehe CSV)" -f ($hot.Count - 25)) -ForegroundColor DarkGray }

    $cpuTage = [math]::Round((($hot | Measure-Object CpuSek -Sum).Sum / 86400), 1)
    Write-Host ''
    Write-Host ("  Summe verbrannter CPU-Zeit dieser Instanzen: {0} Tage" -f $cpuTage) -ForegroundColor Red
}

# --- Verteilung ---
Write-Host ''
Write-Host '--- VERTEILUNG DER DAUERLAST ---' -ForegroundColor Cyan
$buckets = @(
    @{ N = 'unter 1%';   F = { [double]$_.CpuProzent -lt 1 } },
    @{ N = '1 - 5%';     F = { [double]$_.CpuProzent -ge 1  -and [double]$_.CpuProzent -lt 5 } },
    @{ N = '5 - 10%';    F = { [double]$_.CpuProzent -ge 5  -and [double]$_.CpuProzent -lt 10 } },
    @{ N = '10 - 25%';   F = { [double]$_.CpuProzent -ge 10 -and [double]$_.CpuProzent -lt 25 } },
    @{ N = '25% und mehr'; F = { [double]$_.CpuProzent -ge 25 } }
)
foreach ($b in $buckets) {
    $c = @($inst | Where-Object $b.F).Count
    $bar = '#' * [math]::Min(50, [int]($c * 50 / [math]::Max(1, $inst.Count)))
    Write-Host ("  {0,-13} {1,4}  {2}" -f $b.N, $c, $bar) -ForegroundColor $(if ($b.N -match '25%|10 -') { 'Red' } else { 'DarkCyan' })
}

if ($warn.Count) {
    Write-Host ''
    Write-Host '--- PROBLEME ---' -ForegroundColor DarkYellow
    $warn | Group-Object Hinweis | Sort-Object Count -Descending | ForEach-Object {
        Write-Host ("  [{0,3}x] {1}" -f $_.Count, $_.Name) -ForegroundColor DarkYellow
    }
}
foreach ($h in $offline) {
    $all.Add([pscustomobject]@{
        Computer = $h; Prozess = $null; Pid = $null; SessionId = $null; Benutzer = $null
        SessionStatus = $null; GetrenntSeit = $null; LaufzeitStd = $null; CpuSek = $null
        CpuProzent = $null; SpeicherMB = $null; Hinweis = 'Server nicht erreichbar' })
}

if ($OutputCsv) {
    $all | Sort-Object -Property @{e={[double]$_.CpuProzent}; Descending=$true} |
        Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    Write-Host ''
    Write-Host "CSV exportiert: $OutputCsv" -ForegroundColor Cyan
}

return $all

#endregion