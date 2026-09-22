<#
.SYNOPSIS
    Findet verwaiste FSLogix-VHDX-Attaches auf Terminalservern und loest sie auf Wunsch auf.

.DESCRIPTION
    Ein FSLogix-Profilcontainer bleibt manchmal auf einem Server attached, obwohl der Benutzer
    dort keine Session mehr hat. Meldet er sich auf einem anderen Host an, scheitert das
    Attachen dort mit ERROR_SHARING_VIOLATION (32) / FrxStatus 31 und er landet im Ersatzprofil.

    Das Skript ermittelt je Server:
      - alle attachten VHD(X) (BusType 'File Backed Virtual') und den zugehoerigen Benutzer
      - alle Sessions ueber die WTS-API (WTSEnumerateSessions / WTSSessionInfoEx):
        SessionId, Status als Enum und Trennzeitpunkt - sprachunabhaengig und auch
        ueber WinRM nutzbar, anders als quser/qwinsta
      - die geltenden RDS-Timeouts (MaxDisconnectionTime / MaxIdleTime)

    Daraus wird jede attachte Disk klassifiziert:
      AKTIV        - Benutzer hat eine aktive Session          -> alles in Ordnung
      GETRENNT     - Session existiert, ist aber getrennt      -> sauber abmelden (logoff)
      VERWAIST     - Benutzer hat gar keine Session mehr       -> Disk kann getrennt werden
      UNBEKANNT    - Sessionstatus nicht ermittelbar           -> wird nie angefasst

    OHNE -Fix wird nur berichtet. Mit -Fix werden ausschliesslich VERWAISTE Disks getrennt und
    GETRENNTE Sessions abgemeldet, die laenger als -MaxDisconnectHours bestehen. Aktive Sessions
    werden nie angefasst.

.PARAMETER SearchBase
    DN einer AD-OU, aus der die Server gelesen werden. Alternativ -ComputerName verwenden.

.PARAMETER ComputerName
    Explizite Serverliste (z. B. die Server, die laut Logauswertung Disks sperren).

.PARAMETER MaxDisconnectHours
    Ab wie vielen Stunden eine getrennte Session als abmeldereif gilt (Default: 2).

.PARAMETER Fix
    Verwaiste Disks trennen und ueberfaellige getrennte Sessions abmelden.
    Unterstuetzt -WhatIf und -Confirm.

.PARAMETER User
    Nur Disks/Sessions dieses Benutzers betrachten (Wildcards erlaubt).

.EXAMPLE
    # Nur berichten - die Server aus der Logauswertung
    .\Find-FslogixOrphanedDisks.ps1 -ComputerName srv-ts10,srv-ts02,srv-ts04,srv-ts05,srv-ts06,srv-ts07,srv-ts08,srv-ts09,srv-ts01,srv-ts03

.EXAMPLE
    # Ganze Farm pruefen
    .\Find-FslogixOrphanedDisks.ps1 -SearchBase "OU=FARMP10,OU=WTS 10.25,OU=Servers,OU=AHP Infrastructure Objects,DC=contoso,DC=local"

.EXAMPLE
    # Erst simulieren, dann wirklich aufloesen
    .\Find-FslogixOrphanedDisks.ps1 -ComputerName srv-ts10 -Fix -WhatIf
    .\Find-FslogixOrphanedDisks.ps1 -ComputerName srv-ts10 -Fix

.EXAMPLE
    # Gezielt einen Benutzer freiraeumen
    .\Find-FslogixOrphanedDisks.ps1 -SearchBase "OU=FARMP10,...,DC=contoso,DC=local" -User u000001 -Fix
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'OU')]
param(
    [Parameter(Mandatory, ParameterSetName = 'OU')]
    [string]$SearchBase,

    [Parameter(Mandatory, ParameterSetName = 'List')]
    [string[]]$ComputerName,

    [string]$ComputerFilter = '*',
    [string]$User = '*',

    # Ab wann eine getrennte Session abgemeldet werden darf.
    # Bewusst hoch (ueber Nacht): in einer WTS-Farm sind tagsueber fast alle Profildisks an
    # getrennten Sessions - das ist der Normalzustand, kein Fehler. Ein niedriger Wert wuerde
    # im laufenden Betrieb reihenweise Anwender abmelden und ungespeicherte Arbeit vernichten.
    [int]$MaxDisconnectHours = 12,

    # Sicherheitsgrenze: mehr Abmeldungen als das werden ohne -Force verweigert.
    [int]$MaxLogoffCount = 25,
    [switch]$Force,

    [switch]$Fix,
    [switch]$Diagnose,

    [string]$OutputCsv,
    [int]$BatchSize = 20,
    [int]$ThrottleLimit = 10,
    [switch]$SkipPing
)

#region --- Inventar-Scriptblock (nur lesen) --------------------------------------------

$InventoryBlock = {
    param([hashtable]$Cfg)

    $UserFilter = $Cfg.UserFilter
    $me = $env:COMPUTERNAME
    $out = New-Object System.Collections.Generic.List[object]

    function Add-Row {
        param($Kind, $Status, $UserName, $Sid, $SessionId, $SessionState, $Since, $OffMin, $Path, $Note)
        $out.Add([pscustomobject]@{
            Computer = $me; Kind = $Kind; Status = $Status; User = $UserName; Sid = $Sid
            SessionId = $SessionId; SessionState = $SessionState; Since = $Since; OffMin = $OffMin
            Path = $Path; Note = $Note
        })
    }

    # ---------- Session-Timeouts an ALLEN relevanten Stellen ----------
    # Die Einstellungen "Session Time Limits" gibt es unter Computer- UND Benutzerkonfiguration.
    # Computer -> HKLM\SOFTWARE\Policies\...   Benutzer -> HKCU bzw. HKU\<SID>\Software\Policies\...
    # Ohne Loopback-Verarbeitung greift die Benutzerseite auf einem Terminalserver nicht wie erwartet.
    # Zusaetzlich kann die WinStation-Konfiguration und das AD-Benutzerobjekt Limits setzen.
    $fmt = { param($ms)
        if ($null -eq $ms) { 'nicht gesetzt' }
        elseif ($ms -eq 0) { 'nie' }
        else { '{0:n0} min' -f ($ms / 60000) } }

    # 1) Computerrichtlinie
    $ts = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue
    Add-Row 'Policy' 'INFO' $null $null $null $null $null $null 'HKLM Policies' `
        ("Computerrichtlinie: MaxDisconnectionTime={0}; MaxIdleTime={1}; RemoteAppLogoffTimeLimit={2}" -f `
            (& $fmt $ts.MaxDisconnectionTime), (& $fmt $ts.MaxIdleTime), (& $fmt $ts.RemoteAppLogoffTimeLimit))

    # 2) Benutzerrichtlinie je Benutzerhive - Werte MERKEN, um sie spaeter der Session zuzuordnen.
    #    Wichtig: verschiedene Benutzer koennen unterschiedliche Limits haben (z.B. eine
    #    Power-User-Richtlinie mit "Never"). Deshalb die Verteilung ausgeben, nicht ein Beispiel.
    $userPol = @{}
    foreach ($h in @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
                     Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) {
        $up = Get-ItemProperty ("Registry::{0}\Software\Policies\Microsoft\Windows NT\Terminal Services" -f $h.Name) -ErrorAction SilentlyContinue
        if ($up -and ($null -ne $up.MaxDisconnectionTime -or $null -ne $up.MaxIdleTime)) {
            $userPol[$h.PSChildName] = [pscustomobject]@{
                DiscMin = if ($null -ne $up.MaxDisconnectionTime) { [int]($up.MaxDisconnectionTime / 60000) } else { $null }
                IdleMin = if ($null -ne $up.MaxIdleTime) { [int]($up.MaxIdleTime / 60000) } else { $null }
            }
        }
    }
    if ($userPol.Count) {
        $byVal = $userPol.Values | Group-Object { "Disc={0} Idle={1}" -f (& $fmt ($_.DiscMin * 60000)), (& $fmt ($_.IdleMin * 60000)) }
        foreach ($g in ($byVal | Sort-Object Count -Descending)) {
            Add-Row 'Policy' 'INFO' $null $null $null $null $null $null 'HKU Policies' `
                ("Benutzerrichtlinie: {0} Hive(s) mit {1}" -f $g.Count, $g.Name)
        }
    } else {
        Add-Row 'Policy' 'INFO' $null $null $null $null $null $null 'HKU Policies' `
            'Benutzerrichtlinie: in keinem geladenen Benutzerhive gesetzt'
    }

    # 3) WinStation-Konfiguration (lokale RDS-Einstellung, greift wenn keine Policy da ist)
    foreach ($w in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations' -ErrorAction SilentlyContinue)) {
        $wp = Get-ItemProperty $w.PSPath -ErrorAction SilentlyContinue
        if ($null -eq $wp.MaxDisconnectionTime -and $null -eq $wp.MaxIdleTime) { continue }
        Add-Row 'Policy' 'INFO' $null $null $null $null $null $null "WinStation $($w.PSChildName)" `
            ("WinStation {0}: MaxDisconnectionTime={1}; MaxIdleTime={2}" -f `
                $w.PSChildName, (& $fmt $wp.MaxDisconnectionTime), (& $fmt $wp.MaxIdleTime))
    }

    # 4) Wird die GPO ueberhaupt angewendet? Angewendete GPOs aus der Gruppenrichtlinien-Historie lesen.
    # Die History-Struktur enthaelt Binaerwerte, die beim Auslesen casten koennen -> defensiv.
    $hist = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($k in @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History' -Recurse -Depth 2 -ErrorAction SilentlyContinue)) {
            try {
                $dn = $k.GetValue('DisplayName')
                if ($dn -and -not $hist.Contains([string]$dn)) { $hist.Add([string]$dn) }
            } catch { }
        }
    } catch { }
    Add-Row 'Policy' 'INFO' $null $null $null $null $null $null 'GPO-Historie' `
        ("{0} Computer-GPOs angewendet: {1}" -f $hist.Count, (($hist | Select-Object -First 12) -join ' | '))

    # 5) Citrix-Policy-Timer (falls per Citrix statt per GPO gesteuert)
    $cx = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Citrix' -ErrorAction SilentlyContinue
    if ($cx) {
        $cxVals = @($cx.PSObject.Properties | Where-Object { $_.Name -match 'Timer|Timeout|Idle|Disconnect' } |
                    ForEach-Object { "$($_.Name)=$($_.Value)" })
        if ($cxVals.Count) {
            Add-Row 'Policy' 'INFO' $null $null $null $null $null $null 'Citrix Policy' ("Citrix-Timer: " + ($cxVals -join '; '))
        }
    }

    # ---------- Sessions ueber die WTS-API ----------
    # quser/qwinsta sind in einer WinRM-Session nicht nutzbar (keine Konsolensession) und ihre
    # Ausgabe ist lokalisiert. Win32_LogonSession taugt ebenfalls nicht: die Logon-Session
    # ueberlebt das Ende der RDP-Session - also genau den Fall, den wir finden wollen.
    # WTSEnumerateSessionsEx liefert SessionId, Status als Enum und den Trennzeitpunkt.
    # Hinweis: Add-Type -MemberDefinition kann KEINE Structs aufnehmen (nur Klassenmember),
    # daher -TypeDefinition mit vollstaendigem Namespace. Die Enumeration selbst laeuft in C#,
    # damit das Pointer-Marshalling nicht in PowerShell nachgebaut werden muss.
    $typeErr = $null
    if (-not ('Wts.Api' -as [type])) {
        try {
            Add-Type -ErrorAction Stop -TypeDefinition @'
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
    public int SessionId;
    public int State;
    public string UserName;
    public string DomainName;
    public DateTime? LogonTime;
    public DateTime? DisconnectTime;
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
          if (si.SessionId == 0) continue;               // Services-Session

          IntPtr buf; int n;
          // 25 = WTSSessionInfoEx
          if (WTSQuerySessionInformationW(IntPtr.Zero, si.SessionId, 25, out buf, out n) == 0) continue;
          try {
            // WTSINFOEX = { DWORD Level; <4 Byte Padding>; WTSINFOEX_LEVEL1 Data }
            INFOEX1 x = (INFOEX1)Marshal.PtrToStructure(new IntPtr(buf.ToInt64() + 8), typeof(INFOEX1));
            if (string.IsNullOrEmpty(x.UserName)) continue;
            Session s = new Session();
            s.SessionId = si.SessionId;
            s.State = x.SessionState;
            s.UserName = x.UserName;
            s.DomainName = x.DomainName;
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
        } catch { $typeErr = $_.Exception.Message }
    }

    # Sessions je Benutzername (klein geschrieben)
    $sessions = @{}
    $wtsOk = $false
    if ($typeErr) {
        Add-Row 'Fehler' 'WARN' $null $null $null $null $null $null $null "WTS-Typ nicht kompilierbar: $typeErr"
    } else {
        try {
            foreach ($x in [Wts.Api]::GetSessions()) {
                # WTS_CONNECTSTATE_CLASS: 0=Active 1=Connected 2=ConnectQuery 3=Shadow 4=Disconnected
                $stateName = switch ($x.State) {
                    0 { 'Aktiv' } 1 { 'Verbunden' } 2 { 'ConnectQuery' } 3 { 'Shadow' }
                    4 { 'Getrennt' } 5 { 'Idle' } 6 { 'Listen' } 7 { 'Reset' } 8 { 'Down' } 9 { 'Init' }
                    default { "Status $($x.State)" }
                }
                $disc = $x.State -eq 4
                $offMin = 0
                if ($disc -and $x.DisconnectTime) { $offMin = [int]((Get-Date) - $x.DisconnectTime).TotalMinutes }

                $sessions[$x.UserName.ToLower()] = [pscustomobject]@{
                    Id = $x.SessionId; State = $stateName; Disconnected = $disc
                    OffMin = $offMin; DiscSince = $x.DisconnectTime; LogonTime = $x.LogonTime
                    Domain = $x.DomainName
                }
            }
            $wtsOk = $true
        } catch {
            Add-Row 'Fehler' 'WARN' $null $null $null $null $null $null $null "WTS-Sessionabfrage fehlgeschlagen: $($_.Exception.Message)"
        }
    }

    if (-not $wtsOk) {
        Add-Row 'Fehler' 'WARN' $null $null $null $null $null $null $null `
            'WTS-Sessions nicht lesbar - Klassifizierung unsicher, keine Aktion moeglich'
    } elseif ($Cfg.Diagnose) {
        Add-Row 'Info' 'INFO' $null $null $null $null $null $null $null `
            ("{0} Sessions erkannt ({1} getrennt)" -f $sessions.Count, @($sessions.Values | Where-Object Disconnected).Count)
    }

    # ---------- Attachte FSLogix-Disks ----------
    $disks = @()
    try {
        $disks = @(Get-Disk -ErrorAction Stop | Where-Object {
            $_.BusType -eq 'File Backed Virtual' -and $_.Location -match '\.vhdx?$'
        })
    } catch {
        Add-Row 'Fehler' 'WARN' $null $null $null $null $null $null $null "Get-Disk fehlgeschlagen: $($_.Exception.Message)"
    }

    if (-not $disks.Count) {
        Add-Row 'Info' 'INFO' $null $null $null $null $null $null $null 'Keine attachten VHD(X) vorhanden'
    }

    foreach ($d in $disks) {
        $path = $d.Location

        # Pfadmuster: ...\S-1-5-21-..-<rid>_<user>\Profile_<user>.VHDX  bzw. <user>_S-1-5-...
        $sid = $null; $u = $null
        if ($path -match '(?<sid>S-1-5-21-[\d-]+)') { $sid = $Matches.sid }
        if ($path -match '(?i)(Profile|ODFC)[_-](?<u>[^\\\.]+)\.vhdx?$') { $u = $Matches.u }
        elseif ($path -match '(?i)S-1-5-21-[\d-]+_(?<u>[^\\]+)\\') { $u = $Matches.u }
        elseif ($path -match '(?i)(?<u>[^\\]+)_S-1-5-21-[\d-]+\\') { $u = $Matches.u }

        if (-not $sid -and $u) {
            try { $sid = (New-Object System.Security.Principal.NTAccount($u)).Translate(
                          [System.Security.Principal.SecurityIdentifier]).Value } catch { }
        }
        if (-not $u -and $sid) {
            try { $u = ((New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate(
                        [System.Security.Principal.NTAccount]).Value -split '\\')[-1] } catch { }
        }
        if ($UserFilter -ne '*' -and $u -notlike $UserFilter) { continue }

        $sess = if ($u) { $sessions[$u.ToLower()] } else { $null }

        if (-not $wtsOk) {
            $status = 'UNBEKANNT'
            $note   = 'Sessionstatus nicht ermittelbar - wird nicht angefasst'
        }
        elseif ($sess -and -not $sess.Disconnected) {
            $status = 'AKTIV'
            $note   = 'Benutzer arbeitet auf diesem Server'
        }
        elseif ($sess) {
            # Gegen das Limit pruefen, das FUER DIESEN BENUTZER gilt.
            # 0 = "Never" (z.B. Power-User-Richtlinie) -> bewusst unbegrenzt, kein Fehler.
            $pol = if ($sid) { $userPol[$sid] } else { $null }
            $lim = if ($pol) { $pol.DiscMin } else { $null }
            $seit = "getrennt seit {0:yyyy-MM-dd HH:mm}" -f $sess.DiscSince

            if ($null -eq $lim) {
                $status = 'GETRENNT'
                $note   = "$seit; kein Limit im Benutzerhive lesbar"
            }
            elseif ($lim -eq 0) {
                $status = 'GETRENNT-UNBEGRENZT'
                $note   = "$seit; Richtlinie fuer diesen Benutzer: NIE abmelden (Power-User) - kein Fehler"
            }
            elseif ($sess.OffMin -gt ($lim + 15)) {
                $status = 'UEBERFAELLIG'
                $note   = "$seit; Limit {0} min ueberschritten ({1} min) - Timer greift nicht" -f $lim, $sess.OffMin
            }
            else {
                $status = 'GETRENNT'
                $note   = "$seit; innerhalb des Limits von {0} min" -f $lim
            }
        }
        else {
            $status = 'VERWAIST'
            $note   = 'Keine Session des Benutzers auf diesem Server - Disk haengt'
        }

        Add-Row 'Disk' $status $u $sid $(if ($sess) { $sess.Id }) `
                $(if ($sess) { $sess.State }) `
                $(if ($sess -and $sess.LogonTime) { '{0:yyyy-MM-dd HH:mm}' -f $sess.LogonTime }) `
                $(if ($sess) { $sess.OffMin }) $path $note
    }

    # ---------- Getrennte Sessions ohne attachte Disk ----------
    foreach ($k in $sessions.Keys) {
        $s = $sessions[$k]
        if (-not $s.Disconnected) { continue }
        if ($UserFilter -ne '*' -and $k -notlike $UserFilter) { continue }
        if (@($disks | Where-Object { $_.Location -like "*_$k\*" -or $_.Location -like "*$k`_S-1-5-21*" }).Count) { continue }
        Add-Row 'Session' 'GETRENNT' $k $null $s.Id $s.State `
            $(if ($s.LogonTime) { '{0:yyyy-MM-dd HH:mm}' -f $s.LogonTime }) $s.OffMin $null `
            ("Getrennte Session ohne attachte Disk, getrennt seit {0:yyyy-MM-dd HH:mm}" -f $s.DiscSince)
    }

    return $out
}

#endregion

#region --- Aktions-Scriptblock (aendert etwas) -----------------------------------------

$ActionBlock = {
    param([hashtable]$Cfg)

    $res = New-Object System.Collections.Generic.List[object]
    $me = $env:COMPUTERNAME

    # Disks trennen
    foreach ($p in @($Cfg.DismountPaths)) {
        if (-not $p) { continue }
        $ok = $false; $msg = ''
        try {
            # Sicherheitsnetz: direkt vor dem Trennen nochmal pruefen, dass die Disk
            # nicht zwischenzeitlich von einer neuen Session belegt wurde.
            $d = Get-Disk -ErrorAction Stop | Where-Object { $_.Location -eq $p }
            if (-not $d) { $msg = 'Disk nicht mehr attached (bereits geloest)' }
            else {
                Dismount-DiskImage -ImagePath $p -ErrorAction Stop | Out-Null
                $ok = $true; $msg = 'Disk getrennt'
            }
        } catch { $msg = "Trennen fehlgeschlagen: $($_.Exception.Message)" }
        $res.Add([pscustomobject]@{ Computer = $me; Aktion = 'Dismount'; Ziel = $p; Erfolg = $ok; Meldung = $msg })
    }

    # Sessions abmelden
    foreach ($id in @($Cfg.LogoffIds)) {
        if ($null -eq $id) { continue }
        $ok = $false; $msg = ''
        try {
            & logoff.exe $id 2>&1 | Out-Null
            Start-Sleep -Seconds 3
            $still = (& quser.exe 2>$null) -match "\s$id\s"
            $ok = -not $still
            $msg = if ($ok) { 'Session abgemeldet' } else { 'Abmeldung angestossen, Session noch vorhanden' }
        } catch { $msg = "Abmelden fehlgeschlagen: $($_.Exception.Message)" }
        $res.Add([pscustomobject]@{ Computer = $me; Aktion = 'Logoff'; Ziel = "SessionId $id"; Erfolg = $ok; Meldung = $msg })
    }

    return $res
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

Write-Host ("{0} Server werden geprueft. Benutzerfilter: {1}" -f $hosts.Count, $User) -ForegroundColor Cyan

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
    if ($offline.Count) { Write-Warning ("Nicht erreichbar: {0}" -f ($offline -join ', ')) }
}

#endregion

#region --- Inventur --------------------------------------------------------------------

$inv = New-Object System.Collections.Generic.List[object]
$cfg = @{ UserFilter = $User; Diagnose = [bool]$Diagnose }
$total = $online.Count
$batches = [Math]::Max(1, [Math]::Ceiling($total / $BatchSize))

for ($b = 0; $b -lt $batches; $b++) {
    $slice = $online[($b * $BatchSize)..([Math]::Min(($b + 1) * $BatchSize - 1, $total - 1))]
    Write-Progress -Activity 'Inventur' -Status ("Batch {0}/{1}" -f ($b + 1), $batches) `
        -PercentComplete ((($b + 1) / $batches) * 100)
    $rmErr = $null
    $r = Invoke-Command -ComputerName $slice -ThrottleLimit $ThrottleLimit `
        -ScriptBlock $InventoryBlock -ArgumentList $cfg -ErrorAction SilentlyContinue -ErrorVariable rmErr
    foreach ($x in $r) {
        $inv.Add([pscustomobject]@{
            Computer = $x.PSComputerName; Kind = $x.Kind; Status = $x.Status; User = $x.User; Sid = $x.Sid
            SessionId = $x.SessionId; SessionState = $x.SessionState; Since = $x.Since; OffMin = $x.OffMin
            Path = $x.Path; Note = $x.Note })
    }
    foreach ($e in $rmErr) {
        $t = $e.TargetObject; if (-not $t) { $t = $e.OriginInfo.PSComputerName }
        $inv.Add([pscustomobject]@{ Computer = $t; Kind = 'Fehler'; Status = 'WARN'; User = $null; Sid = $null
            SessionId = $null; SessionState = $null; Since = $null; OffMin = $null; Path = $null
            Note = "WinRM: $($e.Exception.Message)" })
    }
}
Write-Progress -Activity 'Inventur' -Completed

#endregion

#region --- Bericht ---------------------------------------------------------------------

$disks    = @($inv | Where-Object Kind -eq 'Disk')
$orphan   = @($disks | Where-Object Status -eq 'VERWAIST')
$disc     = @($inv   | Where-Object { $_.Status -like 'GETRENNT*' -or $_.Status -eq 'UEBERFAELLIG' })
$discOld  = @($disc  | Where-Object { $_.OffMin -ge ($MaxDisconnectHours * 60) })
$active   = @($disks | Where-Object Status -eq 'AKTIV')
$unknown  = @($disks | Where-Object Status -eq 'UNBEKANNT')
$overdue  = @($disks | Where-Object Status -eq 'UEBERFAELLIG')
$unlim    = @($disks | Where-Object Status -eq 'GETRENNT-UNBEGRENZT')
$warn     = @($inv   | Where-Object Kind -eq 'Fehler')

Write-Host ''
Write-Host '==================== ZUSAMMENFASSUNG ====================' -ForegroundColor Yellow
Write-Host ("Server geprueft: {0}   attachte Disks: {1}" -f $online.Count, $disks.Count)
Write-Host ("  AKTIV     : {0}" -f $active.Count) -ForegroundColor Green
Write-Host ("  GETRENNT  : {0}   (davon aelter als {1}h: {2})" -f $disc.Count, $MaxDisconnectHours, $discOld.Count) `
    -ForegroundColor $(if ($disc.Count) { 'Yellow' } else { 'Green' })
Write-Host ("  VERWAIST  : {0}" -f $orphan.Count) -ForegroundColor $(if ($orphan.Count) { 'Red' } else { 'Green' })
Write-Host ("  UNBEGRENZT: {0}   (Power-User-Richtlinie 'nie abmelden' - so gewollt)" -f $unlim.Count) -ForegroundColor Gray
Write-Host ("  UEBERFAELL: {0}   (eigenes Limit ueberschritten - Timer greift nicht)" -f $overdue.Count) `
    -ForegroundColor $(if ($overdue.Count) { 'Red' } else { 'Green' })
if ($unknown.Count) {
    Write-Host ("  UNBEKANNT : {0}   (Sessionstatus nicht lesbar - keine Aktion)" -f $unknown.Count) -ForegroundColor DarkYellow
}

if ($overdue.Count) {
    Write-Host ''
    Write-Host '--- TIMER GREIFT NICHT (Limit gesetzt, aber ueberschritten) ---' -ForegroundColor Red
    $overdue | Sort-Object -Property @{e={$_.OffMin}; Descending=$true} |
        Format-Table Computer, User, SessionId, @{n='Getrennt (h)'; e={ '{0:n1}' -f ($_.OffMin/60) }}, Note -AutoSize -Wrap
}

if ($unlim.Count) {
    Write-Host ''
    Write-Host ('--- BEWUSST UNBEGRENZT ({0} Sessions, Power-User-Richtlinie) ---' -f $unlim.Count) -ForegroundColor Gray
    Write-Host ('  Betroffene Benutzer: ' + ((@($unlim | Select-Object -ExpandProperty User -Unique) | Sort-Object) -join ', ')) -ForegroundColor DarkGray
    Write-Host '  Diese Disks bleiben dauerhaft gesperrt - genau das erzeugt die Ersatzprofile.' -ForegroundColor DarkGray
}

if ($orphan.Count) {
    Write-Host ''
    Write-Host '--- VERWAISTE DISKS (blockieren die Anmeldung anderswo) ---' -ForegroundColor Red
    $orphan | Sort-Object Computer, User | Format-Table Computer, User, Path -AutoSize -Wrap
}

if ($disc.Count) {
    Write-Host ''
    Write-Host '--- GETRENNTE SESSIONS ---' -ForegroundColor Yellow
    $disc | Sort-Object -Property @{e={$_.OffMin}; Descending=$true} |
        Format-Table Computer, User, SessionId, SessionState, @{n='Getrennt (h)'; e={ '{0:n1}' -f ($_.OffMin/60) }}, Since, Note -AutoSize
}

$pol = @($inv | Where-Object Kind -eq 'Policy')
if ($pol.Count) {
    Write-Host ''
    Write-Host '--- RDS-TIMEOUTS (je Auspraegung) ---' -ForegroundColor Cyan
    foreach ($grp in ($pol | Group-Object Path | Sort-Object Name)) {
        Write-Host ("  [{0}]" -f $grp.Name) -ForegroundColor Cyan
        $grp.Group | Group-Object Note | Sort-Object Count -Descending | ForEach-Object {
            Write-Host ("     {0,3}x  {1}" -f $_.Count, $_.Name) -ForegroundColor DarkCyan
        }
    }
    if (@($pol | Where-Object Note -match 'Computerrichtlinie:.*MaxDisconnectionTime=(nie|nicht gesetzt)').Count) {
        Write-Host ''
        Write-Host '  ACHTUNG: Als Computerrichtlinie ist KEIN Disconnect-Limit wirksam.' -ForegroundColor Red
        Write-Host '  Ist die GPO im GPMC gesetzt, greift sie hier nicht - moegliche Ursachen:' -ForegroundColor Red
        Write-Host '    - Einstellung steht unter Benutzer- statt Computerkonfiguration (Loopback noetig)' -ForegroundColor Red
        Write-Host '    - GPO nicht auf die Server-OU verknuepft / Verknuepfung deaktiviert' -ForegroundColor Red
        Write-Host '    - Sicherheitsfilterung oder WMI-Filter schliesst die Server aus' -ForegroundColor Red
    }
}

if ($warn.Count) {
    Write-Host ''
    Write-Host '--- PROBLEME ---' -ForegroundColor DarkYellow
    $warn | Group-Object Note | Sort-Object Count -Descending | ForEach-Object {
        Write-Host ("  [{0,3}x] {1}" -f $_.Count, $_.Name) -ForegroundColor DarkYellow
        Write-Host ('        ' + ((@($_.Group.Computer) | Select-Object -First 8) -join ', ')) -ForegroundColor DarkGray
    }
}
foreach ($h in $offline) {
    $inv.Add([pscustomobject]@{ Computer = $h; Kind = 'Fehler'; Status = 'WARN'; User = $null; Sid = $null
        SessionId = $null; SessionState = $null; Since = $null; OffMin = $null; Path = $null
        Note = 'Server nicht erreichbar' })
}

# --- Limits am AD-Benutzerobjekt pruefen ---
# msTSLimitDisconnectedTime / msTSLimitIdleTime am Benutzer koennen die Maschinenrichtlinie
# ueberschreiben. Nur fuer die auffaelligsten Faelle abfragen, um das AD nicht zu fluten.
$checkUsers = @($disc | Sort-Object -Property @{e={$_.OffMin}; Descending=$true} |
    Select-Object -ExpandProperty User -Unique | Select-Object -First 10)
if ($checkUsers.Count -and (Get-Module -ListAvailable ActiveDirectory)) {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    $adRows = foreach ($u in $checkUsers) {
        try {
            $a = Get-ADUser -Identity $u -Properties msTSLimitDisconnectedTime, msTSLimitIdleTime -ErrorAction Stop
            [pscustomobject]@{
                Benutzer = $u
                DiscLimit = if ($null -ne $a.msTSLimitDisconnectedTime) { '{0:n0} min' -f ($a.msTSLimitDisconnectedTime / 60000) } else { '-' }
                IdleLimit = if ($null -ne $a.msTSLimitIdleTime) { '{0:n0} min' -f ($a.msTSLimitIdleTime / 60000) } else { '-' }
            }
        } catch { }
    }
    $set = @($adRows | Where-Object { $_.DiscLimit -ne '-' -or $_.IdleLimit -ne '-' })
    Write-Host ''
    Write-Host '--- LIMITS AM AD-BENUTZEROBJEKT (Top 10 der laengsten Trennungen) ---' -ForegroundColor Cyan
    if ($set.Count) {
        Write-Host '  Achtung: gesetzte Benutzerlimits ueberschreiben die Maschinenrichtlinie.' -ForegroundColor Yellow
        $adRows | Format-Table -AutoSize
    } else {
        Write-Host '  Keine Limits am Benutzerobjekt gesetzt - es gilt die Richtlinie.' -ForegroundColor Cyan
    }
}

if ($OutputCsv) {
    $inv | Sort-Object Status, Computer, User | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    Write-Host ''
    Write-Host "CSV exportiert: $OutputCsv" -ForegroundColor Cyan
}

#endregion

#region --- Aufloesen -------------------------------------------------------------------

if (-not $Fix) {
    if ($orphan.Count -or $discOld.Count) {
        Write-Host ''
        Write-Host 'Zum Aufloesen dasselbe Kommando mit -Fix aufrufen (vorher gern mit -WhatIf).' -ForegroundColor Cyan
    }
    return $inv
}

# Pro Server zusammenstellen, was zu tun ist
$plan = @{}
foreach ($o in $orphan) {
    if (-not $plan[$o.Computer]) { $plan[$o.Computer] = @{ Dismount = @(); Logoff = @() } }
    $plan[$o.Computer].Dismount += $o.Path
}
# Abzumelden sind vor allem die UEBERFAELLIGEN: dort hat der Timer sein eigenes Limit
# ueberschritten, die Session haengt also nachweislich. Zusaetzlich alles, was die
# -MaxDisconnectHours-Schwelle reisst. Bewusst unbegrenzte (Power-User) bleiben aussen vor.
foreach ($d in @($overdue + $discOld | Where-Object { $_.Status -ne 'GETRENNT-UNBEGRENZT' })) {
    if ($null -eq $d.SessionId) { continue }
    if (-not $plan[$d.Computer]) { $plan[$d.Computer] = @{ Dismount = @(); Logoff = @() } }
    if ($plan[$d.Computer].Logoff -notcontains $d.SessionId) {
        $plan[$d.Computer].Logoff += $d.SessionId
    }
}

if (-not $plan.Keys.Count) {
    Write-Host ''
    Write-Host 'Nichts aufzuloesen.' -ForegroundColor Green
    return $inv
}

# Sicherheitsgrenze: eine Massenabmeldung im laufenden Betrieb kostet ungespeicherte Arbeit.
$logoffTotal = @($plan.Values | ForEach-Object { $_.Logoff }).Count
if ($logoffTotal -gt $MaxLogoffCount -and -not $Force) {
    Write-Host ''
    Write-Warning ("ABBRUCH: {0} Sessions waeren abzumelden, erlaubt sind {1}." -f $logoffTotal, $MaxLogoffCount)
    Write-Warning ("Das sind getrennte Sessions von Anwendern - eine Abmeldung verwirft ungespeicherte Arbeit.")
    Write-Warning ("Entweder -MaxDisconnectHours hoeher setzen (nur wirklich haengende Sessions treffen)")
    Write-Warning ("oder bewusst mit -Force und passendem -MaxLogoffCount aufrufen.")
    return $inv
}

Write-Host ''
Write-Host '==================== AUFLOESEN ====================' -ForegroundColor Yellow

$actions = New-Object System.Collections.Generic.List[object]
foreach ($srv in ($plan.Keys | Sort-Object)) {
    $dm = @($plan[$srv].Dismount)
    $lo = @($plan[$srv].Logoff)
    $desc = "{0}: {1} Disk(s) trennen, {2} Session(s) abmelden" -f $srv, $dm.Count, $lo.Count

    if (-not $PSCmdlet.ShouldProcess($srv, $desc)) { continue }

    try {
        $r = Invoke-Command -ComputerName $srv -ScriptBlock $ActionBlock `
            -ArgumentList @{ DismountPaths = $dm; LogoffIds = $lo } -ErrorAction Stop
        foreach ($x in $r) {
            $actions.Add([pscustomobject]@{ Computer = $x.Computer; Aktion = $x.Aktion; Ziel = $x.Ziel
                Erfolg = $x.Erfolg; Meldung = $x.Meldung })
        }
    } catch {
        $actions.Add([pscustomobject]@{ Computer = $srv; Aktion = 'Fehler'; Ziel = $null
            Erfolg = $false; Meldung = $_.Exception.Message })
    }
}

if ($actions.Count) {
    Write-Host ''
    $actions | Format-Table Computer, Aktion, Erfolg, Meldung, Ziel -AutoSize -Wrap
    Write-Host ("Erfolgreich: {0} von {1}" -f @($actions | Where-Object Erfolg).Count, $actions.Count) `
        -ForegroundColor $(if (@($actions | Where-Object { -not $_.Erfolg }).Count) { 'Yellow' } else { 'Green' })
    if ($OutputCsv) {
        $actions | Export-Csv -Path ($OutputCsv -replace '\.csv$', '-aktionen.csv') -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    }
}

return $inv

#endregion