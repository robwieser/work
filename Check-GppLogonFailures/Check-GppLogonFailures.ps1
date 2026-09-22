<#
.SYNOPSIS
    Farmweite Analyse fehlgeschlagener Group-Policy-Preferences-Verarbeitung (Event 8194 / 0x80070003).

.DESCRIPTION
    Liest alle aktivierten Computer aus einer OU, verbindet sich per PowerShell-Remoting
    und sammelt pro Server:

      - Application-Log : Event 8194 (GPP CSE-Level-Fehler) inkl. GPO-Name und Fehlercode
                          Event 1085, optional Event 4098 (GPP Item-Level)
      - GroupPolicy/Operational : Event 4001 (Logon-Start inkl. Benutzer) und 6016/7016
                          (CSE mit Warnung/Fehler beendet). Beide werden ueber die
                          ActivityId korreliert - nur so bekommt man den betroffenen
                          Benutzer, denn 8194 wird im SYSTEM-Kontext geschrieben.
      - GPP-History     : Anzahl der {GPO}\<SID>-Ordner (User-Seite) vs. {GPO}\Machine-Ordner
      - FSLogix         : effektiver Wert von GroupPolicyState, Agent-Version
      - Registry        : Anzahl geroamter GP-State-SIDs unter HKLM\...\Group Policy

    Auswertung: Uebersicht pro Server, Top-GPOs, betroffene Benutzer, Zeitverlauf pro Tag.
    Alle Rohdaten werden zusaetzlich als CSV abgelegt.

.PARAMETER SearchBase
    DN der OU, z.B. 'OU=FARMP10,OU=WTS 10.25,OU=Servers,OU=AHP Infrastructure Objects,DC=medi,DC=local'

.PARAMETER Days
    Rueckblick in Tagen. Default 14. Achtung: die Spalte AppLogAb zeigt, wie weit das
    Application-Log tatsaechlich zurueckreicht - bei stark beschriebenen Logs ist der
    effektive Zeitraum kuerzer als angefordert.

.EXAMPLE
    .\Check-GppLogonFailures.ps1 -SearchBase 'OU=FARMP10,OU=Servers,DC=medi,DC=local' -Days 21

.NOTES
    Voraussetzung: RSAT ActiveDirectory-Modul, PowerShell-Remoting (WinRM 5985) auf den
    Zielservern, lokale Adminrechte dort. PowerShell 5.1 kompatibel.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SearchBase,

    [int]$Days = 14,

    [string]$OutputFolder = (Join-Path $env:USERPROFILE 'Desktop\GPP-Analyse'),

    [int]$ThrottleLimit = 24,

    [switch]$IncludeItemLevel,

    [System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

if (-not (Test-Path $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null }
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'


# ---------------------------------------------------------------------------
# 1) Server aus der OU lesen
# ---------------------------------------------------------------------------

Write-Host "`n=== Computer aus OU lesen ===" -ForegroundColor Cyan
Write-Host "SearchBase : $SearchBase"

$Computers = Get-ADComputer -SearchBase $SearchBase -Filter 'Enabled -eq $true' -Properties OperatingSystem |
             Sort-Object Name

if (-not $Computers) { throw "Keine aktivierten Computerobjekte unter '$SearchBase' gefunden." }

$Names = $Computers.Name
Write-Host ("Gefunden   : {0} Computerobjekte" -f $Names.Count) -ForegroundColor Green


# ---------------------------------------------------------------------------
# 2) Sammel-Scriptblock (laeuft auf jedem Zielserver)
# ---------------------------------------------------------------------------

$Collect = {
    param($Days, $IncludeItemLevel)

    $Start      = (Get-Date).AddDays(-$Days)
    $HistoryDir = 'C:\ProgramData\Microsoft\Group Policy\History'
    $GpRoot     = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy'

    function Get-Ev {
        param([string]$LogName, [int[]]$Ids)
        try {
            @(Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = $Ids; StartTime = $Start } -ErrorAction Stop)
        } catch {
            @()   # "No events were found" wirft - das ist kein Fehler
        }
    }

    # --- Application: 8194 / 1085 / optional 4098 ---------------------------
    $Ev8194 = Get-Ev -LogName 'Application' -Ids 8194
    $Ev1085 = Get-Ev -LogName 'Application' -Ids 1085
    $Ev4098 = if ($IncludeItemLevel) { Get-Ev -LogName 'Application' -Ids 4098 } else { @() }

    $Details = foreach ($e in ($Ev8194 + $Ev4098)) {
        $Msg  = $e.Message
        $Gpo  = $null
        $Code = $null

        if ($Msg -match "['""]([^'""]*\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\})['""]") {
            $Gpo = $Matches[1]
        }
        if ($Msg -match '(0x[0-9A-Fa-f]{8})') { $Code = $Matches[1] }

        [pscustomobject]@{
            Server    = $env:COMPUTERNAME
            Time      = $e.TimeCreated
            EventId   = $e.Id
            Provider  = $e.ProviderName
            Gpo       = $Gpo
            ErrorCode = $Code
        }
    }

    # --- Operational: Benutzer ueber ActivityId korrelieren ------------------
    # 8194 wird unter SYSTEM geschrieben und traegt keinen Benutzer.
    # 4001 = "Starting user logon Policy processing for <Domain>\<User>"
    $EvOper = Get-Ev -LogName 'Microsoft-Windows-GroupPolicy/Operational' -Ids @(4001, 6016, 7016)

    $UserByActivity = @{}
    foreach ($e in ($EvOper | Where-Object { $_.Id -eq 4001 })) {
        try {
            $Xml  = [xml]$e.ToXml()
            $Name = ($Xml.Event.EventData.Data | Where-Object { $_.Name -eq 'PrincipalSamName' }).'#text'
            if ($e.ActivityId -and $Name) { $UserByActivity[$e.ActivityId.Guid] = $Name }
        } catch { }
    }

    $CseFailures = foreach ($e in ($EvOper | Where-Object { $_.Id -eq 6016 -or $_.Id -eq 7016 })) {
        $User = $null
        if ($e.ActivityId -and $UserByActivity.ContainsKey($e.ActivityId.Guid)) {
            $User = $UserByActivity[$e.ActivityId.Guid]
        }
        [pscustomobject]@{
            Server  = $env:COMPUTERNAME
            Time    = $e.TimeCreated
            EventId = $e.Id
            User    = $User
            Text    = (($e.Message -split "`r?`n") | Where-Object { $_ } | Select-Object -First 1)
        }
    }

    # --- GPP-History-Struktur ----------------------------------------------
    $SidDirs     = @()
    $MachineDirs = @()
    $HistoryOk   = Test-Path $HistoryDir
    if ($HistoryOk) {
        $Lvl = @(Get-ChildItem $HistoryDir -Recurse -Directory -Depth 1 -ErrorAction SilentlyContinue)
        $SidDirs     = @($Lvl | Where-Object { $_.Name -like 'S-1-5-21-*' })
        $MachineDirs = @($Lvl | Where-Object { $_.Name -eq 'Machine' })
    }

    # --- FSLogix ------------------------------------------------------------
    $FslLocal  = Get-ItemProperty 'HKLM:\SOFTWARE\FSLogix\Profiles'          -ErrorAction SilentlyContinue
    $FslPolicy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\FSLogix\Profiles' -ErrorAction SilentlyContinue

    if     ($null -ne $FslPolicy.GroupPolicyState) { $GpState = "$($FslPolicy.GroupPolicyState) (Policy)" }
    elseif ($null -ne $FslLocal.GroupPolicyState)  { $GpState = "$($FslLocal.GroupPolicyState) (lokal)" }
    else                                           { $GpState = 'nicht gesetzt -> Default 1' }

    $FrxVer = (Get-Item 'C:\Program Files\FSLogix\Apps\frxsvc.exe' -ErrorAction SilentlyContinue).VersionInfo.FileVersion

    $StateSids = @(Get-ChildItem $GpRoot -ErrorAction SilentlyContinue |
                   Where-Object { $_.PSChildName -like 'S-1-5-21-*' }).Count

    try   { $Oldest = (Get-WinEvent -LogName Application -MaxEvents 1 -Oldest -ErrorAction Stop).TimeCreated }
    catch { $Oldest = $null }

    $Os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue

    [pscustomobject]@{
        Server             = $env:COMPUTERNAME
        OS                 = $Os.Caption
        LastBoot           = $Os.LastBootUpTime
        AppLogAb           = $Oldest
        GroupPolicyState   = $GpState
        FSLogixVersion     = $FrxVer
        HistoryRoot        = $HistoryOk
        HistorySidDirs     = $SidDirs.Count
        HistoryMachineDirs = $MachineDirs.Count
        RoamedStateSids    = $StateSids
        Count8194          = $Ev8194.Count
        Count1085          = $Ev1085.Count
        CountCseFailures   = @($CseFailures).Count
        Count4098          = $Ev4098.Count
        Details            = $Details
        CseFailures        = $CseFailures
    }
}


# ---------------------------------------------------------------------------
# 3) Remote ausfuehren
# ---------------------------------------------------------------------------

Write-Host "`n=== Daten sammeln (Rueckblick: $Days Tage) ===" -ForegroundColor Cyan

$IcmParams = @{
    ComputerName  = $Names
    ScriptBlock   = $Collect
    ArgumentList  = @($Days, [bool]$IncludeItemLevel)
    ThrottleLimit = $ThrottleLimit
    ErrorAction   = 'SilentlyContinue'
    ErrorVariable = 'ConnErrors'
}
if ($Credential) { $IcmParams['Credential'] = $Credential }

$Results = Invoke-Command @IcmParams

$Reached     = @($Results | Select-Object -ExpandProperty Server -Unique)
$Unreachable = @($Names | Where-Object { $_ -notin $Reached })

Write-Host ("Erreicht   : {0}" -f $Reached.Count) -ForegroundColor Green
if ($Unreachable.Count) {
    Write-Host ("Nicht erreichbar: {0}" -f $Unreachable.Count) -ForegroundColor Yellow
    $Unreachable | ForEach-Object { Write-Host "  - $_" -ForegroundColor DarkYellow }
}

if (-not $Results) { throw 'Kein einziger Server hat geantwortet - WinRM / Rechte pruefen.' }


# ---------------------------------------------------------------------------
# 4) Auswertung
# ---------------------------------------------------------------------------

$Summary = $Results |
    Select-Object Server, GroupPolicyState, FSLogixVersion,
                  HistorySidDirs, HistoryMachineDirs, RoamedStateSids,
                  Count8194, CountCseFailures, AppLogAb, LastBoot, OS,
                  @{ n = 'Bewertung'; e = {
                        if ($_.Count8194 -gt 0 -and $_.HistorySidDirs -eq 0)   { 'BETROFFEN - User-GPP laeuft nie durch' }
                        elseif ($_.Count8194 -gt 0)                            { 'Teilweise betroffen' }
                        elseif ($_.HistorySidDirs -gt 0)                       { 'unauffaellig' }
                        elseif ($_.RoamedStateSids -le 1)                      { 'frisch installiert / keine User-Logons' }
                        else                                                   { 'keine Events im Zeitraum' }
                     }} |
    Sort-Object Count8194 -Descending

$AllDetails = @($Results | ForEach-Object { $_.Details }     | Where-Object { $_ -ne $null })
$AllCse     = @($Results | ForEach-Object { $_.CseFailures } | Where-Object { $_ -ne $null })

Write-Host "`n=== Uebersicht pro Server ===" -ForegroundColor Cyan
$Summary | Format-Table Server, GroupPolicyState, HistorySidDirs, HistoryMachineDirs,
                        RoamedStateSids, Count8194, AppLogAb, Bewertung -AutoSize

Write-Host "`n=== Gesamtbild ===" -ForegroundColor Cyan
$Summary | Group-Object Bewertung | Sort-Object Count -Descending |
    Select-Object Count, @{ n = 'Bewertung'; e = { $_.Name } } | Format-Table -AutoSize

if ($AllDetails.Count) {

    Write-Host "`n=== Betroffene GPOs ===" -ForegroundColor Cyan
    $AllDetails | Where-Object Gpo | Group-Object Gpo | Sort-Object Count -Descending |
        Select-Object Count,
                      @{ n = 'GPO';     e = { $_.Name } },
                      @{ n = 'Server';  e = { @($_.Group.Server | Sort-Object -Unique).Count } } |
        Format-Table -AutoSize

    Write-Host "`n=== Fehlercodes ===" -ForegroundColor Cyan
    $AllDetails | Where-Object ErrorCode | Group-Object ErrorCode | Sort-Object Count -Descending |
        Select-Object Count, @{ n = 'Code'; e = { $_.Name } } | Format-Table -AutoSize

    Write-Host "`n=== Zeitverlauf pro Tag (Application 8194) ===" -ForegroundColor Cyan
    Write-Host "  Beginnt die Haeufung an einem Datum? -> Hinweis auf einen Ausloeser." -ForegroundColor DarkGray
    Write-Host "  Vorher immer mit AppLogAb abgleichen: aeltere Tage koennen schlicht ausgerollt sein." -ForegroundColor DarkGray

    $ByDay = $AllDetails |
        Where-Object { $_.Time } |
        Group-Object { ([datetime]$_.Time).ToString('yyyy-MM-dd') } |
        Sort-Object Name

    if ($ByDay) {
        $Max = ($ByDay | Measure-Object Count -Maximum).Maximum
        foreach ($d in $ByDay) {
            $Bar = '#' * [int][Math]::Ceiling(($d.Count / [Math]::Max($Max, 1)) * 50)
            Write-Host ('{0}  {1,6}  {2}' -f $d.Name, $d.Count, $Bar)
        }
    }
}
else {
    Write-Host "`nKeine 8194/4098-Events im Betrachtungszeitraum gefunden." -ForegroundColor Green
}

if ($AllCse.Count) {
    Write-Host "`n=== Betroffene Benutzer (aus GroupPolicy/Operational, Top 30) ===" -ForegroundColor Cyan
    $AllCse | Where-Object User | Group-Object User | Sort-Object Count -Descending |
        Select-Object -First 30 |
        Select-Object Count,
                      @{ n = 'User';   e = { $_.Name } },
                      @{ n = 'Server'; e = { @($_.Group.Server | Sort-Object -Unique).Count } } |
        Format-Table -AutoSize

    $UniqueUsers = @($AllCse | Where-Object User | Select-Object -ExpandProperty User -Unique).Count
    Write-Host ("Betroffene Benutzer gesamt : {0}" -f $UniqueUsers) -ForegroundColor Yellow
}


# ---------------------------------------------------------------------------
# 5) Export
# ---------------------------------------------------------------------------

$F1 = Join-Path $OutputFolder "GPP-Summary-$Stamp.csv"
$F2 = Join-Path $OutputFolder "GPP-Events-$Stamp.csv"
$F3 = Join-Path $OutputFolder "GPP-CseFailures-$Stamp.csv"
$F4 = Join-Path $OutputFolder "GPP-Unreachable-$Stamp.csv"

$Summary | Export-Csv -Path $F1 -NoTypeInformation -Encoding UTF8 -Delimiter ';'
if ($AllDetails.Count)  { $AllDetails | Export-Csv -Path $F2 -NoTypeInformation -Encoding UTF8 -Delimiter ';' }
if ($AllCse.Count)      { $AllCse     | Export-Csv -Path $F3 -NoTypeInformation -Encoding UTF8 -Delimiter ';' }
if ($Unreachable.Count) {
    $Unreachable | ForEach-Object { [pscustomobject]@{ Server = $_ } } |
        Export-Csv -Path $F4 -NoTypeInformation -Encoding UTF8 -Delimiter ';'
}

Write-Host "`n=== Export ===" -ForegroundColor Cyan
Write-Host "  $F1"
if ($AllDetails.Count)  { Write-Host "  $F2" }
if ($AllCse.Count)      { Write-Host "  $F3" }
if ($Unreachable.Count) { Write-Host "  $F4" }
Write-Host ''