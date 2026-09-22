<#
.SYNOPSIS
    Vergleicht die GPP-Fehlerrate vor und nach dem Setzen von GroupPolicyState = 0,
    getrennt nach Fix-Gruppe und Kontrollgruppe.

.DESCRIPTION
    Teilt die Server einer OU anhand des effektiven FSLogix-Wertes GroupPolicyState auf:
      - "Fix"        : GroupPolicyState = 0
      - "Kontrolle"  : nicht gesetzt (Default 1) oder 1

    Misst pro Server in zwei gleich langen Zeitfenstern (vor / nach dem Cutoff):
      - GppLaeufe : Anzahl 4016-Events "Group Policy Registry Extension" (Nenner)
      - Fehler    : Anzahl 8194-Events von Provider "Group Policy Registry"
      - Rate      : Fehler / GppLaeufe

    Die Normierung auf die Lauf-Anzahl ist entscheidend: ein Server ohne Anmeldungen
    hat null Fehler und sieht sonst faelschlich "geheilt" aus.

.PARAMETER Cutoff
    Zeitpunkt des Eingriffs, z.B. '2026-09-22 12:00'. Das Vorher-Fenster ist gleich lang
    wie das Nachher-Fenster (bis jetzt).

.EXAMPLE
    .\Compare-GppFixEffect.ps1 -SearchBase 'OU=FARMP10,OU=WTS 10.25,OU=Servers,OU=AHP Infrastructure Objects,DC=medi,DC=local' -Cutoff '2026-09-22 12:00'

.NOTES
    Die CSE-Namen im Operational-Log sind sprachabhaengig. Bei deutschsprachigem OS
    das Muster in $CseFilter anpassen.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SearchBase,
    [Parameter(Mandatory = $true)][datetime]$Cutoff,
    [string]$CseFilter    = 'Group Policy Registry Extension',
    [string]$ProviderName = 'Group Policy Registry',
    [string]$OutputFolder = (Join-Path $env:USERPROFILE 'Desktop\GPP-Analyse'),
    [int]$ThrottleLimit   = 24,
    [System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
if (-not (Test-Path $OutputFolder)) { New-Item $OutputFolder -ItemType Directory -Force | Out-Null }

$Now      = Get-Date
$Span     = $Now - $Cutoff
$PreStart = $Cutoff - $Span

Write-Host "`nVorher-Fenster : $PreStart  bis  $Cutoff" -ForegroundColor Cyan
Write-Host "Nachher-Fenster: $Cutoff  bis  $Now"        -ForegroundColor Cyan
Write-Host ("Fensterlaenge  : {0:N1} Stunden" -f $Span.TotalHours) -ForegroundColor Cyan

$Names = (Get-ADComputer -SearchBase $SearchBase -Filter 'Enabled -eq $true' | Sort-Object Name).Name
Write-Host ("Server         : {0}" -f $Names.Count) -ForegroundColor Green

$Collect = {
    param($Cutoff, $PreStart, $CseFilter, $ProviderName)

    function Get-Ev {
        param($Log, [int[]]$Ids, $From, $To)
        try { @(Get-WinEvent -FilterHashtable @{ LogName = $Log; Id = $Ids; StartTime = $From; EndTime = $To } -EA Stop) }
        catch { @() }
    }

    $FslLocal = Get-ItemProperty 'HKLM:\SOFTWARE\FSLogix\Profiles'          -EA SilentlyContinue
    $FslPol   = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\FSLogix\Profiles' -EA SilentlyContinue
    if     ($null -ne $FslPol.GroupPolicyState)   { $Gps = [int]$FslPol.GroupPolicyState }
    elseif ($null -ne $FslLocal.GroupPolicyState) { $Gps = [int]$FslLocal.GroupPolicyState }
    else                                          { $Gps = 1 }

    $Now = Get-Date

    $PreRuns  = @(Get-Ev 'Microsoft-Windows-GroupPolicy/Operational' 4016 $PreStart $Cutoff |
                  Where-Object { $_.Message -like "*$CseFilter*" }).Count
    $PostRuns = @(Get-Ev 'Microsoft-Windows-GroupPolicy/Operational' 4016 $Cutoff  $Now    |
                  Where-Object { $_.Message -like "*$CseFilter*" }).Count

    $PreFail  = @(Get-Ev 'Application' 8194 $PreStart $Cutoff | Where-Object { $_.ProviderName -eq $ProviderName }).Count
    $PostFail = @(Get-Ev 'Application' 8194 $Cutoff  $Now     | Where-Object { $_.ProviderName -eq $ProviderName }).Count

    [pscustomobject]@{
        Server           = $env:COMPUTERNAME
        Gruppe           = if ($Gps -eq 0) { 'Fix' } else { 'Kontrolle' }
        GroupPolicyState = $Gps
        GppLaeufeVorher  = $PreRuns
        FehlerVorher     = $PreFail
        GppLaeufeNachher = $PostRuns
        FehlerNachher    = $PostFail
    }
}

$Icm = @{
    ComputerName  = $Names
    ScriptBlock   = $Collect
    ArgumentList  = @($Cutoff, $PreStart, $CseFilter, $ProviderName)
    ThrottleLimit = $ThrottleLimit
    ErrorAction   = 'SilentlyContinue'
}
if ($Credential) { $Icm['Credential'] = $Credential }

$R = Invoke-Command @Icm | Select-Object Server, Gruppe, GroupPolicyState,
        GppLaeufeVorher, FehlerVorher, GppLaeufeNachher, FehlerNachher,
        @{ n = 'RateVorher';  e = { if ($_.GppLaeufeVorher)  { [math]::Round($_.FehlerVorher  / $_.GppLaeufeVorher,  2) } } },
        @{ n = 'RateNachher'; e = { if ($_.GppLaeufeNachher) { [math]::Round($_.FehlerNachher / $_.GppLaeufeNachher, 2) } } }

Write-Host "`n=== Pro Server (nur Server mit Laeufen im Nachher-Fenster) ===" -ForegroundColor Cyan
$R | Where-Object GppLaeufeNachher -gt 0 |
    Sort-Object Gruppe, Server |
    Format-Table Server, Gruppe, GppLaeufeVorher, FehlerVorher, GppLaeufeNachher, FehlerNachher, RateNachher -AutoSize

Write-Host "`n=== Gesamtvergleich ===" -ForegroundColor Cyan
$R | Group-Object Gruppe | ForEach-Object {
    $G  = $_.Group
    $PR = ($G | Measure-Object GppLaeufeVorher  -Sum).Sum
    $PF = ($G | Measure-Object FehlerVorher     -Sum).Sum
    $OR = ($G | Measure-Object GppLaeufeNachher -Sum).Sum
    $OF = ($G | Measure-Object FehlerNachher    -Sum).Sum
    [pscustomobject]@{
        Gruppe      = $_.Name
        Server      = $G.Count
        LaeufeVor   = $PR
        FehlerVor   = $PF
        RateVor     = if ($PR) { [math]::Round($PF / $PR, 3) } else { $null }
        LaeufeNach  = $OR
        FehlerNach  = $OF
        RateNach    = if ($OR) { [math]::Round($OF / $OR, 3) } else { $null }
    }
} | Format-Table -AutoSize

Write-Host "Lesart: RateNach in der Fix-Gruppe nahe 0, in der Kontrollgruppe unveraendert" -ForegroundColor DarkGray
Write-Host "        -> Wirkung belegt. Beide Gruppen gleich -> nicht belegt.`n" -ForegroundColor DarkGray

$F = Join-Path $OutputFolder ("GPP-FixEffect-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$R | Export-Csv $F -NoTypeInformation -Encoding UTF8 -Delimiter ';'
Write-Host "Export: $F`n"