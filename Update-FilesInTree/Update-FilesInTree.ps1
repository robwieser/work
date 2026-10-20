<#
.SYNOPSIS
	Ersetzt gleichnamige Dateien unterhalb eines Pfades (lokal oder UNC) durch eine neue Version.
.DESCRIPTION
	Universelles Werkzeug zum Austausch beliebiger Dateien (ps1, dll, exe, xml, json, config, ...):

	- Sucht rekursiv nach Dateien mit dem Zielnamen (Standard: Dateiname der Quelldatei)
	- Dry-Run ist Standard: ohne -Apply wird nichts veraendert, nur protokolliert
	- Ueberspringt Dateien, die bereits identisch zur Quelle sind (SHA256)
	- Optionale Filter, damit nur die "richtigen" Dateien ersetzt werden:
	    -RequireText / -ExcludeText   Inhaltsfilter (Regex, nur fuer Textdateien)
	    -OnlyIfOlder                  nur ersetzen, wenn das Ziel aelter (LastWriteTime) ist
	    -OnlyIfLowerVersion           nur ersetzen, wenn die Dateiversion (exe/dll) niedriger ist
	    -ExcludePath                  Pfade ausnehmen (Wildcards)
	    -MaxDepth                     Suchtiefe begrenzen
	- Sichert jede ersetzte Datei vorher in einen Backup-Ordner (Ordnerstruktur gespiegelt), ausser -NoBackup
	- Prueft nach dem Kopieren den Hash und schreibt ein CSV-Protokoll
	- Mehrere Quelldateien pro Lauf moeglich (-SourceFile a.dll, b.dll)
	- Kompatibel mit Windows PowerShell 5.1 und PowerShell 7
.PARAMETER SearchPath
	Wurzelpfad, z.B. '\\server\share\Packages' oder 'D:\Apps'
.PARAMETER SourceFile
	Neue Datei(en), die verteilt werden soll(en). Der Name der Zieldatei entspricht dem Namen der Quelle,
	ausser -TargetName ist gesetzt.
.PARAMETER TargetName
	Name der zu ersetzenden Dateien (Wildcards erlaubt, z.B. 'Deploy-Package.ps1' oder '*.config').
	Nur zusammen mit genau einer Quelldatei. Die ersetzte Datei behaelt immer ihren eigenen Namen.
.PARAMETER RequireText
	Regex. Nur Dateien ersetzen, deren Inhalt darauf passt (z.B. 'Open-ADTSession'). Nur fuer Textdateien.
.PARAMETER ExcludeText
	Regex. Dateien, deren Inhalt darauf passt, werden uebersprungen. Nur fuer Textdateien.
.PARAMETER OnlyIfOlder
	Nur ersetzen, wenn die Zieldatei aelter ist als die Quelle.
.PARAMETER OnlyIfLowerVersion
	Nur ersetzen, wenn die Dateiversion (VersionInfo) des Ziels niedriger ist. Fehlt die Version, wird uebersprungen.
.PARAMETER ExcludePath
	Wildcard-Muster auf den vollen Pfad, z.B. '*\_Archive\*'.
.PARAMETER MaxDepth
	Maximale Suchtiefe unterhalb von SearchPath (0 = nur SearchPath selbst). Standard: unbegrenzt.
.PARAMETER BackupRoot
	Zielordner fuer Sicherungen. Standard: .\Backup_<Zeitstempel> neben dem Skript.
.PARAMETER NoBackup
	Keine Sicherung anlegen (nicht empfohlen).
.PARAMETER Apply
	Aenderungen wirklich durchfuehren. Ohne diesen Schalter: Dry-Run.
.PARAMETER HideSkipped
	Uebersprungene Dateien nicht in der Konsole auflisten (CSV enthaelt sie trotzdem).
.PARAMETER PassThru
	Ergebnisobjekte zusaetzlich auf der Pipeline ausgeben.
.EXAMPLE
	# Dry-Run: Deploy-Package.ps1 nur in PPB-5-Paketen ersetzen
	.\Update-FilesInTree.ps1 -SearchPath '\\srv\Packages' -SourceFile C:\Temp\Deploy-Package.ps1 -RequireText 'Open-ADTSession'
.EXAMPLE
	# Scharf ausfuehren
	.\Update-FilesInTree.ps1 -SearchPath '\\srv\Packages' -SourceFile C:\Temp\Deploy-Package.ps1 -RequireText 'Open-ADTSession' -Apply
.EXAMPLE
	# Zwei DLLs austauschen, aber nur wenn die vorhandene Version niedriger ist
	.\Update-FilesInTree.ps1 -SearchPath 'D:\Apps' -SourceFile C:\Temp\a.dll, C:\Temp\b.dll -OnlyIfLowerVersion -Apply
.EXAMPLE
	# Datei unter anderem Namen bereitgestellt: neue_app.config ersetzt alle app.config
	.\Update-FilesInTree.ps1 -SearchPath 'D:\Apps' -SourceFile C:\Temp\neue_app.config -TargetName app.config -Apply
#>
#Requires -Version 5.1
[CmdletBinding()]
param (
	[Parameter(Mandatory = $true)][string]$SearchPath,
	[Parameter(Mandatory = $true)][string[]]$SourceFile,
	[string]$TargetName = $null,
	[string]$RequireText = $null,
	[string]$ExcludeText = $null,
	[switch]$OnlyIfOlder,
	[switch]$OnlyIfLowerVersion,
	[string[]]$ExcludePath = @(),
	[int]$MaxDepth = -1,
	[string]$BackupRoot = $null,
	[switch]$NoBackup,
	[switch]$Apply,
	[switch]$HideSkipped,
	[switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$separators = [char[]]@('\', '/')

function Get-FileVersionObject([string]$path)
{
	try
	{
		$vi = (Get-Item -LiteralPath $path).VersionInfo
		if ($vi -eq $null) { return $null }
		$v = New-Object System.Version -ArgumentList $vi.FileMajorPart, $vi.FileMinorPart, $vi.FileBuildPart, $vi.FilePrivatePart
		if ($v -eq (New-Object System.Version -ArgumentList 0, 0, 0, 0)) { return $null }
		return $v
	}
	catch { return $null }
}

# --- Eingaben pruefen ---------------------------------------------------------------------------
if (!(Test-Path -LiteralPath $SearchPath -PathType Container)) { throw "SearchPath nicht erreichbar: $SearchPath" }
$SearchPath = (Resolve-Path -LiteralPath $SearchPath).ProviderPath.TrimEnd($separators)

$sources = @()
foreach ($s in $SourceFile)
{
	if (!(Test-Path -LiteralPath $s -PathType Leaf)) { throw "SourceFile nicht gefunden: $s" }
	$sources += (Resolve-Path -LiteralPath $s).ProviderPath
}
if (![string]::IsNullOrEmpty($TargetName) -and ($sources.Count -gt 1)) { throw "-TargetName ist nur mit genau einer Quelldatei erlaubt." }

foreach ($rx in @($RequireText, $ExcludeText))
{
	if (![string]::IsNullOrEmpty($rx)) { try { [void][regex]::new($rx) } catch { throw "Ungueltiger Regex '$rx': $($_.Exception.Message)" } }
}

if ([string]::IsNullOrEmpty($BackupRoot))
{
	$base = $(if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path })
	$BackupRoot = Join-Path $base "Backup_$timestamp"
}
$BackupRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BackupRoot)
$logPath = Join-Path (Split-Path $BackupRoot -Parent) "Update-FilesInTree_$timestamp.csv"

$modeText = $(if ($Apply) { 'APPLY (aendert Dateien)' } else { 'DRY-RUN (keine Aenderung)' })
Write-Host "Modus      : $modeText" -ForegroundColor $(if ($Apply) { 'Yellow' } else { 'Cyan' })
Write-Host "Suchpfad   : $SearchPath"
Write-Host "Quellen    : $([string]::Join(', ', ($sources | % { Split-Path $_ -Leaf })))"
if (![string]::IsNullOrEmpty($TargetName)) { Write-Host "Zielname   : $TargetName" }
$filters = @()
if ($RequireText) { $filters += "RequireText='$RequireText'" }
if ($ExcludeText) { $filters += "ExcludeText='$ExcludeText'" }
if ($OnlyIfOlder) { $filters += 'OnlyIfOlder' }
if ($OnlyIfLowerVersion) { $filters += 'OnlyIfLowerVersion' }
if ($ExcludePath.Count -gt 0) { $filters += "ExcludePath=$([string]::Join(',', $ExcludePath))" }
if ($filters.Count -gt 0) { Write-Host "Filter     : $([string]::Join('; ', $filters))" }
Write-Host "Backup     : $(if ($NoBackup) { '(deaktiviert)' } else { $BackupRoot })"
Write-Host "Protokoll  : $logPath"

$results = New-Object System.Collections.Generic.List[object]

# --- Verarbeitung je Quelldatei ---------------------------------------------------------------------
foreach ($source in $sources)
{
	$sourceItem = Get-Item -LiteralPath $source
	$sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
	$sourceVersion = $(if ($OnlyIfLowerVersion) { Get-FileVersionObject $source } else { $null })
	$nameToFind = $(if (![string]::IsNullOrEmpty($TargetName)) { $TargetName } else { $sourceItem.Name })

	Write-Host "`n=== $($sourceItem.Name)  [SHA256 $($sourceHash.Substring(0, 12))...]  -> suche '$nameToFind' ===" -ForegroundColor White
	if ($OnlyIfLowerVersion -and ($sourceVersion -eq $null)) { Write-Warning "Quelle '$($sourceItem.Name)' hat keine Dateiversion - alle Ziele werden mit -OnlyIfLowerVersion uebersprungen." }
	Write-Host "Suche laeuft (bei UNC-Pfaden kann das dauern) ..."

	$gci = @{ LiteralPath = $SearchPath; Filter = $nameToFind; File = $true; Recurse = $true; ErrorAction = 'SilentlyContinue' }
	if ($MaxDepth -ge 0) { $gci['Depth'] = $MaxDepth }
	$targets = @(Get-ChildItem @gci)

	# Quelle selbst und Backup nie anfassen
	$targets = @($targets | Where-Object {
		($_.FullName -ine $source) -and
		($NoBackup -or !$_.FullName.StartsWith($BackupRoot, [System.StringComparison]::OrdinalIgnoreCase))
	})
	foreach ($ex in $ExcludePath) { $targets = @($targets | Where-Object { $_.FullName -notlike $ex }) }

	Write-Host "Gefunden   : $($targets.Count) Datei(en)"
	$i = 0

	foreach ($file in $targets)
	{
		$i++
		$status = $null; $detail = $null; $oldHash = $null

		try
		{
			$oldHash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash

			if ($oldHash -eq $sourceHash)
			{
				$status = 'Skipped-Identical'
			}
			elseif ($OnlyIfOlder -and ($file.LastWriteTimeUtc -ge $sourceItem.LastWriteTimeUtc))
			{
				$status = 'Skipped-NotOlder'
				$detail = "Ziel $($file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')), Quelle $($sourceItem.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))"
			}
			elseif ($OnlyIfLowerVersion)
			{
				$targetVersion = Get-FileVersionObject $file.FullName
				if (($sourceVersion -eq $null) -or ($targetVersion -eq $null))
				{
					$status = 'Skipped-NoVersion'
					$detail = "Quelle: $sourceVersion, Ziel: $targetVersion"
				}
				elseif ($targetVersion -ge $sourceVersion)
				{
					$status = 'Skipped-NotLower'
					$detail = "Ziel $targetVersion >= Quelle $sourceVersion"
				}
			}

			if ($status -eq $null -and (![string]::IsNullOrEmpty($RequireText) -or ![string]::IsNullOrEmpty($ExcludeText)))
			{
				$text = [System.IO.File]::ReadAllText($file.FullName)
				if (![string]::IsNullOrEmpty($RequireText) -and ($text -notmatch $RequireText))
				{
					$status = 'Skipped-NoMatch'
					$detail = "Inhalt passt nicht auf RequireText '$RequireText'"
				}
				elseif (![string]::IsNullOrEmpty($ExcludeText) -and ($text -match $ExcludeText))
				{
					$status = 'Skipped-Excluded'
					$detail = "Inhalt passt auf ExcludeText '$ExcludeText'"
				}
			}

			if ($status -eq $null)
			{
				if (!$Apply)
				{
					$status = 'WouldReplace'
				}
				else
				{
					$backupPath = $null
					if (!$NoBackup)
					{
						$relative = $file.FullName.Substring($SearchPath.Length).TrimStart($separators)
						$backupPath = Join-Path $BackupRoot $relative
						New-Item -ItemType Directory -Path (Split-Path $backupPath -Parent) -Force | Out-Null
						Copy-Item -LiteralPath $file.FullName -Destination $backupPath -Force
					}

					if ($file.IsReadOnly) { $file.IsReadOnly = $false }
					Copy-Item -LiteralPath $source -Destination $file.FullName -Force

					$newHash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
					if ($newHash -ne $sourceHash) { throw "Hash nach Kopieren stimmt nicht$(if ($backupPath) { " - Backup liegt unter $backupPath" })" }
					$status = 'Replaced'
					$detail = $backupPath
				}
			}
		}
		catch
		{
			$status = 'Error'
			$detail = $_.Exception.Message
		}

		if (!($HideSkipped -and $status -like 'Skipped-*'))
		{
			$color = switch -Wildcard ($status) { 'Replaced' { 'Green' } 'WouldReplace' { 'Cyan' } 'Error' { 'Red' } default { 'DarkGray' } }
			Write-Host ("[{0,4}/{1}] {2,-18} {3}" -f $i, $targets.Count, $status, $file.FullName) -ForegroundColor $color
			if ($status -eq 'Error') { Write-Host "         $detail" -ForegroundColor Red }
		}

		$results.Add([pscustomobject]@{
			Source = $sourceItem.Name
			Status = $status
			Path = $file.FullName
			OldHash = $oldHash
			NewHash = $sourceHash
			Detail = $detail
		})
	}
}

# --- Protokoll & Zusammenfassung ---------------------------------------------------------------------
if ($results.Count -gt 0)
{
	$logDir = Split-Path $logPath -Parent
	if (!(Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
	$results | Export-Csv -LiteralPath $logPath -NoTypeInformation -Delimiter ';' -Encoding UTF8
}

Write-Host "`nZusammenfassung:" -ForegroundColor White
if ($results.Count -eq 0) { Write-Host "  Keine passenden Dateien gefunden." }
else
{
	$results | Group-Object Source, Status | Sort-Object Name | ForEach-Object { Write-Host ("  {0,-50} {1}" -f $_.Name, $_.Count) }
	Write-Host "Protokoll: $logPath"
}
if (!$Apply) { Write-Host "`nDry-Run beendet. Zum Ausfuehren mit -Apply erneut starten." -ForegroundColor Cyan }

if ($PassThru) { $results }