# --- KONFIGURATION ---
$OUPath   = "OU=Groups Applications,OU=AHP Infrastructure Objects,DC=,DC="
$Prefix   = "AHP APP*"
$MaxUsers = 8
# ---------------------

# 1. Alle Parent-Gruppen finden
$ParentGroups = Get-ADGroup -Filter "Name -like '$Prefix'" -SearchBase $OUPath -Properties Member

# 2. Alle DistinguishedNames der Mitglieder sammeln (einmalig)
$AllMemberDNs = $ParentGroups.Member | Select-Object -Unique

# 3. Nur die DNs herausfiltern, die wirklich GRUPPEN sind (vermeidet die User-Fehler)
# Wir verarbeiten alle DNs in einem Rutsch, das ist massiv schneller
Write-Host "Verarbeite Gruppen-Mitglieder... Bitte warten." -ForegroundColor Yellow

$Results = foreach ($DN in $AllMemberDNs) {
    # Wir holen das Objekt nur, wenn es eine Gruppe ist
    $Group = Get-ADGroup -Identity $DN -Properties Member, Name -ErrorAction SilentlyContinue
    
    if ($Group) {
        $Count = if ($Group.Member) { $Group.Member.Count } else { 0 }
        
        if ($Count -lt $MaxUsers) {
            [PSCustomObject]@{
                TenantGroupName   = $Group.Name
                UserCount         = $Count
                DistinguishedName = $Group.DistinguishedName
            }
        }
    }
}

# 4. Dubletten entfernen (falls eine Gruppe über verschiedene Pfade gefunden wurde)
$FinalResult = $Results | Sort-Object TenantGroupName -Unique

# Ausgabe
if ($FinalResult) {
    $FinalResult | Sort-Object UserCount | Out-GridView -Title "Eindeutige Tenant-Gruppen (< $MaxUsers Mitglieder)"
} else {
    Write-Host "Keine passenden Gruppen gefunden." -ForegroundColor Cyan
}