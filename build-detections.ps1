# build-detections.ps1
# Pour chaque CVE du mois :
#   1. Génère un script PowerShell de détection basé sur la présence des KB correctifs
#      (Windows Update COM API)
#   2. Injecte le résultat dans data\{month}.json sous "cveDetection"
#
# Détection par KB : pour les CVEs Microsoft Patch Tuesday, vérifier la présence
# du KB correctif EST la méthode de détection canonique. (L'ancien pipeline OVAL
# via CISecurity/OVALRepo a été retiré : ce dépôt est archivé depuis ~2019 et ne
# couvre aucune CVE récente.)
#
# Usage : .\build-detections.ps1 [-Month "2026-May"]
#
# Après exécution : git add data\{month}.json && git commit && git push

param(
    [string]$Month = ""
)

Set-StrictMode -Version Latest
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding             = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "Stop"

# -- Helpers ------------------------------------------------------------------

function Get-JsonFile([string]$path) {
    Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Save-JsonFile([string]$path, $data) {
    $data | ConvertTo-Json -Depth 15 | Set-Content $path -Encoding UTF8
}

function Build-KBScript([string]$cveId, [string[]]$kbs) {
    $kbArray = ($kbs | ForEach-Object { "`"$_`"" }) -join ", "
    return @"
# Détection par KB correctif : $cveId
# Les KB listés couvrent plusieurs versions de Windows ; une machine n'en
# installe qu'UN (celui de son OS). Donc : protégé dès qu'UN correctif est présent.
`$kbCorrecifs = @($kbArray)
`$Session  = New-Object -ComObject Microsoft.Update.Session
`$Searcher = `$Session.CreateUpdateSearcher()
`$Updates  = `$Searcher.Search("IsInstalled=1").Updates
`$installes = `$Updates | ForEach-Object { `$_.KBArticleIDs } | ForEach-Object { "KB`$_" }
`$presents = `$kbCorrecifs | Where-Object { `$installes -contains `$_ }
if (`$presents.Count -gt 0) {
    Write-Host "✅ PROTÉGÉ   - $cveId : correctif présent (`$(`$presents -join ', '))" -ForegroundColor Green
} else {
    Write-Host "⚠️  VULNÉRABLE - $cveId : aucun correctif installé (ou CVE non applicable à cet OS)" -ForegroundColor Red
}
"@
}

# -- Main ----------------------------------------------------------------------

$dataDir = Join-Path $PSScriptRoot "data"
if (-not $Month) {
    $files = Get-ChildItem -Path $dataDir -Filter "*.json" |
             Where-Object { $_.Name -notlike "_*" } |
             Sort-Object Name -Descending
    if (-not $files) { Write-Error "Aucun fichier JSON dans $dataDir"; exit 1 }
    $Month = $files[0].BaseName
    Write-Host "Mois auto-détecté : $Month" -ForegroundColor Cyan
}

$jsonPath = Join-Path $dataDir "$Month.json"
if (-not (Test-Path $jsonPath)) { Write-Error "Fichier introuvable : $jsonPath"; exit 1 }

$data = Get-JsonFile $jsonPath

$total    = $data.vulns.Count
$withKB   = 0
$noKB     = 0

Write-Host ""
Write-Host "Génération des scripts de détection (KB) pour $total CVEs ($Month)" -ForegroundColor Cyan
Write-Host ""

$cveDetection = [ordered]@{}
$i = 0

foreach ($vuln in $data.vulns) {
    $i++
    $cveId = $vuln.cveId
    $kbs   = @($vuln.kbs)

    if ($kbs.Count -gt 0) {
        $cveDetection[$cveId] = [ordered]@{
            source = "kb"
            file   = ""
            script = (Build-KBScript $cveId $kbs)
        }
        $withKB++
        Write-Host "[$i/$total] $cveId — KB ($($kbs.Count))" -ForegroundColor Green
    } else {
        # Pas de KB correctif (CVE cloud/Azure, rien à patcher localement)
        $cveDetection[$cveId] = [ordered]@{
            source = "no-kb"
            file   = ""
            script = ""
        }
        $noKB++
        Write-Host "[$i/$total] $cveId — pas de KB" -ForegroundColor DarkGray
    }
}

$data | Add-Member -NotePropertyName cveDetection -NotePropertyValue $cveDetection -Force
Save-JsonFile $jsonPath $data

Write-Host ""
Write-Host "✅ Terminé : $withKB avec KB, $noKB sans KB ($total total)" -ForegroundColor Green
Write-Host "   Fichier mis à jour : $jsonPath"
Write-Host ""
Write-Host "Prochaine étape :" -ForegroundColor Yellow
Write-Host "  git add data\$Month.json && git commit -m `"feat: KB detection scripts $Month`" && git push"
