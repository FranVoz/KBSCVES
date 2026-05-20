# scan-vulns.ps1
# Vérifie la vulnérabilité locale pour chaque CVE du mois et met à jour le JSON de cache.
# Usage : .\scan-vulns.ps1 [-Month "2026-May"]
# Après exécution : git add data\ && git commit && git push
param(
    [string]$Month = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding             = [System.Text.Encoding]::UTF8

# --- Trouver le fichier JSON ---
$dataDir = Join-Path $PSScriptRoot "data"
if (-not $Month) {
    $files = Get-ChildItem -Path $dataDir -Filter "*.json" | Sort-Object Name -Descending
    if (-not $files) { Write-Error "Aucun fichier JSON dans $dataDir"; exit 1 }
    $Month = $files[0].BaseName
    Write-Host "Mois auto-détecté : $Month" -ForegroundColor Cyan
}

$jsonPath = Join-Path $dataDir "$Month.json"
if (-not (Test-Path $jsonPath)) { Write-Error "Fichier introuvable : $jsonPath"; exit 1 }

Write-Host "Chargement de $jsonPath ..." -ForegroundColor Cyan
$data = Get-Content $jsonPath -Raw -Encoding UTF8 | ConvertFrom-Json

# --- Récupérer les KBs installés via Windows Update COM ---
Write-Host "Interrogation du cache Windows Update ..." -ForegroundColor Cyan
$Session  = New-Object -ComObject Microsoft.Update.Session
$Searcher = $Session.CreateUpdateSearcher()
$Updates  = $Searcher.Search("IsInstalled=1").Updates

$installedKBs = @{}
foreach ($u in $Updates) {
    foreach ($kb in $u.KBArticleIDs) {
        $installedKBs["KB$kb"] = $true
    }
}
Write-Host "  $($installedKBs.Count) mises à jour installées détectées." -ForegroundColor Gray

# --- Analyser chaque CVE ---
Write-Host "Analyse de $($data.vulns.Count) CVEs ..." -ForegroundColor Cyan
$cveStatus = [ordered]@{}
$vulnCount = 0
foreach ($vuln in $data.vulns) {
    $missing = @()
    foreach ($kb in $vuln.kbs) {
        if (-not $installedKBs.ContainsKey($kb)) { $missing += $kb }
    }
    $status = if ($vuln.kbs.Count -eq 0) { "unknown" }
              elseif ($missing.Count -eq 0) { "patched" }
              else { "vulnerable" }
    if ($status -eq "vulnerable") { $vulnCount++ }
    $cveStatus[$vuln.cveId] = [ordered]@{
        status     = $status
        missingKbs = $missing
    }
}

# --- Écrire les résultats dans le JSON ---
$data | Add-Member -NotePropertyName scanned   -NotePropertyValue (Get-Date -Format "o") -Force
$data | Add-Member -NotePropertyName scanHost  -NotePropertyValue $env:COMPUTERNAME      -Force
$data | Add-Member -NotePropertyName cveStatus -NotePropertyValue $cveStatus             -Force

$data | ConvertTo-Json -Depth 10 | Set-Content $jsonPath -Encoding UTF8

Write-Host ""
Write-Host "✅ Résultats enregistrés dans $jsonPath" -ForegroundColor Green
Write-Host "   Machine  : $env:COMPUTERNAME"
Write-Host "   CVEs     : $($cveStatus.Count) analysés — $vulnCount vulnérable(s)"
Write-Host ""
Write-Host "Prochaine étape :" -ForegroundColor Yellow
Write-Host "  git add data\$Month.json && git commit -m `"scan: $Month sur $env:COMPUTERNAME`" && git push"
