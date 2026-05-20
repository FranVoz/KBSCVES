# fetch-kb-dates.ps1
# Récupère la date de release de chaque KB via le Microsoft Update Catalog
# (pas d'API officielle — scraping HTML de catalog.update.microsoft.com).
#
# Les dates ne changent jamais → cache permanent dans data\_kb-dates.json
# (clé = numéro KB, valeur = "YYYY-MM-DD"). Le dashboard lit ce fichier.
#
# Usage : .\fetch-kb-dates.ps1 [-Month "2026-May"] [-Force]
# -Force : re-récupère même les KB déjà en cache
#
# Après exécution : git add data\_kb-dates.json && git commit && git push

param(
    [string]$Month = "",
    [switch]$Force
)

Set-StrictMode -Version Latest
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding             = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "Stop"

$dataDir = Join-Path $PSScriptRoot "data"

# -- Collecter les KB uniques de tous les mois (ou d'un mois précis) ----------

$monthFiles = if ($Month) {
    @(Join-Path $dataDir "$Month.json")
} else {
    Get-ChildItem -Path $dataDir -Filter "*.json" |
        Where-Object { $_.Name -notlike "_*" } |
        ForEach-Object { $_.FullName }
}

$allKBs = [System.Collections.Generic.HashSet[string]]::new()
foreach ($f in $monthFiles) {
    if (-not (Test-Path $f)) { Write-Warning "Introuvable : $f"; continue }
    $j = Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($v in $j.vulns) {
        foreach ($kb in @($v.kbs)) { [void]$allKBs.Add($kb) }
    }
}

# -- Cache persistant ---------------------------------------------------------

$cacheFile = Join-Path $dataDir "_kb-dates.json"
$cache = [ordered]@{}
if (Test-Path $cacheFile) {
    $cd = Get-Content $cacheFile -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($cd) { $cd.PSObject.Properties | ForEach-Object { $cache[$_.Name] = $_.Value } }
}

function Save-Cache {
    $cache | ConvertTo-Json -Depth 5 | Set-Content $cacheFile -Encoding UTF8
}

function Get-KBDate([string]$kb) {
    $url = "https://www.catalog.update.microsoft.com/Search.aspx?q=$kb"
    try {
        $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
    } catch {
        return $null
    }
    # Extraire toutes les dates M/D/YYYY, garder la plus ancienne (release initiale)
    $matches = [regex]::Matches($r.Content, '(\d{1,2}/\d{1,2}/\d{4})')
    if ($matches.Count -eq 0) { return $null }
    $dates = $matches | ForEach-Object {
        try { [datetime]::ParseExact($_.Value, 'M/d/yyyy', [Globalization.CultureInfo]::InvariantCulture) } catch { $null }
    } | Where-Object { $_ }
    if (-not $dates) { return $null }
    $earliest = ($dates | Sort-Object)[0]
    return $earliest.ToString('yyyy-MM-dd')
}

# -- Boucle -------------------------------------------------------------------

$kbList   = @($allKBs)
$total    = $kbList.Count
$toFetch  = @($kbList | Where-Object { $Force -or $null -eq $cache[$_] })

Write-Host ""
Write-Host "Dates KB — $total KB uniques, $($cache.Count) en cache, $($toFetch.Count) à récupérer$(if ($Force) {' (-Force actif)'})" -ForegroundColor Cyan
Write-Host "Source : Microsoft Update Catalog" -ForegroundColor Gray
Write-Host ""

$i = 0
$ok = 0
$fail = 0
foreach ($kb in $kbList) {
    $i++
    if (-not $Force -and $null -ne $cache[$kb]) {
        Write-Host "[$i/$total] $kb — cache ($($cache[$kb]))" -ForegroundColor DarkGray
        continue
    }
    Write-Host "[$i/$total] $kb ... " -NoNewline
    $date = Get-KBDate $kb
    if ($date) {
        $cache[$kb] = $date
        $ok++
        Write-Host $date -ForegroundColor Green
    } else {
        $cache[$kb] = "unknown"
        $fail++
        Write-Host "introuvable" -ForegroundColor DarkYellow
    }
    Save-Cache
    Start-Sleep -Milliseconds 800
}

Save-Cache

Write-Host ""
Write-Host "✅ Terminé : $ok dates récupérées, $fail introuvables ($($cache.Count) en cache)" -ForegroundColor Green
Write-Host "   Fichier : $cacheFile"
