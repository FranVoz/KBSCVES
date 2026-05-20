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
# Valeur = objet { date: "YYYY-MM-DD"|"unknown", desc: "..." }
# (Ancien format = string date pure ; migré au chargement.)

$cacheFile = Join-Path $dataDir "_kb-dates.json"
$cache = [ordered]@{}
if (Test-Path $cacheFile) {
    $cd = Get-Content $cacheFile -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($cd) {
        $cd.PSObject.Properties | ForEach-Object {
            $v = $_.Value
            if ($v -is [string]) {
                # Ancien format : string date → objet sans desc
                $cache[$_.Name] = [ordered]@{ date = $v; desc = "" }
            } else {
                $d = if ($v.PSObject.Properties["desc"]) { $v.desc } else { "" }
                $cache[$_.Name] = [ordered]@{ date = $v.date; desc = $d }
            }
        }
    }
}

function Save-Cache {
    $cache | ConvertTo-Json -Depth 5 | Set-Content $cacheFile -Encoding UTF8
}

function Format-KBDesc([string]$title) {
    $t = $title
    $t = $t -replace '\s*\(KB\d+\).*$', ''                                                      # coupe à "(KBxxxx)" et tout ce qui suit
    $t = $t -replace '^\s*\d{4}-\d{2}\s+', ''                                                   # préfixe date "2026-05 "
    $t = $t -replace '\s+for\s+(x64|x86|ARM64|Arm64)(-based)?(\s+(Systems|Client))?\s*$', ''    # " for x64-based Systems"
    $t = $t -replace '\s+(x64|x86|ARM64|Arm64)(-based)?(\s+(Systems|Client))?\s*$', ''          # " x64-based Systems"
    $t = $t -replace '\s+for\s*$', ''                                                           # "for" résiduel en fin
    return ($t -replace '\s+', ' ').Trim()
}

function Get-KBInfo([string]$kb) {
    $url = "https://www.catalog.update.microsoft.com/Search.aspx?q=$kb"
    try {
        $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
    } catch {
        return $null
    }
    # Date : plus ancienne M/D/YYYY trouvée (release initiale)
    $date = "unknown"
    $dm = [regex]::Matches($r.Content, '(\d{1,2}/\d{1,2}/\d{4})') | ForEach-Object {
        try { [datetime]::ParseExact($_.Value, 'M/d/yyyy', [Globalization.CultureInfo]::InvariantCulture) } catch { $null }
    } | Where-Object { $_ }
    if ($dm) { $date = (($dm | Sort-Object)[0]).ToString('yyyy-MM-dd') }

    # Description : premier titre d'update contenant le KB, nettoyé
    $desc = ""
    $tm = [regex]::Match($r.Content, '<a[^>]*>\s*([^<]*\(' + [regex]::Escape($kb) + '\)[^<]*?)\s*</a>', 'Singleline')
    if ($tm.Success) { $desc = Format-KBDesc $tm.Groups[1].Value }

    return [ordered]@{ date = $date; desc = $desc }
}

function Need-Fetch($kb) {
    if ($Force) { return $true }
    $e = $cache[$kb]
    if ($null -eq $e) { return $true }
    # Backfill : entrée sans description (ancien cache date-only)
    if (-not $e.desc) { return $true }
    return $false
}

# -- Boucle -------------------------------------------------------------------

$kbList   = @($allKBs)
$total    = $kbList.Count
$toFetch  = @($kbList | Where-Object { Need-Fetch $_ })

Write-Host ""
Write-Host "KB info — $total KB uniques, $($cache.Count) en cache, $($toFetch.Count) à récupérer$(if ($Force) {' (-Force actif)'})" -ForegroundColor Cyan
Write-Host "Source : Microsoft Update Catalog (date + description)" -ForegroundColor Gray
Write-Host ""

$i = 0
$ok = 0
$fail = 0
foreach ($kb in $kbList) {
    $i++
    if (-not (Need-Fetch $kb)) {
        Write-Host "[$i/$total] $kb — cache ($($cache[$kb].date))" -ForegroundColor DarkGray
        continue
    }
    Write-Host "[$i/$total] $kb ... " -NoNewline
    $info = Get-KBInfo $kb
    if ($info -and $info.date -ne "unknown") {
        $cache[$kb] = $info
        $ok++
        Write-Host "$($info.date) — $($info.desc)" -ForegroundColor Green
    } else {
        $d = if ($info) { $info.desc } else { "" }
        $cache[$kb] = [ordered]@{ date = "unknown"; desc = $d }
        $fail++
        Write-Host "date introuvable" -ForegroundColor DarkYellow
    }
    Save-Cache
    Start-Sleep -Milliseconds 800
}

Save-Cache

Write-Host ""
Write-Host "✅ Terminé : $ok récupérés, $fail sans date ($($cache.Count) en cache)" -ForegroundColor Green
Write-Host "   Fichier : $cacheFile"
