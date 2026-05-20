# fetch-month.ps1
# Récupère un mois Patch Tuesday depuis l'API MSRC CVRF v2.0 et écrit
# data\{month}.json dans le même format que les autres mois.
# Réplique la logique de parseCVRF() du dashboard.
#
# Usage :
#   .\fetch-month.ps1 -Month "2025-Jan"          # un mois
#   .\fetch-month.ps1 -Month "2025-Jan,2025-Feb" # plusieurs (séparés par virgule)
#   .\fetch-month.ps1 -Last 12                    # les N derniers mois MSRC manquants
#   .\fetch-month.ps1 -Force                      # réécrit même si le fichier existe
#
# Après : .\build-detections.ps1 -Month X ; .\fetch-kb-dates.ps1

param(
    [string]$Month = "",
    [int]$Last = 0,
    [switch]$Force
)

# Pas de StrictMode : le CVRF MSRC contient beaucoup de champs optionnels ;
# on veut que l'accès à une propriété absente retourne $null, pas une erreur.
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding             = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "Stop"

$dataDir = Join-Path $PSScriptRoot "data"
$MSRC = "https://api.msrc.microsoft.com/cvrf/v2.0"
$SEV_VALS = @("Critical","Important","Moderate","Low")

function Get-Msrc([string]$url) {
    Invoke-RestMethod -Uri $url -Headers @{ Accept = "application/json" } -ErrorAction Stop
}

function Parse-CVRF($cvrf) {
    # Carte des produits
    $pm = @{}
    foreach ($p in @($cvrf.ProductTree.FullProductName)) {
        if ($null -ne $p) { $pm["$($p.ProductID)"] = $p.Value }
    }

    $vulns = foreach ($v in @($cvrf.Vulnerability)) {
        $threats = @($v.Threats)

        # Sévérité : menace dont la description EST un label connu
        $severity = "Unknown"
        foreach ($t in $threats) {
            $val = $t.Description.Value
            if ($SEV_VALS -contains $val) { $severity = $val; break }
        }
        $cvss = $null
        if ($v.PSObject.Properties["CVSSScoreSets"] -and @($v.CVSSScoreSets).Count -gt 0) {
            $cvss = @($v.CVSSScoreSets)[0].BaseScore
        }
        if ($severity -eq "Unknown" -and $cvss) {
            $severity = if ($cvss -ge 9) { "Critical" } elseif ($cvss -ge 7) { "Important" } elseif ($cvss -ge 4) { "Moderate" } else { "Low" }
        }

        # Exploité / divulgué
        $exploited = $false
        $pubDisc   = $false
        foreach ($t in $threats) {
            $val = ("" + $t.Description.Value).ToLower()
            if ($val -eq "exploited:yes" -or $val -like "*exploitation detected*") { $exploited = $true }
            if ($val -like "*publicly disclosed:yes*") { $pubDisc = $true }
        }

        # KBs : Remediations Type 2 (Vendor Fix), Description = 5-7 chiffres ; + URL ?q=KBxxxx
        $kbs = [System.Collections.Generic.List[string]]::new()
        foreach ($r in @($v.Remediations)) {
            $type = "$($r.Type)"
            if ($type -eq "2" -or $type.ToLower() -eq "vendor fix") {
                $val = ("" + $r.Description.Value).Trim()
                if ($val -match '^\d{5,7}$') {
                    $kb = "KB$val"
                    if (-not $kbs.Contains($kb)) { $kbs.Add($kb) }
                }
            }
            $url = "" + $r.URL
            $m = [regex]::Match($url, '[?&]q=(KB\d+)', 'IgnoreCase')
            if ($m.Success) {
                $kb = $m.Groups[1].Value.ToUpper()
                if (-not $kbs.Contains($kb)) { $kbs.Add($kb) }
            }
        }

        # Produits affectés
        $pids = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($ps in @($v.ProductStatuses)) {
            foreach ($id in @($ps.ProductID)) { [void]$pids.Add("$id") }
        }
        $products = foreach ($id in $pids) { if ($pm.ContainsKey($id)) { $pm[$id] } }
        $products = @($products | Where-Object { $_ })

        # Description (Notes Type 1)
        $desc = ""
        foreach ($n in @($v.Notes)) {
            if ("$($n.Type)" -eq "1" -or "$($n.Type)" -eq "Description") { $desc = $n.Value; break }
        }

        [ordered]@{
            cveId     = $v.CVE
            title     = if ($v.Title.Value) { $v.Title.Value } else { $v.CVE }
            severity  = $severity
            exploited = $exploited
            pubDisc   = $pubDisc
            kbs       = @($kbs)
            products  = $products
            cvss      = $cvss
            desc      = $desc
        }
    }
    return @($vulns)
}

# -- Déterminer la liste des mois à fetch -------------------------------------

$targets = @()
if ($Month) {
    $targets = $Month -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
} elseif ($Last -gt 0) {
    Write-Host "Récupération de la liste MSRC..." -ForegroundColor Gray
    $all = (Get-Msrc "$MSRC/updates").value | ForEach-Object { $_.ID }
    # Trier par date réelle (le tri lexical ne marche pas sur les mois)
    $parsed = $all | ForEach-Object {
        $p = $_ -split '-'
        $dt = try { [datetime]::ParseExact("$($p[0])-$($p[1])-01", 'yyyy-MMM-dd', [Globalization.CultureInfo]::InvariantCulture) } catch { $null }
        if ($dt) { [pscustomobject]@{ Id = $_; Date = $dt } }
    } | Where-Object { $_ } | Sort-Object Date -Descending
    $targets = ($parsed | Select-Object -First $Last).Id
}

if (-not $targets) { Write-Error "Aucun mois spécifié. Utilisez -Month ou -Last."; exit 1 }

Write-Host "Mois à traiter : $($targets -join ', ')" -ForegroundColor Cyan
Write-Host ""

$done = 0
$skip = 0
foreach ($m in $targets) {
    $path = Join-Path $dataDir "$m.json"
    if ((Test-Path $path) -and -not $Force) {
        Write-Host "[$m] déjà présent, ignoré (-Force pour réécrire)" -ForegroundColor DarkGray
        $skip++
        continue
    }
    Write-Host "[$m] fetch CVRF... " -NoNewline
    try {
        $cvrf = Get-Msrc "$MSRC/cvrf/$m"
    } catch {
        Write-Host "ÉCHEC ($($_.Exception.Message))" -ForegroundColor Red
        continue
    }
    $vulns = Parse-CVRF $cvrf
    $out = [ordered]@{
        month   = $m
        fetched = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        source  = "MSRC"
        vulns   = $vulns
    }
    $out | ConvertTo-Json -Depth 15 | Set-Content $path -Encoding UTF8
    Write-Host "$($vulns.Count) CVEs → $path" -ForegroundColor Green
    $done++
}

# -- Régénérer le manifeste des mois disponibles (pour le sélecteur du dashboard)
$present = Get-ChildItem $dataDir -Filter "*.json" | Where-Object { $_.Name -notlike "_*" } | ForEach-Object { $_.BaseName }
$sorted = $present | ForEach-Object {
    $p = $_ -split '-'
    $dt = try { [datetime]::ParseExact("$($p[0])-$($p[1])-01", 'yyyy-MMM-dd', [Globalization.CultureInfo]::InvariantCulture) } catch { $null }
    if ($dt) { [pscustomobject]@{ Id = $_; Date = $dt } }
} | Where-Object { $_ } | Sort-Object Date -Descending | ForEach-Object { $_.Id }
@($sorted) | ConvertTo-Json | Set-Content (Join-Path $dataDir "_months.json") -Encoding UTF8
Write-Host "Manifeste mis à jour : $($sorted.Count) mois" -ForegroundColor Gray

Write-Host ""
Write-Host "✅ Terminé : $done écrits, $skip ignorés" -ForegroundColor Green
Write-Host "   Étape suivante : .\build-detections.ps1 -Month <mois> ; .\fetch-kb-dates.ps1"
