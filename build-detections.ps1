# build-detections.ps1
# Pour chaque CVE du mois :
#   1. Requête CIS OVAL repo (GitHub) pour trouver une définition OVAL
#   2. Parse le XML OVAL : registry tests, file version tests, WMI tests
#   3. Convertit en script PowerShell de détection de vulnérabilité
#   4. Injecte le résultat dans data\{month}.json sous "cveDetection"
#
# Usage : .\build-detections.ps1 [-Month "2026-May"] [-GithubToken "ghp_..."] [-Force]
# -Force : re-génère même si cveDetection existe déjà
# -GithubToken : facultatif mais recommandé (60 req/h sans, 5000 avec)
#
# Après exécution : git add data\{month}.json && git commit && git push

param(
    [string]$Month       = "",
    [string]$GithubToken = "",
    [switch]$Force
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

function Invoke-GitHub([string]$url) {
    $headers = @{ "Accept" = "application/vnd.github.v3+json"; "User-Agent" = "KBSCVES-pipeline" }
    if ($GithubToken) { $headers["Authorization"] = "Bearer $GithubToken" }
    try {
        $r = Invoke-WebRequest -Uri $url -Headers $headers -UseBasicParsing -ErrorAction Stop
        return $r.Content | ConvertFrom-Json
    } catch {
        if ($_.Exception.Response.StatusCode -eq 403) {
            Write-Warning "GitHub rate limit atteint. Utilisez -GithubToken pour augmenter la limite."
        }
        return $null
    }
}

function Get-OVALXml([string]$rawUrl) {
    try {
        $r = Invoke-WebRequest -Uri $rawUrl -UseBasicParsing -ErrorAction Stop
        return [xml]$r.Content
    } catch { return $null }
}

# -- Parse OVAL XML → extraire les tests pour un CVE --------------------------

function Get-OVALDefinitionForCVE([xml]$oval, [string]$cveId) {
    # Cherche la définition référençant ce CVE
    $ns = @{ o = "http://oval.mitre.org/XMLSchema/oval-definitions-5" }
    foreach ($def in $oval.oval_definitions.definitions.definition) {
        $refs = $def.metadata.reference
        if (-not $refs) { continue }
        foreach ($ref in @($refs)) {
            if ($ref.source -eq "CVE" -and $ref.ref_id -eq $cveId) {
                return $def
            }
        }
    }
    return $null
}

function Resolve-TestRefs([xml]$oval, [string[]]$testRefs) {
    $results = @()
    $allTests = @{}

    # Indexer tous les tests
    foreach ($ns in @("win","linux","unix","ind")) {
        $nodes = $oval.oval_definitions.tests.ChildNodes
        if ($nodes) {
            foreach ($t in $nodes) {
                if ($t.id) { $allTests[$t.id] = $t }
            }
        }
    }

    foreach ($ref in $testRefs) {
        if ($allTests.ContainsKey($ref)) { $results += $allTests[$ref] }
    }
    return $results
}

function Get-ObjectById([xml]$oval, [string]$id) {
    foreach ($n in $oval.oval_definitions.objects.ChildNodes) {
        if ($n.id -eq $id) { return $n }
    }
    return $null
}

function Get-StateById([xml]$oval, [string]$id) {
    foreach ($n in $oval.oval_definitions.states.ChildNodes) {
        if ($n.id -eq $id) { return $n }
    }
    return $null
}

# -- Convertir tests OVAL → PowerShell ----------------------------------------

function Convert-RegistryTest($test, [xml]$oval) {
    $obj = Get-ObjectById $oval $test.object.object_ref
    if (-not $obj) { return $null }

    $hive = switch ($obj.hive.'#text') {
        "HKEY_LOCAL_MACHINE" { "HKLM:" }
        "HKEY_CURRENT_USER"  { "HKCU:" }
        "HKEY_CLASSES_ROOT"  { "HKCR:" }
        default              { "HKLM:" }
    }
    $key  = ($obj.key.'#text') -replace '\\','\'
    $name = $obj.name.'#text'
    if (-not $name) { $name = $obj.name }

    $psPath  = "$hive\$key"
    $varName = '$regVal_' + ([System.IO.Path]::GetRandomFileName() -replace '\W','')

    $lines = @()
    $lines += "$varName = `$null"
    $lines += "try { $varName = (Get-ItemProperty -LiteralPath '$psPath' -ErrorAction Stop).'$name' } catch {}"

    # Construire la condition depuis les states
    $stateRef = $test.state.state_ref
    if ($stateRef) {
        $state = Get-StateById $oval $stateRef
        if ($state) {
            $stateNode = $state.ChildNodes | Where-Object { $_.NodeType -eq "Element" } | Select-Object -First 1
            if ($stateNode) {
                $op    = $stateNode.operation
                $dtype = $stateNode.datatype
                $sval  = $stateNode.'#text'

                $cond = switch ($op) {
                    "equals"              { "$varName -eq '$sval'" }
                    "not equal"           { "$varName -ne '$sval'" }
                    "greater than"        { if ($dtype -eq "version") { "(([version]($varName -replace '[^0-9\.]','')) -gt [version]'$sval')" } else { "$varName -gt $sval" } }
                    "less than"           { if ($dtype -eq "version") { "(([version]($varName -replace '[^0-9\.]','')) -lt [version]'$sval')" } else { "$varName -lt $sval" } }
                    "greater than or equal" { if ($dtype -eq "version") { "(([version]($varName -replace '[^0-9\.]','')) -ge [version]'$sval')" } else { "$varName -ge $sval" } }
                    "less than or equal"  { if ($dtype -eq "version") { "(([version]($varName -replace '[^0-9\.]','')) -le [version]'$sval')" } else { "$varName -le $sval" } }
                    "pattern match"       { "$varName -match '$sval'" }
                    default               { "$varName -eq '$sval'" }
                }
                $lines += "# OVAL patch check: $($stateNode.LocalName) $op '$sval'"
                $lines += "`$checks += [bool]($cond)"
            }
        }
    } else {
        # Pas de state = juste vérifier que la clé/valeur existe
        $lines += "`$checks += (`$null -ne $varName)"
    }

    return $lines -join "`n"
}

function Convert-FileTest($test, [xml]$oval) {
    $obj = Get-ObjectById $oval $test.object.object_ref
    if (-not $obj) { return $null }

    $path     = $obj.path.'#text'
    $filename = $obj.filename.'#text'
    if (-not $path -or -not $filename) { return $null }

    $fullPath = Join-Path $path $filename
    $varName  = '$fileVer_' + ([System.IO.Path]::GetRandomFileName() -replace '\W','')

    $lines = @()
    $lines += "$varName = `$null"
    $lines += "if (Test-Path '$fullPath') { $varName = (Get-Item '$fullPath').VersionInfo.FileVersion }"

    $stateRef = $test.state.state_ref
    if ($stateRef) {
        $state = Get-StateById $oval $stateRef
        if ($state) {
            $vNode = $state.file_version
            if ($vNode) {
                $op   = $vNode.operation
                $sval = $vNode.'#text'
                $cond = switch ($op) {
                    "less than"           { "(`$null -ne $varName) -and (([version]($varName -replace '[^0-9\.]','')) -lt [version]'$sval')" }
                    "greater than or equal" { "(`$null -ne $varName) -and (([version]($varName -replace '[^0-9\.]','')) -ge [version]'$sval')" }
                    "equals"              { "$varName -eq '$sval'" }
                    default               { "$varName -eq '$sval'" }
                }
                $lines += "# Fichier : $fullPath - version $op $sval"
                $lines += "`$checks += [bool]($cond)"
            }
        }
    } else {
        $lines += "`$checks += (-not (Test-Path '$fullPath'))"
    }

    return $lines -join "`n"
}

function Build-PSFromOVAL([xml]$oval, [string]$cveId, [string]$platform) {
    $def = Get-OVALDefinitionForCVE $oval $cveId
    if (-not $def) { return $null }

    # Collecter tous les test_refs depuis les critères (récursivement)
    $testRefs = @()
    function Collect-TestRefs($criteria) {
        foreach ($c in @($criteria.criterion)) {
            if ($c.test_ref) { $testRefs += $c.test_ref }
        }
        foreach ($sub in @($criteria.criteria)) {
            if ($sub) { Collect-TestRefs $sub }
        }
    }
    Collect-TestRefs $def.criteria
    if ($testRefs.Count -eq 0) { return $null }

    $checks = @()
    foreach ($ref in $testRefs) {
        foreach ($n in $oval.oval_definitions.tests.ChildNodes) {
            if ($n.id -ne $ref) { continue }
            $localName = $n.LocalName
            $block = switch -Wildcard ($localName) {
                "*registry_test" { Convert-RegistryTest $n $oval }
                "*file_test"     { Convert-FileTest     $n $oval }
                default          { $null }
            }
            if ($block) { $checks += $block }
        }
    }

    if ($checks.Count -eq 0) { return $null }

    $title    = $def.metadata.title
    $descNode = $def.metadata.description
    $desc     = if ($descNode) { $descNode.'#text' } else { "" }

    $script = @"
# Détection OVAL : $cveId
# $title
# Source : CIS OVAL Repository
# Plateforme : $platform
#
# NOTE : `$checks contient les conditions de VULNÉRABILITÉ
# (true = système vulnérable selon cette condition OVAL)

`$checks = @()

$($checks -join "`n`n")

# Résultat
if (`$checks.Count -eq 0) {
    Write-Host "ℹ️  Impossible de déterminer - aucune condition OVAL évaluable" -ForegroundColor Yellow
} elseif (`$checks -contains `$true) {
    Write-Host "⚠️  VULNÉRABLE - $cveId : condition(s) de vulnérabilité vérifiée(s)" -ForegroundColor Red
} else {
    Write-Host "✅ PROTÉGÉ   - $cveId : aucune condition de vulnérabilité active" -ForegroundColor Green
}
"@
    return $script
}

# -- Recherche OVAL sur GitHub -------------------------------------------------

function Find-OVALForCVE([string]$cveId) {
    Write-Host "  OVAL ← $cveId ... " -NoNewline

    # Recherche dans le repo CIS OVAL via GitHub Code Search
    $q   = [Uri]::EscapeDataString("$cveId repo:CISecurity/OVALRepo extension:xml")
    $res = Invoke-GitHub "https://api.github.com/search/code?q=$q&per_page=5"
    if (-not $res -or $res.total_count -eq 0) {
        Write-Host "non trouvé" -ForegroundColor DarkGray
        return $null
    }

    # Prendre le premier résultat pertinent (fichier XML de définition)
    foreach ($item in $res.items) {
        $rawUrl = $item.html_url -replace 'github\.com','raw.githubusercontent.com' `
                                  -replace '/blob/',  '/'
        $xml = Get-OVALXml $rawUrl
        if (-not $xml) { continue }

        $platform = $item.path -replace '.*/','' -replace '\.xml$',''
        $psScript = Build-PSFromOVAL $xml $cveId $platform
        if ($psScript) {
            Write-Host "✅ ($platform)" -ForegroundColor Green
            return @{ script = $psScript; source = "oval-cis"; file = $item.path }
        }
    }

    Write-Host "parsé mais vide" -ForegroundColor DarkYellow
    return $null
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

# Charger le cache existant
$cveDetection = [ordered]@{}
if ($data.PSObject.Properties["cveDetection"] -and $null -ne $data.cveDetection) {
    $data.cveDetection.PSObject.Properties | ForEach-Object {
        $cveDetection[$_.Name] = $_.Value
    }
}

$total   = $data.vulns.Count
$covered = 0
$failed  = 0
$skipped = 0

$cached    = $cveDetection.Count
$toProcess = @($data.vulns | Where-Object { $Force -or $null -eq $cveDetection[$_.cveId] })

Write-Host ""
Write-Host "Génération des scripts de détection OVAL pour $total CVEs ($Month)" -ForegroundColor Cyan
Write-Host "Source : CIS OVAL Repository (GitHub)" -ForegroundColor Gray
Write-Host "Cache : $cached / $total CVEs déjà traités — $($toProcess.Count) à traiter$(if ($Force) {' (-Force actif)'})" -ForegroundColor DarkGray
if (-not $GithubToken) {
    Write-Host "⚠️  Pas de -GithubToken : limite 60 req/h. Recommandé pour $($toProcess.Count) CVEs." -ForegroundColor Yellow
}
Write-Host ""

$i = 0

foreach ($vuln in $toProcess) {
    $i++
    $cveId = $vuln.cveId
    Write-Host "[$i/$($toProcess.Count)] " -NoNewline

    $result = Find-OVALForCVE $cveId

    if ($result) {
        $cveDetection[$cveId] = [ordered]@{
            source = $result.source
            file   = $result.file
            script = $result.script
        }
        $covered++
    } else {
        # Fallback : script KB-based
        $kbs = @($vuln.kbs)
        if ($kbs.Count -gt 0) {
            $kbArray  = ($kbs | ForEach-Object { "`"$_`"" }) -join ", "
            $fallback = @"
# Détection fallback (OVAL non disponible) : $cveId
# Vérifie la présence des correctifs via Windows Update
`$kbCorrecifs = @($kbArray)
`$Session  = New-Object -ComObject Microsoft.Update.Session
`$Searcher = `$Session.CreateUpdateSearcher()
`$Updates  = `$Searcher.Search("IsInstalled=1").Updates
`$installes = `$Updates | ForEach-Object { `$_.KBArticleIDs } | ForEach-Object { "KB`$_" }
`$manquants = `$kbCorrecifs | Where-Object { `$installes -notcontains `$_ }
if (`$manquants.Count -eq 0) {
    Write-Host "✅ PROTÉGÉ   - $cveId : correctifs présents" -ForegroundColor Green
} else {
    Write-Host "⚠️  VULNÉRABLE - $cveId : KBs manquants : `$(`$manquants -join ', ')" -ForegroundColor Red
}
"@
            $cveDetection[$cveId] = [ordered]@{
                source = "kb-fallback"
                file   = ""
                script = $fallback
            }
        } else {
            # Aucune source disponible — mise en cache pour éviter re-requête
            $cveDetection[$cveId] = [ordered]@{
                source = "not-found"
                file   = ""
                script = ""
            }
        }
        $failed++
    }

    # Sauvegarder après chaque CVE pour préserver la progression en cas d'interruption
    $data | Add-Member -NotePropertyName cveDetection -NotePropertyValue $cveDetection -Force
    Save-JsonFile $jsonPath $data

    # Search API : 30 req/min même avec token → pause fixe 2,1 s
    Start-Sleep -Milliseconds 2100
}

$data | Add-Member -NotePropertyName cveDetection -NotePropertyValue $cveDetection -Force
Save-JsonFile $jsonPath $data

Write-Host ""
Write-Host "✅ Terminé : $covered OVAL, $failed fallback/introuvable ($cached en cache, $total total)" -ForegroundColor Green
Write-Host "   Fichier mis à jour : $jsonPath"
Write-Host ""
Write-Host "Prochaine étape :" -ForegroundColor Yellow
Write-Host "  git add data\$Month.json && git commit -m `"feat: OVAL detection scripts $Month`" && git push"
