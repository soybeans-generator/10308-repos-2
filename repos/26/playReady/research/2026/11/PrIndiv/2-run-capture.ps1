# ============ run-capture.ps1 ============
# Corrected runner: launches the helper, resolves the AppContainer temp dir
# DYNAMICALLY, attaches Frida (optional), fires the go signal in the RIGHT
# place, waits for completion, collects artifacts.
#
# Usage:
#   .\run-capture.ps1                                    # no Frida hook
#   .\run-capture.ps1 -HookScript D:\Desktop\hook-winhttp.js
#   .\run-capture.ps1 -HookScript D:\Desktop\hook-kdf.js -HookWaitSeconds 8

param(
    [string]$HookScript = "",          # empty = run without Frida
    [int]$HookWaitSeconds = 5
)

$ErrorActionPreference = "Continue"

# ---- 1. Cleanup leftovers ----
Get-Process PrIndiv -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500
Write-Host "[+] Cleaned up old PrIndiv processes"

# ---- 2. Resolve the package + its AppContainer temp dir DYNAMICALLY ----
$pkg = Get-AppxPackage PrIndivHelper
if (-not $pkg) { throw "PrIndivHelper not installed. Run setup-prindiv.ps1 first." }
$pkgTemp = Join-Path $env:LOCALAPPDATA "Packages\$($pkg.PackageFamilyName)\AC\Temp"
if (-not (Test-Path $pkgTemp)) { New-Item -ItemType Directory -Path $pkgTemp -Force | Out-Null }

Write-Host ("[+] PFN:     {0}" -f $pkg.PackageFamilyName)
Write-Host ("[+] PkgTemp: {0}   <- go.txt goes HERE, not %TEMP%" -f $pkgTemp)

# Clear stale go-file and old captures
Remove-Item "$pkgTemp\go.txt" -ErrorAction SilentlyContinue
Remove-Item "$pkgTemp\pr-req-*.bin", "$pkgTemp\pr-response.bin", `
            "$pkgTemp\pr-req-writechunks.bin" -ErrorAction SilentlyContinue

# ---- 3. Launch the helper (it sits waiting for go.txt) ----
C:\Windows\explorer.exe "shell:AppsFolder\$($pkg.PackageFamilyName)!App"

# ---- 4. Wait for the process to appear, grab PID ----
$proc = $null
for ($i = 0; $i -lt 30; $i++) {
    $proc = Get-Process PrIndiv -ErrorAction SilentlyContinue
    if ($proc) { break }
    Start-Sleep -Milliseconds 500
}
if (-not $proc) { throw "PrIndiv did not start within 15s" }
Write-Host ("[+] PrIndiv running, PID: {0}" -f $proc.Id)

# ---- 5. Wait for the helper to report its WAITING state ----
$logPath = Join-Path $pkgTemp "pr-indiv-log.txt"
$ready = $false
for ($i = 0; $i -lt 60; $i++) {
    if ((Test-Path $logPath) -and
        ((Get-Content $logPath -Raw -ErrorAction SilentlyContinue) -match 'WAITING for go signal')) {
        $ready = $true; break
    }
    Start-Sleep -Milliseconds 500
}
if ($ready) { Write-Host "[+] Helper confirmed WAITING for go signal" }
else { Write-Host "[!] Helper did not report waiting within 30s (check its window)" }

# ---- 6. Attach Frida (if a hook script was given) ----
if ($HookScript -and (Test-Path $HookScript)) {
    Start-Process powershell.exe -ArgumentList @('-NoExit', '-Command',
        ("frida -p {0} -l '{1}'" -f $proc.Id, $HookScript))
    Write-Host ("[+] Frida window launched. Waiting {0}s for hooks to install..." -f $HookWaitSeconds)
    Start-Sleep -Seconds $HookWaitSeconds
} elseif ($HookScript) {
    Write-Host "[!] Hook script not found: $HookScript - running WITHOUT Frida"
} else {
    Write-Host "[*] No hook script specified - running without Frida"
}

# ---- 7. Fire the go signal IN THE CORRECT DIRECTORY ----
New-Item -Path (Join-Path $pkgTemp "go.txt") -ItemType File -Force | Out-Null
Write-Host "[+] Go signal fired at: $pkgTemp\go.txt"
Write-Host "[*] Individualization running..."

# ---- 8. Wait for the helper to finish ----
$finished = $false
for ($i = 0; $i -lt 120; $i++) {
    if ((Test-Path $logPath) -and
        ((Get-Content $logPath -Raw -ErrorAction SilentlyContinue) -match 'Done\.')) {
        $finished = $true; break
    }
    Start-Sleep -Seconds 2
}
if ($finished) { Write-Host "[+] Helper finished" }
else { Write-Host "[!] Helper did not report completion within 4 min (check its window)" }

# ---- 9. Copy artifacts into a timestamped folder ----
$outDir = "D:\Desktop\capture-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
Copy-Item "$pkgTemp\pr-req-*.bin", "$pkgTemp\pr-response.bin", `
           "$pkgTemp\pr-req-writechunks.bin", $logPath `
           -Destination $outDir -ErrorAction SilentlyContinue
Write-Host ("[+] Artifacts -> {0}" -f $outDir)

# ---- 10. Show the helper log ----
Write-Host "`n===== pr-indiv-log.txt ====="
Get-Content $logPath -ErrorAction SilentlyContinue
Write-Host "==========================="
Write-Host "[*] If Frida was attached, check ITS window for hook output."
