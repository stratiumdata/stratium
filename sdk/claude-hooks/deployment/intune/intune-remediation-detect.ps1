# ============================================================
# Intune Remediation: Detect Stratium Claude Code Hooks
# ============================================================
# Detection script — exits 0 (compliant) or 1 (non-compliant)
# Runs as the logged-in user (not SYSTEM)
#
# Pair with: intune-remediation-remediate.ps1
# ============================================================

$RequiredVersion = "1.0.0"
$StratiumGateway = $env:STRATIUM_GATEWAY

# Check if stratium-hooks is installed
try {
    $installedVersion = & stratium-hooks version 2>$null | Select-String -Pattern '\d+\.\d+\.\d+' | ForEach-Object { $_.Matches[0].Value }
    if ($installedVersion -eq $RequiredVersion) {
        # Check configuration exists
        $configPath = Join-Path $env:USERPROFILE ".claude\stratium.json"
        if (Test-Path $configPath) {
            Write-Host "Compliant: stratium-hooks $installedVersion installed and configured"
            exit 0
        } else {
            Write-Host "Non-compliant: stratium-hooks installed but not configured"
            exit 1
        }
    } else {
        Write-Host "Non-compliant: stratium-hooks version $installedVersion (required $RequiredVersion)"
        exit 1
    }
} catch {
    Write-Host "Non-compliant: stratium-hooks not found"
    exit 1
}
