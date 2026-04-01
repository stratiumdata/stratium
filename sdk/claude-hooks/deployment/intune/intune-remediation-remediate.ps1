# ============================================================
# Intune Remediation: Install Stratium Claude Code Hooks
# ============================================================
# Remediation script — runs when detection exits 1 (non-compliant)
# Runs as the logged-in user (not SYSTEM)
#
# Configure via Intune environment variables or update defaults below.
# ============================================================

param(
    [string]$StratiumGateway  = $env:STRATIUM_GATEWAY,
    [string]$StratiumPap      = $env:STRATIUM_PAP,
    [string]$StratiumKeycloak = $env:STRATIUM_KEYCLOAK,
    [string]$StratiumRealm    = $(if ($env:STRATIUM_REALM) { $env:STRATIUM_REALM } else { "master" }),
    [string]$StratiumCacert   = $env:STRATIUM_CACERT,
    [string]$NpmRegistry      = $env:NPM_REGISTRY,
    [string]$FailMode         = $(if ($env:STRATIUM_FAIL_MODE) { $env:STRATIUM_FAIL_MODE } else { "fail_closed" })
)

$RequiredVersion = "1.0.0"
$LogFile = "$env:TEMP\stratium-hooks-install.log"

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
    $line = "[$ts] $Message"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -Force
}

Write-Log "Starting Stratium hooks installation"

# Validate required parameter
if (-not $StratiumGateway) {
    Write-Log "ERROR: STRATIUM_GATEWAY environment variable is required"
    exit 1
}

# Check Node.js
try {
    $nodeVersion = & node --version 2>$null
    $nodeMajor = [int]($nodeVersion -replace 'v(\d+).*', '$1')
    if ($nodeMajor -lt 18) {
        Write-Log "ERROR: Node.js 18+ required (found $nodeVersion)"
        exit 1
    }
    Write-Log "Node.js $nodeVersion found"
} catch {
    Write-Log "ERROR: Node.js not found. Install Node.js 18+ before running this script."
    exit 1
}

# Install npm package
Write-Log "Installing @stratium/claude-hooks@$RequiredVersion..."
$installArgs = @("install", "-g", "--quiet", "--no-fund", "--no-audit", "@stratium/claude-hooks@$RequiredVersion")
if ($NpmRegistry) {
    $installArgs += @("--registry", $NpmRegistry)
}

try {
    & npm @installArgs 2>&1 | Add-Content -Path $LogFile
    Write-Log "Package installed"
} catch {
    Write-Log "ERROR: npm install failed: $_"
    exit 1
}

# Configure
Write-Log "Configuring machine settings..."
$configArgs = @("configure", "--gateway", $StratiumGateway, "--silent")
if ($StratiumPap)      { $configArgs += @("--pap-url",  $StratiumPap) }
if ($StratiumKeycloak) { $configArgs += @("--keycloak", $StratiumKeycloak) }
if ($StratiumRealm -ne "master") { $configArgs += @("--realm", $StratiumRealm) }
if ($StratiumCacert)   { $configArgs += @("--cacert",   $StratiumCacert) }
if ($FailMode -eq "fail_open") { $configArgs += "--fail-open" } else { $configArgs += "--fail-closed" }

try {
    & stratium-hooks @configArgs 2>&1 | Add-Content -Path $LogFile
    Write-Log "Configuration complete"
} catch {
    Write-Log "ERROR: Configuration failed: $_"
    exit 1
}

Write-Log "Stratium Claude Code hooks installed and configured successfully"
exit 0
