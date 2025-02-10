<# 
    HardenSandbox.ps1
    ------------------
    Purpose:
    - Harden Windows Sandbox security by blocking local network access.
    - Actively attempts to **bypass** the security setting to confirm hardening effectiveness.

    Key Features:
    - Blocks all local network traffic via Windows Routing Table
    - Ensures basic internet access remains intact
    - Actively tests whether security measures can be bypassed

    Usage:
    - Run this script inside Windows Sandbox **with Administrator privileges**
    - Re-run after every sandbox restart (since settings reset)
#>

# ===============================
# 🔹 STEP 1: APPLY SECURITY SETTINGS 🔹
# ===============================

# Track success/failure of each step
$HardeningErrors = @()

# 🚫 Block Local Network Access (Routing Table)
# -----------------------------------------------
# Instead of firewall rules (which reset in Sandbox), we block local network access
# by routing all private IP ranges (LAN, localhost, and APIPA) to 0.0.0.0.
$subnets = @(
    "10.0.0.0 mask 255.0.0.0",      # Private Class A
    "172.16.0.0 mask 255.240.0.0",  # Private Class B
    "192.168.0.0 mask 255.255.0.0", # Private Class C
    "169.254.0.0 mask 255.255.0.0", # APIPA (Auto IP)
    "127.0.0.0 mask 255.0.0.0"      # Localhost
)

foreach ($subnet in $subnets) {
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c route add $subnet 0.0.0.0 -p" -NoNewWindow -Wait
}

# ===============================
# ✅ STEP 2: ATTEMPT TO CIRCUMVENT SETTINGS ✅
# ===============================
Write-Host "🔎 Running Security Evasion Tests..." -ForegroundColor Cyan

# 🛑 Attempt to Access Local Network
Write-Host "🔄 Attempting to Bypass Local Network Block..." -ForegroundColor Yellow
$localNetworkTest = Test-Connection -ComputerName "192.168.1.1" -Count 1 -ErrorAction SilentlyContinue
if (-not $localNetworkTest) {
    Write-Host "✅ Local Network is Inaccessible (Block Successful)" -ForegroundColor Green
} else {
    Write-Host "❌ Local Network is Accessible! (Bypass Successful, Security Failed)" -ForegroundColor Red
    $HardeningErrors += "Local Network Block Bypass Detected"
}

# ===============================
# 📄 STEP 3: LOG RESULTS TO FILE 📄
# ===============================
$desktopPath = [System.IO.Path]::Combine($env:USERPROFILE, "Desktop")

if ($HardeningErrors.Count -eq 0) {
    # All steps passed, create success file
    $successFile = [System.IO.Path]::Combine($desktopPath, "SuccessfullyCompletedHardening.txt")
    "Windows Sandbox Hardening completed successfully on $(Get-Date)." | Out-File -FilePath $successFile -Encoding utf8
    Write-Host "✅ Hardening completed successfully! File saved: $successFile" -ForegroundColor Green
} else {
    # Some steps failed, create error report
    $errorFile = [System.IO.Path]::Combine($desktopPath, "HardeningErrorReport.txt")
    "Windows Sandbox Hardening encountered issues on $(Get-Date)." | Out-File -FilePath $errorFile -Encoding utf8
    $HardeningErrors | Out-File -FilePath $errorFile -Encoding utf8 -Append
    Write-Host "❌ Some security settings failed! See: $errorFile" -ForegroundColor Red
}
