# ===============================
# 🔹 STEP 1: DISABLE SECURITY-RISK FEATURES 🔹
# ===============================

# Track success/failure of each step
$HardeningErrors = @()

# 🚫 Disable Commonly Abused Features by Malware
$featuresToDisable = @(
    # 🔹 SYSTEM SECURITY 🔹
    @{ Name = "Windows Script Host (WSH)"; Key = "HKLM:\Software\Microsoft\Windows Script Host\Settings"; ValueName = "Enabled"; Value = 0; Type = "DWORD" }
    @{ Name = "PowerShell Execution"; Key = "HKLM:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell"; ValueName = "ExecutionPolicy"; Value = "Restricted"; Type = "String" }
    @{ Name = "Remote Desktop (RDP)"; Key = "HKLM:\System\CurrentControlSet\Control\Terminal Server"; ValueName = "fDenyTSConnections"; Value = 1; Type = "DWORD" }
    @{ Name = "AutoRun & AutoPlay"; Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; ValueName = "NoDriveTypeAutoRun"; Value = 255; Type = "DWORD" }

    # 🔹 REMOTE ACCESS 🔹
    @{ Name = "SMB File Sharing"; Key = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; ValueName = "SMB1"; Value = 0; Type = "DWORD" }
    @{ Name = "Windows Remote Shell"; Key = "HKLM:\SYSTEM\CurrentControlSet\Services\WinRM"; ValueName = "Start"; Value = 4; Type = "DWORD" }
    @{ Name = "Remote Assistance"; Key = "HKLM:\System\CurrentControlSet\Control\Remote Assistance"; ValueName = "fAllowToGetHelp"; Value = 0; Type = "DWORD" }

    # 🔹 NETWORK & COMMUNICATION 🔹
    @{ Name = "NetBIOS over TCP/IP"; Key = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"; ValueName = "EnableNetbiosOverTcpip"; Value = 2; Type = "DWORD" }
    @{ Name = "IPv6 Teredo Tunneling"; Key = "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters"; ValueName = "DisabledComponents"; Value = 255; Type = "DWORD" }
    @{ Name = "ICMP (Ping)"; Key = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; ValueName = "DisableICMP"; Value = 1; Type = "DWORD" }

    # 🔹 UNNEEDED SERVICES 🔹
    @{ Name = "Windows Installer"; Key = "HKLM:\SYSTEM\CurrentControlSet\Services\MSIServer"; ValueName = "Start"; Value = 4; Type = "DWORD" }
    @{ Name = "Background Intelligent Transfer Service (BITS)"; Key = "HKLM:\SYSTEM\CurrentControlSet\Services\BITS"; ValueName = "Start"; Value = 4; Type = "DWORD" }
    @{ Name = "Task Scheduler"; Key = "HKLM:\SYSTEM\CurrentControlSet\Services\Schedule"; ValueName = "Start"; Value = 4; Type = "DWORD" }
    @{ Name = "WebClient (WebDAV)"; Key = "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient"; ValueName = "Start"; Value = 4; Type = "DWORD" }

    # 🔹 APPLICATION BLOCKING 🔹
    @{ Name = "Internet Explorer"; Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; ValueName = "NoInternetOpenWith"; Value = 1; Type = "DWORD" }
    @{ Name = "Windows Media Sharing"; Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; ValueName = "NoMediaSharing"; Value = 1; Type = "DWORD" }
    @{ Name = "Game Bar"; Key = "HKCU:\Software\Microsoft\GameBar"; ValueName = "AllowAutoGameMode"; Value = 0; Type = "DWORD" }
    @{ Name = "Xbox Game DVR"; Key = "HKCU:\System\GameConfigStore"; ValueName = "GameDVR_Enabled"; Value = 0; Type = "DWORD" }
    @{ Name = "Windows Search Indexing"; Key = "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch"; ValueName = "Start"; Value = 4; Type = "DWORD" }
    @{ Name = "OneDrive Integration"; Key = "HKLM:\Software\Policies\Microsoft\Windows\OneDrive"; ValueName = "DisableFileSyncNGSC"; Value = 1; Type = "DWORD" }
    @{ Name = "Windows Error Reporting"; Key = "HKLM:\Software\Microsoft\Windows\Windows Error Reporting"; ValueName = "Disabled"; Value = 1; Type = "DWORD" }
    @{ Name = "Camera Access"; Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"; ValueName = "Value"; Value = "Deny"; Type = "String" }
    @{ Name = "Microphone Access"; Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"; ValueName = "Value"; Value = "Deny"; Type = "String" }
    @{ Name = "Windows Store"; Key = "HKLM:\Software\Policies\Microsoft\WindowsStore"; ValueName = "RemoveWindowsStore"; Value = 1; Type = "DWORD" }
    @{ Name = "Speech Recognition"; Key = "HKLM:\Software\Policies\Microsoft\Speech"; ValueName = "AllowSpeechServices"; Value = 0; Type = "DWORD" }
    @{ Name = "Wi-Fi Sense"; Key = "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config"; ValueName = "AutoConnectAllowedOEM"; Value = 0; Type = "DWORD" }
)

foreach ($feature in $featuresToDisable) {
    # Check if the key exists
    if (-not (Test-Path $feature.Key)) {
        New-Item -Path $feature.Key -Force | Out-Null
    }

    # Apply correct type (String vs. DWORD)
    if ($feature.Type -eq "String") {
        New-ItemProperty -Path $feature.Key -Name $feature.ValueName -Value $feature.Value -PropertyType String -Force | Out-Null
    } else {
        New-ItemProperty -Path $feature.Key -Name $feature.ValueName -Value $feature.Value -PropertyType DWord -Force | Out-Null
    }
}

# ===============================
# ✅ STEP 2: BLOCK INTERNAL NETWORK ACCESS ✅
# ===============================

$subnets = @(
    "10.0.0.0 mask 255.0.0.0",      
    "172.16.0.0 mask 255.240.0.0",  
    "192.168.0.0 mask 255.255.0.0"      
)

foreach ($subnet in $subnets) {
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c route add $subnet 0.0.0.0 -p" -NoNewWindow -Wait
}

# ===============================
# ✅ STEP 3: VERIFY SETTINGS ✅
# ===============================

# Test connectivity to each blocked subnet
$testAddresses = @(
    "10.0.0.1",
    "172.16.0.1",
    "192.168.1.1"
)

foreach ($testIP in $testAddresses) {
    $testResult = Test-Connection -ComputerName $testIP -Count 1 -ErrorAction SilentlyContinue
    if ($testResult) {
        $HardeningErrors += "Local Network Block Bypass Detected for $testIP"
    }
}

# Verify feature disabling
foreach ($feature in $featuresToDisable) {
    $currentValue = (Get-ItemProperty -Path $feature.Key -Name $feature.ValueName -ErrorAction SilentlyContinue).$($feature.ValueName)
    
    if ($feature.Type -eq "String") {
        if ($currentValue -ne $feature.Value) {
            $HardeningErrors += "Feature still enabled: $($feature.Name)"
        }
    } elseif ($currentValue -ne [int]$feature.Value) {
        $HardeningErrors += "Feature still enabled: $($feature.Name)"
    }
}

# ===============================
# 📄 STEP 4: LOG RESULTS TO FILE 📄
# ===============================

$desktopPath = [System.IO.Path]::Combine($env:USERPROFILE, "Desktop")

if ($HardeningErrors.Count -eq 0) {
    $successFile = [System.IO.Path]::Combine($desktopPath, "SuccessfullyCompletedHardening.txt")
    "Windows Sandbox Hardening completed successfully on $(Get-Date)." | Out-File -FilePath $successFile -Encoding utf8
} else {
    $errorFile = [System.IO.Path]::Combine($desktopPath, "HardeningErrorReport.txt")
    "Windows Sandbox Hardening encountered issues on $(Get-Date)." | Out-File -FilePath $errorFile -Encoding utf8
    $HardeningErrors | Out-File -FilePath $errorFile -Encoding utf8 -Append
}
