# Add a Category property to SecurityFeature class to control sequencing
class SecurityFeature {
    [string]$Name
    [string]$RegistryKey
    [string]$ValueName
    [object]$Value
    [string]$Type
    [string]$Category
    [int]$SequenceOrder

    SecurityFeature([string]$name, [string]$key, [string]$valueName, [object]$value, [string]$type, [string]$category, [int]$sequenceOrder) {
        $this.Name = $name
        $this.RegistryKey = $key
        $this.ValueName = $valueName
        $this.Value = $value
        $this.Type = $type
        $this.Category = $category
        $this.SequenceOrder = $sequenceOrder
    }
}

class NetworkBlock {
    [string]$Subnet
    [string]$Mask
    [string]$TestIP
    [string]$Description

    NetworkBlock([string]$subnet, [string]$mask, [string]$testIP, [string]$description) {
        $this.Subnet = $subnet
        $this.Mask = $mask
        $this.TestIP = $testIP
        $this.Description = $description
    }
}

class HardeningManager {
    [System.Collections.Generic.List[SecurityFeature]]$Features
    [System.Collections.Generic.List[NetworkBlock]]$NetworkBlocks
    [System.Collections.Generic.List[string]]$Errors
    [string]$LogPath
    [System.Collections.Generic.HashSet[string]]$AllowedProcesses

    HardeningManager() {
        $this.Features = [System.Collections.Generic.List[SecurityFeature]]::new()
        $this.NetworkBlocks = [System.Collections.Generic.List[NetworkBlock]]::new()
        $this.Errors = [System.Collections.Generic.List[string]]::new()
        $this.LogPath = [System.IO.Path]::Combine($env:USERPROFILE, "Desktop")
        $this.AllowedProcesses = [System.Collections.Generic.HashSet[string]]::new()
        $this.InitializeFeatures()
        $this.InitializeNetworkBlocks()
        $this.InitializeAllowedProcesses()
    }

    [void]AddFeature([string]$name, [string]$key, [string]$valueName, [object]$value, [string]$type, [string]$category, [int]$sequenceOrder) {
        $feature = [SecurityFeature]::new($name, $key, $valueName, $value, $type, $category, $sequenceOrder)
        $this.Features.Add($feature)
    }

    [void]InitializeFeatures() {
        # Early Stage Hardening (Sequence 1)
        $this.AddFeature("Network Discovery", "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkDiscovery", "AllowNetworkDiscovery", 0, "DWORD", "Network", 1)
        $this.AddFeature("NetBIOS over TCP/IP", "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters", "EnableNetbiosOverTcpip", 2, "DWORD", "Network", 1)
        $this.AddFeature("IPv6", "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters", "DisabledComponents", 255, "DWORD", "Network", 1)

        # Mid Stage Hardening (Sequence 2)
        $this.AddFeature("Windows Script Host", "HKLM:\Software\Microsoft\Windows Script Host\Settings", "Enabled", 0, "DWORD", "System", 2)
        $this.AddFeature("PowerShell Execution", "HKLM:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "ExecutionPolicy", "Restricted", "String", "System", 2)
        $this.AddFeature("Remote Desktop", "HKLM:\System\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", 1, "DWORD", "System", 2)

        # Browser Hardening (Sequence 3)
        $this.AddFeature("Edge SmartScreen", "HKLM:\SOFTWARE\Policies\Microsoft\Edge", "SmartScreenEnabled", 1, "DWORD", "Browser", 3)
        $this.AddFeature("Edge JavaScript JIT", "HKLM:\SOFTWARE\Policies\Microsoft\Edge", "JavaScript JIT", 0, "DWORD", "Browser", 3)
        $this.AddFeature("Edge Downloads", "HKLM:\SOFTWARE\Policies\Microsoft\Edge", "DownloadRestrictions", 3, "DWORD", "Browser", 3)
        $this.AddFeature("Edge Extensions", "HKLM:\SOFTWARE\Policies\Microsoft\Edge", "ExtensionInstallBlocklist", "*", "String", "Browser", 3)

        # Final Stage Hardening (Sequence 4)
        $this.AddFeature("Disable Registry Tools", "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableRegistryTools", 1, "DWORD", "System", 4)
        $this.AddFeature("Disable Task Manager", "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr", 1, "DWORD", "System", 4)
        
        # Very Last Features (Sequence 5)
        $this.AddFeature("Disable CMD", "HKCU:\Software\Policies\Microsoft\Windows\System", "DisableCMD", 1, "DWORD", "System", 5)
    }

    [void]InitializeNetworkBlocks() {
        # Block common malicious network ranges
        $this.NetworkBlocks.Add([NetworkBlock]::new("10.0.0.0", "255.0.0.0", "10.0.0.1", "Private Network - RFC1918"))
        $this.NetworkBlocks.Add([NetworkBlock]::new("172.16.0.0", "255.240.0.0", "172.16.0.1", "Private Network - RFC1918"))
        $this.NetworkBlocks.Add([NetworkBlock]::new("192.168.0.0", "255.255.0.0", "192.168.0.1", "Private Network - RFC1918"))
        $this.NetworkBlocks.Add([NetworkBlock]::new("169.254.0.0", "255.255.0.0", "169.254.0.1", "Link Local - RFC3927"))
    }

    [void]InitializeAllowedProcesses() {
        # Add essential Windows processes
        $this.AllowedProcesses.Add("explorer.exe")
        $this.AllowedProcesses.Add("svchost.exe")
        $this.AllowedProcesses.Add("lsass.exe")
        $this.AllowedProcesses.Add("services.exe")
        $this.AllowedProcesses.Add("winlogon.exe")
        $this.AllowedProcesses.Add("msedge.exe")
        $this.AllowedProcesses.Add("spoolsv.exe")
        $this.AllowedProcesses.Add("wininit.exe")
        $this.AllowedProcesses.Add("csrss.exe")
        $this.AllowedProcesses.Add("smss.exe")
    }

    # Helper method to convert subnet mask to CIDR notation
    hidden [int]ConvertMaskToCIDR([string]$subnetMask) {
        $octets = $subnetMask.Split('.')
        $binary = $octets | ForEach-Object { [Convert]::ToString([byte]$_, 2).PadLeft(8, '0') }
        return ($binary -join '').TrimEnd('0').Length
    }

    [void]ApplyNetworkBlocks() {
        foreach ($block in $this.NetworkBlocks) {
            try {
                # Remove any existing routes for this subnet
                $existingRoute = Get-NetRoute -DestinationPrefix "$($block.Subnet)/$($this.ConvertMaskToCIDR($block.Mask))" -ErrorAction SilentlyContinue
                if ($existingRoute) {
                    Remove-NetRoute -DestinationPrefix "$($block.Subnet)/$($this.ConvertMaskToCIDR($block.Mask))" -Confirm:$false
                }

                # Get the interface index of the default route
                $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Where-Object { $_.NextHop -ne "0.0.0.0" } | Select-Object -First 1
                if (-not $defaultRoute) {
                    throw "No default route found"
                }

                # Add black hole route using the same interface as the default route
                New-NetRoute -DestinationPrefix "$($block.Subnet)/$($this.ConvertMaskToCIDR($block.Mask))" `
                    -InterfaceIndex $defaultRoute.InterfaceIndex `
                    -NextHop "0.0.0.0" `
                    -RouteMetric 1 `
                    -PolicyStore ActiveStore `
                    -ErrorAction Stop | Out-Null

                # Test connectivity
                $result = Test-Connection -ComputerName $block.TestIP -Count 1 -Quiet
                if ($result) {
                    $this.Errors.Add("Warning: Still able to reach $($block.TestIP) after blocking $($block.Description)")
                }
            }
            catch {
                $this.Errors.Add("Failed to apply network block for $($block.Subnet): $_")
            }
        }
    }

    [void]ApplyProcessRestrictions() {
        try {
            # Create Software Restriction Policies key if it doesn't exist
            $srpKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
            if (-not (Test-Path $srpKey)) {
                New-Item -Path $srpKey -Force | Out-Null
            }

            # Enable Software Restriction Policies
            Set-ItemProperty -Path $srpKey -Name "DefaultLevel" -Value 262144 -Type DWORD
            Set-ItemProperty -Path $srpKey -Name "PolicyScope" -Value 1 -Type DWORD
            Set-ItemProperty -Path $srpKey -Name "ExecutableTypes" -Value "COM;EXE;BAT;CMD;VBS;JS;MSI;REG;PS1;PSC1" -Type String

            # Create rules for allowed processes
            $rulesKey = Join-Path $srpKey "0\Paths"
            if (-not (Test-Path $rulesKey)) {
                New-Item -Path $rulesKey -Force | Out-Null
            }

            foreach ($process in $this.AllowedProcesses) {
                $processPath = Join-Path $env:SystemRoot "System32\$process"
                if (Test-Path $processPath) {
                    $hashValue = Get-FileHash -Path $processPath -Algorithm SHA256
                    $ruleName = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($processPath))
                    $ruleKey = Join-Path $rulesKey $ruleName

                    if (-not (Test-Path $ruleKey)) {
                        New-Item -Path $ruleKey -Force | Out-Null
                    }

                    Set-ItemProperty -Path $ruleKey -Name "SaferFlags" -Value 0 -Type DWORD
                    Set-ItemProperty -Path $ruleKey -Name "ItemData" -Value $processPath -Type String
                }
            }
        }
        catch {
            $this.Errors.Add("Failed to apply process restrictions: $_")
        }
    }

    [void]ConfigureEdgeBrowser() {
        try {
            $edgePolicyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
            
            if (-not (Test-Path $edgePolicyKey)) {
                New-Item -Path $edgePolicyKey -Force | Out-Null
            }

            # Additional Edge security settings with their types
            $edgeSettings = @(
                @{Name = "AllowFileSelectionDialogs"; Value = 0; Type = "DWORD"},
                @{Name = "AutofillCreditCardEnabled"; Value = 0; Type = "DWORD"},
                @{Name = "AutofillAddressEnabled"; Value = 0; Type = "DWORD"},
                @{Name = "PasswordManagerEnabled"; Value = 0; Type = "DWORD"},
                @{Name = "AllowPopupsDuringPageUnload"; Value = 0; Type = "DWORD"},
                @{Name = "DefaultPopupsSetting"; Value = 2; Type = "DWORD"},
                @{Name = "DefaultGeolocationSetting"; Value = 2; Type = "DWORD"},
                @{Name = "DefaultNotificationsSetting"; Value = 2; Type = "DWORD"},
                @{Name = "DefaultFileSystemReadGuardSetting"; Value = 2; Type = "DWORD"},
                @{Name = "DefaultFileSystemWriteGuardSetting"; Value = 2; Type = "DWORD"},
                @{Name = "DefaultWebBluetoothGuardSetting"; Value = 2; Type = "DWORD"},
                @{Name = "DefaultWebUsbGuardSetting"; Value = 2; Type = "DWORD"},
                @{Name = "EnableOnlineRevocationChecks"; Value = 1; Type = "DWORD"},
                @{Name = "SSLVersionMin"; Value = "tls1.2"; Type = "String"},
                @{Name = "AuthSchemes"; Value = "negotiate,ntlm"; Type = "String"},
                @{Name = "AllowDiagnosticData"; Value = 0; Type = "DWORD"}
            )

            foreach ($setting in $edgeSettings) {
                Set-ItemProperty -Path $edgePolicyKey -Name $setting.Name -Value $setting.Value -Type $setting.Type
            }
        }
        catch {
            $this.Errors.Add("Failed to configure Edge browser: $_")
        }
    }

    [void]VerifySettings() {
        foreach ($feature in $this.Features) {
            try {
                $value = Get-ItemProperty -Path $feature.RegistryKey -Name $feature.ValueName -ErrorAction Stop
                if ($value.$($feature.ValueName) -ne $feature.Value) {
                    $this.Errors.Add("Verification failed for $($feature.Name): Expected $($feature.Value), got $($value.$($feature.ValueName))")
                }
            }
            catch {
                $this.Errors.Add("Failed to verify $($feature.Name): $_")
            }
        }

        # Verify network blocks
        foreach ($block in $this.NetworkBlocks) {
            $existingRoute = Get-NetRoute -DestinationPrefix "$($block.Subnet)/$($this.ConvertMaskToCIDR($block.Mask))" -ErrorAction SilentlyContinue
            if (-not $existingRoute) {
                $this.Errors.Add("Network block route missing for $($block.Description)")
            }
            elseif ($existingRoute.NextHop -ne "0.0.0.0") {
                $this.Errors.Add("Network block route incorrectly configured for $($block.Description): NextHop should be 0.0.0.0")
            }
        }

        # Verify process restrictions
        $srpKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
        if (-not (Test-Path $srpKey)) {
            $this.Errors.Add("Software Restriction Policies key not found")
        }
        else {
            $defaultLevel = (Get-ItemProperty -Path $srpKey).DefaultLevel
            if ($defaultLevel -ne 262144) {
                $this.Errors.Add("Software Restriction Policies DefaultLevel incorrect: $defaultLevel")
            }
        }
    }

    [void]LogResults() {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $logFile = Join-Path $this.LogPath "HardeningResults_$timestamp.log"
        
        try {
            $output = @"
Windows Security Hardening Results
================================
Timestamp: $(Get-Date)
Computer Name: $env:COMPUTERNAME
Windows Version: $((Get-WmiObject Win32_OperatingSystem).Version)

Applied Security Features:
------------------------
$($this.Features | ForEach-Object { 
    "Name: $($_.Name)`n" + 
    "Category: $($_.Category)`n" +
    "Sequence: $($_.SequenceOrder)`n" +
    "Registry Key: $($_.RegistryKey)`n" +
    "Value Name: $($_.ValueName)`n" +
    "Value: $($_.Value)`n" +
    "------------------------"
} | Out-String)

Network Blocks Applied:
---------------------
$($this.NetworkBlocks | ForEach-Object {
    "Subnet: $($_.Subnet)`n" +
    "Mask: $($_.Mask)`n" +
    "Description: $($_.Description)`n" +
    "------------------------"
} | Out-String)

Allowed Processes:
----------------
$($this.AllowedProcesses | ForEach-Object { "- $_" } | Out-String)

Errors and Warnings:
------------------
$($this.Errors | ForEach-Object { "- $_" } | Out-String)

Summary:
-------
Total Features Applied: $($this.Features.Count)
Total Network Blocks: $($this.NetworkBlocks.Count)
Total Allowed Processes: $($this.AllowedProcesses.Count)
Total Errors/Warnings: $($this.Errors.Count)

==========================================
End of Hardening Report
==========================================
"@
            $output | Out-File -FilePath $logFile -Force
            Write-Host "Hardening results have been logged to: $logFile"
        }
        catch {
            Write-Error "Failed to write log file: $_"
        }
    }

    [void]ApplyHardening() {
        # Apply features in sequence
        for ($sequence = 1; $sequence -le 5; $sequence++) {
            $this.ApplyFeatureControlsBySequence($sequence)
            
            # Apply network blocks after initial hardening but before CMD disable
            if ($sequence -eq 1) {
                $this.ApplyNetworkBlocks()
            }

            # Apply process restrictions after network blocks but before final lockdown
            if ($sequence -eq 3) {
                $this.ApplyProcessRestrictions()
                $this.ConfigureEdgeBrowser()
            }
        }

        $this.VerifySettings()
        $this.LogResults()
    }

    [void]ApplyFeatureControlsBySequence([int]$sequence) {
        $sequenceFeatures = $this.Features | Where-Object { $_.SequenceOrder -eq $sequence }
        
        foreach ($feature in $sequenceFeatures) {
            try {
                if (-not (Test-Path $feature.RegistryKey)) {
                    New-Item -Path $feature.RegistryKey -Force | Out-Null
                }

                $params = @{
                    Path = $feature.RegistryKey
                    Name = $feature.ValueName
                    Value = $feature.Value
                    Type = $feature.Type
                    Force = $true
                    ErrorAction = "Stop"
                }

                Set-ItemProperty @params
            }
            catch {
                $this.Errors.Add("Failed to configure $($feature.Name): $_")
            }
        }
    }
}

# Execute hardening with elevated privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script requires administrative privileges to run"
}

$hardening = [HardeningManager]::new()
$hardening.ApplyHardening()