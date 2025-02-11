# Windows Security Hardening Script
# Provides systematic hardening of Windows environments through feature control and network isolation

class SecurityFeature {
    [string]$Name
    [string]$RegistryKey
    [string]$ValueName
    [object]$Value
    [string]$Type

    SecurityFeature([string]$name, [string]$key, [string]$valueName, [object]$value, [string]$type) {
        $this.Name = $name
        $this.RegistryKey = $key
        $this.ValueName = $valueName
        $this.Value = $value
        $this.Type = $type
    }
}

class NetworkBlock {
    [string]$Subnet
    [string]$Mask
    [string]$TestIP

    NetworkBlock([string]$subnet, [string]$mask, [string]$testIP) {
        $this.Subnet = $subnet
        $this.Mask = $mask
        $this.TestIP = $testIP
    }
}

class HardeningManager {
    [System.Collections.Generic.List[SecurityFeature]]$Features
    [System.Collections.Generic.List[NetworkBlock]]$NetworkBlocks
    [System.Collections.Generic.List[string]]$Errors
    [string]$LogPath

    HardeningManager() {
        $this.Features = [System.Collections.Generic.List[SecurityFeature]]::new()
        $this.NetworkBlocks = [System.Collections.Generic.List[NetworkBlock]]::new()
        $this.Errors = [System.Collections.Generic.List[string]]::new()
        $this.LogPath = [System.IO.Path]::Combine($env:USERPROFILE, "Desktop")
        $this.InitializeFeatures()
        $this.InitializeNetworkBlocks()
    }

    [void]InitializeFeatures() {
        # System Security
        $this.AddFeature("Windows Script Host", "HKLM:\Software\Microsoft\Windows Script Host\Settings", "Enabled", 0, "DWORD")
        $this.AddFeature("PowerShell Execution", "HKLM:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "ExecutionPolicy", "Restricted", "String")
        $this.AddFeature("Remote Desktop", "HKLM:\System\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", 1, "DWORD")
        
        # Remote Access
        $this.AddFeature("SMB File Sharing", "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", 0, "DWORD")
        $this.AddFeature("Windows Remote Shell", "HKLM:\SYSTEM\CurrentControlSet\Services\WinRM", "Start", 4, "DWORD")
        
        # Network Security
        $this.AddFeature("NetBIOS over TCP/IP", "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters", "EnableNetbiosOverTcpip", 2, "DWORD")
        $this.AddFeature("IPv6 Teredo", "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters", "DisabledComponents", 255, "DWORD")
        
        # Application Control
        $this.AddFeature("Windows Store", "HKLM:\Software\Policies\Microsoft\WindowsStore", "RemoveWindowsStore", 1, "DWORD")
        $this.AddFeature("OneDrive", "HKLM:\Software\Policies\Microsoft\Windows\OneDrive", "DisableFileSyncNGSC", 1, "DWORD")
        $this.AddFeature("Error Reporting", "HKLM:\Software\Microsoft\Windows\Windows Error Reporting", "Disabled", 1, "DWORD")
    }

    [void]InitializeNetworkBlocks() {
        $this.NetworkBlocks.Add([NetworkBlock]::new("10.0.0.0", "255.0.0.0", "10.0.0.1"))
        $this.NetworkBlocks.Add([NetworkBlock]::new("172.16.0.0", "255.240.0.0", "172.16.0.1"))
        $this.NetworkBlocks.Add([NetworkBlock]::new("192.168.0.0", "255.255.0.0", "192.168.1.1"))
    }

    [void]AddFeature([string]$name, [string]$key, [string]$valueName, [object]$value, [string]$type) {
        $this.Features.Add([SecurityFeature]::new($name, $key, $valueName, $value, $type))
    }

    [void]ApplyHardening() {
        $this.ApplyFeatureControls()
        $this.ApplyNetworkBlocks()
        $this.VerifySettings()
        $this.LogResults()
    }

    [void]ApplyFeatureControls() {
        foreach ($feature in $this.Features) {
            try {
                if (-not (Test-Path $feature.RegistryKey)) {
                    New-Item -Path $feature.RegistryKey -Force | Out-Null
                }

                $params = @{
                    Path = $feature.RegistryKey
                    Name = $feature.ValueName
                    Value = $feature.Value
                    PropertyType = $feature.Type
                    Force = $true
                    ErrorAction = "Stop"
                }

                New-ItemProperty @params | Out-Null
            }
            catch {
                $this.Errors.Add("Failed to configure $($feature.Name): $_")
            }
        }
    }

    [void]ApplyNetworkBlocks() {
        foreach ($block in $this.NetworkBlocks) {
            try {
                $command = "route add $($block.Subnet) mask $($block.Mask) 0.0.0.0 -p"
                Start-Process -FilePath "cmd.exe" -ArgumentList "/c $command" -NoNewWindow -Wait
            }
            catch {
                $this.Errors.Add("Failed to block network $($block.Subnet): $_")
            }
        }
    }

    [void]VerifySettings() {
        $this.VerifyNetworkBlocks()
        $this.VerifyFeatures()
    }

    [void]VerifyNetworkBlocks() {
        foreach ($block in $this.NetworkBlocks) {
            $testResult = Test-Connection -ComputerName $block.TestIP -Count 1 -ErrorAction SilentlyContinue
            if ($testResult) {
                $this.Errors.Add("Network block bypass detected for $($block.TestIP)")
            }
        }
    }

    [void]VerifyFeatures() {
        foreach ($feature in $this.Features) {
            try {
                $currentValue = (Get-ItemProperty -Path $feature.RegistryKey -Name $feature.ValueName -ErrorAction Stop).$($feature.ValueName)
                
                if ($feature.Type -eq "String") {
                    if ($currentValue -ne $feature.Value) {
                        $this.Errors.Add("Feature still enabled: $($feature.Name)")
                    }
                }
                elseif ($currentValue -ne [int]$feature.Value) {
                    $this.Errors.Add("Feature still enabled: $($feature.Name)")
                }
            }
            catch {
                $this.Errors.Add("Failed to verify $($feature.Name): $_")
            }
        }
    }

    [void]LogResults() {
        $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $logFile = if ($this.Errors.Count -eq 0) {
            Join-Path $this.LogPath "HardeningSuccess_$timestamp.log"
        }
        else {
            Join-Path $this.LogPath "HardeningErrors_$timestamp.log"
        }

        $status = if ($this.Errors.Count -eq 0) {
            "Windows Security Hardening completed successfully"
        }
        else {
            "Windows Security Hardening encountered issues:`n`n$($this.Errors | ForEach-Object { "- $_`n" })"
        }

        $status | Out-File -FilePath $logFile -Encoding utf8
    }
}

# Execute hardening
$hardening = [HardeningManager]::new()
$hardening.ApplyHardening()