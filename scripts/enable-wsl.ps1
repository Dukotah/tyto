# tyto — elevated WSL2 enablement. Enables the features WSL2 needs, logs results.
$ErrorActionPreference = 'Continue'
$log = 'C:\Users\dukot\tyto\wsl-setup.log'
"=== tyto WSL2 enable run ===" | Out-File $log

"--- BEFORE: feature states ---" | Out-File $log -Append
Get-WindowsOptionalFeature -Online |
  Where-Object { $_.FeatureName -match 'Linux|VirtualMachinePlatform|Hyper-V-All' } |
  Select-Object FeatureName, State | Format-Table -AutoSize | Out-String | Out-File $log -Append

"--- firmware virtualization (real check, elevated) ---" | Out-File $log -Append
$proc = Get-CimInstance Win32_Processor
"VirtualizationFirmwareEnabled = $($proc.VirtualizationFirmwareEnabled)" | Out-File $log -Append
$hv = (Get-CimInstance Win32_ComputerSystem).HypervisorPresent
"HypervisorPresent = $hv" | Out-File $log -Append

"--- enabling VirtualMachinePlatform ---" | Out-File $log -Append
$r1 = Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -All -NoRestart -ErrorAction Continue
"VMPlatform RestartNeeded = $($r1.RestartNeeded)" | Out-File $log -Append

"--- enabling Microsoft-Windows-Subsystem-Linux ---" | Out-File $log -Append
$r2 = Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -All -NoRestart -ErrorAction Continue
"WSL RestartNeeded = $($r2.RestartNeeded)" | Out-File $log -Append

"--- wsl --update (best effort) ---" | Out-File $log -Append
wsl.exe --update 2>&1 | Out-File $log -Append

"--- AFTER: feature states ---" | Out-File $log -Append
Get-WindowsOptionalFeature -Online |
  Where-Object { $_.FeatureName -match 'Linux|VirtualMachinePlatform|Hyper-V-All' } |
  Select-Object FeatureName, State | Format-Table -AutoSize | Out-String | Out-File $log -Append

"=== DONE. Reboot required if either RestartNeeded was True. ===" | Out-File $log -Append
