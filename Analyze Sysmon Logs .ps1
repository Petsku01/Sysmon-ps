# Analyze-SysmonLogs.ps1
# Analyzes Sysmon logs for suspicious activity

# Get Sysmon events
$processCreationEvents = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' | 
                          Where-Object { $_.Id -eq 1 } # Process creation

# Define suspicious criteria (example: parent process is cmd.exe)
$suspiciousProcesses = $processCreationEvents | Where-Object { 
    $_.Message -like "*cmd.exe*" -and 
    $_.Message -like "*powershell.exe*" 
}

# Display suspicious events
if ($suspiciousProcesses) {
    Write-Host "Suspicious process creation detected:"
    $suspiciousProcesses | Select-Object TimeCreated, Id, Message | Format-Table -AutoSize
} else {
    Write-Host "No suspicious process creation detected."
}
