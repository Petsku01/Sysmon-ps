# Export-SysmonLogs.ps1
# Exports Sysmon event logs to a CSV file

# Define output file path
$outputFile = "C:\Path\To\SysmonLogs.csv"

# Get Sysmon events
$sysmonEvents = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational'

# Export to CSV
$sysmonEvents | Select-Object TimeCreated, Id, Message | Export-Csv -Path $outputFile -NoTypeInformation

Write-Host "Sysmon logs exported to $outputFile"
