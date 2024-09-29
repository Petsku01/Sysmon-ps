# Get-SysmonEvents.ps1
# Retrieves Sysmon event logs filtered by specific event IDs

# Define event IDs to filter
$eventIDs = @(1, 2, 3) # Process creation, file creation, network connection

# Get Sysmon events
$sysmonEvents = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' | 
                Where-Object { $eventIDs -contains $_.Id }

# Display the results
$sysmonEvents | Select-Object TimeCreated, Id, Message | Format-Table -AutoSize
