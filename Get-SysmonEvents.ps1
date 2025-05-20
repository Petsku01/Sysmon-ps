# Get-SysmonEvents.ps1
# Retrieves and filters Sysmon event logs by specified event IDs with enhanced error handling and output options

param (
    [Parameter(Mandatory=$false)]
    [int[]]$EventIDs = @(1, 2, 3), # Default: Process creation, File creation, Network connection
    [Parameter(Mandatory=$false)]
    [string]$OutputCsvPath,
    [Parameter(Mandatory=$false)]
    [int]$MaxEvents = 1000, # Limit number of events to retrieve
    [Parameter(Mandatory=$false)]
    [switch]$VerboseOutput
)

# Function to map event IDs to descriptions
function Get-EventDescription {
    param ($EventId)
    $eventDescriptions = @{
        1 = "Process Creation"
        2 = "File Creation Time Changed"
        3 = "Network Connection"
    }
    return $eventDescriptions[$EventId] ?? "Unknown Event ID"
}

try {
    # Validate if Sysmon log exists
    $logName = 'Microsoft-Windows-Sysmon/Operational'
    if (-not (Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue)) {
        throw "Sysmon event log ($logName) not found. Ensure Sysmon is installed and operational."
    }

    # Retrieve Sysmon events with filter
    $filterHashtable = @{
        LogName = $logName
        ID = $EventIDs
    }
    if ($MaxEvents) {
        $filterHashtable.MaxEvents = $MaxEvents
    }

    $sysmonEvents = Get-WinEvent -FilterHashtable $filterHashtable -ErrorAction Stop

    # Process and format events
    $formattedEvents = $sysmonEvents | ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            EventID     = $_.Id
            EventType   = Get-EventDescription -EventId $_.Id
            Message     = $_.Message -split "`n" | Select-Object -First 1 # Limit to first line for brevity
        }
    }

    # Display results
    if ($VerboseOutput) {
        $formattedEvents | Format-Table -AutoSize -Property TimeCreated, EventID, EventType, Message
    } else {
        $formattedEvents | Format-Table -AutoSize -Property TimeCreated, EventID, EventType
    }

    # Export to CSV if specified
    if ($OutputCsvPath) {
        $formattedEvents | Export-Csv -Path $OutputCsvPath -NoTypeInformation
        Write-Host "Events exported to $OutputCsvPath"
    }
}
catch {
    Write-Error "An error occurred: $_"
}
finally {
    if (-not $sysmonEvents -and -not $Error) {
        Write-Warning "No events found for the specified Event IDs: $($EventIDs -join ', ')"
    }
}
