# Analyze-SysmonLogs.ps1
# Analyzes Sysmon logs for suspicious activity with configurable criteria and output options

# Explanation: Script header describing its purpose—analyzing Sysmon logs to detect suspicious activity with enhanced flexibility and output options.

param (
    [Parameter(Mandatory=$false)]
    [int[]]$EventIDs = @(1), # Default: Process creation events
    [Parameter(Mandatory=$false)]
    [string[]]$SuspiciousPatterns = @("*cmd.exe*", "*powershell.exe*", "*wscript.exe*"), # Default suspicious process patterns
    [Parameter(Mandatory=$false)]
    [string]$OutputCsvPath,
    [Parameter(Mandatory=$false)]
    [int]$MaxEvents = 1000, # Limit number of events to retrieve
    [Parameter(Mandatory=$false)]
    [switch]$VerboseOutput
)

# Explanation: Defines script parameters for configurability:
# - `$EventIDs`: Array of event IDs to analyze (defaults to 1 for process creation).
# - `$SuspiciousPatterns`: Array of strings for pattern matching in event messages (defaults to cmd.exe, powershell.exe, wscript.exe).
# - `$OutputCsvPath`: Optional path for exporting results to CSV.
# - `$MaxEvents`: Limits the number of events retrieved (defaults to 1000).
# - `$VerboseOutput`: Switch to include detailed event messages in output.

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

# Explanation: Helper function to map event IDs to human-readable descriptions:
# - Uses a hashtable to map IDs (e.g., 1 to "Process Creation").
# - Returns "Unknown Event ID" for unrecognized IDs using the null-coalescing operator (`??`).
# Enhances output readability by providing descriptive event types.

try {
    # Validate if Sysmon log exists
    $logName = 'Microsoft-Windows-Sysmon/Operational'
    if (-not (Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue)) {
        throw "Sysmon event log ($logName) not found. Ensure Sysmon is installed and operational."
    }

    # Explanation: Verifies the Sysmon log exists:
    # - Stores log name in `$logName` for reuse.
    # - Uses `Get-WinEvent -ListLog` to check log existence; `-ErrorAction SilentlyContinue` prevents error interruptions.
    # - Throws an error if the log isn’t found, ensuring the user knows Sysmon is required.

    # Retrieve Sysmon events with filter
    $filterHashtable = @{
        LogName = $logName
        ID = $EventIDs
    }
    if ($MaxEvents) {
        $filterHashtable.MaxEvents = $MaxEvents
    }

    # Explanation: Constructs a filter for efficient event retrieval:
    # - Creates `$filterHashtable` with log name and event IDs.
    # - Adds `$MaxEvents` to limit retrieved events if specified, improving performance.
    # Using a hashtable is faster than pipeline filtering.

    $sysmonEvents = Get-WinEvent -FilterHashtable $filterHashtable -ErrorAction Stop

    # Explanation: Fetches events from Sysmon log:
    # - Uses `Get-WinEvent` with `$filterHashtable` for optimized filtering.
    # - `-ErrorAction Stop` ensures errors (e.g., access issues) are caught by the try-catch block.

    # Analyze for suspicious activity
    $suspiciousEvents = $sysmonEvents | Where-Object {
        $message = $_.Message
        $isSuspicious = $false
        foreach ($pattern in $SuspiciousPatterns) {
            if ($message -like $pattern) {
                $isSuspicious = $true
                break
            }
        }
        $isSuspicious
    }

    # Explanation: Identifies suspicious events:
    # - Iterates through `$sysmonEvents` and checks each event’s message against `$SuspiciousPatterns`.
    # - Uses a foreach loop to test each pattern; sets `$isSuspicious` to `$true` if any pattern matches.
    # - Breaks the loop on the first match for efficiency.
    # - Returns `$isSuspicious` to filter events where any pattern matches.

    # Format suspicious events
    $formattedEvents = $suspiciousEvents | ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            EventID     = $_.Id
            EventType   = Get-EventDescription -EventId $_.Id
            Message     = $_.Message -split "`n" | Select-Object -First 1 # Limit to first line for brevity
        }
    }

    # Explanation: Formats suspicious events into a structured object:
    # - Creates a `[PSCustomObject]` for each suspicious event with:
    #   - `TimeCreated`: Event timestamp.
    #   - `EventID`: Numeric event ID.
    #   - `EventType`: Descriptive name from `Get-EventDescription`.
    #   - `Message`: First line of the event message for concise output.
    # This structure improves readability and export compatibility.

    # Display results
    if ($formattedEvents) {
        Write-Host "Suspicious activity detected:" -ForegroundColor Yellow
        if ($VerboseOutput) {
            $formattedEvents | Format-Table -AutoSize -Property TimeCreated, EventID, EventType, Message
        } else {
            $formattedEvents | Format-Table -AutoSize -Property TimeCreated, EventID, EventType
        }
    } else {
        Write-Host "No suspicious activity detected for Event IDs: $($EventIDs -join ', ') and patterns: $($SuspiciousPatterns -join ', ')" -ForegroundColor Green
    }

    # Explanation: Displays results:
    # - If `$formattedEvents` exists, outputs a warning message in yellow and displays the events.
    # - Uses `Format-Table -AutoSize` to show `TimeCreated`, `EventID`, `EventType`, and optionally `Message` if `-VerboseOutput` is set.
    # - If no suspicious events are found, outputs a green message listing the event IDs and patterns checked.
    # Color-coded output enhances user experience.

    # Export to CSV if specified
    if ($OutputCsvPath) {
        $formattedEvents | Export-Csv -Path $OutputCsvPath -NoTypeInformation
        Write-Host "Suspicious events exported to $OutputCsvPath" -ForegroundColor Green
    }

    # Explanation: Exports suspicious events to CSV if `$OutputCsvPath` is provided:
    # - Uses `Export-Csv` with `-NoTypeInformation` to create a clean CSV file.
    # - Outputs a confirmation message in green with the file path.
}
catch {
    Write-Error "An error occurred: $_"
}

# Explanation: Catches errors from the try block:
# - Outputs the error message (`$_`) using `Write-Error` for clear feedback (e.g., log access issues, invalid parameters).

finally {
    if (-not $sysmonEvents -and -not $Error) {
        Write-Warning "No events found for the specified Event IDs: $($EventIDs -join ', ')"
    }
}

# Explanation: Runs in all cases (success or failure):
# - Checks if no events were retrieved (`-not $sysmonEvents`) and no errors occurred (`-not $Error`).
# - Outputs a warning if no events were found for the specified `$EventIDs`, improving user feedback.
