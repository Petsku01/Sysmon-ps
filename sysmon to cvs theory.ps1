# Export-SysmonLogs.ps1
# Exports Sysmon event logs to a CSV file with enhanced error handling and filtering options

# Parameters
param (
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\Logs\SysmonLogs_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$MaxEvents = 1000,
    
    [Parameter(Mandatory=$false)]
    [datetime]$StartTime,
    
    [Parameter(Mandatory=$false)]
    [datetime]$EndTime,
    
    [Parameter(Mandatory=$false)]
    [int[]]$EventIDs
)

# Function to write log messages
function Write-Log {
    param ([string]$Message)
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    Write-Host $logMessage
}

# Function to validate file path
function Test-ValidFilePath {
    param ([string]$Path)
    try {
        $null = [System.IO.Path]::GetFullPath($Path)
        return $true
    } catch {
        return $false
    }
}

try {
    # Validate output path
    if (-not (Test-ValidFilePath -Path $OutputPath)) {
        throw "Invalid output path: $OutputPath. Ensure the path is valid and contains no illegal characters."
    }

    # Validate output directory
    $outputDir = Split-Path $OutputPath -Parent
    if (-not (Test-Path $outputDir)) {
        Write-Log "Creating output directory: $outputDir"
        New-Item -ItemType Directory -Path $outputDir -Force -ErrorAction Stop | Out-Null
    }

    # Check if Sysmon log exists
    if (-not (Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue)) {
        throw "Sysmon log 'Microsoft-Windows-Sysmon/Operational' not found or inaccessible."
    }

    # Build filter hashtable
    $filter = @{LogName = 'Microsoft-Windows-Sysmon/Operational'}
    if ($StartTime) { $filter['StartTime'] = $StartTime }
    if ($EndTime) { $filter['EndTime'] = $EndTime }
    if ($EventIDs) { $filter['ID'] = $EventIDs }

    # Get Sysmon events
    Write-Log "Retrieving Sysmon events..."
    $sysmonEvents = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop

    # Check if events were found
    if ($sysmonEvents.Count -eq 0) {
        Write-Log "No Sysmon events found matching the specified criteria."
        return
    }

    # Select and format relevant event properties
    $formattedEvents = $sysmonEvents | Select-Object @{
        Name = 'TimeCreated'; 
        Expression = {$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}
    },
    @{Name = 'EventID'; Expression = {$_.Id}},
    @{Name = 'EventType'; Expression = {$_.LevelDisplayName}},
    @{Name = 'Message'; Expression = {$_.Message -replace "[`n`r]+"," " -replace '"','""'}},
    @{Name = 'ProcessID'; Expression = {$_.ProcessId}},
    @{Name = 'Computer'; Expression = {$_.MachineName}}

    # Export to CSV
    Write-Log "Exporting events to $OutputPath..."
    $formattedEvents | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

    Write-Log "Successfully exported $($sysmonEvents.Count) Sysmon events to $OutputPath"

} catch {
    Write-Log "Error: $($_.Exception.Message)"
    exit 1
} finally {
    Write-Log "Script execution completed."
}
