# InstallSysmon.ps1
# Installs Sysmon with a specified configuration file

# Path to Sysmon executable
$symonPath = "C:\Path\To\Sysmon.exe"
# Path to Sysmon configuration file
$configFilePath = "C:\Path\To\sysmon-config.xml"

# Check if Sysmon is already installed
if (Get-Service -Name Sysmon -ErrorAction SilentlyContinue) {
    Write-Host "Sysmon is already installed."
} else {
    # Install Sysmon
    & $symonPath -accepteula -install $configFilePath
    Write-Host "Sysmon installed successfully."
}
