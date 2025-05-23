[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SQLServerName
)

# Function to test server connectivity
function Test-ServerConnectivity {
    param([string]$ServerName)
    
    Write-Host "Testing connectivity to $ServerName..."
    
    # Test DNS resolution first
    try {
        $null = [System.Net.Dns]::GetHostEntry($ServerName)
    }
    catch {
        throw "DNS resolution failed for '$ServerName'. Please verify the server name is correct and can be resolved."
    }
    
    # Test if WinRM is available
    $winrmTest = Test-WSMan -ComputerName $ServerName -ErrorAction SilentlyContinue
    if (-not $winrmTest) {
        throw "WinRM is not accessible on '$ServerName'. Please ensure that:
        1. WinRM is enabled on the remote server (run 'winrm quickconfig' on the SQL Server)
        2. Your account has appropriate permissions
        3. Any firewalls allow WinRM traffic (TCP 5985 for HTTP, TCP 5986 for HTTPS)
        4. The server can be reached on the network"
    }
}

# Ensure we're running with adequate permissions
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "This script must be run with administrative privileges"
}

# Ensure we have the required modules
$requiredModules = @("GroupPolicy")
foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        throw "Required module $module is not installed. Please install it first."
    }
}

# Test connectivity before proceeding
Test-ServerConnectivity -ServerName $SQLServerName

Write-Host "Creating remote session to SQL Server: $SQLServerName..."
try {
    $session = New-PSSession -ComputerName $SQLServerName -ErrorAction Stop
    
    # Execute the SQLServerAVExclusionFind script remotely
    Write-Host "Running SQLServerAVExclusionFind.ps1 remotely..."
    $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
    $remoteScript = Get-Content "$scriptPath\SQLServerAVExclusionFind.ps1" -Raw
    
    Invoke-Command -Session $session -ScriptBlock {
        param($script)
        $tempFile = [System.IO.Path]::GetTempFileName()
        Set-Content -Path $tempFile -Value $script
        & $tempFile
        Remove-Item $tempFile -Force
    } -ArgumentList $remoteScript
    
    # Copy the generated JSON file back to the management host
    Write-Host "Retrieving generated exclusions file..."
    $localPath = "$scriptPath\SqlServer_AV_Exclusions.json"
    Copy-Item -FromSession $session -Path "C:\SqlServer_AV_Exclusions.json" -Destination $localPath -Force
    
    # Remove the remote JSON file
    Invoke-Command -Session $session { Remove-Item "C:\SqlServer_AV_Exclusions.json" -Force }
}
catch {
    Write-Error "Failed to execute remote script: $_"
    if ($session) { Remove-PSSession $session }
    exit 1
}
finally {
    if ($session) { Remove-PSSession $session }
}

# Now run the Create-DefenderGPO script locally
Write-Host "Creating Defender GPO with the exclusions..."
try {
    & "$scriptPath\Create-DefenderGPO.ps1"
    Write-Host "Successfully completed Defender configuration!" -ForegroundColor Green
}
catch {
    Write-Error "Failed to create Defender GPO: $_"
    exit 1
}
