# === Smart Exchange Server AV Exclusion Finder ===

# Define common Exchange paths and variables
$exchangeInstallPaths = @(
    "C:\Program Files\Microsoft\Exchange Server\V15",
    "C:\Program Files\Microsoft\Exchange Server\V16"  # Future-proofing for newer versions
)
$foundPaths = @{}
$processesToFind = @(
    "ComplianceAuditService.exe",
    "Dsamain.exe",
    "EdgeTransport.exe",
    "fms.exe",
    "hostcontrollerservice.exe",
    "inetinfo.exe",
    "Microsoft.Exchange.AntispamUpdateSvc.exe",
    "Microsoft.Exchange.ContentFilter.Wrapper.exe",
    "Microsoft.Exchange.Diagnostics.Service.exe",
    "Microsoft.Exchange.Directory.TopologyService.exe",
    "Microsoft.Exchange.EdgeCredentialSvc.exe",
    "Microsoft.Exchange.EdgeSyncSvc.exe",
    "Microsoft.Exchange.Imap4.exe",
    "Microsoft.Exchange.Imap4service.exe",
    "Microsoft.Exchange.Notifications.Broker.exe",
    "Microsoft.Exchange.Pop3.exe",
    "Microsoft.Exchange.Pop3service.exe",
    "Microsoft.Exchange.ProtectedServiceHost.exe",
    "Microsoft.Exchange.RPCClientAccess.Service.exe",
    "Microsoft.Exchange.Search.Service.exe",
    "Microsoft.Exchange.Servicehost.exe",
    "Microsoft.Exchange.Store.Service.exe",
    "Microsoft.Exchange.Store.Worker.exe",
    "Microsoft.Exchange.UM.CallRouter.exe",
    "MSExchangeCompliance.exe",
    "MSExchangeDagMgmt.exe",
    "MSExchangeDelivery.exe",
    "MSExchangeFrontendTransport.exe",
    "MSExchangeHMHost.exe",
    "MSExchangeHMWorker.exe",
    "MSExchangeMailboxAssistants.exe",
    "MSExchangeMailboxReplication.exe",
    "MSExchangeRepl.exe",
    "MSExchangeSubmission.exe",
    "MSExchangeTransport.exe",
    "MSExchangeTransportLogSearch.exe",
    "MSExchangeThrottling.exe",
    "Noderunner.exe",
    "OleConverter.exe",
    "ParserServer.exe",
    "ScanEngineTest.exe",
    "ScanningProcess.exe",
    "UmService.exe",
    "UmWorkerProcess.exe",
    "UpdateService.exe",
    "wsbexchange.exe"
)
$processResults = @{}
$extensionsToExclude = @(
    "*.config",
    "*.chk",
    "*.edb",
    "*.jfm",
    "*.JRS",
    "*.Log",
    "*.Que",
    "*.Dsc",
    "*.txt",
    "*.cfg",
    "*.GRXML",
    "*.lzx"
)

# Helper function to find files recursively
function Find-Files {
    param (
        [string]$Path,
        [string[]]$Patterns,
        [int]$MaxDepth = 3
    )
    
    if ($MaxDepth -lt 0) { return @() }
    
    $results = @()
    try {
        foreach ($pattern in $Patterns) {
            $results += Get-ChildItem -Path $Path -Filter $pattern -File -ErrorAction SilentlyContinue
        }
        
        Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $results += Find-Files -Path $_.FullName -Patterns $Patterns -MaxDepth ($MaxDepth - 1)
        }
    }
    catch {
        Write-Warning "Error accessing path: $Path"
    }
    
    return $results
}

# 1. Detect Exchange Installation
$exchangeInstallPath = $null
foreach ($path in $exchangeInstallPaths) {
    if (Test-Path $path) {
        $exchangeInstallPath = $path
        break
    }
}

if (-not $exchangeInstallPath) {
    Write-Warning "No Exchange Server installation found in common paths."
    exit
}

Write-Host "`n=== Exchange Server Installation Found ===" -ForegroundColor Green
Write-Host "Installation Path: $exchangeInstallPath"

# 2. Collect Important Exchange Paths
$paths = [ordered]@{
    InstallPath           = $exchangeInstallPath
    BinPath              = Join-Path $exchangeInstallPath "Bin"
    ClientAccessPath     = Join-Path $exchangeInstallPath "ClientAccess"
    FrontEndPath        = Join-Path $exchangeInstallPath "FrontEnd"
    TransportRolesPath  = Join-Path $exchangeInstallPath "TransportRoles"
    UnifiedMessagingPath = Join-Path $exchangeInstallPath "UnifiedMessaging"
    WorkingPath         = Join-Path $exchangeInstallPath "Working"
    LoggingPath         = Join-Path $exchangeInstallPath "Logging"
    MailboxPath         = Join-Path $exchangeInstallPath "Mailbox"
    FIPFSPath           = Join-Path $exchangeInstallPath "FIP-FS"
    GroupMetricsPath    = Join-Path $exchangeInstallPath "GroupMetrics"
    IISPath             = "C:\inetpub\temp\IIS Temporary Compressed Files"
    ClusterPath         = "$env:SystemRoot\Cluster"
    TempPath            = "$env:SystemRoot\Temp"
}

# Add DAG paths if present
$dagPaths = @()
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $adSite = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name
    $dagPaths += Get-ChildItem -Path "$env:SystemDrive\DAGFileShareWitnesses" -Directory -ErrorAction SilentlyContinue | 
                 Select-Object -ExpandProperty FullName
}
catch {
    Write-Warning "Could not check for DAG paths: $($_.Exception.Message)"
}
if ($dagPaths) {
    $paths["DAGPaths"] = $dagPaths
}

# 3. Find Processes
Write-Host "`n=== Scanning for Exchange Processes ===" -ForegroundColor Green
foreach ($process in $processesToFind) {
    $locations = Find-Files -Path $exchangeInstallPath -Patterns @($process)
    if ($locations) {
        $processResults[$process] = $locations.FullName
        Write-Host "Found $process at:" -ForegroundColor Cyan
        foreach ($loc in $locations.FullName) {
            Write-Host "  $loc"
        }
    }
}

# 4. Find Files by Extension
Write-Host "`n=== Scanning for Exchange File Extensions ===" -ForegroundColor Green
foreach ($path in $paths.GetEnumerator()) {
    if (Test-Path $path.Value) {
        $foundFiles = Find-Files -Path $path.Value -Patterns $extensionsToExclude
        if ($foundFiles) {
            $foundPaths[$path.Key] = @{
                Path = $path.Value
                Files = $foundFiles | Select-Object -ExpandProperty FullName
                Extensions = $foundFiles | Select-Object -ExpandProperty Extension -Unique
            }
        }
    }
}

# 5. Export Results
$output = [ordered]@{
    ExchangePaths = $paths
    ProcessLocations = $processResults
    FilesByPath = $foundPaths
    RecommendedExtensionExclusions = $extensionsToExclude
}

$outputPath = Join-Path (Get-Location) "Exchange_AV_Exclusions.json"
$output | ConvertTo-Json -Depth 6 | Out-File -FilePath $outputPath -Encoding UTF8

Write-Host "`n✅ Exchange Server AV exclusions exported to:`n$outputPath" -ForegroundColor Green
Write-Host "`nImportant Notes:" -ForegroundColor Yellow
Write-Host "1. Review the JSON file and verify the paths before implementing exclusions"
Write-Host "2. Some paths may be dynamic or configurable - check Exchange Management Shell for actual locations"
Write-Host "3. Additional paths may be needed based on your specific Exchange configuration"
Write-Host "4. Test exclusions in a non-production environment first"
