# === Smart SQL Server AV Exclusion Finder ===

$executablesToFind = @("sqlservr.exe", "sqlagent.exe", "sqlbrowser.exe", "SQLDumper.exe")
$requiredExtensions = @(".mdf", ".ldf", ".ndf", ".bak", ".trn", ".trc", ".xel", ".xem", ".sqlaudit", ".sql", ".mdmp")
$instancePaths = @{}
$exeResults = @{}
$searchRoots = @()

# 1. Collect SQL paths from registry
$instanceRoot = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
if (Test-Path $instanceRoot) {
    $instances = Get-ItemProperty -Path $instanceRoot
    foreach ($instance in $instances.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) {
        $instanceName = $instance.Name
        $instanceId = $instance.Value
        $setupPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instanceId\Setup"
        $configPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instanceId\MSSQLServer"

        $paths = [ordered]@{
            SQLBinRoot      = $null
            SQLPath         = $null
            SharedDir       = $null
            SharedWOWDir    = $null
            DefaultData     = $null
            DefaultLog      = $null
            ErrorLogPath    = $null
            BackupDirectory = $null
            DetectedPaths   = @()
            DetectedFiles   = @()
        }

        if (Test-Path $setupPath) {
            $setup = Get-ItemProperty -Path $setupPath

            $paths["SQLBinRoot"]   = $setup.SQLBinRoot
            $paths["SQLPath"]      = $setup.SQLPath
            $paths["SharedDir"]    = $setup.SharedDirectory
            $paths["SharedWOWDir"] = $setup.SharedWOWDirectory

            $searchRoots += @($setup.SQLBinRoot, $setup.SQLPath, $setup.SharedDirectory, $setup.SharedWOWDirectory)
        }

        if (Test-Path $configPath) {
            $config = Get-ItemProperty -Path $configPath

            $paths["DefaultData"]     = $config.DefaultData
            $paths["DefaultLog"]      = $config.DefaultLog
            $paths["ErrorLogPath"]    = $config.ErrorLog
            $paths["BackupDirectory"] = $config.BackupDirectory
        }

        # Fallback guesses for important paths
        if (-not $paths["DefaultData"] -and $paths["SQLPath"]) {
            $guess = Join-Path $paths["SQLPath"] "DATA"
            if (Test-Path $guess) { $paths["DefaultData"] = $guess }
        }

        if (-not $paths["ErrorLogPath"] -and $paths["SQLPath"]) {
            $guess = Join-Path $paths["SQLPath"] "LOG"
            if (Test-Path $guess) { $paths["ErrorLogPath"] = $guess }
        }

        if (-not $paths["SharedDir"]) {
            $guess = "C:\Program Files\Microsoft SQL Server\160\Shared"
            if (Test-Path $guess) { $paths["SharedDir"] = $guess }
        }

        # Detect known file types in any of the paths
        $checkedPaths = $paths.Values | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
        foreach ($dir in $checkedPaths) {
            foreach ($ext in $requiredExtensions) {
                $files = Get-ChildItem -Path $dir -Recurse -Include "*$ext" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
                if ($files) {
                    $paths["DetectedPaths"] += $dir
                    $paths["DetectedFiles"] += $files
                }
            }
        }

        $instancePaths[$instanceName] = $paths
    }
}

# 2. Add default root folders and search for custom locations
$searchRoots = @()

# Start with Program Files locations
$programFilesPaths = @(
    "$env:ProgramFiles\Microsoft SQL Server",
    "$env:ProgramFiles(x86)\Microsoft SQL Server"
) | Where-Object { Test-Path $_ }
$searchRoots += $programFilesPaths

# Search all fixed drives for SQL Server installations
$allDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { 
    $_.Free -gt 0 -and $_.Root -notmatch '^(C:|D:)$' -and (Test-Path $_.Root) 
}

# Recursively search for "Microsoft SQL Server" folders on all drives
foreach ($drive in $allDrives) {
    try {
        $sqlFolders = Get-ChildItem -Path $drive.Root -Directory -Recurse -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -eq "Microsoft SQL Server" } |
            Select-Object -ExpandProperty FullName
        if ($sqlFolders) {
            $searchRoots += $sqlFolders
        }
    } catch {
        Write-Warning "Could not search drive $($drive.Root): $($_.Exception.Message)"
    }
}

# Find all Shared folders under any SQL Server installation
$sharedDirs = @()
foreach ($root in $searchRoots) {
    # Find immediate Shared folders
    $sharedDirs += Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue | 
        Where-Object { $_.Name -eq "Shared" } |
        Select-Object -ExpandProperty FullName
        
    # Also look for version-specific Shared folders (like 160\Shared)
    $sharedDirs += Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue | 
        ForEach-Object {
            $versionPath = Join-Path $_.FullName "Shared"
            if (Test-Path $versionPath) { $versionPath }
        }
}

$searchRoots += $sharedDirs
$searchRoots = $searchRoots | Where-Object { Test-Path $_ } | Select-Object -Unique

# 3. Find executables
foreach ($exe in $executablesToFind) {
    $exeMatches = @()
    foreach ($root in $searchRoots) {
        $found = Get-ChildItem -Path $root -Recurse -Filter $exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
        $exeMatches += $found
    }
    $exeResults[$exe] = $exeMatches | Sort-Object -Unique
}

# 4. Final Output
$output = [ordered]@{
    SQLInstances = $instancePaths
    Executables  = $exeResults
}

# 5. Export to JSON
$outputPath = Join-Path (Get-Location) "SqlServer_AV_Exclusions.json"
$output | ConvertTo-Json -Depth 6 | Out-File -FilePath $outputPath -Encoding UTF8

Write-Host "`n✅ SQL Server AV exclusions exported to:`n$outputPath" -ForegroundColor Green
