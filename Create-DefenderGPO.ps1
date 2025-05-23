# === Create and Import Windows Defender GPO for SQL Server Exclusions ===
param(
    [Parameter(Mandatory = $false)]
    [string]$JsonPath = "SqlServer_AV_Exclusions.json",
    [Parameter(Mandatory = $false)]
    [string]$GpoName = "SQL Server - Windows Defender Exclusions",
    [Parameter(Mandatory = $false)]
    [string]$BackupFolder = "GPO_Backup"
)

# Ensure we have the required modules and permissions
$requiredModules = @('GroupPolicy', 'ActiveDirectory')
foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        throw "$module PowerShell module is required. Install RSAT tools with: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
    }
}

# Check if we're running as admin
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    throw "This script must be run as Administrator to create and import GPOs"
}

# Import JSON data
$exclusions = Get-Content -Path $JsonPath -Raw | ConvertFrom-Json

# Create arrays for exclusions
$processExclusions = @()
$pathExclusions = @()

# Add executable paths to process exclusions
foreach ($exe in $exclusions.Executables.PSObject.Properties) {
    if ($exe.Value -is [string]) {
        $processExclusions += $exe.Value
    } elseif ($exe.Value -is [array]) {
        $processExclusions += $exe.Value
    }
}

# Add important paths to path exclusions from SQLInstances
foreach ($instance in $exclusions.SQLInstances.PSObject.Properties) {
    $paths = @(
        $instance.Value.SQLBinRoot,
        $instance.Value.SQLPath,
        $instance.Value.SharedDir,
        $instance.Value.SharedWOWDir,
        $instance.Value.DefaultData,
        $instance.Value.DefaultLog,
        $instance.Value.ErrorLogPath,
        $instance.Value.BackupDirectory
    )
    $pathExclusions += $paths | Where-Object { $_ }
}

# Add detected paths
foreach ($instance in $exclusions.SQLInstances.PSObject.Properties) {
    $pathExclusions += $instance.Value.DetectedPaths
}

# Ensure uniqueness and remove nulls
$processExclusions = $processExclusions | Where-Object { $_ } | Select-Object -Unique
$pathExclusions = $pathExclusions | Where-Object { $_ } | Select-Object -Unique

# Create GPO backup folder structure with proper GUIDs
$backupId = [guid]::NewGuid().ToString()
$gpoId = [guid]::NewGuid().ToString()
$gpoBackupPath = Join-Path $BackupFolder $backupId  # <-- No curly braces!
$gpoBackupSysvolPath = Join-Path $gpoBackupPath "DomainSysvol\GPO"

# Create folder structure matching the example GPO
$requiredFolders = @(
    $gpoBackupPath,
    (Join-Path $gpoBackupSysvolPath "Machine"),
    (Join-Path $gpoBackupSysvolPath "User")
)

# Create all required folders
foreach ($folder in $requiredFolders) {
    if (-not (Test-Path $folder)) {
        New-Item -Path $folder -ItemType Directory -Force | Out-Null
    }
}

# Create comment.cmtx
$commentCmtx = @"
<?xml version='1.0' encoding='utf-8'?>
<policyComments xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <policyNamespaces>
    <using prefix="ns0" namespace="Microsoft.Policies.WindowsDefender"></using>
  </policyNamespaces>
  <comments>
    <admTemplate>
      <comment policyRef="ns0:Exclusions_Paths" commentText="$(($pathExclusions | ForEach-Object {"• $_"}) -join "`n")" />
      <comment policyRef="ns0:Exclusions_Processes" commentText="$(($processExclusions | ForEach-Object {"• $_"}) -join "`n")" />
    </admTemplate>
  </comments>
</policyComments>
"@
$commentCmtx | Out-File -FilePath (Join-Path $gpoBackupSysvolPath "Machine\comment.cmtx") -Encoding UTF8

# Create backup.xml with proper format
$backupXml = @"
<?xml version="1.0" encoding="utf-8"?>
<GroupPolicyBackupScheme bkp:version="2.0" bkp:type="GroupPolicyBackupTemplate" xmlns:bkp="http://www.microsoft.com/GroupPolicy/GPOOperations" xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations">
    <GroupPolicyObject>
        <SecurityGroups>
            <Group bkp:Source="FromDACL">
                <Sid><![CDATA[S-1-5-32-544]]></Sid>
                <SamAccountName><![CDATA[Administrators]]></SamAccountName>
                <Type><![CDATA[BuiltinGroup]]></Type>
            </Group>
        </SecurityGroups>
        <FilePaths/>
        <GroupPolicyCoreSettings>
            <ID><![CDATA[{$gpoId}]]></ID>
            <Domain><![CDATA[$(([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name)]]></Domain>
            <SecurityDescriptor>01 00 04 9c 00 00 00 00 00 00 00 00 00 00 00 00 14 00 00 00 04 00 ec 00 08 00 00 00 05 02 28 00</SecurityDescriptor>
            <DisplayName><![CDATA[$GpoName]]></DisplayName>
            <Options><![CDATA[0]]></Options>
            <UserVersionNumber><![CDATA[0]]></UserVersionNumber>
            <MachineVersionNumber><![CDATA[196611]]></MachineVersionNumber>
            <MachineExtensionGuids><![CDATA[[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]]]></MachineExtensionGuids>
            <UserExtensionGuids/>
            <WMIFilter/>
        </GroupPolicyCoreSettings>        <GroupPolicyExtension bkp:ID="{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" bkp:DescName="Registry">
            <FSObjectFile bkp:Path="%GPO_MACH_FSPATH%\registry.pol" bkp:SourceExpandedPath="\\%DOMAINCONTROLLER%\sysvol\%DOMAIN%\Policies\{%GUID%}\Machine\registry.pol" bkp:Location="DomainSysvol\GPO\Machine\registry.pol"/>
            <FSObjectFile bkp:Path="%GPO_FSPATH%\Adm\*.*" bkp:SourceExpanded=""/>
        </GroupPolicyExtension>
        <GroupPolicyExtension bkp:ID="{F15C46CD-82A0-4C2D-A210-5D0D3182A418}" bkp:DescName="Unknown Extension">
            <FSObjectFile bkp:Path="%GPO_MACH_FSPATH%\comment.cmtx" bkp:Location="DomainSysvol\GPO\Machine\comment.cmtx"/>
        </GroupPolicyExtension>
    </GroupPolicyObject>
</GroupPolicyBackupScheme>
"@
$backupXml | Out-File -FilePath (Join-Path $gpoBackupPath "Backup.xml") -Encoding UTF8

# Create bkupInfo.xml with proper format
$currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$domainController = Get-ADDomainController
$bkupInfoXml = @"
<?xml version="1.0" encoding="utf-8"?>
<BackupInst xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations/Manifest">
    <GPOGuid><![CDATA[{$gpoId}]]></GPOGuid>
    <GPODomain><![CDATA[$($currentDomain.Name)]]></GPODomain>
    <GPODomainGuid><![CDATA[{$($currentDomain.Forest.SchemaRoleOwner.Guid)}]]></GPODomainGuid>
    <GPODomainController><![CDATA[$($domainController.HostName)]]></GPODomainController>
    <BackupTime><![CDATA[$([DateTime]::Now.ToString("yyyy-MM-ddTHH:mm:ss"))]]></BackupTime>
    <ID><![CDATA[{$backupId}]]></ID>
    <Comment><![CDATA[SQL Server Windows Defender Exclusions]]></Comment>
    <GPODisplayName><![CDATA[$GpoName]]></GPODisplayName>
</BackupInst>
"@
$bkupInfoXml | Out-File -FilePath (Join-Path $gpoBackupPath "bkupInfo.xml") -Encoding UTF8

# Create gpreport.xml with proper format and Defender settings
$gpreportXml = @"
<?xml version="1.0" encoding="utf-16"?>
<GPO xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.microsoft.com/GroupPolicy/Settings">
    <Identifier>
        <Identifier xmlns="http://www.microsoft.com/GroupPolicy/Types">{$gpoId}</Identifier>
        <Domain xmlns="http://www.microsoft.com/GroupPolicy/Types">$($currentDomain.Name)</Domain>
    </Identifier>
    <Name>$GpoName</Name>
    <IncludeComments>true</IncludeComments>
    <CreatedTime>$([DateTime]::Now.ToString("yyyy-MM-ddTHH:mm:ss"))</CreatedTime>
    <ModifiedTime>$([DateTime]::Now.ToString("yyyy-MM-ddTHH:mm:ss"))</ModifiedTime>
    <ReadTime>$([DateTime]::Now.ToString("yyyy-MM-ddTHH:mm:ss.fffffff\Z"))</ReadTime>
    <SecurityDescriptor>
        <SDDL xmlns="http://www.microsoft.com/GroupPolicy/Types/Security">O:DAG:DAD:PAI(OA;CI;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;AU)(A;;CCDCLCSWRPWPDTLOSDRCWDWO;;;DA)(A;CI;CCDCLCSWRPWPDTLOSDRCWDWO;;;DA)(A;CI;LCRPLORC;;;ED)(A;CI;LCRPLORC;;;AU)(A;CI;CCDCLCSWRPWPDTLOSDRCWDWO;;;SY)(A;CIIO;CCDCLCSWRPWPDTLOSDRCWDWO;;;CO)S:AI</SDDL>
        <Owner xmlns="http://www.microsoft.com/GroupPolicy/Types/Security">
            <SID xmlns="http://www.microsoft.com/GroupPolicy/Types">S-1-5-32-544</SID>
            <Name xmlns="http://www.microsoft.com/GroupPolicy/Types">BUILTIN\Administrators</Name>
        </Owner>
        <Group xmlns="http://www.microsoft.com/GroupPolicy/Types/Security">
            <SID xmlns="http://www.microsoft.com/GroupPolicy/Types">S-1-5-32-544</SID>
            <Name xmlns="http://www.microsoft.com/GroupPolicy/Types">BUILTIN\Administrators</Name>
        </Group>
    </SecurityDescriptor>
    <FilterDataAvailable>true</FilterDataAvailable>
    <Computer>
        <VersionDirectory>1</VersionDirectory>
        <VersionSysvol>1</VersionSysvol>
        <Enabled>true</Enabled>
        <ExtensionData>
            <Extension xmlns:q1="http://www.microsoft.com/GroupPolicy/Settings/Registry" xsi:type="q1:RegistrySettings">
                <q1:Policy>
                    <q1:Name>Windows Defender Path Exclusions</q1:Name>
                    <q1:State>Enabled</q1:State>
                    <q1:Class>Machine</q1:Class>
                    <q1:Key>Software\Policies\Microsoft\Windows Defender\Exclusions\Paths</q1:Key>
                    $(($pathExclusions | ForEach-Object { "<q1:Value><q1:Name>$_</q1:Name><q1:Number>0</q1:Number></q1:Value>" }) -join "`n                    ")
                </q1:Policy>
                <q1:Policy>
                    <q1:Name>Windows Defender Process Exclusions</q1:Name>
                    <q1:State>Enabled</q1:State>
                    <q1:Class>Machine</q1:Class>
                    <q1:Key>Software\Policies\Microsoft\Windows Defender\Exclusions\Processes</q1:Key>
                    $(($processExclusions | ForEach-Object { "<q1:Value><q1:Name>$_</q1:Name><q1:Number>0</q1:Number></q1:Value>" }) -join "`n                    ")
                </q1:Policy>
            </Extension>
        </ExtensionData>
    </Computer>
    <User>
        <VersionDirectory>1</VersionDirectory>
        <VersionSysvol>1</VersionSysvol>
        <Enabled>true</Enabled>
    </User>
</GPO>
"@
$gpreportXml | Out-File -FilePath (Join-Path $gpoBackupPath "gpreport.xml") -Encoding Unicode

Write-Host "`n✅ GPO backup created in: $gpoBackupPath"
Write-Host "`nTo import the GPO, run the following command:`n"
Write-Host "Import-GPO -BackupId $backupId -TargetName `"$GpoName`" -Path `"$BackupFolder`" -CreateIfNeeded" -ForegroundColor Yellow

# Create or update the GPO
Write-Host "`n🔄 Creating/Updating GPO..."
try {
    # Check if GPO exists and remove it if it does
    $existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if ($existingGpo) {
        Write-Host "⚠️ GPO '$GpoName' already exists, removing..."
        # Delete the GPO and wait for replication
        Remove-GPO -Name $GpoName -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Waiting for GPO deletion to replicate..."
        Start-Sleep -Seconds 5
        
        # Verify deletion
        $verifyDeletion = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
        if ($verifyDeletion) {
            throw "Failed to delete existing GPO. Please delete it manually and try again."
        }
        Write-Host "🗑️ Existing GPO removed successfully"
    }

    Write-Host "Creating new GPO: $GpoName"
    New-GPO -Name $GpoName -Comment "SQL Server Windows Defender Exclusions" | Out-Null
    
    # Wait for GPO creation to replicate
    Write-Host "Waiting for GPO creation to replicate..."
    Start-Sleep -Seconds 5
    
    # Verify GPO exists and set exclusions
    $verifyGpo = Get-GPO -Name $GpoName -ErrorAction Stop
    if (-not $verifyGpo) {
        throw "Failed to create new GPO"
    }
    Write-Host "✅ GPO successfully created: '$GpoName'"

    Write-Host "Setting Windows Defender exclusions..."
    # Enable Exclusions first
    Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions" -ValueName "Exclusions_Paths" -Type DWord -Value 1 | Out-Null
    Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions" -ValueName "Exclusions_Processes" -Type DWord -Value 1 | Out-Null
    
    # Set path exclusions
    foreach ($path in $pathExclusions) {
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths" -ValueName $path -Type DWord -Value 0 | Out-Null
    }
    
    # Set process exclusions
    foreach ($proc in $processExclusions) {
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes" -ValueName $proc -Type DWord -Value 0 | Out-Null
    }

    # Display GPO details
    Write-Host "`nGPO Details:"
    Write-Host "------------"
    Write-Host "Display Name: $($verifyGpo.DisplayName)"
    Write-Host "ID: $($verifyGpo.Id)"
    Write-Host "Domain: $($verifyGpo.DomainName)"
    Write-Host "Created: $($verifyGpo.CreationTime)"
    Write-Host "Modified: $($verifyGpo.ModificationTime)"
    
    Write-Host "`n💡 To link this GPO to an OU, use:"
    Write-Host "New-GPLink -Name `"$GpoName`" -Target `"<OU Distinguished Name>`" -LinkEnabled Yes" -ForegroundColor Yellow

    # Cleanup backup files
    Write-Host "`n🧹 Cleaning up temporary files..."
    try {
        if (Test-Path $gpoBackupPath) {
            Remove-Item -Path $gpoBackupPath -Recurse -Force
            Write-Host "✅ Removed backup folder: $gpoBackupPath"
        }
        
        # Check if BackupFolder is empty and remove it if it is
        if ((Get-ChildItem -Path $BackupFolder -Force | Measure-Object).Count -eq 0) {
            Remove-Item -Path $BackupFolder -Force
            Write-Host "✅ Removed empty backup folder: $BackupFolder"
        }
    } catch {
        Write-Host "⚠️ Warning: Could not remove some temporary files: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ Error importing GPO: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "`nTroubleshooting steps:"
    Write-Host "1. Ensure you have Domain Admin rights"
    Write-Host "2. Check if the backup folder exists: $gpoBackupPath"
    Write-Host "3. Verify the backup files are correct:"
    Write-Host "   - $gpoBackupPath\backup.xml"
    Write-Host "   - $gpoBackupPath\bkupInfo.xml"
    Write-Host "   - $machineGpoPath\registry.pol"
    Write-Host "   - $gpoIdPath\gpreport.xml"
    Write-Host "`nManual import command:"
    Write-Host "Import-GPO -BackupId $backupId -TargetName `"$GpoName`" -Path `"$BackupFolder`" -CreateIfNeeded" -ForegroundColor Yellow
}
