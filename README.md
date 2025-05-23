# SQL Server Defender Exclusion Management

This repository contains PowerShell scripts to automatically discover and configure Windows Defender exclusions for SQL Server environments through Group Policy (GPO).

## Scripts

### Set-SQLDefenderExclusionsGPO.ps1
Main orchestration script that:
- Remotely discovers SQL Server paths and processes that need exclusions
- Generates a standardized exclusions configuration
- Creates/Updates a GPO with the required exclusions

### SQLServerAVExclusionFind.ps1
Discovery script that:
- Scans SQL Server installations
- Identifies critical paths, processes, and file types
- Generates a JSON file containing all required exclusions

### Create-DefenderGPO.ps1
GPO management script that:
- Reads the generated exclusions JSON file
- Creates or updates a Group Policy Object
- Configures Windows Defender exclusions in the GPO

## Prerequisites

- Windows PowerShell 5.1 or PowerShell 7+
- Administrative privileges on the management host
- GroupPolicy PowerShell module
- WinRM enabled on SQL Servers
- Appropriate permissions to create/modify GPOs

## Usage

1. Run the script from a domain controller or management host:
```powershell
.\Set-SQLDefenderExclusionsGPO.ps1 -SQLServerName "your-sql-server"
```

2. The script will:
   - Connect to the specified SQL Server
   - Discover required exclusions
   - Create/Update the Defender GPO automatically

## Output

- `SqlServer_AV_Exclusions.json`: Contains discovered paths and processes
- A Group Policy Object with configured Windows Defender exclusions

## Notes

- Always review the generated exclusions before applying them in production
- Test the GPO in a non-production environment first
- Regular reviews of exclusions are recommended as SQL Server configurations may change

## Security Considerations

- Only exclude necessary paths and processes
- Regularly audit exclusions
- Document any changes to exclusions
- Monitor excluded paths for potential security issues

## Contributing

Feel free to submit issues and enhancement requests!
