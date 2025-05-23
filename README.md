# Microsoft Defender Repository

A comprehensive collection of tools, scripts, and resources for Microsoft Defender management and configuration across different environments.

## Contents

- [Defender for Servers](#defender-for-servers)
  - [SQL Server Antivirus Exclusions](#sql-server-antivirus-exclusions)
  - [Exchange Server Antivirus Exclusions](#exchange-server-antivirus-exclusions)


## Defender for Servers

### SQL Server Antivirus Exclusions

Located in the `/defender` directory, these scripts help automate the configuration of Windows Defender exclusions for SQL Server environments through Group Policy (GPO).

#### Available Scripts

1. **Set-SQLDefenderExclusionsGPO.ps1**
   - Orchestrates the entire exclusion configuration process
   - Discovers SQL Server paths and processes remotely
   - Creates or updates GPOs with standardized exclusions

2. **SQLServerAVExclusionFind.ps1**
   - Performs detailed SQL Server installation scanning
   - Identifies paths, processes, and file types requiring exclusions
   - Generates structured JSON output for configuration

3. **Create-DefenderGPO.ps1**
   - Handles GPO creation and management
   - Applies discovered exclusions to Group Policy
   - Ensures consistent configuration across environments

#### Prerequisites

- Windows PowerShell 5.1 or PowerShell 7+
- Administrative privileges on the management host
- GroupPolicy PowerShell module
- WinRM enabled on SQL Servers
- Appropriate permissions to create/modify GPOs

#### Quick Start

1. Run from a domain controller or management host:
```powershell
.\Set-SQLDefenderExclusionsGPO.ps1 -SQLServerName "your-sql-server"
```

2. Review the generated `SqlServer_AV_Exclusions.json` file
3. Monitor the created/updated GPO in Group Policy Management Console

#### Output

- `SqlServer_AV_Exclusions.json`: Contains discovered paths and processes
- A Group Policy Object with configured Windows Defender exclusions

#### Security Best Practices

- Review all exclusions before applying in production
- Test configurations in non-production first
- Perform regular audits of applied exclusions
- Document any modifications to exclusion lists
- Monitor excluded paths for security events

### Exchange Server Antivirus Exclusions

Located in the `/defender` directory, this script helps identify and document required Windows Defender exclusions for Microsoft Exchange Server environments.

#### Available Scripts

1. **ExchangeAVExclusionFind.ps1**
   - Performs comprehensive Exchange Server installation scanning
   - Discovers critical paths, processes, and file extensions
   - Identifies Database Availability Group (DAG) components
   - Generates structured JSON output for configuration

#### Key Features

- Automatic Exchange installation detection
- Complete process discovery
- File extension pattern matching
- DAG component identification
- Unified Messaging path detection
- Transport role configuration scanning
- IIS component detection

#### Prerequisites

- Windows PowerShell 5.1 or PowerShell 7+
- Administrative privileges on the Exchange Server
- Exchange Server 2016 or later installed

#### Quick Start

1. Run on an Exchange Server:
```powershell
.\ExchangeAVExclusionFind.ps1
```

2. Review the generated `Exchange_AV_Exclusions.json` file
3. Use the findings to configure your antivirus exclusions

#### Output

- `Exchange_AV_Exclusions.json`: Contains discovered paths, processes, and recommended exclusions
- Console output with real-time discovery information

## Contributing

Contributions are welcome! Please feel free to submit:
- Bug reports
- Feature requests
- Pull requests
- Documentation improvements

## License

This repository is licensed under the MIT License - see the LICENSE file for details.

## Security Notes

When implementing any security configurations, especially exclusions:
1. Always follow the principle of least privilege
2. Document all changes thoroughly
3. Implement proper change management procedures
4. Regular review and cleanup of configurations
