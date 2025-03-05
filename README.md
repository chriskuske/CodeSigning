# TeledyneDevOps Code Signing Framework

This repository contains the Teledyne code signing framework - a streamlined solution for digitally signing PowerShell scripts and executables using Azure Key Vault certificates.

## Overview

The Code Signing Framework simplifies the process of digitally signing code artifacts to ensure:
- Code integrity verification
- Protection against tampering
- Enhanced security compliance
- Standardized signing process across Teledyne teams

## Key Features

- **Azure Key Vault Integration** - Securely uses certificates stored in Azure Key Vault
- **Batch Processing** - Sign multiple files with a single command
- **Recursive Directory Support** - Process entire directory trees
- **SIEM Integration** - Structured logging compatible with Exabeam
- **Certificate Management** - Easily store and manage code signing credentials
- **Comprehensive Logging** - Detailed logging for audit and troubleshooting

## Requirements

- PowerShell 5.1 or higher
- Azure KeyVault access
- Appropriate certificate permissions

## Quick Start

### Basic Usage

```powershell
# Navigate to the repository
cd path\to\repo

# Sign a single file
.\CodeSignWrapper.ps1 -Path "C:\path\to\file.ps1"

# Sign all PowerShell scripts in a directory
.\CodeSignWrapper.ps1 -Path "C:\path\to\directory" -Recurse

# Sign with a specific certificate
.\CodeSignWrapper.ps1 -Path "C:\path\to\file.ps1" -CertificateName "Your-Certificate-Name"
```

### Configuration

The framework uses a `config.json` file that stores:
- Key Vault URL
- Default certificate name
- Client ID and Tenant ID
- Timestamp server URL

This file is automatically created on first run with default values.

## Components

- **CodeSignWrapper.ps1** - Main script for code signing operations
- **CredentialManager.ps1** - Manages signing credentials
- **AzureSignTool.exe** - Backend signing utility (auto-downloaded if missing)
- **config.json** - Configuration settings

## SIEM Integration

The framework includes built-in integration with Exabeam SIEM, providing:
- Structured logging for all signing operations
- Detailed metadata for each signed file
- Comprehensive audit trail
- Success/failure status reporting

## Troubleshooting

Common issues and their resolutions:

1. **Certificate Access Issues**:
   - Verify Azure Key Vault permissions
   - Check certificate name matches exactly what's in Key Vault

2. **Signing Failures**:
   - Examine log files in the logs directory
   - Use the `-Force` parameter to attempt re-signing

3. **Configuration Problems**:
   - Delete config.json to regenerate with defaults
   - Run with `-Verbose` for additional diagnostic information

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

Internal Teledyne use only. All rights reserved.

## Contact

For support or questions, contact: Matthew Mueller (matthew.mueller@teledyne.com)# TeledyneDevOps Code Signing Framework

This repository contains the Teledyne code signing framework - a streamlined solution for digitally signing PowerShell scripts and executables using Azure Key Vault certificates.

## Overview

The Code Signing Framework simplifies the process of digitally signing code artifacts to ensure:
- Code integrity verification
- Protection against tampering
- Enhanced security compliance
- Standardized signing process across Teledyne teams

## Key Features

- **Azure Key Vault Integration** - Securely uses certificates stored in Azure Key Vault
- **Batch Processing** - Sign multiple files with a single command
- **Recursive Directory Support** - Process entire directory trees
- **SIEM Integration** - Structured logging compatible with Exabeam
- **Certificate Management** - Easily store and manage code signing credentials
- **Comprehensive Logging** - Detailed logging for audit and troubleshooting

## Requirements

- PowerShell 5.1 or higher
- Azure KeyVault access
- Appropriate certificate permissions

## Quick Start

### Basic Usage

```powershell
# Navigate to the repository
cd path\to\repo

# Sign a single file
.\CodeSignWrapper.ps1 -Path "C:\path\to\file.ps1"

# Sign all PowerShell scripts in a directory
.\CodeSignWrapper.ps1 -Path "C:\path\to\directory" -Recurse

# Sign with a specific certificate
.\CodeSignWrapper.ps1 -Path "C:\path\to\file.ps1" -CertificateName "Your-Certificate-Name"
```

### Configuration

The framework uses a `config.json` file that stores:
- Key Vault URL
- Default certificate name
- Client ID and Tenant ID
- Timestamp server URL

This file is automatically created on first run with default values.

## Components

- **CodeSignWrapper.ps1** - Main script for code signing operations
- **CredentialManager.ps1** - Manages signing credentials
- **AzureSignTool.exe** - Backend signing utility (auto-downloaded if missing)
- **config.json** - Configuration settings

## SIEM Integration

The framework includes built-in integration with Exabeam SIEM, providing:
- Structured logging for all signing operations
- Detailed metadata for each signed file
- Comprehensive audit trail
- Success/failure status reporting

## Troubleshooting

Common issues and their resolutions:

1. **Certificate Access Issues**:
   - Verify Azure Key Vault permissions
   - Check certificate name matches exactly what's in Key Vault

2. **Signing Failures**:
   - Examine log files in the logs directory
   - Use the `-Force` parameter to attempt re-signing

3. **Configuration Problems**:
   - Delete config.json to regenerate with defaults
   - Run with `-Verbose` for additional diagnostic information

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

Internal Teledyne use only. All rights reserved.

## Contact

For support or questions, contact: Matthew Mueller (matthew.mueller@teledyne.com)
