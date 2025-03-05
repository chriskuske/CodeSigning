# Azure Code Signing Tool

A PowerShell-based code signing solution that uses certificates stored in Azure Key Vault.

## Prerequisites

- Windows PowerShell 5.1 or later
- Access to an Azure Key Vault containing your code signing certificate
- Azure Key Vault application credentials (Client ID, Tenant ID)

## Files Included

- `CodeSignWrapper.ps1` - Main script for code signing
- `CredentialManager.ps1` - Helper functions for certificate name management
- `AzureSignTool.exe` - Binary tool for Azure Key Vault signing

## Quick Start

1. Extract all files to a directory of your choice
2. Run `CodeSignWrapper.ps1` with no parameters for interactive mode
3. Select or enter your certificate name
4. Enter your Key Vault secret when prompted
5. Enter the path to the file or directory you want to sign

## Features

### Certificate Management
- Store frequently used certificate names
- List stored certificates
- Remove stored certificates
- Quick selection from stored certificates

### Signing Options

# Sign a single file
.\CodeSignWrapper.ps1 -Path ".\script.ps1"

# Sign all supported files in a directory
.\CodeSignWrapper.ps1 -Path ".\Scripts" -Recurse

# Force re-signing of already signed files
.\CodeSignWrapper.ps1 -Path ".\Scripts" -Force

# Use a specific certificate
.\CodeSignWrapper.ps1 -Path ".\Scripts" -CertificateName "MyCert"

- Parameters
  - `-Path` - File or directory to sign
  - `-Include` - File patterns to include (default: *.ps1, *.psm1, *.psd1, *.dll, *.exe)
  - `-Exclude` - File patterns to exclude
  - `-Recurse` - Process subdirectories
  - `-Force` - Re-sign already signed files
  - `-CertificateName` - Specify certificate name directly

### Configuration
The script creates a config.json with default settings:

{
    "KeyVaultUrl": "https://your-vault.vault.azure.net/",
    "DefaultCertificateName": "YourDefaultCert",
    "ClientId": "your-client-id",
    "TenantId": "your-tenant-id",
    "TimestampServer": "http://timestamp.digicert.com"
}

### Security Features
- Secure secret handling (never stored)
- Certificate name storage for convenience
- Azure Key Vault integration
- RFC3161 timestamp server support

### Logging
- Detailed logging in logs directory
- Color-coded console output
- Success/failure statistics
- Certificate details for signed files