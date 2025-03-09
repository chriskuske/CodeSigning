# Azure Code Signing Tool

A PowerShell-based code signing solution that uses certificates stored in Azure Key Vault, providing a streamlined interface for signing PowerShell scripts, modules, and executables in enterprise environments.

## Overview

This tool simplifies the code signing process by:
- Managing connections to Azure Key Vault to access code signing certificates
- Providing a user-friendly interface for certificate selection
- Handling batch signing operations with detailed logging
- Integrating with enterprise SIEM systems for security monitoring
- Securely managing certificate information for repeated use

## Prerequisites

- Windows PowerShell 5.1 or later
- Access to an Azure Key Vault containing a code signing certificate
- Azure Key Vault application credentials (Client ID, Tenant ID)
- Appropriate permissions to the certificate in Azure Key Vault

## Installation

1. Download and extract the ZIP package to a directory of your choice
2. Ensure all files are extracted together in the same directory:
   - `CodeSignWrapper.ps1` (Main script)
   - `CredentialManager.ps1` (Helper functions)
   - `AzureSignTool.exe` (Core signing binary)
   - `config.json` (Configuration file)

No formal installation is required; the tool operates directly from the extracted location.

## First-Time Setup

1. The `config.json` file is pre-configured with organization-wide settings:
   ```json
   {
       "KeyVaultUrl": "https://itss-managed-certs.vault.azure.net/",
       "DefaultCertificateName": "ITSS-Code-Signing",
       "ClientId": "c699b1cf-73bd-4896-8dd2-74ea7d99dc60",
       "TenantId": "e324592a-2653-45c7-9bfc-597c36917127",
       "TimestampServer": "http://timestamp.digicert.com"
   }
   ```

2. **Important:** Do not modify the ClientId, TenantId, or TimestampServer values as these are standardized across the organization.

3. You only need to update the following if necessary:
   - `DefaultCertificateName`: Only if you have a different default certificate you prefer to use

3. Test the configuration by running a simple signing operation:
   ```powershell
   .\CodeSignWrapper.ps1 -Path "test.ps1"
   ```

## Basic Usage

### Interactive Mode

Running the script without parameters launches interactive mode:

```powershell
.\CodeSignWrapper.ps1
```

This will:
1. Present a menu of available certificates
2. Prompt for the Key Vault secret
3. Ask for the file or directory to sign

### Command-Line Mode

Sign a single file:
```powershell
.\CodeSignWrapper.ps1 -Path "C:\Scripts\MyScript.ps1"
```

Sign all supported files in a directory:
```powershell
.\CodeSignWrapper.ps1 -Path "C:\Scripts" -Recurse
```

Use a specific certificate:
```powershell
.\CodeSignWrapper.ps1 -Path "C:\Scripts" -CertificateName "MyCertificate"
```

Force re-signing of already signed files:
```powershell
.\CodeSignWrapper.ps1 -Path "C:\Scripts" -Force
```

## Advanced Usage

### Custom File Patterns

Specify which file types to include:
```powershell
.\CodeSignWrapper.ps1 -Path "C:\Scripts" -Include "*.ps1","*.psm1","*.dll"
```

Exclude specific file patterns:
```powershell
.\CodeSignWrapper.ps1 -Path "C:\Scripts" -Recurse -Exclude "*-old.ps1","*-test.ps1"
```

### Certificate Management

Store a certificate name for quick access:
```powershell
# The wrapper will prompt you to save new certificate names
.\CodeSignWrapper.ps1 -CertificateName "NewCertName" -RememberCertificate
```

Access the certificate management menu:
```powershell
# Run the tool and select "Manage stored certificates" from the menu
.\CodeSignWrapper.ps1
```

### Environment Variables

You can use environment variables for non-interactive usage:
```powershell
$env:AZURE_CERT_NAME = "MyCertificate"
$env:AZURE_KEYVAULT_SECRET = "YourSecretValue"  # Handle securely in production
.\CodeSignWrapper.ps1 -Path "C:\Scripts"
```

## Configuration Reference

The `config.json` file contains the following settings:

| Setting | Description | Can Modify |
|---------|-------------|------------|
| `KeyVaultUrl` | URL of your Azure Key Vault | **NO** - Organization standard |
| `DefaultCertificateName` | The default certificate to use when none is specified | Yes - based on your needs |
| `ClientId` | The Azure AD application ID with Key Vault access | **NO** - Organization standard |
| `TenantId` | Your Azure AD tenant ID | **NO** - Organization standard |
| `TimestampServer` | The RFC3161 timestamp server URL | **NO** - Organization standard |

**Note:** The ClientId, TenantId, and TimestampServer are standardized across the organization and should not be modified. These values are managed centrally to ensure consistent security policies.

## SIEM Integration

This tool automatically logs all signing activities to the organization's SIEM system in accordance with IT Policy requirements. This integration is:

- Pre-configured in the script
- Mandatory for compliance and security monitoring
- Not modifiable by end users

All code signing events will be logged with appropriate metadata for audit purposes.

## Logging

All signing operations are logged to the `logs` directory with timestamps:
- Success and failure counts
- Certificate details
- File information
- Error messages

Review logs in:
```
.\logs\signing_YYYYMMDD_HHMMSS.log
```

## Security Best Practices

1. **Secret Management**:
   - Never store Key Vault secrets in plain text files
   - The tool does not persist secrets between sessions
   - Consider using a secure secret management solution for automation

2. **Certificate Handling**:
   - Only store certificate names, not credentials, for repeated use
   - Regularly rotate certificates following your organization's policy
   - Use the `-RememberCertificate` option only on trusted workstations

3. **Access Control**:
   - Limit Azure Key Vault access to necessary users and services
   - Use separate certificates for different applications or teams
   - Leverage SIEM integration for auditing all signing operations

## Troubleshooting

### Common Issues

**Error: "Failed to validate configuration"**
- Verify Key Vault URL is correct
- Ensure certificate name exists in the vault
- Check that the ClientId has GET permissions on certificates and secrets

**Error: "Access denied to Key Vault"**
- Verify the secret is correct
- Check Azure AD application permissions
- Ensure the certificate exists and hasn't expired

**Error: "AzureSignTool not found"**
- Ensure AzureSignTool.exe is in the same directory as the wrapper
- Try running with `-Force` to re-download the binary

### Debug Mode

For detailed troubleshooting, run in verbose mode:
```powershell
$VerbosePreference = 'Continue'
.\CodeSignWrapper.ps1 -Path "C:\Scripts"
```

## Version Information

**Version:** 1.0 (March 2025)
**Author:** Matt Mueller (matthew.mueller@teledyne.com)

## License

This project is licensed under the MIT License - see the LICENSE file for details.
