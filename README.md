# Code Signing Wrapper for Azure Key Vault

A PowerShell-based tool for signing code artifacts using certificates stored in Azure Key Vault.

## Overview

This tool provides a streamlined interface for code signing PowerShell scripts, executables, and various other file types using certificates stored in Azure Key Vault. It handles certificate management, signatures, and verification in one comprehensive solution.

## Features

- Sign multiple file types with a single command
- Store certificate names for quick access
- Support for recursive directory signing
- SIEM integration for security logging
- Certificate management interface
- Progress tracking with detailed statistics
- "Remember last certificate" functionality

## Requirements

- PowerShell 5.1 or higher
- Access to an Azure Key Vault with a code signing certificate
- AzureSignTool.exe (automatically downloaded if not present)

## Supported File Types

The tool supports signing the following file types:

| Category | File Extensions |
|----------|----------------|
| Scripts | .ps1, .psm1, .psd1, .vbs, .js, .wsf |
| Executables | .exe, .dll, .sys |
| Installers | .msi, .msp, .msix, .appx |
| Containers | .msix, .appx, .cab |

> **Note on ZIP files:** Standard ZIP files (.zip) cannot be directly signed with Authenticode. To sign files in a ZIP archive, extract them first, sign each file individually, then repackage the ZIP.

## Usage

### Basic Usage

```powershell
.\CodeSignWrapper.ps1 -Path "C:\Path\To\File\Or\Directory"
```

### Signing Recursively

```powershell
.\CodeSignWrapper.ps1 -Path "C:\Path\To\Directory" -Recurse
```

### Forcing Re-signing of Already Signed Files

```powershell
.\CodeSignWrapper.ps1 -Path "C:\Path\To\File" -Force
```

### Using a Specific Certificate

```powershell
.\CodeSignWrapper.ps1 -Path "C:\Path\To\File" -CertificateName "MyCertName"
```

### Remembering Last Used Certificate

```powershell
.\CodeSignWrapper.ps1 -Path "C:\Path\To\File" -RememberCertificate
```

## Environment Variables

- `AZURE_CERT_NAME` - Set certificate name without interactive prompt
- `AZURE_KEYVAULT_SECRET` - Set Key Vault secret without interactive prompt

## Troubleshooting

### Common Errors

| Error | Solution |
|-------|----------|
| Configuration validation failed | Check your certificate name and Key Vault secret |
| Failed to sign ZIP file | ZIP files cannot be directly signed. Extract contents, sign individual files, then repackage |
| Signature verification failed | Ensure the file type is supported for signing |

## Security Considerations

- Key Vault secrets are never saved to disk
- Certificate operations are logged to SIEM (if enabled)
- All credential storage is handled securely through Windows Credential Manager

## Example Workflow

1. Run the script without parameters: `.\CodeSignWrapper.ps1`
2. Select your certificate from the menu or enter a new one
3. Enter the Key Vault secret when prompted
4. Enter the path to the file or directory to sign
5. The tool will process and sign all eligible files

## Log Files

Logs are saved in the `logs` subdirectory with timestamps for each signing operation.
