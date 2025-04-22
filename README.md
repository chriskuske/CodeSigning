# Code Signing Wrapper for Azure Key Vault

A PowerShell-based tool for signing code artifacts and container images using certificates stored in Azure Key Vault.

## Overview

This tool provides a streamlined interface for code signing PowerShell scripts, executables, and various other file types using certificates stored in Azure Key Vault. It also supports signing Docker container images using Cosign. It handles certificate management, signatures, and verification in one comprehensive solution.

## Features

- Sign multiple file types with a single command
- Store certificate names for quick access
- Support for recursive directory signing
- SIEM integration for security logging
- Certificate management interface
- Progress tracking with detailed statistics
- "Remember last certificate" functionality
- Sign Docker container images with Cosign

## Requirements

- PowerShell 5.1 or higher
- Access to an Azure Key Vault with a code signing certificate
- AzureSignTool-x64.exe v6.0.1 (automatically downloaded if not present)
- Cosign.exe v2.2.3 (automatically downloaded if needed for container signing)
- Internet connectivity for tool download (first run only)
- Appropriate permissions to Azure Key Vault

## Supported File Types

The tool supports signing the following file types:

| Category | File Extensions |
|----------|----------------|
| Scripts | .ps1, .psm1, .psd1, .vbs, .js, .wsf |
| Executables | .exe, .dll, .sys |
| Installers | .msi, .msp, .msix, .appx |
| Containers | .msix, .appx, .cab |
| Docker Containers | .container, .tar, .oci or using -UseContainerSigning |

> **Note on ZIP files:** Standard ZIP files (.zip) cannot be directly signed with Authenticode. To sign files in a ZIP archive, extract them first, sign each file individually, then repackage the ZIP.

> **Note on container signing:** Container signing uses Cosign with Azure Key Vault integration.

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

### Signing Docker Container Images

```powershell
.\CodeSignWrapper.ps1 -Path "mycontainer:latest" -UseContainerSigning
```

You can also create a text file with the container reference and sign that:

```powershell
.\CodeSignWrapper.ps1 -Path "C:\Path\To\containerref.container" 
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
| AzureSignTool authentication failed | Verify your Key Vault permissions and secret values are correct |
| AzureSignTool not found | The tool will automatically download v6.0.1 x64 version, but may fail if internet access is restricted |
| Container signing fails | Ensure the container exists and you have proper permissions to access the registry |
| Cosign errors | Check if the key in Azure KeyVault is compatible with Cosign (ECDSA P-256) |

## Security Considerations

- Key Vault secrets are never saved to disk
- Certificate operations are logged to SIEM (if enabled)
- All credential storage is handled securely through Windows Credential Manager
- Temporary secrets are zeroed out from memory after use
- All commands are logged with detailed attribution

## Example Workflow

1. Run the script without parameters: `.\CodeSignWrapper.ps1`
2. Select your certificate from the menu or enter a new one
3. Enter the Key Vault secret when prompted
4. Enter the path to the file or directory to sign
5. The tool will process and sign all eligible files

## Container Signing

The tool integrates with Cosign for container signing. It uses the same Azure Key Vault certificates that are used for code signing, providing a consistent security model.

### Container Signing Requirements

- Container must exist in a registry accessible to the signing machine
- The Azure Key Vault key must be compatible with Cosign's ECDSA requirements
- Container images should be specified either:
  - Directly as a parameter with -UseContainerSigning
  - In a file with .container extension containing the image reference
  - As an OCI artifact (.oci file)
  - As a TAR archive (.tar file)

### Verifying Container Signatures

To verify a signed container:

```powershell
cosign verify --key azurekms://[keyvault-url]/[key-name] [container-reference]
```

## Log Files

Logs are saved in the `logs` subdirectory with timestamps for each signing operation. These logs contain detailed information about each signing operation including:

- Files processed
- Signing status (success/failure)
- Certificate details
- Timestamps
- Error messages (if applicable)

## Author Information

Developed by Matt Mueller (matthew.mueller@teledyne.com) for Teledyne Technologies Incorporated.

Updated: April 22, 2025

© 2025 Teledyne Technologies Incorporated. All rights reserved.
