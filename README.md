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
| Path errors with spaces | Paths with spaces are now properly handled. If you see "File not found" errors where the path is split at spaces, make sure you're using the latest version of the script |

### Handling Paths with Spaces

The CodeSignWrapper now properly handles paths with spaces in the filenames or directories. If you encounter any errors related to paths being split at spaces (like "File 'C:\Path\To\My' does not exist. File 'File.dll' does not exist"), please update to the latest version which addresses this issue.

For CI/CD systems like Bamboo, Jenkins, or Azure DevOps:
- No special escaping is needed for paths with spaces
- Paths are automatically quoted correctly when passed to signing tools
- Both relative and absolute paths are supported

## Release Notes

### v1.2.0 (April 25, 2025)
- Fixed handling of paths containing spaces
- Enhanced error reporting with specific messages
- Improved JSON configuration validation with better error messages
- Fixed container signing with quoted paths

### v1.1.0 (April 22, 2025)
- Added support for container signing with Cosign
- Enhanced SIEM logging format
- Added certificate management interface
- Added remembered certificate functionality

### v1.0.0 (February 11, 2024)
- Initial release with support for code signing using Azure Key Vault certificates
- Support for multiple file types and recursive directory signing
