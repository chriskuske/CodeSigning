# Code Signing Wrapper for Azure Key Vault

A PowerShell-based tool for signing code artifacts and container images using certificates stored in Azure Key Vault.

## Quick Start

1. **Download all files** (`CodeSignWrapper.ps1`, `CredentialManager.ps1`, `config.json`) to the same directory.
2. Open PowerShell 5.1+ **on Windows**.
3. Run:
   ```powershell
   .\CodeSignWrapper.ps1 -Path "C:\Path\To\FileOrDirectory"
   ```
4. Follow prompts for certificate and secret if needed.

## One-Click Installer & Context Menu (No Admin Required)

To install CodeSignWrapper and add the right-click context menu for files and folders:

1. Run `Install-CodeSignWrapper.ps1` as your user (no admin needed).
2. All files will be copied to `%LOCALAPPDATA%\CodeSignWrapper`.
3. The context menu "Sign with Azure Key Vault" will be available for files and folders.
4. You may need to restart Explorer or log off/on for the menu to appear.
5. To uninstall, remove `%LOCALAPPDATA%\CodeSignWrapper` and delete the related registry keys under `HKEY_CURRENT_USER\Software\Classes\*\shell\CodeSignWithAzure` and `HKEY_CURRENT_USER\Software\Classes\Directory\shell\CodeSignWithAzure`.

## Simple GUI

A basic GUI is available for users who prefer not to use the command line:

- Run `CodeSignGui.ps1` to open a window where you can browse for a file and sign it with one click.

## Overview

This tool provides a streamlined interface for code signing PowerShell scripts, executables, and various other file types using certificates stored in Azure Key Vault. It also supports signing Docker/container images using Cosign. It handles certificate management, signatures, verification, and SIEM logging in one comprehensive solution.

## Features

- Sign multiple file types with a single command
- Store certificate names for quick access
- Support for recursive directory signing
- SIEM integration for security logging (with structured JSON output)
- Certificate management interface (add/remove/list)
- Progress tracking with detailed statistics
- "Remember last certificate" functionality
- Sign Docker/container images with Cosign and Azure Key Vault
- Enhanced error handling and validation
- Handles paths with spaces robustly
- **Right-click context menu integration (no admin required)**
- **Simple GUI for file selection and signing**

## Requirements

- **Windows** with PowerShell 5.1 or higher (not cross-platform)
- Access to an Azure Key Vault with a code signing certificate
- AzureSignTool-x64.exe v6.0.1 (auto-downloaded if not present)
- Cosign.exe v2.2.3 (auto-downloaded if needed for container signing)
- Internet connectivity for tool download (first run only)
- Appropriate permissions to Azure Key Vault
- For Cosign: **Key must be ECDSA P-256** in Azure Key Vault

## Supported File Types

The tool supports signing the following file types:

| Category      | File Extensions                                      |
|---------------|-----------------------------------------------------|
| Scripts       | .ps1, .psm1, .psd1, .vbs, .js, .wsf                 |
| Executables   | .exe, .dll, .sys                                    |
| Installers    | .msi, .msp, .msix, .appx, .msm, .dat                |
| Containers    | .msix, .appx, .cab, .jar                            |
| Docker/OCI    | .container, .tar, .oci or using -UseContainerSigning|

> **Note on ZIP files:** Standard ZIP files (.zip) cannot be directly signed with Authenticode. To sign files in a ZIP archive, extract them first, sign each file individually, then repackage the ZIP.

> **Note on container signing:** Container signing uses Cosign with Azure Key Vault integration. Both direct references and reference files are supported. **Cosign requires an ECDSA P-256 key in Azure Key Vault.**

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

### Signing Docker/OCI Container Images

```powershell
.\CodeSignWrapper.ps1 -Path "mycontainer:latest" -UseContainerSigning
```

You can also create a text file with the container reference and sign that:

```powershell
.\CodeSignWrapper.ps1 -Path "C:\Path\To\containerref.container"
```

### Using the GUI

```powershell
.\CodeSignGui.ps1
```
- Select a file and click "Sign".

### Using the Context Menu

- After running `Install-CodeSignWrapper.ps1`, right-click any file or folder and choose **"Sign with Azure Key Vault"**.

### Installing/Uninstalling the Context Menu

- **Install:** Run `Install-CodeSignWrapper.ps1` (no admin required).
- **Uninstall:** Delete `%LOCALAPPDATA%\CodeSignWrapper` and remove the registry keys as described above.

## Certificate Management

You can manage stored certificate names via the interactive menu:
- List stored certificates
- Remove stored certificates
- Add new certificates (with optional secret storage)

## Environment Variables

- `AZURE_CERT_NAME` - Set certificate name without interactive prompt
- `AZURE_KEYVAULT_SECRET` - Set Key Vault secret without interactive prompt

## Logging and SIEM Integration

- All operations are logged to a timestamped log file in the `logs` directory.
- Structured JSON logs are sent to SIEM (configurable server/port/protocol).
- Summary and per-file results are included for audit and compliance.

## Updating Tools

- To update AzureSignTool or Cosign, delete the respective `.exe` file in the script directory. The script will auto-download the latest supported version on next run.

## CI/CD Integration

- The script returns exit code `1` on fatal errors (e.g., config validation failure).
- Use standard PowerShell execution in your pipeline scripts.
- No special escaping is needed for paths with spaces.
- Example for Azure DevOps:
  ```yaml
  - powershell: |
      .\CodeSignWrapper.ps1 -Path "$(Build.ArtifactStagingDirectory)" -Recurse
    displayName: 'Code Sign Artifacts'
  ```

## Troubleshooting

### Common Errors

| Error                          | Solution                                                                 |
|--------------------------------|--------------------------------------------------------------------------|
| Configuration validation failed| Check your certificate name and Key Vault secret                         |
| Failed to sign ZIP file        | ZIP files cannot be directly signed. Extract contents, sign, repackage   |
| Signature verification failed  | Ensure the file type is supported for signing                            |
| AzureSignTool authentication failed | Verify your Key Vault permissions and secret values are correct    |
| AzureSignTool not found        | The tool will auto-download v6.0.1 x64, but may fail if internet is blocked|
| Container signing fails        | Ensure the container exists and you have proper registry permissions     |
| Cosign errors                  | Check if the key in Azure KeyVault is compatible with Cosign (ECDSA P-256)|
| Path errors with spaces        | Paths with spaces are now handled. Update to the latest script version   |

### Handling Paths with Spaces

The CodeSignWrapper now properly handles paths with spaces in filenames or directories. If you encounter errors related to paths being split at spaces, update to the latest version.

For CI/CD systems (Bamboo, Jenkins, Azure DevOps):
- No special escaping is needed for paths with spaces
- Paths are automatically quoted for signing tools
- Both relative and absolute paths are supported

## FAQ

**Q: Can I use this on Linux or macOS?**  
A: No, this script is designed for Windows PowerShell 5.1+ only.

**Q: How do I update the signing tools?**  
A: Delete the `AzureSignTool-x64.exe` or `cosign.exe` file and rerun the script.

**Q: What if my certificate is not ECDSA P-256?**  
A: Cosign requires ECDSA P-256 keys in Azure Key Vault for container signing.

**Q: How do I back up my stored credentials?**  
A: Credentials are stored in Windows Credential Manager. Use Windows tools to export/import if needed.

**Q: How do I get the right-click menu?**  
A: Run `Install-CodeSignWrapper.ps1` as your user. No admin rights are required.

**Q: How do I use the GUI?**  
A: Run `CodeSignGui.ps1` and use the window to select and sign a file.

## Contributors

- Matt Mueller (matthew.mueller@teledyne.com)
- Ankit Chahar (ankit.chahar@teledyne.com)

## Release Notes

### v1.4.0 (May 27, 2025)
- Added installer script for right-click context menu (no admin required)
- Added simple GUI for file selection and signing
- Documentation updates for new install and GUI features

### v1.3.0 (May 27, 2025)
- Improved error handling and certificate validation
- Enhanced SIEM logging with structured JSON output
- Support for additional file/container formats (.dat, .msm, .oci, .tar)
- Improved handling of paths with spaces
- Certificate management UI and "remember last certificate" feature
- Cosign integration for container signing
- Performance and reliability improvements

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
