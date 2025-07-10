<#
.SYNOPSIS
    Installs CodeSignWrapper and adds right-click context menu for current user (no admin required).
.DESCRIPTION
    Copies all required files to %LOCALAPPDATA%\CodeSignWrapper, adds context menu for files/folders,
    and signs the .reg file using CodeSignWrapper if desired.
.NOTES
    Run this script as the user (no elevation needed).
#>

$TargetDir = "$env:LOCALAPPDATA\CodeSignWrapper"
$ScriptFiles = @(
    "CodeSignWrapper.ps1",
    "CredentialManager.ps1",
    "config.json"
)
# Copy all files to local appdata
if (-not (Test-Path $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir | Out-Null
}
foreach ($file in $ScriptFiles) {
    Copy-Item -Path (Join-Path $PSScriptRoot $file) -Destination $TargetDir -Force
}

# Write the .reg file for HKCU (current user only)
$regPath = Join-Path $TargetDir "AddCodeSignContextMenu.reg"
$ps1Path = $TargetDir.Replace('\', '\\') + '\\CodeSignWrapper.ps1'
@"
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Classes\*\shell\CodeSignWithAzure]
@="Sign with Azure Key Vault"
"Icon"="powershell.exe"

[HKEY_CURRENT_USER\Software\Classes\*\shell\CodeSignWithAzure\command]
@="powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$ps1Path`" -Path `"%1`""

[HKEY_CURRENT_USER\Software\Classes\Directory\shell\CodeSignWithAzure]
@="Sign with Azure Key Vault"
"Icon"="powershell.exe"

[HKEY_CURRENT_USER\Software\Classes\Directory\shell\CodeSignWithAzure\command]
@="powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$ps1Path`" -Path `"%1`" -Recurse"
"@ | Set-Content $regPath -Encoding ASCII

# Optionally sign the .reg file using CodeSignWrapper (uncomment if desired)
# & "$TargetDir\CodeSignWrapper.ps1" -Path $regPath

# Import the .reg file for current user (no elevation needed)
Start-Process reg.exe -ArgumentList "import `"$regPath`"" -Wait

Write-Host "CodeSignWrapper installed to $TargetDir"
Write-Host "Right-click any file or folder to sign with Azure Key Vault."
Write-Host "You may need to restart Explorer or log off/on for the menu to appear."
