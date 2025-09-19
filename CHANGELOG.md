# Changelog

All notable changes to this project are documented in this file.

## [Unreleased] - 2025-09-18
- Fix: Avoid re-downloading AzureSignTool/cosign when executables already exist in script directory.
- Add: New CLI switch `-UpdateTools` to force tool re-download when needed.
- Clarify: CredentialManager returns metadata only (secrets not retrievable via cmdkey).
- Docs: README updated to document -UpdateTools and tool behavior.

## [Unreleased] - 2025-09-17
### Changed
- Prevent unnecessary re-downloads of AzureSignTool/cosign when the executables already exist in the script directory.
- Introduced a new CLI switch `-UpdateTools` to force re-download of AzureSignTool and cosign when required.
- Tool lookup and download logic now consistently resolves tools from the script directory (`$scriptDir`) and downloads on-demand.
- CodeSignWrapper no longer fails at startup if AzureSignTool is missing — the tool will be downloaded when first needed.

### Fixed
- Avoided tying the tool-download behavior to the `-Force` switch (which is only for re-signing).
- CredentialManager: clarified that cmdkey does not expose secrets; Get-CodeSigningCredential now returns metadata only.
- Get-CodeSigningCredentialList returns an empty array when no credentials exist (avoids null handling errors).

### Added
- Install-CodeSignWrapper.ps1 installer script (per-user context menu).
- CodeSignGui.ps1 simple GUI to pick file/folder and invoke signing.
- README.md updated with -UpdateTools documentation and credential/export/import clarifications.
- CHANGELOG.md and COMMIT_MESSAGE.txt added.

### Notes
- CI usage: if your Jenkins workspace is a static folder, the script will reuse the existing executables in that directory and will not re-download them each run. Use `-UpdateTools` only when you explicitly want to refresh the tools.
- To update tools manually, either delete the `AzureSignTool-x64.exe` / `cosign.exe` from the script directory or run:
  `. \CodeSignWrapper.ps1 -Path "<path>" -UpdateTools`
