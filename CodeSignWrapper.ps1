<#
.SYNOPSIS
    Wrapper script for code signing using Azure Key Vault certificates
.DESCRIPTION
    Provides a streamlined interface for code signing PowerShell scripts, executables,
    and containers using certificates stored in Azure Key Vault. Supports storing 
    certificate names for quick access and handles all aspects of the signing process.
.NOTES
    Created: February 11, 2024
    Updated: May 27, 2025
    Author: Matt Mueller (matthew.mueller@teledyne.com)
    Company: Teledyne Technologies Incorporated
    Contributors: Ankit Chahar (ankit.chahar@teledyne.com)
.LINK
    https://github.com/TeledyneDevOps/CodeSigning
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    # Path to file or directory to be signed
    [Parameter(Mandatory=$false, Position=0)]
    [string]$Path,
    
    # File patterns to include for signing - Added .dat and .msm per Ankit's changes
    [Parameter(Mandatory=$false)]
    [string[]]$Include = @("*.ps1", "*.psm1", "*.psd1", "*.dll", "*.exe", "*.zip", "*.msi", "*.msix", 
                         "*.appx", "*.cab", "*.sys", "*.vbs", "*.js", "*.wsf", "*.cat", "*.msp", "*.jar",
                         "*.container", "*.tar", "*.oci", "*.dat", "*.msm"),
    
    # File patterns to exclude from signing
    [Parameter(Mandatory=$false)]
    [string[]]$Exclude = @(),
    
    # Path to configuration file
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = "$PSScriptRoot\config.json",
    
    # Directory for storing log files
    [Parameter(Mandatory=$false)]
    [string]$LogDir = "$PSScriptRoot\logs",
    
    # Name of certificate to use for signing
    [Parameter(Mandatory=$false)]
    [string]$CertificateName,
    
    # Process directories recursively
    [Parameter(Mandatory=$false)]
    [switch]$Recurse,
    
    # Force signing of already signed files
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    # SIEM server address for logging
    [Parameter(Mandatory=$false)]
    [string]$SIEMServer = "us1-nslb-ecs.tdy.teledyne.com",
    
    # SIEM server port for logging
    [Parameter(Mandatory=$false)]
    [int]$SIEMPort = 11818,
    
    # Protocol to use for SIEM logging
    [Parameter(Mandatory=$false)]
    [ValidateSet("TCP", "UDP")]
    [string]$SIEMProtocol = "TCP",
    
    # Enable/disable SIEM logging
    [Parameter(Mandatory=$false)]
    [bool]$EnableSIEM = $true,
    
    # Remember the selected certificate for future use
    [Parameter(Mandatory=$false)]
    [switch]$RememberCertificate,
    
    # Use Cosign for container signing instead of AzureSignTool
    [Parameter(Mandatory=$false)]
    [switch]$UseContainerSigning
)

Begin {
    $ErrorActionPreference = "Stop"
    Set-StrictMode -Version Latest
    
    # Ensure script can find its dependencies regardless of where it's run from
    $scriptPath = $MyInvocation.MyCommand.Path
    $scriptDir = Split-Path -Parent $scriptPath
    
    # Update paths to be relative to script location
    $ConfigPath = Join-Path $scriptDir "config.json"
    $LogDir = Join-Path $scriptDir "logs"
    $credentialManagerPath = Join-Path $scriptDir "CredentialManager.ps1"
    $lastUsedCertPath = Join-Path $scriptDir "lastcert.txt"
    
    # Create directories if they don't exist
    if (-not (Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }

    # Initialize log file with timestamp
    $LogFile = Join-Path $LogDir ("signing_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))

    # Enhanced SIEM logging for better visibility
    function Send-ToSIEM {
        param(
            [string]$Message,
            [string]$Level = "INFO",
            [string]$EventType = "CodeSigning",
            [string]$Action = "",
            [hashtable]$Properties = @{ },
            [switch]$ForceSend = $false
        )
        
        # Only send to SIEM if explicitly forced or if EnableSIEM is true
        # This allows us to collect logs but only send the final summary
        if ((-not $EnableSIEM) -and (-not $ForceSend)) { return }
        
        try {
            # Create a structured log event with Exabeam expected fields
            $eventProperties = @{
                # Standard Exabeam fields based on your screenshot
                "activity" = $EventType
                "activity_type" = "code-signing"  
                "landscape" = "endpoint security"
                # Improved mapping of log levels to outcomes
                "outcome" = switch ($Level) {
                    "SUCCESS" { "success" }
                    "ERROR" { "failure" }
                    "WARN" { "warning" }
                    "INFO" { "informational" }
                    default { "informational" }
                }
                "platform" = "Windows"
                "product" = "CodeSignWrapper"
                "product_category" = "security operation"
                "subject" = $Action
                "time" = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                "vendor" = "Teledyne"
                "src_ip" = [string](Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" } | Select-Object -First 1 -ExpandProperty IPAddress)
                "user" = $env:USERNAME
                "host" = $env:COMPUTERNAME
                "Message" = $Message
            }
            
            # Add any additional properties 
            foreach ($key in $Properties.Keys) {
                $eventProperties[$key] = $Properties[$key]
            }
            
            # Convert to JSON for better parsing in SIEM
            $jsonEvent = $eventProperties | ConvertTo-Json -Compress
            
            if ($SIEMProtocol -eq "TCP") {
                $client = New-Object System.Net.Sockets.TcpClient
                $client.Connect($SIEMServer, $SIEMPort)
                $stream = $client.GetStream()
                $writer = New-Object System.IO.StreamWriter($stream)
                $writer.WriteLine($jsonEvent)
                $writer.Flush()
                $writer.Close()
                $stream.Close()
                $client.Close()
            }
            else { # UDP
                $endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($SIEMServer), $SIEMPort)
                $udpClient = New-Object System.Net.Sockets.UdpClient
                $bytes = [System.Text.Encoding]::ASCII.GetBytes($jsonEvent)
                $udpClient.Send($bytes, $bytes.Length, $endpoint)
                $udpClient.Close()
            }
        }
        catch {
            # Log error locally but don't fail the main operation
            $errorMessage = "Failed to send to SIEM: $_"
            Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [ERROR] $errorMessage"
            Write-Host $errorMessage -ForegroundColor Red
        }
    }
    
    function Write-Log {
        <#
        .SYNOPSIS
            Writes formatted log messages to both file and console, and SIEM if enabled
        .DESCRIPTION
            Handles logging of messages with timestamps and different severity levels,
            writing to a log file, optionally to the console with color coding,
            and to SIEM if enabled.
        .PARAMETER Message
            The message to log
        .PARAMETER Level
            The severity level (INFO, WARN, ERROR, SUCCESS)
        .PARAMETER Console
            Switch to indicate if message should also be written to console
        .PARAMETER Properties
            Additional properties to include in SIEM logs as a hashtable
        #>
        param(
            [string]$Message,
            [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')]
            [string]$Level = "INFO",
            [switch]$Console,
            [string]$EventType = "CodeSigning",
            [string]$Action = "",
            [hashtable]$Properties = @{ },
            [switch]$SendToSIEM = $false
        )
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "$timestamp [$Level] $Message"
        
        # Write to log file
        Add-Content -Path $LogFile -Value $logMessage
        
        # Write to console if requested or for important messages
        if ($Console -or $Level -in @('ERROR', 'SUCCESS') -or $VerbosePreference -eq 'Continue') {
            $color = switch ($Level) {
                'ERROR' { 'Red' }
                'WARN'  { 'Yellow' }
                'SUCCESS' { 'Green' }
                default { 'Gray' }
            }
            Write-Host $logMessage -ForegroundColor $color
        }
        
        # Only send to SIEM if explicitly requested now - we'll do a comprehensive send at the end
        if ($SendToSIEM) {
            Send-ToSIEM -Message $Message -Level $Level -EventType $EventType -Action $Action -Properties $Properties
        }
    }

    # Check for required files
    $requiredFiles = @(
        @{Name = "CredentialManager.ps1"; Path = $credentialManagerPath},
        @{Name = "AzureSignTool-x64.exe"; Path = (Join-Path $scriptDir "AzureSignTool-x64.exe")}
    )

    foreach ($file in $requiredFiles) {
        if (-not (Test-Path $file.Path)) {
            throw "Required file '$($file.Name)' not found in script directory. Please ensure all components are extracted together."
        }
    }

    # Load CredentialManager
    . $credentialManagerPath

    # Initialize or load config with better error handling
    if (-not (Test-Path $ConfigPath)) {
        try {
            @{
                KeyVaultUrl = "https://itss-managed-certs.vault.azure.net/"
                DefaultCertificateName = "ITSS-Code-Signing"
                ClientId = "c699b1cf-73bd-4896-8dd2-74ea7d99dc60"
                TenantId = "e324592a-2653-45c7-9bfc-597c36917127"
                TimestampServer = "http://timestamp.digicert.com"
            } | ConvertTo-Json | Set-Content $ConfigPath -ErrorAction Stop
            Write-Log "Created default configuration at $ConfigPath" -Console
        }
        catch {
            throw "Failed to create config file at '$ConfigPath': $_"
        }
    }

    try {
        # Read the raw content of the config file first for validation
        $rawConfig = Get-Content $ConfigPath -Raw -ErrorAction Stop
        
        # Look for common JSON errors before parsing
        if ($rawConfig.StartsWith("//")) {
            throw "JSON files cannot contain comments. Remove any comment lines starting with // from the config file."
        }
        
        if ($rawConfig -match '(^|\s)//') {
            throw "JSON files cannot contain comments. Remove any comment lines containing // from the config file."
        }
        
        # Now try to parse as JSON
        try {
            $config = $rawConfig | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            # Provide a more helpful error message
            if ($_.Exception.Message -match "Invalid JSON primitive") {
                throw "Invalid JSON format in '$ConfigPath'. JSON files cannot contain comments or trailing commas. Error: $_"
            }
            else {
                throw "Failed to parse JSON from '$ConfigPath': $_"
            }
        }
        
        # Validate required fields
        $requiredFields = @("KeyVaultUrl", "DefaultCertificateName", "ClientId", "TenantId", "TimestampServer")
        $missingFields = $requiredFields.Where({ -not $config.PSObject.Properties.Name.Contains($_) })
        
        if ($missingFields.Count -gt 0) {
            throw "Config file is missing required fields: $($missingFields -join ', ')"
        }
    }
    catch {
        throw "Failed to load config from '$ConfigPath': $_"
    }

    # Track statistics
    $stats = @{
        Total = 0
        Success = 0
        Failed = 0
        Skipped = 0
    }
    
    # Add array to track all signed files with details
    $signedFilesDetails = @()
    
    function Get-AzureSignTool {
        <#
        .SYNOPSIS
            Downloads or returns path to AzureSignTool executable
        .DESCRIPTION
            Manages the AzureSignTool executable, downloading it if not present
            or returning the path if it exists. Handles backup/restore during updates.
        .OUTPUTS
            String containing the path to AzureSignTool-x64.exe
        .NOTES
            The tool is downloaded from GitHub if not present or if Force is specified.
            A backup is created during updates to ensure recoverability.
        #>
        $toolPath = "$PSScriptRoot\AzureSignTool-x64.exe"
        if ((Test-Path $toolPath) -and (-not $Force)) { return $toolPath }

        try {
            Write-Log "Downloading Azure Sign Tool..." -Console
            # Always use the x64 version as specified
            $url = "https://github.com/vcsjones/AzureSignTool/releases/download/v6.0.1/AzureSignTool-x64.exe"
            
            if (Test-Path $toolPath) { Copy-Item $toolPath "$toolPath.backup" -Force }
            
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $url -OutFile $toolPath
            if (Test-Path "$toolPath.backup") { Remove-Item "$toolPath.backup" -Force }
            Write-Log "Azure Sign Tool v6.0.1 downloaded successfully" -Console
            return $toolPath
        }
        catch {
            Write-Log $_.Exception.Message -Level ERROR -Console
            if (Test-Path "$toolPath.backup") { 
                Move-Item "$toolPath.backup" $toolPath -Force
                Write-Log "Restored previous version" -Level WARN
            }
            throw
        }
    }

    function Get-Cosign {
        <#
        .SYNOPSIS
            Downloads or returns path to Cosign executable
        .DESCRIPTION
            Manages the Cosign executable, downloading it if not present
            or returning the path if it exists. Used for container signing.
        .OUTPUTS
            String containing the path to cosign.exe
        .NOTES
            The tool is downloaded from GitHub if not present or if Force is specified.
            A backup is created during updates to ensure recoverability.
            Cosign v2.2.3 is used for container signing with Azure Key Vault integration.
        #>
        $toolPath = "$PSScriptRoot\cosign.exe"
        if ((Test-Path $toolPath) -and (-not $Force)) { return $toolPath }
        
        try {
            Write-Log "Downloading Cosign tool for container signing..." -Console
            # Download latest version of Cosign
            $url = "https://github.com/sigstore/cosign/releases/download/v2.2.3/cosign-windows-amd64.exe"
            
            if (Test-Path $toolPath) { Copy-Item $toolPath "$toolPath.backup" -Force }
            
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $url -OutFile $toolPath
            if (Test-Path "$toolPath.backup") { Remove-Item "$toolPath.backup" -Force }
            Write-Log "Cosign v2.2.3 downloaded successfully" -Console
            return $toolPath
        }
        catch {
            Write-Log $_.Exception.Message -Level ERROR -Console
            if (Test-Path "$toolPath.backup") { 
                Move-Item "$toolPath.backup" $toolPath -Force
                Write-Log "Restored previous version" -Level WARN
            }
            throw
        }
    }

    function Test-FileSignable {
        <#
        .SYNOPSIS
            Tests if a file can and should be signed
        .DESCRIPTION
            Checks if a file meets all criteria for signing:
            - Exists and is not empty
            - Matches include patterns
            - Doesn't match exclude patterns
            - Is a supported file type for signing
            - Not already signed (unless Force is specified)
        .PARAMETER FilePath
            The path to the file to test
        .OUTPUTS
            Boolean indicating if the file should be signed
        .NOTES
            Special handling is included for container files and archives.
            Already signed files are skipped unless Force is specified.
        #>
        param([string]$FilePath)
        
        try {
            # Check if file exists and is not empty
            if (-not (Test-Path $FilePath -PathType Leaf)) { return $false }
            $fileObj = Get-Item $FilePath
            if ($fileObj.Length -eq 0) { return $false }
            
            # Check if file matches include patterns
            $fileName = Split-Path $FilePath -Leaf
            $included = $false
            foreach ($pattern in $Include) {
                if ($fileName -like $pattern) {
                    $included = $true
                    break
                }
            }
            if (-not $included) { return $false }
            
            # Check if file matches exclude patterns
            foreach ($pattern in $Exclude) {
                if ($fileName -like $pattern) { return $false }
            }
            
            # Handle special case for container images and OCI artifacts
            $extension = [System.IO.Path]::GetExtension($fileName).ToLower()
            if ($extension -in @('.container', '.tar', '.oci') -or $UseContainerSigning) {
                # Container files or references need special handling with Cosign
                Write-Log "Detected container artifact for Cosign signing" -Level INFO -Console
                return $true
            }
            
            # Handle special case for .zip and archive files - they must be PE files or valid scripts
            if ($extension -in @('.zip', '.msix', '.appx', '.cab', '.jar')) {
                # We can't sign regular ZIP files directly, but can sign some container formats
                if ($extension -eq '.zip') {
                    Write-Log "Warning: Standard ZIP files cannot be directly signed with Authenticode." -Level WARN -Console
                    Write-Log "Only PE files inside ZIP archives can be signed (after extraction)." -Level WARN -Console
                    return $false # Skip ZIP files by default
                }
                else {
                    # Other container formats like MSIX can be signed
                    Write-Log "Note: $extension file will be signed as a container. Contents won't be individually signed." -Level INFO -Console
                }
            }
            
            # If Force is true or file isn't signed, allow signing
            try {
                # Not all files support Get-AuthenticodeSignature, so wrap in try/catch
                $sig = Get-AuthenticodeSignature $FilePath -ErrorAction SilentlyContinue
                if ($null -ne $sig -and -not $Force -and $sig.Status -eq "Valid") {
                    # Enhanced logging for already signed files
                    $fileObj = Get-Item $FilePath
                    $fileMetadata = @{
                        "FileName" = $fileObj.Name
                        "FilePath" = $fileObj.FullName
                        "FileSize" = $fileObj.Length
                        "FileType" = $fileObj.Extension.TrimStart('.')
                        "SignatureStatus" = $sig.Status.ToString()
                    }
                    
                    # Add certificate details if available
                    if ($sig.SignerCertificate -ne $null) {
                        $fileMetadata["CertificateSubject"] = $sig.SignerCertificate.Subject
                        $fileMetadata["CertificateIssuer"] = $sig.SignerCertificate.Issuer
                        $fileMetadata["CertificateExpiry"] = $sig.SignerCertificate.NotAfter.ToString()
                        $fileMetadata["CertificateThumbprint"] = $sig.SignerCertificate.Thumbprint
                    }
                    
                    Write-Log -Message "File already signed: $FilePath" -Level INFO -Console -EventType "CodeSigning" -Action "AlreadySigned" -Properties $fileMetadata
                    
                    return $false
                }
                
                return $true
            }
            catch {
                # If we can't check signature status, assume file is signable if it matched our patterns
                Write-Log "Unable to verify signature on $FilePath. Will attempt to sign based on extension." -Level WARN -Console
                return $true
            }
        }
        catch {
            # Enhanced error logging with structured data
            $errorMetadata = @{
                "EventType" = "CodeSigning" 
                "Action" = "Error"
                "FilePath" = $FilePath
                "FileName" = (Split-Path $FilePath -Leaf)
                "ErrorMessage" = $_.Exception.Message
            }
            Write-Log "Error checking file $FilePath : $_" -Level ERROR -Properties $errorMetadata
            return $false
        }
    }

    function Get-LastUsedCertificate {
        if (Test-Path $lastUsedCertPath) {
            return Get-Content $lastUsedCertPath -ErrorAction SilentlyContinue
        }
        return $null
    }
    
    function Set-LastUsedCertificate {
        param([string]$CertName)
        
        if ($RememberCertificate -and -not [string]::IsNullOrWhiteSpace($CertName)) {
            $CertName | Out-File $lastUsedCertPath -Force
        }
    }

    # Enhanced certificate selection with visual menu
    function Select-Certificate {
        # Get stored certificates first
        $storedCerts = @(cmdkey /list | Select-String "CodeSigning_" | ForEach-Object {
            $_.ToString() -replace ".*CodeSigning_", ""
        })
        
        $lastUsed = Get-LastUsedCertificate
        
        # Create options array with padding for better display
        $options = @()
        
        # Fix: Handle empty $storedCerts collection
        $storedCertMaxLength = 0
        if ($storedCerts.Count -gt 0) {
            $storedCertMaxLength = ($storedCerts | Measure-Object -Property Length -Maximum).Maximum
        }
        
        # Fix: Chain Math::Max calls to handle multiple values
        $maxLength = [Math]::Max(
            [Math]::Max(
                $config.DefaultCertificateName.Length,
                $storedCertMaxLength
            ),
            [Math]::Max(
                "Enter different name".Length,
                "Manage stored certificates".Length
            )
        ) + 5
        
        # Replace Unicode box drawing with ASCII characters
        Write-Host "`n+$("-" * ($maxLength + 6))+" -ForegroundColor Cyan
        Write-Host "| Certificate Selection Menu  |" -ForegroundColor Cyan
        Write-Host "+$("-" * ($maxLength + 6))+" -ForegroundColor Cyan
        
        # Default certificate option
        $defaultLabel = "$($config.DefaultCertificateName) (Default)"
        if ($config.DefaultCertificateName -eq $lastUsed) {
            $defaultLabel += " [Last Used]"
        }
        Write-Host "  [1] " -ForegroundColor Yellow -NoNewline
        Write-Host $defaultLabel
        $options += $config.DefaultCertificateName

        # Last used certificate if different from default
        if ($lastUsed -and $lastUsed -ne $config.DefaultCertificateName) {
            Write-Host "  [2] " -ForegroundColor Yellow -NoNewline
            Write-Host "$lastUsed [Last Used]"
            $options += $lastUsed
            $startIdx = 3
        } else {
            $startIdx = 2
        }
        
        # Stored certificates
        $certIdx = $startIdx
        foreach ($cert in $storedCerts) {
            # Skip if already listed as default or last used
            if ($cert -eq $config.DefaultCertificateName -or $cert -eq $lastUsed) {
                continue
            }
            Write-Host "  [$certIdx] " -ForegroundColor Yellow -NoNewline
            Write-Host $cert
            $options += $cert
            $certIdx++
        }
        
        # Additional options
        Write-Host "  [$certIdx] " -ForegroundColor Yellow -NoNewline
        Write-Host "Enter different name"
        $enterDiffIdx = $certIdx
        $certIdx++
        
        Write-Host "  [$certIdx] " -ForegroundColor Yellow -NoNewline
        Write-Host "Manage stored certificates" -ForegroundColor Cyan
        $manageIdx = $certIdx
        
        $choice = Read-Host "`nSelect option (1-$certIdx)"
        
        # Handle numeric choice
        if ([int]::TryParse($choice, [ref]$null)) {
            $choiceNum = [int]$choice
            
            # Direct certificate selection
            if ($choiceNum -ge 1 -and $choiceNum -lt $enterDiffIdx) {
                $selectedCert = $options[$choiceNum - 1]
                Set-LastUsedCertificate -CertName $selectedCert
                return $selectedCert
            }
            # Enter different name
            elseif ($choiceNum -eq $enterDiffIdx) {
                $inputName = Read-Host "Enter certificate name"
                if ([string]::IsNullOrWhiteSpace($inputName)) {
                    Write-Host "Using default certificate" -ForegroundColor Yellow
                    Set-LastUsedCertificate -CertName $config.DefaultCertificateName
                    return $config.DefaultCertificateName
                }
                
                # Prompt to store if this is a new certificate name
                if ($inputName -notin $storedCerts -and $inputName -ne $config.DefaultCertificateName) {
                    $saveChoice = Read-Host "Do you want to save this certificate name for future use? (Y/N)"
                    if ($saveChoice -eq 'Y') {
                        Save-CodeSigningCredential -CertificateName $inputName -Secret (New-Object SecureString)
                    }
                }
                
                Set-LastUsedCertificate -CertName $inputName
                return $inputName
            }
            # Manage certificates
            elseif ($choiceNum -eq $manageIdx) {
                Show-CertificateManager
                return (Select-Certificate) # Recursive call for new selection
            }
        }
        
        # Default fallback
        Write-Host "Invalid selection. Using default certificate." -ForegroundColor Yellow
        Set-LastUsedCertificate -CertName $config.DefaultCertificateName
        return $config.DefaultCertificateName
    }
    
    function Show-CertificateManager {
        $storedCerts = @(cmdkey /list | Select-String "CodeSigning_" | ForEach-Object {
            $_.ToString() -replace ".*CodeSigning_", ""
        })
        
        # Replace Unicode box drawing with ASCII characters
        Write-Host "`n+$("-" * 30)+" -ForegroundColor Cyan
        Write-Host "| Certificate Management  |" -ForegroundColor Cyan
        Write-Host "+$("-" * 30)+" -ForegroundColor Cyan
        Write-Host "  [1] " -ForegroundColor Yellow -NoNewline
        Write-Host "List stored certificates"
        Write-Host "  [2] " -ForegroundColor Yellow -NoNewline
        Write-Host "Remove stored certificate"
        Write-Host "  [3] " -ForegroundColor Yellow -NoNewline
        Write-Host "Back to certificate selection"
        
        $mgmtChoice = Read-Host "`nSelect option (1-3)"
        
        switch ($mgmtChoice) {
            "1" {
                # Replace Unicode box drawing with ASCII characters
                Write-Host "`n+ Stored Certificates +" -ForegroundColor Cyan
                if ($storedCerts) {
                    foreach ($cert in $storedCerts) {
                        Write-Host "  - $cert"
                    }
                } else {
                    Write-Host "  (No stored certificates)" -ForegroundColor Gray
                }
                
                Write-Host "`nPress Enter to continue..." -ForegroundColor Yellow
                Read-Host | Out-Null
                return
            }
            "2" {
                if ($storedCerts) {
                    Write-Host "`nSelect certificate to remove:" -ForegroundColor Yellow
                    for ($i = 0; $i -lt $storedCerts.Count; $i++) {
                        Write-Host "  [$($i + 1)] $($storedCerts[$i])"
                    }
                    
                    $removeChoice = Read-Host "`nEnter number (or 'C' to cancel)"
                    
                    if ($removeChoice -ne 'C' -and [int]::TryParse($removeChoice, [ref]$null)) {
                        $index = [int]$removeChoice - 1
                        if ($index -ge 0 -and $index -lt $storedCerts.Count) {
                            Remove-CodeSigningCredential -CertificateName $storedCerts[$index]
                            Write-Host "Certificate removed successfully" -ForegroundColor Green
                        }
                    }
                } else {
                    Write-Host "`nNo stored certificates to remove." -ForegroundColor Yellow
                }
                
                Write-Host "`nPress Enter to continue..." -ForegroundColor Yellow
                Read-Host | Out-Null
                return
            }
            default {
                return
            }
        }
    }

    $azureSignToolPath = Get-AzureSignTool

    # Get Cosign if needed for container signing
    if ($UseContainerSigning) {
        $cosignPath = Get-Cosign
        Write-Log "Container signing enabled, using Cosign from: $cosignPath" -Console
    }

    # Modified certificate selection with management options
    if (-not $CertificateName) {
        $CertificateName = if ($env:AZURE_CERT_NAME) {
            $env:AZURE_CERT_NAME
        } else {
            Select-Certificate
        }
    }

    if ([string]::IsNullOrWhiteSpace($CertificateName)) {
        $CertificateName = $config.DefaultCertificateName
    }

    Write-Log "Using certificate: $CertificateName" -Console

    # Simplified Key Vault secret handling - always prompt
    if (-not $env:AZURE_KEYVAULT_SECRET) {
        $secureSecret = Read-Host "Enter Key Vault Secret" -AsSecureString
        $env:AZURE_KEYVAULT_SECRET = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureSecret)
        )
    }

    # Validate certificate and credentials before asking for file
    Write-Log "Validating configuration..." -Console
    $testArgs = @(
        "sign",
        "--quiet",
        "--continue-on-error",
        "--kvu", $config.KeyVaultUrl,
        "--kvc", $CertificateName,
        "--azure-key-vault-client-id", $config.ClientId,
        "--azure-key-vault-tenant-id", $config.TenantId,
        "--kvs", $env:AZURE_KEYVAULT_SECRET,
        "--timestamp-rfc3161", $config.TimestampServer,
        "--help",
        "--quiet"
    )

    $null = Start-Process -FilePath $azureSignToolPath -ArgumentList $testArgs -NoNewWindow -Wait -PassThru -RedirectStandardError "$LogDir\stderr.txt"
    if (Test-Path "$LogDir\stderr.txt") {
        $errorContent = Get-Content "$LogDir\stderr.txt"
        if ($errorContent) {
            $configErrorData = @{
                "KeyVaultUrl" = $config.KeyVaultUrl
                "CertificateName" = $CertificateName
                "ErrorDetails" = $errorContent -join "`n"
            }
            Write-Log -Message "Configuration validation failed" -Level ERROR -Console -EventType "CodeSigning" -Action "ConfigValidationFailed" -Properties $configErrorData
            Write-Log -Message $errorContent -Level ERROR -Console -EventType "CodeSigning" -Action "ConfigValidationFailed" -Properties $configErrorData
            exit 1
        }
        Remove-Item "$LogDir\stderr.txt"
    }
    
    $configSuccessData = @{
        "KeyVaultUrl" = $config.KeyVaultUrl
        "CertificateName" = $CertificateName
    }
    Write-Log -Message "Configuration validated successfully" -Level SUCCESS -Console -EventType "CodeSigning" -Action "ConfigValidationSuccess" -Properties $configSuccessData

    # Now prompt for file path if not provided using command-line input instead of GUI
    if (-not $Path) {
        $Path = Read-Host "Enter path to file or directory to sign"
        
        # If user entered empty path, exit gracefully
        if ([string]::IsNullOrWhiteSpace($Path)) {
            Write-Host "No path provided. Operation canceled." -ForegroundColor Yellow
            exit 0
        }
    }

    # Validate path
    if (-not (Test-Path $Path)) {
        throw "The specified path '$Path' does not exist"
    }
}

Process {
    try {
        # Modified certificate verification
        try {
            Write-Log "Verifying certificate '$CertificateName' in KeyVault..." -Console
            
            # Try to verify with quiet mode
            $testArgs = @(
                "sign",
                "--quiet",
                "--continue-on-error",
                "--kvu", $config.KeyVaultUrl,
                "--kvc", $CertificateName,
                "--azure-key-vault-client-id", $config.ClientId,
                "--azure-key-vault-tenant-id", $config.TenantId,
                "--kvs", $env:AZURE_KEYVAULT_SECRET,
                "--timestamp-rfc3161", $config.TimestampServer,
                "--help"
            )
            
            $testResult = Start-Process -FilePath $azureSignToolPath `
                -ArgumentList $testArgs `
                -NoNewWindow `
                -Wait `
                -PassThru `
                -RedirectStandardError "$LogDir\stderr.txt" `
                -RedirectStandardOutput "$LogDir\stdout.txt"

            # Clean up temp files
            Remove-Item "$LogDir\stdout.txt" -ErrorAction SilentlyContinue
            if (Test-Path "$LogDir\stderr.txt") {
                $errorContent = Get-Content "$LogDir\stderr.txt"
                Remove-Item "$LogDir\stderr.txt"
                if ($errorContent) {
                    throw "Validation failed: $errorContent"
                }
            }
            
            if ($testResult.ExitCode -ne 0) {
                throw "AzureSignTool validation failed with exit code: $($testResult.ExitCode)"
            }
            
            Write-Log "Azure Sign Tool validation successful" -Level SUCCESS -Console
            Write-Log "Proceeding with certificate: $CertificateName" -Level INFO -Console
        }
        catch {
            Write-Log "Tool validation failed: $_" -Level ERROR -Console
            Write-Log "Common issues:" -Level WARN -Console
            Write-Log " - Certificate name mismatch" -Level WARN -Console
            Write-Log " - Insufficient KeyVault permissions" -Level WARN -Console
            Write-Log " - Invalid Key Vault secret" -Level WARN -Console
            throw
        }

        # Get list of files to process with proper recursion and single file support (Ankit's improvement)
        if (Test-Path $Path -PathType Leaf) {
            # Single file
            $files = @()
            if (Test-FileSignable $Path) {
                $files += Get-Item $Path
            }
        } else {
            # Directory
            $files = @(Get-ChildItem -Path $Path -File -Recurse:$Recurse | 
                    Where-Object { Test-FileSignable $_.FullName })
        }
        
        $stats.Total = @($files).Count
        Write-Log "Found $($stats.Total) files to process" -Console
        
        # Add progress bar and counters
        $activity = "Signing files with certificate '$CertificateName'"
        $fileCounter = 0
        
        foreach ($file in $files) {
            try {
                $fileCounter++
                $progressPercent = [Math]::Min(($fileCounter / $stats.Total * 100), 100)
                
                # Update progress bar with detailed status
                $status = "Processing file $fileCounter of $($stats.Total): $($file.Name)"
                $statusDetail = "Success: $($stats.Success) | Failed: $($stats.Failed) | Skipped: $($stats.Skipped)"
                Write-Progress -Activity $activity -Status $status -PercentComplete $progressPercent -CurrentOperation $statusDetail
                
                Write-Log "Processing: $($file.FullName)" -Console
                
                # Get pre-signing certificate info if exists
                $preSig = Get-AuthenticodeSignature $file.FullName
                if ($preSig.Status -eq "Valid") {
                    Write-Log "File already signed by: $($preSig.SignerCertificate.Subject)" -Level WARN -Console
                }

                # Get file extension
                $extension = [System.IO.Path]::GetExtension($file.Name).ToLower()
                
                # Determine if special parameters are needed for this file type
                $additionalParams = @()
                
                # Handle container signing with Cosign
                if ($extension -in @('.container', '.tar', '.oci') -or $UseContainerSigning) {
                    # Download Cosign if not already available
                    if (-not $cosignPath) {
                        $cosignPath = Get-Cosign
                    }
                    
                    # Get container reference - either direct path or content of reference file
                    $containerRef = $file.FullName
                    if ($file.Extension -in @('.container', '.txt')) {
                        # If the file is a reference file, read the reference from its content
                        $containerRef = Get-Content $file.FullName -Raw
                    }
                    
                    Write-Log "Signing container: $containerRef with Cosign" -Console
                    
                    if ($PSCmdlet.ShouldProcess($file.FullName, "Sign Container")) {
                        # Set up environment variables required by Cosign for Azure Key Vault access
                        $env:COSIGN_AZUREKMS_RESOURCEID = $config.KeyVaultUrl
                        $env:COSIGN_AZUREKMS_CLIENTID = $config.ClientId
                        $env:COSIGN_AZUREKMS_TENANT = $config.TenantId
                        
                        try {
                            # Prepare Cosign command-line arguments - ensure proper quoting
                            $signArgs = @(
                                "sign",
                                "--key", "azurekms://$($config.KeyVaultUrl)/$CertificateName",
                                "`"$containerRef`""  # Ensure path is quoted to handle spaces
                            )
                            
                            # Execute Cosign with properly quoted arguments
                            $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
                            $processStartInfo.FileName = $cosignPath
                            $processStartInfo.Arguments = $signArgs -join ' '
                            $processStartInfo.RedirectStandardError = $true
                            $processStartInfo.UseShellExecute = $false
                            $processStartInfo.CreateNoWindow = $true
                            
                            $process = New-Object System.Diagnostics.Process
                            $process.StartInfo = $processStartInfo
                            [void]$process.Start()
                            $stderr = $process.StandardError.ReadToEnd()
                            $process.WaitForExit()
                            
                            # Check for errors
                            if ($process.ExitCode -ne 0) { 
                                $stderr | Out-File "$LogDir\stderr.txt"
                                throw "Container signing failed with exit code $($process.ExitCode). Details: $stderr"
                            }
                            
                            # Log successful signing
                            $successMessage = "Successfully signed container '$containerRef' using Cosign with certificate '$CertificateName'"
                            Write-Log $successMessage -Level SUCCESS -Console
                            
                            # Track signing details for reporting
                            $signingDetails = @{
                                "EventType" = "ContainerSigning"
                                "Action" = "Signed"
                                "FilePath" = $file.FullName
                                "FileName" = $file.Name
                                "ContainerRef" = $containerRef
                                "FileSize" = $file.Length
                                "FileType" = "container"
                                "CertificateName" = $CertificateName
                                "SignatureMethod" = "Cosign"
                                "KeyVaultUrl" = $config.KeyVaultUrl
                                "SignedBy" = $env:USERNAME
                                "SignedOn" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                                "SignedOnComputer" = $env:COMPUTERNAME
                            }
                            
                            $signedFilesDetails += $signingDetails
                            $stats.Success++
                            
                            # Clean up environment variables for security
                            $env:COSIGN_AZUREKMS_RESOURCEID = $null
                            $env:COSIGN_AZUREKMS_CLIENTID = $null
                            $env:COSIGN_AZUREKMS_TENANT = $null
                        }
                        catch {
                            throw "Cosign signing failed: $_"
                        }
                    } else {
                        $stats.Skipped++
                    }
                    
                    # Skip the standard signing process for container files
                    continue
                }

                # Specific file type handling
                switch ($extension) {
                    '.zip' {
                        # ZIP files require special handling - we skip them in Test-FileSignable now
                        # but this is left here in case we add special ZIP handling in the future
                        Write-Log "ZIP files cannot be directly signed with Authenticode. Skipping." -Level WARN -Console
                        continue
                    }
                    { $_ -in @('.msix', '.appx', '.cab', '.jar') } {
                        # For container files that ARE supported, use appropriate parameters
                        Write-Log "Treating $extension file as a container format" -Level INFO -Console
                    }
                    { $_ -in @('.msi', '.msp', '.msm') } {
                        # Special handling for Windows Installer files (added .msm per Ankit)
                        $additionalParams += @("--file-digest", "sha256")
                    }
                    default {
                        # Default handling for executable/script files
                    }
                }

                # In the signing section, update arguments
                $signArgs = @(
                    "sign",
                    "--quiet",
                    "--continue-on-error",
                    "--kvu", $config.KeyVaultUrl,
                    "--kvc", $CertificateName,
                    "--azure-key-vault-client-id", $config.ClientId,
                    "--azure-key-vault-tenant-id", $config.TenantId,
                    "--kvs", $env:AZURE_KEYVAULT_SECRET,
                    "--timestamp-rfc3161", $config.TimestampServer,
                    "--colors"
                )
                
                # Add any file-specific parameters
                $signArgs += $additionalParams
                
                if ($PSCmdlet.ShouldProcess($file.FullName, "Sign")) {
                    # Create a properly quoted command line to handle spaces in paths
                    $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
                    $processStartInfo.FileName = $azureSignToolPath
                    $processStartInfo.Arguments = "$($signArgs -join ' ') `"$($file.FullName)`""
                    $processStartInfo.RedirectStandardError = $true
                    $processStartInfo.UseShellExecute = $false
                    $processStartInfo.CreateNoWindow = $true
                    
                    $process = New-Object System.Diagnostics.Process
                    $process.StartInfo = $processStartInfo
                    [void]$process.Start()
                    $stderr = $process.StandardError.ReadToEnd()
                    $process.WaitForExit()
                    
                    if ($process.ExitCode -ne 0) { 
                        $stderr | Out-File "$LogDir\stderr.txt"
                        throw "Signing failed with exit code $($process.ExitCode). Details: $stderr"
                    }
                    
                    # Enhanced signature verification with structured SIEM logging
                    $sig = Get-AuthenticodeSignature $file.FullName
                    if ($sig.Status -eq "Valid") {
                        # Prepare complete certificate details for structured logging
                        $signingDetails = @{
                            "EventType" = "CodeSigning"
                            "Action" = "Signed"
                            "FilePath" = $file.FullName
                            "FileName" = $file.Name
                            "FileSize" = $file.Length
                            "FileType" = [System.IO.Path]::GetExtension($file.Name).TrimStart('.')
                            "CertificateName" = $CertificateName
                            "CertificateSubject" = $sig.SignerCertificate.Subject
                            "CertificateIssuer" = $sig.SignerCertificate.Issuer
                            "CertificateExpiry" = $sig.SignerCertificate.NotAfter.ToString()
                            "CertificateThumbprint" = $sig.SignerCertificate.Thumbprint
                            "SignatureStatus" = $sig.Status.ToString()
                            "KeyVaultUrl" = $config.KeyVaultUrl
                            "TimestampServer" = $config.TimestampServer
                            "SignedBy" = $env:USERNAME
                            "SignedOn" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                            "SignedOnComputer" = $env:COMPUTERNAME
                        }
                        
                        # Add to our tracking array
                        $signedFilesDetails += $signingDetails
                        
                        # Consolidated log message that includes all the key information
                        $successMessage = "Successfully signed file '$($file.Name)' using certificate '$CertificateName' ($($sig.SignerCertificate.Thumbprint))"
                        Write-Log $successMessage -Level SUCCESS -Console
                        
                        $stats.Success++
                    } else {
                        throw "Signature verification failed: $($sig.Status). StatusMessage: $($sig.StatusMessage)"
                    }
                } else {
                    $stats.Skipped++
                }
            }
            catch {
                # Add enhanced error reporting to SIEM
                $errorDetails = @{
                    "EventType" = "CodeSigning" 
                    "Action" = "Error"
                    "FilePath" = $file.FullName
                    "FileName" = $file.Name
                    "ErrorMessage" = $_.ToString()
                }
                
                Write-Log "Failed to sign $($file.Name)" -Level ERROR -Console
                Write-Log "Error details: $_" -Level ERROR -Console
                if (Test-Path "$LogDir\stderr.txt") {
                    $toolOutput = Get-Content "$LogDir\stderr.txt" -Raw
                    Write-Log "Tool output: $toolOutput" -Level ERROR -Console
                    $errorDetails["ToolOutput"] = $toolOutput
                }
                $stats.Failed++
                continue
            }
        }
        
        # Clear the progress bar when done
        Write-Progress -Activity $activity -Completed
    }
    finally {
        if (Test-Path "$LogDir\stderr.txt") { Remove-Item "$LogDir\stderr.txt" -Force }
        $env:AZURE_KEYVAULT_SECRET = $null
    }
}

End {
    # Create a detailed file list for the summary
    $fileList = if ($stats.Success -gt 0) {
        ($signedFilesDetails | Select-Object -First 5 | ForEach-Object { $_.FileName }) -join ", "
    } else { "None" }
    
    # Add truncation indicator if more than 5 files
    if ($stats.Success -gt 5) {
        $fileList += "... (and $($stats.Success - 5) more)"
    }
    
    # Only send summary to SIEM if we actually attempted to sign files
    if ($stats.Total -gt 0) {
        # Comprehensive summary message
        $summaryMessage = "Code signing operation completed by $($env:USERNAME). " +
                         "Successfully signed $($stats.Success) of $($stats.Total) files " + 
                         "using certificate '$CertificateName'."
        
        # Determine the actual summary outcome based on success percentage
        $summaryOutcome = if ($stats.Success -eq $stats.Total) {
            "SUCCESS" # Complete success
        } elseif ($stats.Success -gt 0) {
            "WARN"   # Partial success
        } else {
            "ERROR"  # Complete failure
        }
        
        # Create a complete summary for SIEM with all details
        $siemSummary = @{
            "TotalFiles" = $stats.Total
            "SuccessfulSigns" = $stats.Success
            "FailedSigns" = $stats.Failed
            "SkippedFiles" = $stats.Skipped
            "Certificate" = $CertificateName
            "CertificateThumbprint" = if ($signedFilesDetails.Count -gt 0) { $signedFilesDetails[0].CertificateThumbprint } else { "N/A" }
            "CertificateSubject" = if ($signedFilesDetails.Count -gt 0) { $signedFilesDetails[0].CertificateSubject } else { "N/A" }
            "KeyVaultUrl" = $config.KeyVaultUrl
            "SignedFiles" = $fileList
            "SignedFilesDetails" = ($signedFilesDetails | Select-Object FileName, FilePath, FileSize, FileType, SignatureStatus, SignedBy, SignedOn)
            "Operation" = "Code signing batch operation"
            "SignedBy" = $env:USERNAME
            "SignedByDomain" = $env:USERDOMAIN
            "SignedOnComputer" = $env:COMPUTERNAME
            "CompletedAt" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        }
        
        # Send to SIEM with complete details - and force sending regardless of EnableSIEM setting
        Send-ToSIEM -Message $summaryMessage `
                   -Level $summaryOutcome `
                   -EventType "CodeSigningSummary" `
                   -Action "Complete" `
                   -Properties $siemSummary `
                   -ForceSend
    }
    else {
        # Special case: No files were found to sign
        $noFilesMessage = "Code signing operation completed by $($env:USERNAME). No signable files found at '$Path'."
        Write-Log $noFilesMessage -Level INFO -Console
        
        # Only send a minimal info message to SIEM for no-files-found case
        Send-ToSIEM -Message $noFilesMessage `
                   -Level "INFO" `
                   -EventType "CodeSigningSummary" `
                   -Action "NoFilesFound" `
                   -Properties @{
                        "Certificate" = $CertificateName
                        "KeyVaultUrl" = $config.KeyVaultUrl
                        "SearchPath" = $Path
                        "Recurse" = $Recurse
                        "SignedBy" = $env:USERNAME
                        "SignedByDomain" = $env:USERDOMAIN
                        "SignedOnComputer" = $env:COMPUTERNAME
                        "CompletedAt" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                   } `
                   -ForceSend
    }
    
    # Enhanced console display with border
    $border = "-" * 50
    Write-Host "`n+$border+" -ForegroundColor Cyan
    Write-Host "| Signing Operation Summary                          |" -ForegroundColor Cyan
    Write-Host "+$border+" -ForegroundColor Cyan
    Write-Host "| Certificate: $($CertificateName.PadRight(36))|" -ForegroundColor Cyan
    
    if ($stats.Total -gt 0) {
        Write-Host "| Total files processed: $($stats.Total.ToString().PadRight(26))|" -ForegroundColor Cyan
        Write-Host "| Successfully signed: $($stats.Success.ToString().PadRight(28))|" -ForegroundColor Green
        Write-Host "| Failed to sign: $($stats.Failed.ToString().PadRight(32))|" -ForegroundColor $(if ($stats.Failed -gt 0) {"Red"} else {"Gray"})
        Write-Host "| Skipped: $($stats.Skipped.ToString().PadRight(39))|" -ForegroundColor Gray
    }
    else {
        Write-Host "| No signable files found in specified path         |" -ForegroundColor Yellow
    }
    
    Write-Host "+$border+" -ForegroundColor Cyan
}
# SIG # Begin signature block
# MIIvTwYJKoZIhvcNAQcCoIIvQDCCLzwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAbrRlwcDQ9bEvu
# J//EjLs2dFIsd9yA0bhCM4+UfCR456CCFDkwggWQMIIDeKADAgECAhAFmxtXno4h
# MuI5B72nd3VcMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0xMzA4MDExMjAwMDBaFw0z
# ODAxMTUxMjAwMDBaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0
# IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/z
# G6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZ
# anMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7s
# Wxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL
# 2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfb
# BHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3
# JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3c
# AORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqx
# YxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0
# viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aL
# T8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjQjBAMA8GA1Ud
# EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBTs1+OC0nFdZEzf
# Lmc/57qYrhwPTzANBgkqhkiG9w0BAQwFAAOCAgEAu2HZfalsvhfEkRvDoaIAjeNk
# aA9Wz3eucPn9mkqZucl4XAwMX+TmFClWCzZJXURj4K2clhhmGyMNPXnpbWvWVPjS
# PMFDQK4dUPVS/JA7u5iZaWvHwaeoaKQn3J35J64whbn2Z006Po9ZOSJTROvIXQPK
# 7VB6fWIhCoDIc2bRoAVgX+iltKevqPdtNZx8WorWojiZ83iL9E3SIAveBO6Mm0eB
# cg3AFDLvMFkuruBx8lbkapdvklBtlo1oepqyNhR6BvIkuQkRUNcIsbiJeoQjYUIp
# 5aPNoiBB19GcZNnqJqGLFNdMGbJQQXE9P01wI4YMStyB0swylIQNCAmXHE/A7msg
# dDDS4Dk0EIUhFQEI6FUy3nFJ2SgXUE3mvk3RdazQyvtBuEOlqtPDBURPLDab4vri
# RbgjU2wGb2dVf0a1TD9uKFp5JtKkqGKX0h7i7UqLvBv9R0oN32dmfrJbQdA75PQ7
# 9ARj6e/CVABRoIoqyc54zNXqhwQYs86vSYiv85KZtrPmYQ/ShQDnUBrkG5WdGaG5
# nLGbsQAe79APT0JsyQq87kP6OnGlyE0mpTX9iV28hWIdMtKgK1TtmlfB2/oQzxm3
# i0objwG2J5VT6LaJbVu8aNQj6ItRolb58KaAoNYes7wPD1N1KarqE3fk3oyBIa0H
# EEcRrYc9B9F1vM/zZn4wggawMIIEmKADAgECAhAIrUCyYNKcTJ9ezam9k67ZMA0G
# CSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0
# IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0zNjA0MjgyMzU5NTla
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDVtC9C
# 0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0JAfhS0/TeEP0F9ce
# 2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJrQ5qZ8sU7H/Lvy0da
# E6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhFLqGfLOEYwhrMxe6T
# SXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+FLEikVoQ11vkunKoA
# FdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh3K3kGKDYwSNHR7Oh
# D26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJwZPt4bRc4G/rJvmM
# 1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQayg9Rc9hUZTO1i4F4z
# 8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbIYViY9XwCFjyDKK05
# huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchApQfDVxW0mdmgRQRNY
# mtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRroOBl8ZhzNeDhFMJlP
# /2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IBWTCCAVUwEgYDVR0T
# AQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+YXsIiGX0TkIwHwYD
# VR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYY
# aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2Fj
# ZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNV
# HR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAEDMAgGBmeBDAEEATAN
# BgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql+Eg08yy25nRm95Ry
# sQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFFUP2cvbaF4HZ+N3HL
# IvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1hmYFW9snjdufE5Btf
# Q/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3RywYFzzDaju4ImhvTnh
# OE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5UbdldAhQfQDN8A+KVssIh
# dXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw8MzK7/0pNVwfiThV
# 9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnPLqR0kq3bPKSchh/j
# wVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatEQOON8BUozu3xGFYH
# Ki8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bnKD+sEq6lLyJsQfmC
# XBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQjiWQ1tygVQK+pKHJ6l
# /aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbqyK+p/pQd52MbOoZW
# eE4wggftMIIF1aADAgECAhABg0HAZ+Xwq/zP2GToyihnMA0GCSqGSIb3DQEBCwUA
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTEwHhcNMjUwMTIzMDAwMDAwWhcNMjgwMTI1MjM1OTU5WjCB9TET
# MBEGCysGAQQBgjc8AgEDEwJVUzEZMBcGCysGAQQBgjc8AgECEwhEZWxhd2FyZTEd
# MBsGA1UEDwwUUHJpdmF0ZSBPcmdhbml6YXRpb24xEDAOBgNVBAUTBzMwODMwNTQx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1UaG91
# c2FuZCBPYWtzMSswKQYDVQQKEyJUZWxlZHluZSBUZWNobm9sb2dpZXMgSW5jb3Jw
# b3JhdGVkMSswKQYDVQQDEyJUZWxlZHluZSBUZWNobm9sb2dpZXMgSW5jb3Jwb3Jh
# dGVkMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjKpnX528gwhrmne0
# Z2lXDsWht9HiWWYzGkMP8iDix0Mge2ZgBiWw8NgA/DHmj1tCzgFbB8Kc9/Lh4w5R
# lNPs0M2g+QyE7DJtaTMsOj8mIP6ThdxoDfohyyB17hPLlDX1sYcw/w3nuuRAE3Qk
# yqhRiReU6E37ew8ktxOPEa0y2me3EMEiWz16I6T+dlGYPzBZUUCQ9rfFS1zVpcPe
# eFaGFGSh2WMh9bYbsG/xUni81/r5MJb4U+PJrzQWWnclXaIMXMsoCJsvPEkuGJDj
# 72SYJ7zcezsSyieD7uLIr+Ctm9bNWejYBZie/2yY7cO5oW4FcWYlkTIR9mpPn6tf
# WkpMdSyEaqCgRw2xk1SxA5qr/MBjXQBaugkq16PgtnkQfZJHtBoNhEZ++8ehPOUf
# 9fBVyGK84OUy0q7fAuyt6pHlBqe7UPKzR51dDr9wrDEZqAe8vXVjWjX+fHVUM/xv
# 9cVXC02ft1cevLlxu8HOirARnsHtsmlIuVMRthOmAZ14WXZOV+sIU9kiBl0RZuzP
# gy/M3Arn10nS9rcVMIvgoPt9qsGIoR/9OQT/WlC4KuVX2ta12WEcz7bMG9etwm4s
# 6erUhMfkmfYZ6fgzgcydzBcLHRu2ZWCEfA8zJ/jVagGThjPsyUjaY4fXckFocKcK
# xabPQBxRYTAEVjD5lq/Wh6Nu0TsCAwEAAaOCAgIwggH+MB8GA1UdIwQYMBaAFGg3
# 4Ou2O/hfEYb7/mF7CIhl9E5CMB0GA1UdDgQWBBT97y3EZzfmedAajrEbfWpGub+F
# bzA9BgNVHSAENjA0MDIGBWeBDAEDMCkwJwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cu
# ZGlnaWNlcnQuY29tL0NQUzAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
# BQUHAwMwgbUGA1UdHwSBrTCBqjBToFGgT4ZNaHR0cDovL2NybDMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAy
# MUNBMS5jcmwwU6BRoE+GTWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMIGU
# BggrBgEFBQcBAQSBhzCBhDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNl
# cnQuY29tMFwGCCsGAQUFBzAChlBodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0Ex
# LmNydDAJBgNVHRMEAjAAMA0GCSqGSIb3DQEBCwUAA4ICAQAKDwZT38qesrKUO8mC
# PFihP4sW90EAJj3ECQRP4JV3e2KizMeZGA8c9wn5aUjNyrq11U0NXe7MrPeGP5v4
# xZhHMQC2iIq1ZI6z6D4bgBOo8q8mX4L/e3XYqCpgyXQq6a6kdZhnA0i6GtKNfrVO
# WeAar4nObk/2lTJtLfw1q/KHzYUYtJSUFPl031tyUAg969xbhUiX09CI+l3E7C7y
# zeZcQ2aqSy3qdYAz1BQCr3sK50AohAlTNOZD2TDJDA3vdsbIPSWpFT8SPeLQMMD+
# jJPKiTiFs/anjUvZFbURcdT517/BBupC7FjzQRBWS4A3AiodRv1cBeEy0j7rdFMU
# fqk1ONh+tdxrxPCj+e1e7tjgpyppOVyYfGMsvxqXR7quTZnni//fOzI7vRxlzrBS
# epsHelnSVRae62IFvCz9eh5qzksL72EZVHvBSb6f3ZPQ/N7t8UmfBs5vnQ4O/o8E
# 7T81BllWuNSh6pv5M37VN5BQaRRRyRYgG4bEn2Q0l6tnRlr+4FNluv/lijFA2gUZ
# Yw2P+owlX/Q5TIgL9HAfN0LlQy4ZKsBmD42bslA8lBe0363fFc/5FKRpB7YiUGC4
# qQ5Au65g67V/ElU8ks3xzE1evYVFvckWXWot6tNX9b5FFfW2FqhSAD3hwsz5VjcO
# lGSgOYajIVk1aK52IJz8WgCXrDGCGmwwghpoAgEBMH0waTELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVz
# dGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMQIQAYNB
# wGfl8Kv8z9hk6MooZzANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQow
# CKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcC
# AQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC9dDGvZSaeWVhusm2p
# YF+PL4lLvk3GC6x+WpqM/CjOOTANBgkqhkiG9w0BAQEFAASCAgAFSE5hv1EGHC/o
# 4on4Uh+OzhE+MjDMlSvf2QcJlNVdPoHmFOpzI9DDw0IcApF1Zn+9FNP9P9XL3HC9
# N87Kka3oGjtj/lHZs98b7+jLZU1GDiPywxjZXeLRSWTlo9GnDtunZsPV6r2zq6nw
# 0XWbRRUIgjGBcqrgMOirIH7ATNVO3LwZSPswVp8cJt8g6WtBl9DYF3F33IABA9aZ
# ZZ5DHOvGL2QuL4JU/RYLvXpn4JrMNz2mwXDMJgPReYUZXctkXqMrkZCe9H50LETD
# LUyRsaQT1WTsyxR8eCw5wiyEmV1aU+dUCY4IDfH7os3VUBloug/q1v+giwnPmd62
# QRODVw/MwIHQIMHfoaz9LnvJDPVzSRjz9PgJyph7NC+tAy6bY5hFYx7z7WvEP2s2
# ur6byp7klANvZ3fc5cVeyYORtR+HJR9brXu436hUo0kaC1y0mzt7o1M2sYcRPYmD
# jiuEBv+ImogZhbbILrhEVv/GS4VBFvWHYUAFY5fsBL5rGZl2bq/2k3lk8ndMi55M
# IfBaSBWVCjYkMqHVqT7Ba0rpmkq3XI4bFxHdBCzn1ECjjWEXsbwh4P8u4CN9yiAn
# 0WTD165hGCbXjLrr6115gTxULaNlNrccr6YHuimuknl0uAR0ICuC3WJMPGzNKMPt
# 43qsAI4pG8MN64rbLXg6VOlnoFg5W6GCFzkwghc1BgorBgEEAYI3AwMBMYIXJTCC
# FyEGCSqGSIb3DQEHAqCCFxIwghcOAgEDMQ8wDQYJYIZIAWUDBAIBBQAwdwYLKoZI
# hvcNAQkQAQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCAQ
# vDmj23Y5XlFkED5YP6r/tZKeGcd27hpinP8g9iqA4AIQTjFpRlkq7PEQvOk+c6wY
# KhgPMjAyNTA1MjcyMDQ2NDJaoIITAzCCBrwwggSkoAMCAQICEAuuZrxaun+Vh8b5
# 6QTjMwQwDQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQw
# OTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTAeFw0yNDA5MjYwMDAwMDBaFw0zNTEx
# MjUyMzU5NTlaMEIxCzAJBgNVBAYTAlVTMREwDwYDVQQKEwhEaWdpQ2VydDEgMB4G
# A1UEAxMXRGlnaUNlcnQgVGltZXN0YW1wIDIwMjQwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQC+anOf9pUhq5Ywultt5lmjtej9kR8YxIg7apnjpcH9CjAg
# QxK+CMR0Rne/i+utMeV5bUlYYSuuM4vQngvQepVHVzNLO9RDnEXvPghCaft0djvK
# KO+hDu6ObS7rJcXa/UKvNminKQPTv/1+kBPgHGlP28mgmoCw/xi6FG9+Un1h4eN6
# zh926SxMe6We2r1Z6VFZj75MU/HNmtsgtFjKfITLutLWUdAoWle+jYZ49+wxGE1/
# UXjWfISDmHuI5e/6+NfQrxGFSKx+rDdNMsePW6FLrphfYtk/FLihp/feun0eV+pI
# F496OVh4R1TvjQYpAztJpVIfdNsEvxHofBf1BWkadc+Up0Th8EifkEEWdX4rA/FE
# 1Q0rqViTbLVZIqi6viEk3RIySho1XyHLIAOJfXG5PEppc3XYeBH7xa6VTZ3rOHNe
# iYnY+V4j1XbJ+Z9dI8ZhqcaDHOoj5KGg4YuiYx3eYm33aebsyF6eD9MF5IDbPgjv
# wmnAalNEeJPvIeoGJXaeBQjIK13SlnzODdLtuThALhGtyconcVuPI8AaiCaiJnfd
# zUcb3dWnqUnjXkRFwLtsVAxFvGqsxUA2Jq/WTjbnNjIUzIs3ITVC6VBKAOlb2u29
# Vwgfta8b2ypi6n2PzP0nVepsFk8nlcuWfyZLzBaZ0MucEdeBiXL+nUOGhCjl+QID
# AQABo4IBizCCAYcwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwFgYDVR0l
# AQH/BAwwCgYIKwYBBQUHAwgwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9
# bAcBMB8GA1UdIwQYMBaAFLoW2W1NhS9zKXaaL3WMaiCPnshvMB0GA1UdDgQWBBSf
# VywDdw4oFZBmpWNe7k+SH3agWzBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3Js
# My5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGlt
# ZVN0YW1waW5nQ0EuY3JsMIGQBggrBgEFBQcBAQSBgzCBgDAkBggrBgEFBQcwAYYY
# aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMFgGCCsGAQUFBzAChkxodHRwOi8vY2Fj
# ZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2
# VGltZVN0YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQA9rR4fdplb4ziE
# EkfZQ5H2EdubTggd0ShPz9Pce4FLJl6reNKLkZd5Y/vEIqFWKt4oKcKz7wZmXa5V
# gW9B76k9NJxUl4JlKwyjUkKhk3aYx7D8vi2mpU1tKlY71AYXB8wTLrQeh83pXnWw
# wsxc1Mt+FWqz57yFq6laICtKjPICYYf/qgxACHTvypGHrC8k1TqCeHk6u4I/VBQC
# 9VK7iSpU5wlWjNlHlFFv/M93748YTeoXU/fFa9hWJQkuzG2+B7+bMDvmgF8VlJt1
# qQcl7YFUMYgZU1WM6nyw23vT6QSgwX5Pq2m0xQ2V6FJHu8z4LXe/371k5QrN9FQB
# hLLISZi2yemW0P8ZZfx4zvSWzVXpAb9k4Hpvpi6bUe8iK6WonUSV6yPlMwerwJZP
# /Gtbu3CKldMnn+LmmRTkTXpFIEB06nXZrDwhCGED+8RsWQSIXZpuG4WLFQOhtloD
# RWGoCwwc6ZpPddOFkM2LlTbMcqFSzm4cd0boGhBq7vkqI1uHRz6Fq1IX7TaRQuR+
# 0BGOzISkcqwXu7nMpFu3mgrlgbAW+BzikRVQ3K2YHcGkiKjA4gi4OA/kz1YCsdhI
# BHXqBzR0/Zd2QwQ/l4Gxftt/8wY3grcc/nS//TVkej9nmUYu83BDtccHHXKibMs/
# yXHhDXNkoPIdynhVAku7aRZOwqw6pDCCBq4wggSWoAMCAQICEAc2N7ckVHzYR6z9
# KGYqXlswDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERp
# Z2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMY
# RGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIyMDMyMzAwMDAwMFoXDTM3MDMy
# MjIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRp
# bWVTdGFtcGluZyBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMaG
# NQZJs8E9cklRVcclA8TykTepl1Gh1tKD0Z5Mom2gsMyD+Vr2EaFEFUJfpIjzaPp9
# 85yJC3+dH54PMx9QEwsmc5Zt+FeoAn39Q7SE2hHxc7Gz7iuAhIoiGN/r2j3EF3+r
# GSs+QtxnjupRPfDWVtTnKC3r07G1decfBmWNlCnT2exp39mQh0YAe9tEQYncfGpX
# evA3eZ9drMvohGS0UvJ2R/dhgxndX7RUCyFobjchu0CsX7LeSn3O9TkSZ+8OpWNs
# 5KbFHc02DVzV5huowWR0QKfAcsW6Th+xtVhNef7Xj3OTrCw54qVI1vCwMROpVymW
# Jy71h6aPTnYVVSZwmCZ/oBpHIEPjQ2OAe3VuJyWQmDo4EbP29p7mO1vsgd4iFNmC
# KseSv6De4z6ic/rnH1pslPJSlRErWHRAKKtzQ87fSqEcazjFKfPKqpZzQmiftkaz
# nTqj1QPgv/CiPMpC3BhIfxQ0z9JMq++bPf4OuGQq+nUoJEHtQr8FnGZJUlD0UfM2
# SU2LINIsVzV5K6jzRWC8I41Y99xh3pP+OcD5sjClTNfpmEpYPtMDiP6zj9NeS3YS
# UZPJjAw7W4oiqMEmCPkUEBIDfV8ju2TjY+Cm4T72wnSyPx4JduyrXUZ14mCjWAkB
# KAAOhFTuzuldyF4wEr1GnrXTdrnSDmuZDNIztM2xAgMBAAGjggFdMIIBWTASBgNV
# HRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBS6FtltTYUvcyl2mi91jGogj57IbzAf
# BgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzAB
# hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9j
# YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMG
# A1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG
# /WwHATANBgkqhkiG9w0BAQsFAAOCAgEAfVmOwJO2b5ipRCIBfmbW2CFC4bAYLhBN
# E88wU86/GPvHUF3iSyn7cIoNqilp/GnBzx0H6T5gyNgL5Vxb122H+oQgJTQxZ822
# EpZvxFBMYh0MCIKoFr2pVs8Vc40BIiXOlWk/R3f7cnQU1/+rT4osequFzUNf7WC2
# qk+RZp4snuCKrOX9jLxkJodskr2dfNBwCnzvqLx1T7pa96kQsl3p/yhUifDVinF2
# ZdrM8HKjI/rAJ4JErpknG6skHibBt94q6/aesXmZgaNWhqsKRcnfxI2g55j7+6ad
# cq/Ex8HBanHZxhOACcS2n82HhyS7T6NJuXdmkfFynOlLAlKnN36TU6w7HQhJD5TN
# OXrd/yVjmScsPT9rp/Fmw0HNT7ZAmyEhQNC3EyTN3B14OuSereU0cZLXJmvkOHOr
# pgFPvT87eK1MrfvElXvtCl8zOYdBeHo46Zzh3SP9HSjTx/no8Zhf+yvYfvJGnXUs
# HicsJttvFXseGYs2uJPU5vIXmVnKcPA3v5gA3yAWTyf7YGcWoWa63VXAOimGsJig
# K+2VQbc61RWYMbRiCQ8KvYHZE/6/pNHzV9m8BPqC3jLfBInwAM1dwvnQI38AC+R2
# AibZ8GV2QqYphwlHK+Z/GqSFD/yYlvZVVCsfgPrA8g4r5db7qS9EFUrnEw4d2zc4
# GqEr9u3WfPwwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3
# DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAX
# BgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3Vy
# ZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBH
# NDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIw
# aTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLK
# EdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4Tm
# dDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembu
# d8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnD
# eMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1
# XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVld
# QnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTS
# YW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSm
# M9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzT
# QRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6Kx
# fgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/
# MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv
# 9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBr
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUH
# MAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJ
# RFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYG
# BFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72a
# rKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFID
# yE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/o
# Wajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv
# 76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30
# fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQxggN2MIID
# cgIBATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7
# MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1l
# U3RhbXBpbmcgQ0ECEAuuZrxaun+Vh8b56QTjMwQwDQYJYIZIAWUDBAIBBQCggdEw
# GgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNTA1
# MjcyMDQ2NDJaMCsGCyqGSIb3DQEJEAIMMRwwGjAYMBYEFNvThe5i29I+e+T2cUhQ
# hyTVhltFMC8GCSqGSIb3DQEJBDEiBCBKSiYsOty7SJoy8CyrU8IBbSmjFaAlrEog
# s8t/VoUceDA3BgsqhkiG9w0BCRACLzEoMCYwJDAiBCB2dp+o8mMvH0MLOiMwrtZW
# df7Xc9sF1mW5BZOYQ4+a2zANBgkqhkiG9w0BAQEFAASCAgCMUNqQqfUBlUfs6NjN
# COxEQn25kLyHdHflq3e5KG8BiT3gC4lsxhVxzljLG3xq48vYxpy3XbifzNLBhAdU
# 5PnPLF/S0O3eHapSHim2CTZHeBF6fToxmPjzHzxxvQXTdo9hqwCbCbd+Ebfv5tkX
# Z0bzjgScPNmIOARNkUcw73KYRFJ92RXuq4pxJ3ICONX2eFIYXSstNKeUIeM0c6Ui
# KDQEAFwt8IlEcxfjKWR95Bb6L45V4Y1cdRMk4g9khawHKZzpPMavFAGgj9UYBsjc
# OFI1rMvoQTgl7fwTV0C5hzWya/LtaeQKYu9pjdS9BrHAjEbFIl8hi8urjDpLeRIR
# X7qK/81pWuwiAOLZA72kVecr3j91oYb6L+StG4ekhV8GksXx7igGnNkoD/jFg/Eg
# hXbzzmmB+7GRWvpY5gSgzoVZIIyq+2vx3fqJ4Do6GD4MX9+tLVT67gi4bnZ0IcWO
# dxSmCr8HqPmi6adwYa7zACH6kIizftLS0Dnr0UzjelFVeGu+ddbw0/sVaKaSSeMM
# 2SucXu+c2FMOnxoQrUaq7UKsmE3YO0wDFb5ZFoK4joGJY3C7WzAzQZfsTqkksNBx
# s6f/gBh9iemoCt/w81diV4uQRJ/dvwQ++qPmetYK1gqpxSc2BnapBpD9yc3kJKF1
# 4kUXzBwtO5NJud/5c/pB58MRNw==
# SIG # End signature block
