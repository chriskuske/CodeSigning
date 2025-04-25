<#
.SYNOPSIS
    Wrapper script for code signing using Azure Key Vault certificates
.DESCRIPTION
    Provides a streamlined interface for code signing PowerShell scripts, executables,
    and containers using certificates stored in Azure Key Vault. Supports storing 
    certificate names for quick access and handles all aspects of the signing process.
.NOTES
    Created: February 11, 2024
    Updated: April 22, 2025
    Author: Matt Mueller (matthew.mueller@teledyne.com)
    Company: Teledyne Technologies Incorporated
.LINK
    https://github.com/TeledyneDevOps/CodeSigning
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    # Path to file or directory to be signed
    [Parameter(Mandatory=$false, Position=0)]
    [string]$Path,
    
    # File patterns to include for signing
    [Parameter(Mandatory=$false)]
    [string[]]$Include = @("*.ps1", "*.psm1", "*.psd1", "*.dll", "*.exe", "*.zip", "*.msi", "*.msix", 
                         "*.appx", "*.cab", "*.sys", "*.vbs", "*.js", "*.wsf", "*.cat", "*.msp", "*.jar",
                         "*.container", "*.tar", "*.oci"),
    
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

        # Get list of files to process with proper recursion
        $searchOption = if ($Recurse) { "AllDirectories" } else { "TopDirectoryOnly" }
        $files = @(Get-ChildItem -Path $Path -File -Recurse:$Recurse | 
                Where-Object { Test-FileSignable $_.FullName })
        
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
                            # Prepare Cosign command-line arguments
                            $signArgs = @(
                                "sign",  # Command to sign a container
                                "--key", "azurekms://$($config.KeyVaultUrl)/$CertificateName",  # Azure Key Vault key reference
                                "$containerRef"  # Container reference to sign
                            )
                            
                            # Execute Cosign and capture any errors
                            $process = Start-Process -FilePath $cosignPath -ArgumentList $signArgs -NoNewWindow -Wait -PassThru -RedirectStandardError "$LogDir\stderr.txt"
                            
                            # Check for errors
                            if ($process.ExitCode -ne 0) { 
                                $errorDetail = Get-Content "$LogDir\stderr.txt" -ErrorAction SilentlyContinue
                                throw "Container signing failed with exit code $($process.ExitCode). Details: $errorDetail"
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
                    { $_ -in @('.msi', '.msp') } {
                        # Special handling for Windows Installer files
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
                
                # Add the filename
                $signArgs += $file.FullName
                
                if ($PSCmdlet.ShouldProcess($file.FullName, "Sign")) {
                    $process = Start-Process -FilePath $azureSignToolPath -ArgumentList $signArgs -NoNewWindow -Wait -PassThru -RedirectStandardError "$LogDir\stderr.txt"
                    if ($process.ExitCode -ne 0) { 
                        $errorDetail = Get-Content "$LogDir\stderr.txt" -ErrorAction SilentlyContinue
                        throw "Signing failed with exit code $($process.ExitCode). Details: $errorDetail"
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