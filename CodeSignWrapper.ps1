<#
.SYNOPSIS
    Wrapper script for code signing using Azure Key Vault certificates
.DESCRIPTION
    Provides a streamlined interface for code signing PowerShell scripts and executables
    using certificates stored in Azure Key Vault. Supports storing certificate names
    for quick access and handles all aspects of the signing process.
.NOTES
    Created: February 11, 2024
    Author: Matt Mueller (matthew.mueller@teledyne.com)
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false, Position=0)]
    [string]$Path,
    
    [Parameter(Mandatory=$false)]
    [string[]]$Include = @("*.ps1", "*.psm1", "*.psd1", "*.dll", "*.exe", "*.zip", "*.msi", "*.msix", 
                         "*.appx", "*.cab", "*.sys", "*.vbs", "*.js", "*.wsf", "*.cat", "*.msp", "*.jar"),
    
    [Parameter(Mandatory=$false)]
    [string[]]$Exclude = @(),
    
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = "$PSScriptRoot\config.json",
    
    [Parameter(Mandatory=$false)]
    [string]$LogDir = "$PSScriptRoot\logs",
    
    [Parameter(Mandatory=$false)]
    [string]$CertificateName,
    
    [Parameter(Mandatory=$false)]
    [switch]$Recurse,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [string]$SIEMServer = "us1-nslb-ecs.tdy.teledyne.com",
    
    [Parameter(Mandatory=$false)]
    [int]$SIEMPort = 11818,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("TCP", "UDP")]
    [string]$SIEMProtocol = "TCP",
    
    [Parameter(Mandatory=$false)]
    [bool]$EnableSIEM = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$RememberCertificate
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
        @{Name = "AzureSignTool.exe"; Path = (Join-Path $scriptDir "AzureSignTool.exe")}
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
        $config = Get-Content $ConfigPath -ErrorAction Stop | ConvertFrom-Json
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
            or returning the path if it exists. Handles architecture detection
            and backup/restore during updates.
        .OUTPUTS
            String containing the path to AzureSignTool.exe
        #>
        $toolPath = "$PSScriptRoot\AzureSignTool.exe"
        if ((Test-Path $toolPath) -and (-not $Force)) { return $toolPath }

        try {
            Write-Log "Downloading Azure Sign Tool..." -Console
            # Replace ternary with if-else
            $arch = if ([System.Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE") -eq "AMD64") {
                "x64"
            } else {
                "arm64"
            }
            $url = "https://github.com/vcsjones/AzureSignTool/releases/download/v6.0.0/AzureSignTool-$arch.exe"
            
            if (Test-Path $toolPath) { Copy-Item $toolPath "$toolPath.backup" -Force }
            
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $url -OutFile $toolPath
            if (Test-Path "$toolPath.backup") { Remove-Item "$toolPath.backup" -Force }
            Write-Log "Azure Sign Tool downloaded successfully" -Console
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
        .PARAMETER FilePath
            The path to the file to test
        .OUTPUTS
            Boolean indicating if the file should be signed
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
            
            # Handle special case for .zip and archive files - they must be PE files or valid scripts
            $extension = [System.IO.Path]::GetExtension($fileName).ToLower()
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
# SIG # Begin signature block
# MIIvUAYJKoZIhvcNAQcCoIIvQTCCLz0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA03LHtrrRJiCsL
# dbKyo+mJ96F1lHWjCXxWNy7kiXGWQaCCFDkwggWQMIIDeKADAgECAhAFmxtXno4h
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
# lGSgOYajIVk1aK52IJz8WgCXrDGCGm0wghppAgEBMH0waTELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVz
# dGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMQIQAYNB
# wGfl8Kv8z9hk6MooZzANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQow
# CKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcC
# AQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAFpUbzQZEMPOjTrUUQ
# yP4HTM51dLUB7KARWoNMY1foXjANBgkqhkiG9w0BAQEFAASCAgAIpZvG2UI9IwJm
# T8c6XfTlYtpXzWQ1EKGhjoS0HrqcxWv9IGmz+ZgUTmL2qULdPkzeq9Z6ITujHRL9
# a7dCLqQvHltt/eVft3KcqxGecBDN4U9gWYYyF21qdgrsf6oicQeGPr2wwnOnT5dj
# muV/iuGr1nS5W3FzYJGkaOy6yethEW6W9Z0jqd3yMPYjPZpyAXNcTUB6AeVV2M0A
# dUroEcDmFlK5t1kLb3Ev0qfH0T0hrHKmUD+w2YA9wdj0ijPBMegi6CrBEuEas0TZ
# f4y6O/tD3vI5ry+MWSm0e1v1w+pCUcMnIrHP8cDy8aIeRJ6KMyTWQBozrv4TVOSa
# qBnTIRrpoX25sExNr3VOCe6Qi/Tr3rn8GQ1n/KQ/URQS9QxZbM0kpngUEHyogXRp
# MswsdI49lTSD3Uem3yjUfwn8KMBQN72GHSIQt4DPAPTEke0sqT496luf52sxLWWw
# KD7kQR8ywqeCR8ONWnaIUDKCC1pNvh7TVNwwEgaZn8sZoU4SJvWzujSKAOxNmcsj
# BWyP4M4n8i4dz2OXW3KKgfiwoRQ6mwQFVvktTUBOvHI1RMO5jkkGauoo+G6/Cyhv
# 54AOzhtbSnATuRs3sE2AmLno/3/TcFq2dNWW28eTDm2LePSMyJ8WiUL3g/oJ8uNH
# XKwQ7c2yew7g5fJJxtNq7Co3J6PrTKGCFzowghc2BgorBgEEAYI3AwMBMYIXJjCC
# FyIGCSqGSIb3DQEHAqCCFxMwghcPAgEDMQ8wDQYJYIZIAWUDBAIBBQAweAYLKoZI
# hvcNAQkQAQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCAQ
# PRcRsfflKp9hGZwzJn7ZHKrLHn7iLjyeUZdxh6a9BAIRAMTPOYjhFl2ivL9Q3PNe
# 3FgYDzIwMjUwMzIxMTcxNTA3WqCCEwMwgga8MIIEpKADAgECAhALrma8Wrp/lYfG
# +ekE4zMEMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0
# MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjQwOTI2MDAwMDAwWhcNMzUx
# MTI1MjM1OTU5WjBCMQswCQYDVQQGEwJVUzERMA8GA1UEChMIRGlnaUNlcnQxIDAe
# BgNVBAMTF0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDI0MIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAvmpzn/aVIauWMLpbbeZZo7Xo/ZEfGMSIO2qZ46XB/Qow
# IEMSvgjEdEZ3v4vrrTHleW1JWGErrjOL0J4L0HqVR1czSzvUQ5xF7z4IQmn7dHY7
# yijvoQ7ujm0u6yXF2v1CrzZopykD07/9fpAT4BxpT9vJoJqAsP8YuhRvflJ9YeHj
# es4fduksTHulntq9WelRWY++TFPxzZrbILRYynyEy7rS1lHQKFpXvo2GePfsMRhN
# f1F41nyEg5h7iOXv+vjX0K8RhUisfqw3TTLHj1uhS66YX2LZPxS4oaf33rp9Hlfq
# SBePejlYeEdU740GKQM7SaVSH3TbBL8R6HwX9QVpGnXPlKdE4fBIn5BBFnV+KwPx
# RNUNK6lYk2y1WSKour4hJN0SMkoaNV8hyyADiX1xuTxKaXN12HgR+8WulU2d6zhz
# XomJ2PleI9V2yfmfXSPGYanGgxzqI+ShoOGLomMd3mJt92nm7Mheng/TBeSA2z4I
# 78JpwGpTRHiT7yHqBiV2ngUIyCtd0pZ8zg3S7bk4QC4RrcnKJ3FbjyPAGogmoiZ3
# 3c1HG93Vp6lJ415ERcC7bFQMRbxqrMVANiav1k425zYyFMyLNyE1QulQSgDpW9rt
# vVcIH7WvG9sqYup9j8z9J1XqbBZPJ5XLln8mS8wWmdDLnBHXgYly/p1DhoQo5fkC
# AwEAAaOCAYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1Ud
# JQEB/wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG
# /WwHATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNVHQ4EFgQU
# n1csA3cOKBWQZqVjXu5Pkh92oFswWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL2Ny
# bDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRp
# bWVTdGFtcGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYBBQUHMAGG
# GGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0cDovL2Nh
# Y2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1
# NlRpbWVTdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAPa0eH3aZW+M4
# hBJH2UOR9hHbm04IHdEoT8/T3HuBSyZeq3jSi5GXeWP7xCKhVireKCnCs+8GZl2u
# VYFvQe+pPTScVJeCZSsMo1JCoZN2mMew/L4tpqVNbSpWO9QGFwfMEy60HofN6V51
# sMLMXNTLfhVqs+e8haupWiArSozyAmGH/6oMQAh078qRh6wvJNU6gnh5OruCP1QU
# AvVSu4kqVOcJVozZR5RRb/zPd++PGE3qF1P3xWvYViUJLsxtvge/mzA75oBfFZSb
# dakHJe2BVDGIGVNVjOp8sNt70+kEoMF+T6tptMUNlehSR7vM+C13v9+9ZOUKzfRU
# AYSyyEmYtsnpltD/GWX8eM70ls1V6QG/ZOB6b6Yum1HvIiulqJ1Elesj5TMHq8CW
# T/xrW7twipXTJ5/i5pkU5E16RSBAdOp12aw8IQhhA/vEbFkEiF2abhuFixUDobZa
# A0VhqAsMHOmaT3XThZDNi5U2zHKhUs5uHHdG6BoQau75KiNbh0c+hatSF+02kULk
# ftARjsyEpHKsF7u5zKRbt5oK5YGwFvgc4pEVUNytmB3BpIiowOIIuDgP5M9WArHY
# SAR16gc0dP2XdkMEP5eBsX7bf/MGN4K3HP50v/01ZHo/Z5lGLvNwQ7XHBx1yomzL
# P8lx4Q1zZKDyHcp4VQJLu2kWTsKsOqQwggauMIIElqADAgECAhAHNje3JFR82Ees
# /ShmKl5bMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxE
# aWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMT
# GERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0zNzAz
# MjIyMzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBU
# aW1lU3RhbXBpbmcgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDG
# hjUGSbPBPXJJUVXHJQPE8pE3qZdRodbSg9GeTKJtoLDMg/la9hGhRBVCX6SI82j6
# ffOciQt/nR+eDzMfUBMLJnOWbfhXqAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9xBd/
# qxkrPkLcZ47qUT3w1lbU5ygt69OxtXXnHwZljZQp09nsad/ZkIdGAHvbREGJ3Hxq
# V3rwN3mfXazL6IRktFLydkf3YYMZ3V+0VAshaG43IbtArF+y3kp9zvU5EmfvDqVj
# bOSmxR3NNg1c1eYbqMFkdECnwHLFuk4fsbVYTXn+149zk6wsOeKlSNbwsDETqVcp
# licu9Yemj052FVUmcJgmf6AaRyBD40NjgHt1biclkJg6OBGz9vae5jtb7IHeIhTZ
# girHkr+g3uM+onP65x9abJTyUpURK1h0QCirc0PO30qhHGs4xSnzyqqWc0Jon7ZG
# s506o9UD4L/wojzKQtwYSH8UNM/STKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ9FHz
# NklNiyDSLFc1eSuo80VgvCONWPfcYd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/TXkt2
# ElGTyYwMO1uKIqjBJgj5FBASA31fI7tk42PgpuE+9sJ0sj8eCXbsq11GdeJgo1gJ
# ASgADoRU7s7pXcheMBK9Rp6103a50g5rmQzSM7TNsQIDAQABo4IBXTCCAVkwEgYD
# VR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUuhbZbU2FL3MpdpovdYxqII+eyG8w
# HwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGG
# MBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcw
# AYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8v
# Y2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBD
# BgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNl
# cnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgB
# hv1sBwEwDQYJKoZIhvcNAQELBQADggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGwGC4Q
# TRPPMFPOvxj7x1Bd4ksp+3CKDaopafxpwc8dB+k+YMjYC+VcW9dth/qEICU0MWfN
# thKWb8RQTGIdDAiCqBa9qVbPFXONASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1DX+1g
# tqpPkWaeLJ7giqzl/Yy8ZCaHbJK9nXzQcAp876i8dU+6WvepELJd6f8oVInw1Ypx
# dmXazPByoyP6wCeCRK6ZJxurJB4mwbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY+/um
# nXKvxMfBwWpx2cYTgAnEtp/Nh4cku0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0ISQ+U
# zTl63f8lY5knLD0/a6fxZsNBzU+2QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr5Dhz
# q6YBT70/O3itTK37xJV77QpfMzmHQXh6OOmc4d0j/R0o08f56PGYX/sr2H7yRp11
# LB4nLCbbbxV7HhmLNriT1ObyF5lZynDwN7+YAN8gFk8n+2BnFqFmut1VwDophrCY
# oCvtlUG3OtUVmDG0YgkPCr2B2RP+v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/AAvk
# dgIm2fBldkKmKYcJRyvmfxqkhQ/8mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMOHds3
# OBqhK/bt1nz8MIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG
# 9w0BAQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkw
# FwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1
# cmVkIElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBi
# MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
# d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3Qg
# RzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAi
# MGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnny
# yhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE
# 5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm
# 7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5
# w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsD
# dV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1Z
# XUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS0
# 0mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hk
# pjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m8
# 00ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+i
# sX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB
# /zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReui
# r/SSy4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0w
# azAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUF
# BzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVk
# SURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAG
# BgRVHSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9
# mqyhhyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxS
# A8hO0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/
# 6Fmo8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSM
# b++hUD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt
# 9H5xaiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMYIDdjCC
# A3ICAQEwdzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4x
# OzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGlt
# ZVN0YW1waW5nIENBAhALrma8Wrp/lYfG+ekE4zMEMA0GCWCGSAFlAwQCAQUAoIHR
# MBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjUw
# MzIxMTcxNTA3WjArBgsqhkiG9w0BCRACDDEcMBowGDAWBBTb04XuYtvSPnvk9nFI
# UIck1YZbRTAvBgkqhkiG9w0BCQQxIgQgyLQ4KgwsoT18o6mWy/wB4B7yhqjqA3xb
# xvRXU/m0ySQwNwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQgdnafqPJjLx9DCzojMK7W
# VnX+13PbBdZluQWTmEOPmtswDQYJKoZIhvcNAQEBBQAEggIAQp3nU05O8Ed78mv7
# 0mQbExRGig81Msb2E26oOfEG8krKXMbzMJ7Bhp9mDoETaUH6w0PzIF3D2Gk2w+X5
# l1hEoc9G6CdcwSCF//fUTKCGlB6fGSjVdvZob/k1ozzqX5DJMobXGREwGKoNjv6e
# jCOllIMDAsLdKaLdp+lfm4QxZJsnu+6Hl0p0gQb3MRZjqfSIBjD4FOTFotQ2saUX
# bXKwoBXzOAwsh0UO4qsUTudDnomWAnwOkXQLMGHM0S+hF+sMUwRpH30ALJA1tcC9
# ZlKR1IoWOE3hx4Z/wYaobDwBrlDE0N4Tkei59bEL0u0NDgrkXgEJarB5ggnDYx+0
# DJWin7vBB6Um2WPiAsSd98+lH4kpyQQ+8AeQJAHtsbhjNHi4Ed16hHKrKWUnOHFU
# yMBG8Hsqg7UH8eDiEB7yqF7i6v7S5HuTk1B+Xzf/xSp16LwKHc081KB+wh+Yq7pi
# 78lhba0OZF2+V7pU+puv27GcNaC82u93edlBMvBIkyZHhjLk8BaphfQC4El5pZxd
# cI9vKcrRt7eowR6Cn4Iy2vl05aJsgcY6Lfw/jESow+tQEQ7r201xWPP4stVnrL8f
# 87b8ulbbXHx6oJzUKi/APTsQuGAD1R7NgIQCYbT5/zeuBBCCNMFI+mW2h3NdX7Hs
# kK/EQhdbC2I1PC6+2sUmygjpcaA=
# SIG # End signature block
