<#
.SYNOPSIS
    Wrapper script for code signing using Azure Key Vault certificates
.EXAMPLES
    # Direct invocation (recommended)
    & "C:\Path\To\CodeSignWrapper.ps1" -Path C:\Build\MyApp.exe

    # From repository folder
    pwsh -File .\CodeSignWrapper.ps1 -Path .\bin\app.exe

    # Dot-sourcing ONLY if you need the helper functions in your session (not required just to sign)
    . .\CodeSignWrapper.ps1
    Sign-Code (future exported functions if any)

    IMPORTANT:
    Do NOT invoke with:
        . { \TeledyneDevOps\CodeSigning\CodeSignWrapper.ps1 }
    That syntax creates a script block; the bare path (starting with backslash) is not resolved and causes:
        The term '\TeledyneDevOps\CodeSigning\CodeSignWrapper.ps1' is not recognized...
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Position=0)] [string]$Path,
    [string[]]$Include = @("*.ps1","*.psm1","*.psd1","*.dll","*.exe","*.zip","*.msi","*.msix","*.appx","*.cab","*.sys","*.vbs","*.js","*.wsf","*.cat","*.msp","*.jar","*.container","*.tar","*.oci","*.dat","*.msm"),
    [string[]]$Exclude = @(),
    [string]$ConfigPath = "$PSScriptRoot\config.json",
    [string]$LogDir = "$PSScriptRoot\logs",
    [string]$CertificateName,
    [switch]$Recurse,
    [switch]$Force,
    [switch]$UpdateTools,
    [string]$SIEMServer = "us1-nslb-ecs.tdy.teledyne.com",
    [int]$SIEMPort = 11818,
    [ValidateSet("TCP","UDP")] [string]$SIEMProtocol = "TCP",
    [bool]$EnableSIEM = $true,
    [switch]$RememberCertificate,
    [switch]$UseContainerSigning,
    [switch]$Help,
    [switch]$Version,
    [switch]$DryRun
)

Begin {
    $ErrorActionPreference = "Stop"
    Set-StrictMode -Version Latest
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $ConfigPath  = Join-Path $scriptDir "config.json"
    $LogDir      = Join-Path $scriptDir "logs"
    $credMgrPath = Join-Path $scriptDir "CredentialManager.ps1"
    $lastUsedCertPath = Join-Path $scriptDir "lastcert.txt"
    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
    $LogFile = Join-Path $LogDir ("signing_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))

    function Send-ToSIEM {
        param(
            [string]$Message,[string]$Level="INFO",[string]$EventType="CodeSigning",
            [string]$Action="",[hashtable]$Properties=@{},[switch]$ForceSend
        )
        if ((-not $EnableSIEM) -and (-not $ForceSend)) { return }
        try {
            $event = @{
                activity=$EventType;activity_type="code-signing";landscape="endpoint security"
                outcome = (switch($Level){SUCCESS{"success"} ERROR{"failure"} WARN{"warning"} INFO{"informational"} default{"informational"}})
                platform="Windows";product="CodeSignWrapper";product_category="security operation"
                subject=$Action;time=(Get-Date -Format 'yyyy-MM-dd HH:mm:ss');vendor="Teledyne"
                src_ip=[string](Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -ne "127.0.0.1"} | Select-Object -First 1 -ExpandProperty IPAddress)
                user=$env:USERNAME;host=$env:COMPUTERNAME;Message=$Message
            }
            foreach($k in $Properties.Keys){ $event[$k]=$Properties[$k] }
            $json = $event | ConvertTo-Json -Compress
            if ($SIEMProtocol -eq "TCP") {
                $client = [Net.Sockets.TcpClient]::new()
                $client.Connect($SIEMServer,$SIEMPort)
                $sw = New-Object IO.StreamWriter($client.GetStream())
                $sw.WriteLine($json);$sw.Flush();$sw.Close();$client.Close()
            } else {
                $udp = [Net.Sockets.UdpClient]::new()
                $bytes=[Text.Encoding]::ASCII.GetBytes($json)
                $udp.Send($bytes,$bytes.Length,$SIEMServer,$SIEMPort)|Out-Null
                $udp.Close()
            }
        } catch {
            $m="Failed to send to SIEM: $($_.Exception.Message)"
            Add-Content $LogFile "$(Get-Date -f 'yyyy-MM-dd HH:mm:ss') [ERROR] $m"
        }
    }

    function Write-Log {
        param(
            [string]$Message,
            [ValidateSet('INFO','WARN','ERROR','SUCCESS')] [string]$Level="INFO",
            [switch]$Console,[string]$EventType="CodeSigning",[string]$Action="",
            [hashtable]$Properties=@{},[switch]$SendToSIEM
        )
        $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $line = "$ts [$Level] $Message"
        Add-Content -Path $LogFile -Value $line
        if ($Console -or $Level -in 'ERROR','SUCCESS') {
            $color = switch($Level){ERROR{'Red'} WARN{'Yellow'} SUCCESS{'Green'} default{'Gray'}}
            Write-Host $line -ForegroundColor $color
        }
        if ($SendToSIEM){ Send-ToSIEM -Message $Message -Level $Level -EventType $EventType -Action $Action -Properties $Properties }
    }

    if ($Help){
@"
Usage:
  & .\CodeSignWrapper.ps1 -Path <file|dir> [options]

Correct Invocation Examples:
  & 'C:\GitRepo\CodeSigning\CodeSignWrapper.ps1' -Path C:\Temp\Test.exe
  pwsh -File .\CodeSignWrapper.ps1 -Path .\dist -Recurse
  .\CodeSignWrapper.ps1 -Path C:\Pkg\setup.msi

Avoid (incorrect):
  . { \TeledyneDevOps\CodeSigning\CodeSignWrapper.ps1 }
    (The braces create a script block and the leading backslash is not a valid drive-qualified path.)

Options:
  -Include / -Exclude
  -CertificateName <name>  (-RememberCertificate to persist)
  -Recurse
  -Force
  -UpdateTools
  -UseContainerSigning
  -DryRun
  -Help / -Version

Use -DryRun to preview without signing.
"@ | Write-Host; exit 0
    }

    if ($Version){
        Write-Host "CodeSignWrapper.ps1 version 1.4.0"
        Write-Host "AzureSignTool v6.0.1"
        Write-Host "Cosign v2.2.3"
        exit 0
    }

    if (-not (Test-Path $credMgrPath)) {
        Write-Host "Missing CredentialManager.ps1" -ForegroundColor Red
        exit 1
    }

    try { "x" | Out-File (Join-Path $LogDir test.tmp); Remove-Item (Join-Path $LogDir test.tmp) -Force } catch { Write-Host "LogDir not writable." -ForegroundColor Red; exit 1 }

    . $credMgrPath

    if (-not (Test-Path $ConfigPath)) {
        @{
            KeyVaultUrl="https://itss-managed-certs.vault.azure.net/"
            DefaultCertificateName="ITSS-Code-Signing"
            ClientId="c699b1cf-73bd-4896-8dd2-74ea7d99dc60"
            TenantId="e324592a-2653-45c7-9bfc-597c36917127"
            TimestampServer="http://timestamp.digicert.com"
        } | ConvertTo-Json | Set-Content $ConfigPath
        Write-Log "Created default configuration at $ConfigPath" -Console
    }

    try {
        $raw = Get-Content $ConfigPath -Raw
        if ($raw -match '(^|\s)//'){ throw "Config JSON may not contain // comments." }
        $config = $raw | ConvertFrom-Json
        foreach($req in "KeyVaultUrl","DefaultCertificateName","ClientId","TenantId","TimestampServer"){
            if (-not $config.PSObject.Properties.Name.Contains($req)){ throw "Missing config field '$req'" }
        }
    } catch { throw "Failed to load config: $_" }

    $stats = [ordered]@{ Total=0; Success=0; Failed=0; Skipped=0 }
    $signedFilesDetails = @()

    function Get-AzureSignTool {
        $toolPath = Join-Path $scriptDir "AzureSignTool-x64.exe"
        if ((Test-Path $toolPath) -and (-not $UpdateTools)) { return $toolPath }
        try {
            Write-Log "Downloading AzureSignTool..." -Console
            $url="https://github.com/vcsjones/AzureSignTool/releases/download/v6.0.1/AzureSignTool-x64.exe"
            if (Test-Path $toolPath){ Copy-Item $toolPath "$toolPath.bak" -Force }
            [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $url -OutFile $toolPath
            Remove-Item "$toolPath.bak" -ErrorAction SilentlyContinue
            return $toolPath
        } catch {
            if (Test-Path "$toolPath.bak"){ Move-Item "$toolPath.bak" $toolPath -Force }
            throw
        }
    }

    function Get-Cosign {
        $toolPath = Join-Path $scriptDir "cosign.exe"
        if ((Test-Path $toolPath) -and (-not $UpdateTools)) { return $toolPath }
        Write-Log "Downloading Cosign..." -Console
        $url="https://github.com/sigstore/cosign/releases/download/v2.2.3/cosign-windows-amd64.exe"
        [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $toolPath
        return $toolPath
    }

    function Test-FileSignable {
        param([string]$FilePath)
        try {
            if (-not (Test-Path $FilePath -PathType Leaf)) { return $false }
            $fileObj = Get-Item $FilePath
            if ($fileObj.Length -eq 0) { return $false }
            $name = $fileObj.Name
            if (-not ($Include | Where-Object { $name -like $_ })) { return $false }
            if ( $Exclude | Where-Object { $name -like $_ }) { return $false }
            $ext = [IO.Path]::GetExtension($name).ToLower()
            if ($ext -in '.container','.tar','.oci' -or $UseContainerSigning){ return $true }
            if ($ext -in '.zip','.msix','.appx','.cab','.jar'){
                if ($ext -eq '.zip'){ return $false } # skip plain zips
            }
            $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
            if ($sig -and $sig.Status -eq 'Valid' -and -not $Force){
                $stats.Skipped++
                Write-Log "Already signed: ${FilePath}" -Level INFO
                return $false
            }
            return $true
        } catch {
            Write-Log "Error checking file ${FilePath}: $($_.Exception.Message)" -Level WARN
            return $false
        }
    }

    function Get-LastUsedCertificate { if (Test-Path $lastUsedCertPath){ Get-Content $lastUsedCertPath -ErrorAction SilentlyContinue } }
    function Set-LastUsedCertificate { param([string]$CertName) if ($RememberCertificate -and $CertName){ $CertName | Out-File $lastUsedCertPath -Force } }

    function Select-Certificate {
        $stored = @(cmdkey /list | Select-String "CodeSigning_" | ForEach-Object { $_ -replace '.*CodeSigning_','' })
        $last = Get-LastUsedCertificate
        $options = @()
        Write-Host ""
        Write-Host "Certificate Selection:" -ForegroundColor Cyan
        Write-Host "[1] $($config.DefaultCertificateName) (Default$(
            if($last -eq $config.DefaultCertificateName){', Last Used'}))"
        $options += $config.DefaultCertificateName
        $idx = 2
        if ($last -and $last -ne $config.DefaultCertificateName){
            Write-Host "[$idx] $last (Last Used)"; $options += $last; $idx++
        }
        foreach($c in $stored){
            if ($c -in $options){ continue }
            Write-Host "[$idx] $c"; $options += $c; $idx++
        }
        Write-Host "[$idx] Enter different name"; $enter=$idx; $idx++
        Write-Host "[$idx] Manage stored certificates"; $manage=$idx
        $choice = Read-Host "Select (1-$idx)"
        if ([int]::TryParse($choice,[ref]0)){
            $n=[int]$choice
            if ($n -ge 1 -and $n -lt $enter){ $sel=$options[$n-1]; Set-LastUsedCertificate $sel; return $sel }
            if ($n -eq $enter){
                $in = Read-Host "Enter certificate name"
                if (-not $in){ $in=$config.DefaultCertificateName }
                Set-LastUsedCertificate $in
                return $in
            }
            if ($n -eq $manage){
                Write-Host "Stored certs:"; if ($stored){$stored|ForEach-Object{" - $_"}} else {Write-Host "(none)"}
                return (Select-Certificate)
            }
        }
        Set-LastUsedCertificate $config.DefaultCertificateName
        return $config.DefaultCertificateName
    }

    $azureSignToolPath = Get-AzureSignTool
    if ($UseContainerSigning){ $null = Get-Cosign }

    if (-not $CertificateName){
        $CertificateName = if ($env:AZURE_CERT_NAME){ $env:AZURE_CERT_NAME } else { Select-Certificate }
    }
    if (-not $CertificateName){ $CertificateName = $config.DefaultCertificateName }
    Write-Log "Using certificate: $CertificateName" -Console

    if (-not $env:AZURE_KEYVAULT_SECRET){
        $sec = Read-Host "Enter Key Vault Secret" -AsSecureString
        $env:AZURE_KEYVAULT_SECRET = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
        )
    }

    # quick validation
    $validateArgs = @("sign","--quiet","--continue-on-error","--kvu",$config.KeyVaultUrl,"--kvc",$CertificateName,
        "--azure-key-vault-client-id",$config.ClientId,"--azure-key-vault-tenant-id",$config.TenantId,
        "--kvs",$env:AZURE_KEYVAULT_SECRET,"--timestamp-rfc3161",$config.TimestampServer,"--help")
    $null = Start-Process -FilePath $azureSignToolPath -ArgumentList $validateArgs -NoNewWindow -Wait -PassThru -RedirectStandardError "$LogDir\stderr.txt"
    if (Test-Path "$LogDir\stderr.txt"){
        $ec = Get-Content "$LogDir\stderr.txt"
        Remove-Item "$LogDir\stderr.txt"
        if ($ec){ Write-Log "Configuration validation failed: $ec" -Level ERROR -Console; exit 1 }
    }
    Write-Log "Configuration validated successfully" -Level SUCCESS -Console

    if (-not $Path){
        $Path = Read-Host "Enter path to file or directory to sign"
        if (-not $Path){ Write-Host "No path provided. Exiting." -ForegroundColor Yellow; exit 0 }
    }
    if (-not (Test-Path $Path)){ throw "Path '$Path' does not exist." }
}

Process {
    try {
        # verify cert again (light)
        Write-Log "Verifying certificate '$CertificateName'..." -Console

        $filesToSign = @()
        if (Test-Path $Path -PathType Leaf){
            if (Test-FileSignable -FilePath $Path){ $filesToSign += (Get-Item -LiteralPath $Path) }
        } else {
            $gci = Get-ChildItem -Path $Path -Recurse:$Recurse -File -Include $Include -ErrorAction SilentlyContinue
            foreach($f in $gci){
                if (Test-FileSignable -FilePath $f.FullName){ $filesToSign += $f }
            }
        }

        if (-not $filesToSign.Count){
            Write-Log "No files matched for signing." -Level WARN -Console
            return
        }

        $stats.Total = $filesToSign.Count

        if ($DryRun){
            Write-Log "DryRun: the following $($filesToSign.Count) file(s) would be signed:" -Console
            $filesToSign | ForEach-Object { Write-Log "  $_" -Level INFO -Console }
            Write-Log "DryRun summary: Total=$($stats.Total) Success=0 Failed=0 Skipped=$($stats.Skipped)" -Level INFO -Console
            return
        }

        foreach($f in $filesToSign){
            $filePath = $f.FullName
            if ($PSCmdlet.ShouldProcess($filePath,"Sign")){
                try {
                    $args = @("sign","--kvu",$config.KeyVaultUrl,"--kvc",$CertificateName,
                        "--azure-key-vault-client-id",$config.ClientId,"--azure-key-vault-tenant-id",$config.TenantId,
                        "--kvs",$env:AZURE_KEYVAULT_SECRET,"--timestamp-rfc3161",$config.TimestampServer,
                        "--quiet","--continue-on-error","--file",$filePath)
                    $pr = Start-Process -FilePath $azureSignToolPath -ArgumentList $args -NoNewWindow -Wait -PassThru
                    if ($pr.ExitCode -eq 0){
                        Write-Log "Signed: ${filePath}" -Level SUCCESS -Console
                        $stats.Success++
                    } else {
                        Write-Log "Failed (exit $($pr.ExitCode)): ${filePath}" -Level ERROR -Console
                        $stats.Failed++
                    }
                } catch {
                    $m = if ($_.Exception){ $_.Exception.Message } else { $_.ToString() }
                    Write-Log "Error signing file ${filePath}: $m" -Level ERROR -Console -Properties @{ Exception=$m }
                    $stats.Failed++
                }
            }
        }

        Write-Log "Summary: Total=$($stats.Total) Success=$($stats.Success) Failed=$($stats.Failed) Skipped=$($stats.Skipped)" -Level INFO -Console -SendToSIEM
    } catch {
        Write-Log "Unexpected error: $($_.Exception.Message)" -Level ERROR -Console
    }
}