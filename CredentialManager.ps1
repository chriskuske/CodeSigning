<#
.SYNOPSIS
    Manages code signing certificate credentials in Windows Credential Manager.
.DESCRIPTION
    Provides functions to save, retrieve, update, export, import, and remove code signing certificate credentials
    using Windows Credential Manager. These functions are used by CodeSignWrapper.ps1
    to maintain a list of frequently used certificates.
.NOTES
    Created: February 11, 2024
    Updated: May 27, 2025
    Author: Matt Mueller (matthew.mueller@teledyne.com)
    Contributors: Ankit Chahar (ankit.chahar@teledyne.com)
    Company: Teledyne Technologies Incorporated
.LINK
    https://github.com/TeledyneDevOps/CodeSigning
#>

function Save-CodeSigningCredential {
    <#
    .SYNOPSIS
        Saves code signing certificate credentials to Windows Credential Manager
    .DESCRIPTION
        Stores a certificate name and its associated secret in Windows Credential Manager
        using the cmdkey utility. Overwrites any existing credential with the same name.
        If the secret is empty or not provided, prompts the user for a password.
    .PARAMETER CertificateName
        The name of the certificate to store, will be prefixed with "CodeSigning_"
    .PARAMETER Secret
        The secure string containing the certificate's secret. If not provided, prompts the user.
    .EXAMPLE
        Save-CodeSigningCredential -CertificateName "MyCert" -Secret $secureString
    .NOTES
        Uses cmdkey.exe to store the credential with a standard naming convention.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$CertificateName,

        [Parameter(Mandatory=$false)]
        [securestring]$Secret
    )

    $credName = "CodeSigning_$CertificateName"

    # Prompt for secret if not provided or empty
    if (-not $Secret -or ($Secret | ConvertFrom-SecureString) -eq (ConvertFrom-SecureString (New-Object SecureString))) {
        Write-Host "Enter password/secret for certificate '$CertificateName':"
        $Secret = Read-Host -AsSecureString
        if (-not $Secret -or ($Secret | ConvertFrom-SecureString) -eq (ConvertFrom-SecureString (New-Object SecureString))) {
            Write-Host "No secret entered. Credential not saved." -ForegroundColor Yellow
            return
        }
    }

    try {
        # Attempt to delete existing credential first to avoid conflicts
        cmdkey /delete:$credName 2>&1 | Out-Null

        # Convert SecureString to plain text for cmdkey (required but handled securely)
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
        $plainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        # Store using cmdkey with the certificate name as both username and target
        $result = cmdkey /add:$credName /user:$CertificateName /pass:$plainText 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Host "Successfully stored credentials for $CertificateName"
        } else {
            throw "Failed to store credentials: $result"
        }
    }
    catch {
        Write-Error "Failed to save credentials: $_"
        throw
    }
    finally {
        # Zero out the memory used for the plain text password
        if ($BSTR) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        }
    }
}

function Get-CodeSigningCredential {
    <#
    .SYNOPSIS
        Retrieves stored code signing credentials from Windows Credential Manager
    .DESCRIPTION
        Looks up and returns the stored secret for a given certificate name from
        Windows Credential Manager. Uses the standard naming convention with
        "CodeSigning_" prefix.
    .PARAMETER CertificateName
        The name of the certificate whose credentials to retrieve
    .EXAMPLE
        $secret = Get-CodeSigningCredential -CertificateName "MyCert"
    .OUTPUTS
        SecureString containing the stored secret, or $null if not found
    .NOTES
        The password is parsed from cmdkey output and returned as a SecureString.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$CertificateName
    )

    $credName = "CodeSigning_$CertificateName"

    try {
        # List credentials and parse the output to find the password
        $result = cmdkey /list:$credName
        if ($result -match 'User:\s*(.+)$') {
            # Look for the password line specifically
            $passwordLine = $result | Where-Object { $_ -match 'Password:\s*(.+)$' }
            if ($passwordLine -match 'Password:\s*(.+)$') {
                $password = $matches[1]
                if ($password) {
                    # Return password as SecureString for better security
                    return (ConvertTo-SecureString -String $password -AsPlainText -Force)
                }
            }
        }
    }
    catch {
        Write-Error "Failed to retrieve credentials: $_"
    }
    return $null
}

function Remove-CodeSigningCredential {
    <#
    .SYNOPSIS
        Removes stored code signing credentials from Windows Credential Manager
    .DESCRIPTION
        Deletes the stored credentials for a given certificate name from Windows
        Credential Manager. Uses the standard naming convention with "CodeSigning_" prefix.
    .PARAMETER CertificateName
        The name of the certificate whose credentials to remove
    .EXAMPLE
        Remove-CodeSigningCredential -CertificateName "MyCert"
    .NOTES
        First checks if credential exists before attempting removal.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$CertificateName
    )

    $credName = "CodeSigning_$CertificateName"

    try {
        # Check if credential exists first
        $exists = cmdkey /list | Select-String "CodeSigning_$CertificateName"
        if (-not $exists) {
            Write-Host "No stored credentials found for $CertificateName"
            return
        }

        # Delete the credential
        $result = cmdkey /delete:$credName 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Successfully removed credentials for $CertificateName"
        } else {
            throw "Failed to remove credentials: $result"
        }
    }
    catch {
        Write-Error "Failed to remove credentials: $_"
        throw
    }
}

function Get-CodeSigningCredentialList {
    <#
    .SYNOPSIS
        Lists all stored code signing credentials in Windows Credential Manager
    .DESCRIPTION
        Returns an array of certificate names that are stored using the "CodeSigning_" prefix.
    .OUTPUTS
        Array of certificate names
    .EXAMPLE
        Get-CodeSigningCredentialList
    #>
    $list = cmdkey /list | Select-String "CodeSigning_" | ForEach-Object {
        $_.ToString() -replace ".*CodeSigning_", ""
    }
    return $list
}

function Test-CodeSigningCredentialExists {
    <#
    .SYNOPSIS
        Checks if a code signing credential exists in Windows Credential Manager
    .DESCRIPTION
        Returns $true if the credential exists, $false otherwise.
    .PARAMETER CertificateName
        The name of the certificate to check
    .OUTPUTS
        Boolean
    .EXAMPLE
        Test-CodeSigningCredentialExists -CertificateName "MyCert"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$CertificateName
    )
    $credName = "CodeSigning_$CertificateName"
    $exists = cmdkey /list | Select-String $credName
    return [bool]$exists
}

function Update-CodeSigningCredential {
    <#
    .SYNOPSIS
        Updates an existing code signing credential in Windows Credential Manager
    .DESCRIPTION
        Overwrites the stored secret for a given certificate name.
    .PARAMETER CertificateName
        The name of the certificate to update
    .PARAMETER Secret
        The new secure string secret
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$CertificateName,
        [Parameter(Mandatory=$true)]
        [securestring]$Secret
    )
    Remove-CodeSigningCredential -CertificateName $CertificateName
    Save-CodeSigningCredential -CertificateName $CertificateName -Secret $Secret
}

function Export-CodeSigningCredentials {
    <#
    .SYNOPSIS
        Exports all code signing credentials to a file (unencrypted)
    .PARAMETER Path
        The path to export the credentials to
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    $list = Get-CodeSigningCredentialList
    $export = @()
    foreach ($cert in $list) {
        $secret = Get-CodeSigningCredential -CertificateName $cert
        if ($secret) {
            $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
            )
            $export += @{ CertificateName = $cert; Secret = $plain }
        }
    }
    $export | ConvertTo-Json | Set-Content $Path
}

function Import-CodeSigningCredentials {
    <#
    .SYNOPSIS
        Imports code signing credentials from a file (unencrypted)
    .PARAMETER Path
        The path to import the credentials from
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    $import = Get-Content $Path | ConvertFrom-Json
    foreach ($item in $import) {
        $secure = ConvertTo-SecureString $item.Secret -AsPlainText -Force
        Save-CodeSigningCredential -CertificateName $item.CertificateName -Secret $secure
    }
}