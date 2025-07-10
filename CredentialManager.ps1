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
# SIG # Begin signature block
# MIIvjQYJKoZIhvcNAQcCoIIvfjCCL3oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDg2X2Yf8eBYTfP
# s4+T9xn2GZl76Vy+5WBwFaS68/v8xqCCFDkwggWQMIIDeKADAgECAhAFmxtXno4h
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
# lGSgOYajIVk1aK52IJz8WgCXrDGCGqowghqmAgEBMH0waTELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVz
# dGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMQIQAYNB
# wGfl8Kv8z9hk6MooZzANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQow
# CKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcC
# AQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCABncWNvPuAuaDV2Toi
# 2ui//DSy3sbuXPo9wdwY4HjolzANBgkqhkiG9w0BAQEFAASCAgAcUEaTNIBI1KZw
# VAQb/XaylM0aV7QrvrhcOZ7HQ4r2byCgPBxKK/WDJDeNEniluoLm/DFXDxdXgLoJ
# Wg3V6bgs86Bnyc3d5xD8UwPVTnSb1UHjKVLv2T1sdStjVfX0T/wf0pkcbVABMJNW
# ycmgrqvjpp4eV652wMggKitUneJSfRihLZ4IiP6C+IsKpkRT6bsAXROORU5d1oc+
# GyTQIMARW+XfoTj8lEjFwmKiFEdLajR2l57RisVlldOwC3kbruo0lnarpOYkdixi
# +cKuCnnYEz3E9HrkCvTlr430OssmTTGo43xt/gUGx9FZBUhVdKJqhPjmBlWjphcK
# nG9eqxwSG939AJ8eD6XmxdncbLEx1ElLRXc69aXnuX5DcYwSPZfbvwVXYyJAgVIs
# 5CBj8MJkqNbZThoCyPynJJPQtD0qglBk5JFdNdlk0bi6sBym2XS8l1v1gv0pXYAo
# B0L8+0pwpeN1NW8mgkiWh6qqpUgB3sd2wPEtvsTozAed9W0ECkwZQ01aQVlhQVWj
# /smWl/WAXJI0tZWTWNC6ulpkg/eCdV8z24xEFWIGtmioqAB+HTaN0SXRWGDa+bfT
# kJO74Z31qFC2OlpkLnCyjcFS+ny8YsM+qwV6W/0ZsrgEVLZ+KFGUvsR7pDkVeRw4
# pn0fmqJ1aSuOXDcmwDtgGAht3kahJqGCF3cwghdzBgorBgEEAYI3AwMBMYIXYzCC
# F18GCSqGSIb3DQEHAqCCF1AwghdMAgEDMQ8wDQYJYIZIAWUDBAIBBQAweAYLKoZI
# hvcNAQkQAQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCBL
# DvXrgdxPrkbfPRECWUHg284FOol9ouECFIczZRQtRwIRAPJCjl95g/pDiZBi9iLB
# lOgYDzIwMjUwNzEwMTcyMzA2WqCCEzowggbtMIIE1aADAgECAhAKgO8YS43xBYLR
# xHanlXRoMA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1l
# U3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwHhcNMjUwNjA0MDAwMDAw
# WhcNMzYwOTAzMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNl
# cnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFNIQTI1NiBSU0E0MDk2IFRpbWVz
# dGFtcCBSZXNwb25kZXIgMjAyNSAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEA0EasLRLGntDqrmBWsytXum9R/4ZwCgHfyjfMGUIwYzKomd8U1nH7C8Dr
# 0cVMF3BsfAFI54um8+dnxk36+jx0Tb+k+87H9WPxNyFPJIDZHhAqlUPt281mHrBb
# ZHqRK71Em3/hCGC5KyyneqiZ7syvFXJ9A72wzHpkBaMUNg7MOLxI6E9RaUueHTQK
# WXymOtRwJXcrcTTPPT2V1D/+cFllESviH8YjoPFvZSjKs3SKO1QNUdFd2adw44wD
# cKgH+JRJE5Qg0NP3yiSyi5MxgU6cehGHr7zou1znOM8odbkqoK+lJ25LCHBSai25
# CFyD23DZgPfDrJJJK77epTwMP6eKA0kWa3osAe8fcpK40uhktzUd/Yk0xUvhDU6l
# vJukx7jphx40DQt82yepyekl4i0r8OEps/FNO4ahfvAk12hE5FVs9HVVWcO5J4dV
# mVzix4A77p3awLbr89A90/nWGjXMGn7FQhmSlIUDy9Z2hSgctaepZTd0ILIUbWuh
# KuAeNIeWrzHKYueMJtItnj2Q+aTyLLKLM0MheP/9w6CtjuuVHJOVoIJ/DtpJRE7C
# e7vMRHoRon4CWIvuiNN1Lk9Y+xZ66lazs2kKFSTnnkrT3pXWETTJkhd76CIDBbTR
# ofOsNyEhzZtCGmnQigpFHti58CSmvEyJcAlDVcKacJ+A9/z7eacCAwEAAaOCAZUw
# ggGRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFOQ7/PIx7f391/ORcWMZUEPPYYzo
# MB8GA1UdIwQYMBaAFO9vU0rp5AZ8esrikFb2L9RJ7MtOMA4GA1UdDwEB/wQEAwIH
# gDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCBlQYIKwYBBQUHAQEEgYgwgYUwJAYI
# KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEFBQcwAoZR
# aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGlt
# ZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3J0MF8GA1UdHwRYMFYwVKBS
# oFCGTmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRp
# bWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNybDAgBgNVHSAEGTAXMAgG
# BmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBAGUqrfEcJwS5
# rmBB7NEIRJ5jQHIh+OT2Ik/bNYulCrVvhREafBYF0RkP2AGr181o2YWPoSHz9iZE
# N/FPsLSTwVQWo2H62yGBvg7ouCODwrx6ULj6hYKqdT8wv2UV+Kbz/3ImZlJ7YXwB
# D9R0oU62PtgxOao872bOySCILdBghQ/ZLcdC8cbUUO75ZSpbh1oipOhcUT8lD8QA
# GB9lctZTTOJM3pHfKBAEcxQFoHlt2s9sXoxFizTeHihsQyfFg5fxUFEp7W42fNBV
# N4ueLaceRf9Cq9ec1v5iQMWTFQa0xNqItH3CPFTG7aEQJmmrJTV3Qhtfparz+BW6
# 0OiMEgV5GWoBy4RVPRwqxv7Mk0Sy4QHs7v9y69NBqycz0BZwhB9WOfOu/CIJnzkQ
# TwtSSpGGhLdjnQ4eBpjtP+XB3pQCtv4E5UCSDag6+iX8MmB10nfldPF9SVD7weCC
# 3yXZi/uuhqdwkgVxuiMFzGVFwYbQsiGnoa9F5AaAyBjFBtXVLcKtapnMG3VH3EmA
# p/jsJ3FVF3+d1SVDTmjFjLbNFZUWMXuZyvgLfgyPehwJVxwC+UpX2MSey2ueIu9T
# HFVkT+um1vshETaWyQo8gmBto/m3acaP9QsuLj3FNwFlTxq25+T4QwX9xa6ILs84
# ZPvmpovq90K8eWyG2N01c4IhSOxqt81nMIIGtDCCBJygAwIBAgIQDcesVwX/IZku
# QEMiDDpJhjANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMM
# RGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQD
# ExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgw
# MTE0MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIElu
# Yy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJT
# QTQwOTYgU0hBMjU2IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAtHgx0wqYQXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUX
# MmxCqvkbsDpz4aH+qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM
# 06qchUP+AbdJgMQB3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37
# QXbDhAktVJMQbzIBHYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+n
# t5pnYJU3Gmq6bNMI1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYO
# szFI2Wv82wnJRfN20VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ
# 0ucS638ZxqU14lDnki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJA
# QQZxst7VvwDDjAmSFTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSK
# i17yVp2NL+cnT6Toy+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6
# bDTnYCTKIsDq1BtmXUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmn
# hFr4yUozZtqgPrHRVHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0w
# ggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2
# L9RJ7MtOMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB
# /wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYI
# KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1
# aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RH
# NC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIw
# CwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4L
# yLU0pn/N0IfFiBowf0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP
# 5kvN2n7Jd2E4/iEIUBO41P5F448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4
# F3/a+Z1jEMK/DMm/axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JY
# sq7pGdogP8HRtrYfctSLANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON
# /gnZruMvNYY2o1f4MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7P
# tspIHBldNE2K9i697cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIq
# Q6Ku/qjTY6hc3hsXMrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ug
# MZyZZd/BdHLiRu7hAWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7Oigizw
# JWeukcyIPbAvjSabnf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/
# 9TCA6TD8dC3JE3rYkrhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scm
# bKvFoW2jNrbM1pD2T7m3XDCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFow
# DQYJKoZIhvcNAQEMBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0
# IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNl
# cnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIz
# NTk1OVowYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcG
# A1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3Rl
# ZCBSb290IEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2je
# u+RdSjwwIjBpM+zCpyUuySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bG
# l20dq7J58soR0uRf1gU8Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBE
# EC7fgvMHhOZ0O21x4i0MG+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/N
# rDRAX7F6Zu53yEioZldXn1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A
# 2raRmECQecN4x7axxLVqGDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8
# IUzUvK4bA3VdeGbZOjFEmjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfB
# aYh2mHY9WV1CdoeJl2l6SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaa
# RBkrfsCUtNJhbesz2cXfSwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZi
# fvaAsPvoZKYz0YkH4b235kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXe
# eqxfjT/JvNNBERJb5RBQ6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g
# /KEexcCPorF+CiaZ9eRpL5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB
# /wQFMAMBAf8wHQYDVR0OBBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQY
# MBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEF
# BQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBD
# BggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# QXNzdXJlZElEUm9vdENBLmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3Js
# My5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1Ud
# IAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22
# Ftf3v1cHvZqsoYcs7IVeqRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih
# 9/Jy3iS8UgPITtAq3votVs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYD
# E3cnRNTnf+hZqPC/Lwum6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c
# 2PR3WlxUjG/voVA9/HYJaISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88n
# q2x2zm8jLfR+cWojayL/ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5
# lDGCA3wwggN4AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0
# LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGlu
# ZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglg
# hkgBZQMEAgEFAKCB0TAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZI
# hvcNAQkFMQ8XDTI1MDcxMDE3MjMwNlowKwYLKoZIhvcNAQkQAgwxHDAaMBgwFgQU
# 3WIwrIYKLTBr2jixaHlSMAf7QX4wLwYJKoZIhvcNAQkEMSIEIJv3iMeS4JHnaibr
# aEb41LYma6kpkQKvuQB4oFxjlXaPMDcGCyqGSIb3DQEJEAIvMSgwJjAkMCIEIEqg
# P6Is11yExVyTj4KOZ2ucrsqzP+NtJpqjNPFGEQozMA0GCSqGSIb3DQEBAQUABIIC
# AEDGlul9zqUxsGZZQYAATNRhPZqPgI7iXbg51/EL2tID052kuInCQdXPXtkE/7hp
# ULQjXQd5KY/R72Tl1nEZehO7r8tB/gD9dnqtbLgeHsDTdnHPOBgde3GoW8r8qi4j
# CDD/SsvYlT4cbUHyj5Uvwalp9cnVo/KWATNbyMxBqFFrp0tod9eoZ5TdlVojVmIH
# 3bnZuQfNlM77f29kP9emHN7JWYgMWRbVZ9iviLj7WvXfQ+NGCL31UMIgp7QxDbK8
# Yp+ZityDhSKJFGzSlsPu8f+OiRmQtmShctMFT9qmaOln6dRhHeU0MiAadShLaqxJ
# LKNHVc7+ERMywXL0udwWZNjT3qbOdhpwXky9WbZ2NHhAS3xd8ZTN1tJ8phIVeJ44
# FMTZyLYN0ac76I+Cm15Ve3Nw8mYufcVwSNWvWAxqRGP7RE4vyqFbtFra1/RjEX7c
# IxjDq5017PzLxCuIvEqG8O9YgNhO3InfS7hahqcBIzbY8JXXCEpcoaEJHIR4i+5O
# pTTVWcEHWz8PBd1Ehq45VBv0j9SavP4bz4tsGwi6aeSxyYAaEZi5wSg03irMDyiq
# QBwWv+DOR+UxcNEfU1WyqeGuMNI6+GFUSssZdgoM+Lvu00qs1uTIIi/JlmoIAUC9
# WxQDPKiqnqiDA9+8Y1JOeonGeAprVrwvo9lh4gBktKFf
# SIG # End signature block
