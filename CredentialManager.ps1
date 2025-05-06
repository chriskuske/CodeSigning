<#
.SYNOPSIS
    Manages code signing certificate credentials in Windows Credential Manager.
.DESCRIPTION
    Provides functions to save, retrieve, and remove code signing certificate credentials
    using Windows Credential Manager. These functions are used by CodeSignWrapper.ps1
    to maintain a list of frequently used certificates.
.NOTES
    Created: February 11, 2024
    Updated: April 25, 2025
    Author: Matt Mueller (matthew.mueller@teledyne.com)
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
# SIG # Begin signature block
# MIIvTwYJKoZIhvcNAQcCoIIvQDCCLzwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDoWMoRX4+sDm/Z
# U2vJnD5PHl+WvaIwnLcSyjXS2D9+lqCCFDkwggWQMIIDeKADAgECAhAFmxtXno4h
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
# eE4wggftMIIF1aADAgECAhAEYWOEV49vBgRnm9PkOq8kMA0GCSqGSIb3DQEBCwUA
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTEwHhcNMjUwMzEwMDAwMDAwWhcNMjcwNDIwMjM1OTU5WjCB9TET
# MBEGCysGAQQBgjc8AgEDEwJVUzEZMBcGCysGAQQBgjc8AgECEwhEZWxhd2FyZTEd
# MBsGA1UEDwwUUHJpdmF0ZSBPcmdhbml6YXRpb24xEDAOBgNVBAUTBzMwODMwNTQx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1UaG91
# c2FuZCBPYWtzMSswKQYDVQQKEyJUZWxlZHluZSBUZWNobm9sb2dpZXMgSW5jb3Jw
# b3JhdGVkMSswKQYDVQQDEyJUZWxlZHluZSBUZWNobm9sb2dpZXMgSW5jb3Jwb3Jh
# dGVkMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAj0vFxAL1QyGl0xIp
# OXn+nrd0OXD2eSqgsRzheF9jNZpDq5//aCMbClFPKXCapgY0tgSiUoRM7kce1jOf
# ksQomnF8LwyQTNS3T+RVhMZurFiHPQZfd9VW0V7NjHanr6HNb8KzXhJ50Rhaz35V
# EEuDRtnL4R/SuLwvZ6SnDCOedbFSB38hUoQnD/ArwuOwMZemKF8DF5Oonse252Y8
# TOqpz/XnGr/eP7DHhhGMIZ+nbsDkgSxzhA4MdErQ6kTVXSsHBL/vMyAf79DtmNu0
# 6iUoB/1aXfiBtL6qe87P8Z20SmedM9oB3iZ0s6h++n+38aQYP9f0/y8ZBaL5kvrB
# FZ0aHrQgGhBodYR8ljBLUrXHH9VpyOc9reLrNcReOMOu0UVFYN/wvbnECg+teXMu
# c+2Mk5PKwWuM/m/sJYpkPL4jwQiSLmQUmcMzMyxLFfYbmyQPcB9+Xiuys67+QYAu
# ykCzi623sZQO82gc8pVGAuaWQ+JQG38DBtRNM1HTVRyyKV9VmjBZtACiaskcjDkU
# cCNjOgGJftZnFBNJf3Fr3dRkCeUQlamdwJDT4Hhi73rIQbbYUZv82nQQUzDvxbXM
# sI78RHLPkXrgQVGwJN4mQ+TiqKZDwgeY7Lo0+EtSrT3fW1cCW8334fhTgd/Xm5TP
# ASNL9fIV+VvKU7R3mqgkF3r8BJcCAwEAAaOCAgIwggH+MB8GA1UdIwQYMBaAFGg3
# 4Ou2O/hfEYb7/mF7CIhl9E5CMB0GA1UdDgQWBBSLsuGf9bamrNu5TbVqi1yKsFV4
# OjA9BgNVHSAENjA0MDIGBWeBDAEDMCkwJwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cu
# ZGlnaWNlcnQuY29tL0NQUzAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
# BQUHAwMwgbUGA1UdHwSBrTCBqjBToFGgT4ZNaHR0cDovL2NybDMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAy
# MUNBMS5jcmwwU6BRoE+GTWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMIGU
# BggrBgEFBQcBAQSBhzCBhDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNl
# cnQuY29tMFwGCCsGAQUFBzAChlBodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0Ex
# LmNydDAJBgNVHRMEAjAAMA0GCSqGSIb3DQEBCwUAA4ICAQBFXmEs0fR0r6q2s5ri
# zdy+7/mgNzySMZbt2SVpEC86Xqfbh0ceVojsiuwlgSi56iW+Wc5w3+rZhXA6R2ye
# 9YVADqk5rg/4z0ZJJihLvOTK7j5uYhffMBaeu2juUDORg57fZ+pfD9Y/YwOfVV7y
# HqMEisdzrs6qWPssDRjLDKZzXSVZSOa5QMYs/fonOORFDyuN8DmKlWKI5BH45tGD
# DJsV4zvzzvsmn2LH3/vycYUAVHSy3v7CakNjO47I4fZd8OBu0O4VHmgofKcdR6x8
# WI2ofVItXqmDpda7S8HBLRoSxvzbJrQGfRF9tIuaArtS8nrtmD5lNhZtulYs6Hc/
# nTtozjMxrw9w942e3LYt5un9PzWfzHZmFcTTlhljN/EOaRGm74em0Yd3+C/5bLv0
# FZ/Yt3SAgq57h+XdeiceLEN6VI9o88/AfgnXMAo9GY1A4IiShq4yP4GFKCYajSud
# AuxNA3FWr9yRtT6uFypHJo78eSKbd1a4/OWHmWSW6CxlJxOSv5ZO4MIZ5poPAzwM
# jRpN0UNp95YrBf/SIln9PLetGSyjpq5kAW6qZ9pH7aenU7Rq/vOFLLLdlkGPiFOH
# fdRtrEC9oJFB8OrN0e0OKOIT5FJYnXfCn+PvREsg4fpvM88dM83msBM95HnPOND/
# Zj35Ixiz//IiS098ycTpFqxhkDGCGmwwghpoAgEBMH0waTELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVz
# dGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMQIQBGFj
# hFePbwYEZ5vT5DqvJDANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQow
# CKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcC
# AQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDF9QBkujyD95+qnwNo
# uHXsYnjISI1aXetorc1Q3kG4bDANBgkqhkiG9w0BAQEFAASCAgA4RkIicj0W6/ek
# G1jJgO63zQT02uTJRCglZXOnLyX79M7h9OvNgjRXwhDa7lMC68EgEzaFwBV1pxqC
# wK4Rcy/Qtnn/Ts1gGF5RSijNCdn8pyUILZCaVammTW2Sa3dZcLV4PWA6xxdyoh0o
# 3M7/kzc4G1LvTRAHTIQPusoAVVi9xhTQZ7mTIQZqHpUmCMUIRFrBD9vYIg7XlW0C
# J5qFgI2dGk/IkYhVLwtX7OMBSdfWTaaEgcCcCBOh9bKUnalwquJYsnIrNde9JM2Y
# nqUA7+c59Xyif3R0SkuWMmMOws2lxv4nNy1nD3A8/HIGVvM3zT96xNNj0S3Tlhr6
# RXlxkcn22CtrXqHvLBcu/hIc8SKNJ0NsKC7ve1FPnUgSU5sUjpR9PNQ9vRFSbDfa
# BKaG6c91krXnASILC6Mpcn8gAKG57im1AW2MQbZnxphMcByS3KHenIriAfNuzVI8
# MtAcsrG/i6vbio4EZrcwpH9Qe0vLiGtz6z8v3+3oX+iQSKExT1pr6sHJQbcwfX9j
# GTHGryDbS1KG6ztqqi4J2FKf/TSSxcRoIbiUncvgmKNdBUvwlO87ROA8D7+MsjDi
# cr7x+M22NIN/qD1UzNhsxPArwCH+vkAhaTDBcdobSQH2fhV4SXSFT6fbeKadapnj
# f6M6TI5vxep/s8k3pAbgqNdVCASIjqGCFzkwghc1BgorBgEEAYI3AwMBMYIXJTCC
# FyEGCSqGSIb3DQEHAqCCFxIwghcOAgEDMQ8wDQYJYIZIAWUDBAIBBQAwdwYLKoZI
# hvcNAQkQAQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCDo
# HA2otMsX4nMSoyd+0StAFdkA0XGgmQPt4EH11fF1EwIQCi5e7HCuJLcRSMJhfBxF
# VxgPMjAyNTA1MDYxMzQ5NThaoIITAzCCBrwwggSkoAMCAQICEAuuZrxaun+Vh8b5
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
# MDYxMzQ5NThaMCsGCyqGSIb3DQEJEAIMMRwwGjAYMBYEFNvThe5i29I+e+T2cUhQ
# hyTVhltFMC8GCSqGSIb3DQEJBDEiBCBY8WFbVE6L+E+EqbnD4FxL4Nv+96OmRofu
# xOss4y5cSzA3BgsqhkiG9w0BCRACLzEoMCYwJDAiBCB2dp+o8mMvH0MLOiMwrtZW
# df7Xc9sF1mW5BZOYQ4+a2zANBgkqhkiG9w0BAQEFAASCAgBHtECO1KvufqJkZ1mR
# ZTwlZIslo47MqicvLNmKdrdNlMu87yFVDKhn/cZUDg05boiGhTNhzRO4Alr6bEKT
# YA8ihKYyuWu8dUIjIcTCD1cTl4ehCzINIffLPpACxCzlTbtGcbyvoV0h02qQ0e2J
# lsxPWp8NN+v1yRP4Puby0iyh0ltnrnxzHeecPAQHPpxQq2ZkgymXqBNV0pdE6Cz2
# dFt9YkndnBVfaofYZHBVEkioxhIOiAMYMIVCazng/RrDwnmz9kDrEFIXLuDjJ4sq
# kaIeqsN66d2ozTzyglf4UwNF413OTJ3UFhjW4MPmCmikFAHZUiXDo7as4MstuXJz
# SoRyANyX0RO+M3nWQRClVlCh2FqaQS6Evi9IbZbZVMIIczXguaJErgH/XHQtPyVC
# 5Xmal4a0r0E8SthBtyZLa46cOISowLchtauSYJ7hohnTWdEGZVWO1K0k3UDDzjI+
# mK4BTnJ62dCMOrHbaV7p5pvu1WRUs+6d5lzQJXR1UyBnPrG040e4J4hfzC1h39uX
# 0vvlydY5iaB5FgbJGErNafoYl2yt9nKSEO4rzo7oSFTi/mVlQ8AM+POJM9BwUVDP
# gI13j3aRZKZJEmxfBaVe77c3aMZhF61eKELFWINr8ltjQ6+zc8mxWLFakCug2iyr
# T6p0bIZGZs3wwCAzEzKWUAmQMg==
# SIG # End signature block
