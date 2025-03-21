<#
.SYNOPSIS
    Sets up Git repository access for the CodeSigning project
.DESCRIPTION
    Helps initialize a Git repository with proper remote URL configuration
    or fixes permissions issues with existing repository.
.NOTES
    Author: Support Team
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$NewRemoteUrl,
    
    [Parameter(Mandatory=$false)]
    [switch]$InitNewRepo,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportToLocal
)

# Ensure we're in the correct directory
Push-Location $PSScriptRoot

function Test-GitRepo {
    # Check if this is a git repository
    $isGitRepo = Test-Path ".git" -PathType Container
    return $isGitRepo
}

function Initialize-GitRepo {
    Write-Host "Initializing new Git repository..." -ForegroundColor Cyan
    git init
    git add .
    git commit -m "Initial commit of CodeSigning Tool"
    Write-Host "Repository initialized with initial commit." -ForegroundColor Green
}

function Export-ToLocalRepo {
    # Get timestamp for folder name
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $exportPath = "C:\Temp\CodeSigning_$timestamp"
    
    # Create directory if it doesn't exist
    if (-not (Test-Path "C:\Temp")) {
        New-Item -ItemType Directory -Path "C:\Temp" | Out-Null
    }
    
    # Copy all files to the new location
    Write-Host "Exporting CodeSigning project to $exportPath..." -ForegroundColor Cyan
    Copy-Item -Path "$PSScriptRoot\*" -Destination $exportPath -Recurse -Force
    
    # Initialize git in the new location
    Push-Location $exportPath
    git init
    git add .
    git commit -m "Initial commit of CodeSigning Tool"
    Pop-Location
    
    Write-Host "Project exported successfully to $exportPath" -ForegroundColor Green
    Write-Host "You can now work with this copy without remote repository issues." -ForegroundColor Green
}

function Update-RemoteUrl {
    param([string]$NewUrl)
    
    # Check if remote exists
    $remoteExists = git remote -v
    
    if ($remoteExists) {
        Write-Host "Updating remote URL..." -ForegroundColor Cyan
        git remote set-url origin $NewUrl
    } else {
        Write-Host "Adding new remote..." -ForegroundColor Cyan
        git remote add origin $NewUrl
    }
    
    Write-Host "Remote URL updated successfully." -ForegroundColor Green
    Write-Host "New remote URL: $NewUrl" -ForegroundColor Green
}

function Show-GitStatus {
    Write-Host "`nCurrent Git Status:" -ForegroundColor Cyan
    git status
    
    Write-Host "`nRemote repositories:" -ForegroundColor Cyan
    git remote -v
}

# Main script logic
if ($ExportToLocal) {
    Export-ToLocalRepo
} elseif ($InitNewRepo -or -not (Test-GitRepo)) {
    Initialize-GitRepo
    if ($NewRemoteUrl) {
        Update-RemoteUrl -NewUrl $NewRemoteUrl
    }
} elseif ($NewRemoteUrl) {
    Update-RemoteUrl -NewUrl $NewRemoteUrl
} else {
    # Show menu if no parameters provided
    Write-Host "CodeSigning Git Repository Setup" -ForegroundColor Cyan
    Write-Host "=================================" -ForegroundColor Cyan
    Write-Host "1. Initialize new Git repository"
    Write-Host "2. Update remote URL"
    Write-Host "3. Export to local repository (no remote)"
    Write-Host "4. Show current Git status"
    Write-Host "5. Exit"
    
    $choice = Read-Host "`nSelect an option (1-5)"
    
    switch ($choice) {
        "1" {
            Initialize-GitRepo
            $url = Read-Host "Enter remote URL (leave empty to skip)"
            if ($url) {
                Update-RemoteUrl -NewUrl $url
            }
        }
        "2" {
            $url = Read-Host "Enter new remote URL"
            Update-RemoteUrl -NewUrl $url
        }
        "3" {
            Export-ToLocalRepo
        }
        "4" {
            Show-GitStatus
        }
        "5" {
            Write-Host "Exiting..."
            return
        }
        default {
            Write-Host "Invalid option. Exiting..." -ForegroundColor Red
        }
    }
}

# Show git status after operations
Show-GitStatus

Pop-Location
