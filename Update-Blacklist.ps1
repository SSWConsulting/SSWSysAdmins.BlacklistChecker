<#
.SYNOPSIS
   Renews the current blacklist file.
.DESCRIPTION
   Renews the current blacklist file, makes 2 copies of it, and triggers a check of the current IPs.
.EXAMPLE
   Triggered by Task Scheduler only.
#>

# Importing the configuration file
$config = Import-PowerShellDataFile $PSScriptRoot\Config.PSD1

# Building variables
$LogFile = $config.LogFile
$LogModuleLocation = $config.LogModuleLocation
$NewMaliciousIPFile = $config.NewMaliciousIPFile
$CurrentBlacklistFile = $config.CurrentBlacklistFile 
$SecondBlacklistFile = $config.SecondBlacklistFile 
$ThirdBlacklistFile = $config.ThirdBlacklistFile 
$BlacklistChecker = $config.BlacklistChecker

# Importing the SSW Write-Log module
Import-Module -Name $LogModuleLocation

function Update-Blacklist {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        $CurrentBlacklistFile ,      
        [Parameter(Position = 1, Mandatory = $true)]
        $SecondBlacklistFile,
        [Parameter(Position = 2, Mandatory = $true)]
        $ThirdBlacklistFile,
        [Parameter(Position = 3, Mandatory = $true)]
        $LogFile,
        [Parameter(Position = 4, Mandatory = $true)]
        $NewMaliciousIPFile,
        [Parameter(Position = 5, Mandatory = $true)]
        $BlacklistChecker
    )
    Write-Log -File $LogFile -Message "Starting malicious IP renewing routine..."

    try {
        # Let's make one copy of the file
        Copy-Item -path $CurrentBlacklistFile -destination $SecondBlacklistFile
        Write-Log -File $LogFile -Message "Successfully made a backup of blacklist file in $SecondBlacklistFle..."

        # Let's make a second copy for...reasons
        Copy-Item -path $CurrentBlacklistFile -destination $ThirdBlacklistFile
        Write-Log -File $LogFile -Message "Successfully made a second backup of blacklist file in $ThirdBlacklistFile for added security..."
    } 
    catch {
        $RecentError = $Error[0]
        Write-Log -File $LogFile -Message "ERROR on making backup copies - $RecentError"
    }
    try {
        # Let's get the content from our base feed and add it to the current malicious IP list, this will be rechecked later down
        $cont = get-content $SecondBlacklistFile
        add-content -path $NewMaliciousIPFile -value $cont
        Write-Log -File $LogFile -Message "Successfully added current feed to malicious IP list at $NewMaliciousIPFile..."
    }
    catch {
        $RecentError = $Error[0]
        Write-Log -File $LogFile -Message "ERROR on importing malicious IP list - $RecentError"
    }
    try {
        # Let's clear our current blacklist file
        Clear-Content $CurrentBlacklistFile 
        Write-Log -File $LogFile -Message "Clearing current blacklist feed $CurrentBlacklistFile ..."
    }
    catch {
        $RecentError = $Error[0]
        Write-Log -File $LogFile -Message "ERROR on clearing current blacklist feed - $RecentError"
    }
    try {
        # Let's trigger a Blacklist Check of all the IPs, keeping the ones that are still blacklisted
        & "$PSScriptRoot\$BlacklistChecker"
        Write-Log -File $LogFile -Message "Successfully triggered the Blacklist IP Checker at $PSScriptRoot\$BlacklistChecker..."
    }
    catch {
        $RecentError = $Error[0]
        Write-Log -File $LogFile -Message "ERROR on triggering $PSScriptRoot\$BlacklistChecker - $RecentError"
    }
    Write-Log -File $LogFile -Message "Finishing malicious IP renewing routine..."    
}

# Let's run one by one now
Update-Blacklist -LogFile $LogFile -CurrentBlacklistFile $CurrentBlacklistFile -SecondBlacklistFile $SecondBlacklistFile -ThirdBlacklistFile $ThirdBlacklistFile -BlacklistChecker $BlacklistChecker -NewMaliciousIPFile $NewMaliciousIPFile
