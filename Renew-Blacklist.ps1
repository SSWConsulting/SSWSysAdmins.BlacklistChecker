<#
.SYNOPSIS
   Renews the current blacklist file.
.DESCRIPTION
   Renews the current blacklist file, makes 2 copies of it, and triggers a check of the current IPs.
.EXAMPLE
   Triggered by Task Scheduler only.
#>

Param(

[Parameter(Position=0,Mandatory=$true)]
[string] $File,
[Parameter(Position=1,Mandatory=$true)]
[string] $BaseFile,
[Parameter(Position=2,Mandatory=$true)]
[string] $LogFile,
[Parameter(Position=3,Mandatory=$true)]
[string] $File2,
[Parameter(Position=4,Mandatory=$true)]
[string] $IPFile
)

# Let's create a log in flea so we can see what is happening
Import-Module Write-Log

Write-Log -File $LogFile -Message "Starting malicious IP renewing/rechecking procedure..."

# Let's make one copy of the file
Copy-Item -path $BaseFile -destination $File
Write-Log -File $LogFile -Message "Copying Blacklist Feed..."

# Let's make a second copy for...reasons
Copy-Item -path $BaseFile -destination $File2
Write-Log -File $LogFile -Message "Copying Blacklist Feed again for added security..."

# Let's get the content from our base feed and add it to the current malicious IP list
$cont = get-content $File
add-content -path $IpFile -value $cont
Write-Log -File $LogFile -Message "Adding current feed to malicious IP list..."

# Let's clear our current feed
Clear-Content $BaseFile
Write-Log -File $LogFile -Message "Clearing current blacklist feed..."

# Let's trigger a Blacklist Check of all the IPs, keeping the ones that are still blacklisted
Write-Log -File $LogFile -Message "Triggering Blacklist IP Checker..."

C:\DataWhatsUp\MaliciousIPChecker\LaunchSSWCheckBlacklistIP.bat
