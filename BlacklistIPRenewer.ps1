<# BlacklistIPRenewer - PS Script to Renew Blacklisted Malicious IPs
 # Created by Kiki Biancatti for SSW
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
Function LogWrite
{
   $username = $env:USERNAME
   
   $PcName = $env:computername

   $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
   $Line = "$Stamp $PcName $Username $args"

   Add-content $Logfile -value $Line
   Write-Host $Line
}

LogWrite "Starting malicious IP renewing/rechecking procedure..."

# Let's make one copy of the file
Copy-Item -path $BaseFile -destination $File
LogWrite "Copying Blacklist Feed..."

# Let's make a second copy for...reasons
Copy-Item -path $BaseFile -destination $File2
LogWrite "Copying Blacklist Feed again for added security..."

# Let's get the content from our base feed and add it to the current malicious IP list
$cont = get-content $File
add-content -path $IpFile -value $cont
LogWrite "Adding current feed to malicious IP list..."

# Let's clear our current feed
Clear-Content $BaseFile
LogWrite "Clearing current blacklist feed..."

# Let's trigger a Blacklist Check of all the IPs, keeping the ones that are still blacklisted
LogWrite "Triggering Blacklist IP Checker..."

C:\DataWhatsUp\MaliciousIPChecker\LaunchSSWCheckBlacklistIP.bat
