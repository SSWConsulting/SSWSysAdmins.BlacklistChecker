<#
.SYNOPSIS
   Script to check blacklists across the web and block potential threats to our company. Includes sending email.

.NOTES
   Created by Kiki Biancatti for SSW.
   This script should be run once per day, as the URLs we are downloading are updated once per day. This might change if we add different URLs.
#>

# Let's time this!
$Script:Stopwatch = [system.diagnostics.stopwatch]::StartNew()

# Importing the configuration file
$config = Import-PowerShellDataFile $PSScriptRoot\Config.PSD1

# Building variables
$LogFile = $config.LogFile
$LogModuleLocation = $config.LogModuleLocation
$TargetEmail = $config.TargetEmail
$OriginEmail = $config.OriginEmail
$CurrentBlacklistFile = $config.CurrentBlacklistFile
$GoodPublicIPs = $config.GoodPublicIPs
$GoodInternalIPs = $config.GoodInternalIPs
$IpSources = $config.IpSources
$LastDownloadedFile = "$PSScriptRoot\$($config.LastDownloadedFile)"
$RawIPFile = "$PSScriptRoot\$($config.RawIPFile)"
$Script:BadIPs = @()

# Importing the SSW Write-Log module
Import-Module -Name $LogModuleLocation

<#
.SYNOPSIS
Function to see if IP address is in CIDR range.

.DESCRIPTION
Function to see if IP address is in CIDR range.
Grabbed it from https://github.com/omniomi/PSMailTools/blob/v0.2.0/src/Private/spf/IPInRange.ps1

.PARAMETER IPAddress
The IP address to search.

.PARAMETER Range
The CIDR range to search it is in.

.EXAMPLE
PS> IPInRange 10.100.32.65 10.100.32.0/16

.NOTES
Credits to omniomi
#>
function IPInRange {
   [cmdletbinding()]
   [outputtype([System.Boolean])]
   param(
      # IP Address to find.
      [parameter(Mandatory,
         Position = 0)]
      [validatescript( {
            ([System.Net.IPAddress]$_).AddressFamily -eq 'InterNetwork'
         })]
      [string]
      $IPAddress,

      # Range in which to search using CIDR notation. (ippaddr/bits)
      [parameter(Mandatory,
         Position = 1)]
      [validatescript( {
            $IP = ($_ -split '/')[0]
            $Bits = ($_ -split '/')[1]

            (([System.Net.IPAddress]($IP)).AddressFamily -eq 'InterNetwork')

            if (-not($Bits)) {
               throw 'Missing CIDR notiation.'
            }
            elseif (-not(0..32 -contains [int]$Bits)) {
               throw 'Invalid CIDR notation. The valid bit range is 0 to 32.'
            }
         })]
      [alias('CIDR')]
      [string]
      $Range
   )

   # Split range into the address and the CIDR notation
   [String]$CIDRAddress = $Range.Split('/')[0]
   [int]$CIDRBits = $Range.Split('/')[1]

   # Address from range and the search address are converted to Int32 and the full mask is calculated from the CIDR notation.
   [int]$BaseAddress = [System.BitConverter]::ToInt32((([System.Net.IPAddress]::Parse($CIDRAddress)).GetAddressBytes()), 0)
   [int]$Address = [System.BitConverter]::ToInt32(([System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()), 0)
   [int]$Mask = [System.Net.IPAddress]::HostToNetworkOrder(-1 -shl ( 32 - $CIDRBits))

   # Determine whether the address is in the range.
   if (($BaseAddress -band $Mask) -eq ($Address -band $Mask)) {
      $true
   }
   else {
      $false
   }
}

<#
.SYNOPSIS
Downloads files from well-known github repos with updated malicious IP addresses.

.DESCRIPTION
Downloads files from well-known github repos with updated malicious IP addresses.
Files are from FireHOL project and URLS can be set in Config file. Updated once daily.

.PARAMETER LogFile
The location of the logfile.

.PARAMETER IpSources
The URLs with malicious IP addresses.

.PARAMETER LastDownloadedFile
The last downloaded file with IP addresses. The file is one of the IpSources.

.PARAMETER RawIPFile
The temporary file with all, concatenated IP addresses from all IpSources.

.EXAMPLE
PS> Import-BlacklistIPFiles -LogFile $LogFile -IpSources $IpSources -LastDownloadedFile $LastDownloadedFile -RawIPFile $RawIPFile
#>
function Import-BlacklistIPFiles {
   [CmdletBinding()]
   Param(
      [Parameter(Position = 0, Mandatory = $true)]
      [string] $LogFile,
      [Parameter(Position = 1, Mandatory = $true)]
      $IpSources,
      [Parameter(Position = 1, Mandatory = $true)]
      [string] $LastDownloadedFile,
      [Parameter(Position = 1, Mandatory = $true)]
      [string] $RawIPFile
   )
   Write-Log -File $LogFile -Message "Starting new IP file import routine..."
   Write-Log -File $LogFile -Message "Logs for this script can be found in $LogFile"
   try {
      Clear-Content $RawIPFile
      Write-Log -File $LogFile -Message "Succesfully cleared list $RawIPFile..."
   }
   catch {
      $RecentError = $Error[0]
      Write-Log -File $LogFile -Message "ERROR clearing $RawIPFile - $RecentError"
   }

   $IpSources | ForEach-Object {
      try {
         Invoke-WebRequest -URI $_ -OutFile $LastDownloadedFile
         Write-Log -File $LogFile -Message "Succesfully downloaded list from $_"
         Get-Content $LastDownloadedFile | ForEach-Object {
            $SplitLine = $_.split('#')[0] 
            if ($SplitLine -ne "") {
               Add-content $RawIPFile -Value $SplitLine
            }                 
         }
         Write-Log -File $LogFile -Message "Succesfully added IP list to $RawIPFile"
      } 
      catch {
         $RecentError = $Error[0]
         Write-Log -File $LogFile -Message "ERROR importing Blacklist IP files - $RecentError"
      }
   }
}

<#
.SYNOPSIS
Gets the IP addresses in different files and checks if they are internal IP addresses.

.DESCRIPTION
Gets the IP addresses in different files and checks if they are internal IP addresses.
Sorts them correctly and, if they aren't, add them to the final blacklist file that will be used by the firewall.

.PARAMETER CurrentBlacklistFile
The .txt with the current blacklist file being used by the firewall.

.PARAMETER LogFile
The location of the logfile.

.PARAMETER GoodPublicIPs
The array with all well-known and good Public IP addresses of the company.

.PARAMETER GoodInternalIPs
The array with all well-known and good internal range of IP addresses of the company.

.EXAMPLE
Set-BlacklistIPAddresses -CurrentBlacklistFile $CurrentBlacklistFile -LogFile $LogFile -GoodPublicIPs $GoodPublicIPs -GoodInternalIPs $GoodInternalIPs 
#>
function Set-BlacklistIPAddresses {
   [CmdletBinding()]
   Param(
      [Parameter(Position = 0, Mandatory = $true)]
      [string] $CurrentBlacklistFile,
      [Parameter(Position = 1, Mandatory = $true)]
      [string] $LogFile,
      [Parameter(Position = 2, Mandatory = $true)]
      $GoodPublicIPs,
      [Parameter(Position = 3, Mandatory = $true)]
      $GoodInternalIPs

   )
   Write-Log -File $LogFile -Message "Starting new Malicious IP routine..."
   Write-Log -File $LogFile -Message "Logs for this script can be found in $LogFile"

   try {
      # Let's import the base list of IPs already being blocked
      $Script:BaseIPs = get-content $CurrentBlacklistFile 
      Write-Log -File $LogFile -Message "Current blacklist found in $CurrentBlacklistFile"
      Write-Log -File $LogFile -Message "Succesfully imported current block list..."
      Write-Log -File $LogFile -Message "Current blacklist count: $($Script:BaseIPs.count)"
   } 
   catch {
      $RecentError = $Error[0]
      Write-Log -File $LogFile -Message "ERROR importing $CurrentBlacklistFile - $RecentError"
   }
   try {
      # Let's import the new IPs from a file
      $IPList = get-content $RawIPFile
      Write-Log -File $LogFile -Message "New IP list found in $RawIPFile"
      Write-Log -File $LogFile -Message "Succesfully imported $($IPList.count) new IPs to be checked..."
   }
   catch {
      $RecentError = $Error[0]
      Write-Log -File $LogFile -Message "ERROR importing $RawIPFile - $RecentError"
   }
   try {
      # Let's remove the duplicate IPs we just imported
      $IPList = $IPList | Sort-Object -unique
      Write-Log -File $LogFile -Message "Succesfully removed new malicious duplicate IPs..."
   }
   catch {
      $RecentError = $Error[0]
      Write-Log -File $LogFile -Message "ERROR removing duplicate IPs - $RecentError"
   }
   try {
      # Let's see if there are any internal ones and get rid of those, while counting them
      $GoodIPs = @()

      $IPList | ForEach-Object {
         $GoodPublicBool = $false
         $GoodInternalBool = $false
         foreach ($i in $GoodPublicIPs) {
            if ($_ -contains "/") {
               if (IPInRange $GoodPublicIP $_) {
                  $GoodPublicBool = $true 
               }
            }
            elseif ($i -eq $_ ) {
               $GoodPublicBool = $true 
            }    
         }
         foreach ($i in $GoodInternalIPs) {
            if ($_ -contains "/") {
               if (IPInRange $GoodInternalIP $_) {
                  $GoodInternalBool = $true 
               }
            }
            elseif ($_ -like $i ) {
               $GoodInternalBool = $true                   
            }       
         }
         if ($GoodPublicBool -eq $true) {
            $GoodIPs += $_
            $GoodPublicBool = $false
            $Script:GoodPublicCounter += 1
            Write-Log -File $LogFile -Message "Added to good IP list (Public) - IP $_"
         }
         elseif ($GoodInternalBool -eq $true) {
            $GoodIPs += $_
            $GoodInternalBool = $false
            $Script:GoodInternalCounter += 1
            Write-Log -File $LogFile -Message "Added to good IP list (Internal) - IP $_"
         }
         else {
            $Script:BadIPs += $_
            Write-Log -File $LogFile -Message "Added to bad IP list - IP $_"
         }

      }
      Write-Log -File $LogFile -Message "Current good list size: $($GoodIPs.count+0) - $($Script:GoodPublicCounter+0) Public and $($Script:GoodInternalCounter+0) Internal..."
      Write-Log -File $LogFile -Message "Current bad list size: $($Script:BadIPs.count+0)"
   }
   catch {
      $RecentError = $Error[0]
      Write-Log -File $LogFile -Message "ERROR removing good internal and public IPs - $RecentError"
   }
   try {
      # Let's count how many IPs we added
      $Script:counter = 0

      # Let's clear the main IP blacklist file
      Clear-Content $CurrentBlacklistFile

      # Let's add the IPs to the main blacklist file
      $Script:BadIPs | ForEach-Object { 
         add-content -path $CurrentBlacklistFile -value $_
         $Script:counter += 1
         Write-Log -File $LogFile -Message "Adding to final firewall blacklist - IP: $_"  
      }
   } 
   catch {
      $RecentError = $Error[0]
      Write-Log -File $LogFile -Message "ERROR adding IPs to current blacklist - $RecentError"
   }
}

<#
.SYNOPSIS
Builds the email to be sent.

.DESCRIPTION
Builds the email to be sent with datafrom previous function.

.PARAMETER LogFile
The location of the logfile.

.PARAMETER TargetEmail
The target the email will be sent to.

.PARAMETER OriginEmail
The sender of the email.

.EXAMPLE
Send-Email -TargetEmail $TargetEmail -OriginEmail $OriginEmail -LogFile $LogFile

#>
function Send-Email {
   [CmdletBinding()]
   Param(
      [Parameter(Position = 0, Mandatory = $true)]
      [string] $LogFile,
      [Parameter(Position = 1, Mandatory = $true)]
      [string] $TargetEmail,
      [Parameter(Position = 2, Mandatory = $true)]
      [string] $OriginEmail

   )

   try {
      # Let's create the HTML body of the email
      $bodyhtml1 = @"
        <div style='font-family:Calibri;'>
        <p>We just imported new Malicious IPs to our Blacklist.</p>
        <p>As per rule: <a href="https://rules.ssw.com.au/do-you-create-your-own-ip-blacklist">Do you create your own IP blacklist?</a></p>
        <p>Old blacklist had $($Script:BadIPs.count) IPs.<br>
        Current blacklist has $($Script:BaseIPs.count) IPs.<br>
        Difference is $($Script:BadIPs.count - $Script:BaseIPs.count) IPs.</p>
        <p> This script is using $($IpSources.count) different internet lists, and they can be changed in the configuration file at $PSScriptRoot\Config.PSD1</p>
        <p>Tip:  We also removed our own $($Script:GoodInternalCounter+0) Internal IPs and our own $($Script:GoodPublicCounter+0) Public IPs - only external IP addresses should be blocked.<br>
        This script took $($Script:Stopwatch.Elapsed.ToString('mm')) minutes and $($Script:Stopwatch.Elapsed.ToString('ss')) seconds to run.
        You can find a log file with more information at <a href=$LogFile> $LogFile </a></p>
        <p>-- Powered by SSW.BlacklistChecker<br> </p>
        <p>
        GitHub: <a href=https://github.com/SSWConsulting/SSWSysAdmins.BlacklistChecker>SSWSysAdmins.BlacklistChecker</a><br>
        Internal Sharepoint: <a href=https://sswcom.sharepoint.com/:w:/g/SysAdmin/EY-FBWPIsolKn0_x_5XXl7YBc9KyoHalLZA6Mfk9cQlqGQ?e=vtZFJb>SSW HowTos - ASA FirePower Blacklist</a><br>
        Server: $env:computername <br>
        Folder: $PSScriptRoot</p>
"@
      # Let's concatenate the whole body of the email
      $body = $bodyhtml1

      if ($Script:counter -gt 0) {

         # Let's send an email for funsies if the number of IPs are greater than 0
         Send-MailMessage -from $OriginEmail -to $TargetEmail -Subject "SSW.Firewall - New IPs added to Blacklist Feed" -Body $body -SmtpServer "ssw-com-au.mail.protection.outlook.com" -bodyashtml
         Write-Log -File $LogFile -Message "Succesfully sent email to $TargetEmail from $OriginEmail..."
      }
      else {
         Write-Log -File $LogFile -Message "Succesfully skipped send email, not enough IPs added to the Blacklist..."
      }        
   }
   catch {
      $RecentError = $Error[0]
      Write-Log -File $LogFile -Message "ERROR sending email to $TargetEmail from $OriginEmail - $RecentError"
   }  
}

# Now let's run the commands one by one
Import-BlacklistIPFiles -LogFile $LogFile -IpSources $IpSources -LastDownloadedFile $LastDownloadedFile -RawIPFile $RawIPFile
Set-BlacklistIPAddresses -CurrentBlacklistFile $CurrentBlacklistFile -LogFile $LogFile -GoodPublicIPs $GoodPublicIPs -GoodInternalIPs $GoodInternalIPs 
Send-Email -TargetEmail $TargetEmail -OriginEmail $OriginEmail -LogFile $LogFile

# Let's stop timing this!
$Script:Stopwatch.Stop();