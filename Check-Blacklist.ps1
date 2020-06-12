<#
.SYNOPSIS
   Script to check blacklists across the web and block potential threats to our company. Includes sending email.

.NOTES
   Created by Kiki Biancatti for SSW.
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
$NewMaliciousIPFile = $config.NewMaliciousIPFile
$CurrentBlacklistFile = $config.CurrentBlacklistFile
$GoodPublicIPs = $config.GoodPublicIPs
$GoodInternalIPs = $config.GoodInternalIPs
$Script:GoodInternalCounter = 0
$Script:GoodPublicCounter = 0

# Importing the SSW Write-Log module
Import-Module -Name $LogModuleLocation

<#
.SYNOPSIS
Gets the IP addresses in a file and checks if they are on blacklists across the web.

.DESCRIPTION
Gets the IP addresses in a file and checks if they are on blacklists across the web. 
Sorts them correctly and, if they are, add them to the final blacklist file that will be used by the firewall.

.PARAMETER NewMaliciousIPFile
The .csv with IPs to be checked.

.PARAMETER CurrentBlacklistFile
The .txt with the current blacklist file being used by the firewall.

.PARAMETER LogFile
The location of the logfile.

.PARAMETER GoodPublicIPs
The array with all well-known and good Public IP addresses of the company.

.PARAMETER GoodInternalIPs
The array with all well-known and good internal range of IP addresses of the company.

.EXAMPLE
Set-BlacklistIPAddresses -NewMaliciousIPFile $NewMaliciousIPFile -CurrentBlacklistFile $CurrentBlacklistFile -LogFile $LogFile -GoodPublicIPs $GoodPublicIPs -GoodInternalIPs $GoodInternalIPs 
#>
function Set-BlacklistIPAddresses {
   [CmdletBinding()]
   Param(
      [Parameter(Position = 0, Mandatory = $true)]
      [string] $NewMaliciousIPFile,
      [Parameter(Position = 1, Mandatory = $true)]
      [string] $CurrentBlacklistFile,
      [Parameter(Position = 2, Mandatory = $true)]
      [string] $LogFile,
      [Parameter(Position = 3, Mandatory = $true)]
      $GoodPublicIPs,
      [Parameter(Position = 4, Mandatory = $true)]
      $GoodInternalIPs

   )
   Write-Log -File $LogFile -Message "Starting new Malicious IP routine..."
   Write-Log -File $LogFile -Message "Logs for this script can be found in $LogFile"

   try {
      # Importing the PSBlacklistChecker module (https://evotec.xyz/hub/scripts/psblacklistchecker/)
      Import-Module PSBlackListChecker
      Write-Log -File $LogFile -Message "Succesfully imported PSBlackListChecker module..."
   } 
   catch {
      $RecentError = $Error[0]
      Write-Log -File $LogFile -Message "ERROR importing PSBlackListChecker module - $RecentError"
   }

   try {
      # Let's import the base list of IPs already being blocked
      $BaseIPs = get-content $CurrentBlacklistFile 
      Write-Log -File $LogFile -Message "Current block list found in $CurrentBlacklistFile"
      Write-Log -File $LogFile -Message "Succesfully imported current block list..."
   } 
   catch {
      $RecentError = $Error[0]
      Write-Log -File $LogFile -Message "ERROR importing $CurrentBlacklistFile - $RecentError"
   }

   try {
      # Let's import the new IPs from a file
      $IPList = import-csv $NewMaliciousIPFile
      Write-Log -File $LogFile -Message "New IP list found in $NewMaliciousIPFile"
      Write-Log -File $LogFile -Message "Succesfully imported $($IPList.count) new IPs to be checked..."
   }
   catch {
      $RecentError = $Error[0]
      Write-Log -File $LogFile -Message "ERROR importing $NewMaliciousIPFile - $RecentError"
   }
   try {
      # Let's remove the duplicate IPs we just imported
      $IPList = $IPList | Sort-Object IpAddress -unique
      Write-Log -File $LogFile -Message "Succesfully removed new malicious duplicate IPs..."

      # Let's compare it with the current IP list and get rid of the ones we already have
      $newips = $IPList | WHERE-OBJECT { $BaseIPs -notcontains $_.IpAddress }
      Write-Log -File $LogFile -Message "Succesfully removed IPs we already had in our block list..."
   }
   catch {
      $RecentError = $Error[0]
      Write-Log -File $LogFile -Message "ERROR removing duplicate IPs - $RecentError"
   }

   try {
      # Let's see if there are any internal ones and get rid of those, while counting them
      $BadIPs = @()
      $GoodIPs = @()

      $newips | ForEach-Object {
         $GoodPublicBool = $false
         $GoodInternalBool = $false
         foreach ($i in $GoodPublicIPs) {
            if ($i -eq $_.IpAddress) {
               $GoodPublicBool = $true                    
            }       
         }
         foreach ($i in $GoodInternalIPs) {
            if ($_.IpAddress -like $i ) {
               $GoodInternalBool = $true                   
            }       
         }
         if ($GoodPublicBool -eq $true) {
            $GoodIPs += $_
            $GoodPublicBool = $false
            $Script:GoodPublicCounter += 1
            Write-Log -File $LogFile -Message "Added to good IP list (Public) - IP $($_.IpAddress)"
         }
         elseif ($GoodInternalBool -eq $true) {
            $GoodIPs += $_
            $GoodInternalBool = $false
            $Script:GoodInternalCounter += 1
            Write-Log -File $LogFile -Message "Added to good IP list (Internal) - IP $($_.IpAddress)"
         }
         else {
            $BadIPs += $_
            Write-Log -File $LogFile -Message "Added to bad IP list - IP $($_.IpAddress)"
         }

      }
      Write-Log -File $LogFile -Message "Current good list size: $($GoodIPs.count) - $Script:GoodPublicCounter Public and $Script:GoodInternalCounter Internal..."
      Write-Log -File $LogFile -Message "Current bad list size to be checked: $($BadIPs.count)"
   }
   catch {
      $RecentError = $Error[0]
      Write-Log -File $LogFile -Message "ERROR removing good internal and public IPs - $RecentError"
   }

   try {
      # Let's create an array to store all the users that got attacked by blacklisted IPs
      $Script:AttackedUsers = @()
      Write-Log -File $LogFile -Message "Succesfully created array to store attacked users..."
   }
   catch {
      $RecentError = $Error[0]
      Write-Log -File $LogFile -Message "ERROR creating array to store attacked users - $RecentError"
   }

   try {
      # Let's count how many IPs we added
      $Script:counter = 0

      # Let's see if the IPs are blacklisted in 80+ blacklist websites
      $BadIPs = $BadIPs | ForEach-Object { 
         $IPValues = Search-BlackList -IP $_.IpAddress
         Write-Log -File $LogFile -Message "Searching web blacklists - IP: $($_.IpAddress)"
    
         # If it is listed in 3 or more sites, add it to the main IP file
         if ( $IPValues.islisted.Count -ge 3 ) {
            $Script:counter += 1
            $trimUser = $_.UserID.split("\") 
            $ad = get-aduser -identity $TrimUser[1]
            $Script:AttackedUsers += $_.UserID + " - (Enabled: " + $ad.Enabled + ")"
            $CurrentIP = $IPValues.IP | Sort-Object IP -unique
            add-content -path $CurrentBlacklistFile -value $CurrentIP
            Write-Log -File $LogFile -Message "Found in $($IPValues.islisted.Count) different web blacklists - IP: $CurrentIP"
            Write-Log -File $LogFile -Message "Adding to final firewall blacklist - IP: $CurrentIP"    
         }
         else {
            $CurrentIP = $IPValues.IP | Sort-Object IP -unique
            Write-Log -File $LogFile -Message "Not adding to final firewall blacklist, not found in enough web blacklists - IP: $CurrentIP"
         }
      }
      # Let's properly format the array of users as HTML for the email
      $Script:AttackedUsers = $Script:AttackedUsers | group | Select Count, Name | ConvertTo-Html
      Write-Log -File $LogFile -Message "New Malicious IPs added to the list: $Script:counter"
      Write-Log -File $LogFile -Message "Finishing Malicious IP routine..."
   }
   catch {
      $RecentError = $Error[0]
      Write-Log -File $LogFile -Message "ERROR searching web blacklists - $RecentError"
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
        <p>We just added $Script:counter Malicious IPs to our Blacklist.</p>
        <p>As per rule: <a href="https://rules.ssw.com.au/do-you-create-your-own-ip-blacklist">Do you create your own IP blacklist?</a></p>
"@
        
      $bodyhtml2 = @"
        <p>Tip:  We also removed our own $Script:GoodInternalCounter Internal IPs and our own $Script:GoodPublicCounter Public IPs - only external IP addresses should be blocked.<br>
        This script took $($Script:Stopwatch.Elapsed.TotalSeconds) seconds to run.
        You can find a log file with more information at <a href=$LogFile> $LogFile </a></p>
        <p>-- Powered by SSW.BlacklistChecker<br> </p>
        <p>
        GitHub: <a href=https://github.com/SSWConsulting/SSWSysAdmins.BlacklistChecker>SSWSysAdmins.BlacklistChecker</a><br>
        Internal Sharepoint: <a href=https://sswcom.sharepoint.com/:w:/g/SysAdmin/EY-FBWPIsolKn0_x_5XXl7YBc9KyoHalLZA6Mfk9cQlqGQ?e=vtZFJb>SSW HowTos - ASA FirePower Blacklist</a><br>
        Server: $env:computername <br>
        Folder: $PSScriptRoot</p>
"@
      # Let's concatenate the whole body of the email
      $body = $bodyhtml1 + $Script:AttackedUsers + $bodyhtml2

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
Set-BlacklistIPAddresses -NewMaliciousIPFile $NewMaliciousIPFile -CurrentBlacklistFile $CurrentBlacklistFile -LogFile $LogFile -GoodPublicIPs $GoodPublicIPs -GoodInternalIPs $GoodInternalIPs 
Send-Email -TargetEmail $TargetEmail -OriginEmail $OriginEmail -LogFile $LogFile

# Let's stop timing this!
$Script:Stopwatch.Stop();