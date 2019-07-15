# PS Script to Add Malicious IPs Automatically to Blacklist File
# Created by Kiki Biancatti for SSW

Param(

[string] $File,
[string] $BaseFile

)

# Let's create a log in flea so we can see what is happening
$Logfile1 = "\\fileserver\Backups\SSWCheckBlacklistIP.log"

Function LogWrite
{
   $username = $env:USERNAME
   
   $PcName = $env:computername

   $Stamp = (Get-Date).toString("dd/MM/yyyy HH:mm:ss")
   $Line = "$Stamp $PcName $Username $args"

   Add-content $Logfile1 -value $Line
   Write-Host $Line
}

LogWrite "Starting new Malicious IP routine..."
LogWrite "This script can be found in C:\DataWhatsUp\MaliciousIPChecker in server SYDMON2016P01"
LogWrite "Logs for this script can be found in $LogFile1"

# Install the PSBlackList Checker that gives the main functionality of checking the IPs in the blacklist
Install-Module -Name PSBlackListChecker

# Now import the module
Import-Module PSBlackListChecker

# Let's import the base list of IPs already being blocked
$BaseFile = "C:\inetpub\wwwroot\SSWBlacklistIP\basefile.txt"
$BaseIPs = get-content $BaseFile 
LogWrite "Current block list found in $BaseFile"
LogWrite "Succesfully imported current block list..."

# Let's import the new IPs from a file
$File = "\\fileserver\Backups\NewMaliciousIPs.csv"
$IPList = import-csv $File
LogWrite "New IP list found in $File"
LogWrite "Succesfully imported new IPs to be checked..."

# Let's remove the duplicate IPs we just imported
$IPList = $IPList.IPAddress | sort -unique
LogWrite "Succesfully removed new malicious duplicate IPs..."

# Let's compare it with the current IP list and get rid of the ones we already have
$newips = $IPList | ForEach-Object { $_ } | WHERE-OBJECT { $BaseIPs -notcontains $_ }
LogWrite "Succesfully removed IPs we already had in our block list..."

# Let's see if there are any internal ones and get rid of those
$newips = $newips | ForEach-Object { $_ } | where-object { ($_ -NotLike "192.168.*") -and ($_ -NotLike "10.100.*") -and ($_ -ne "220.233.130.70") -and ($_ -NotLike "220.233.152.16*") -and ($_ -NotLike "220.233.152.17*") -and ($_ -Notlike "220.233.148.2*") }
LogWrite "Succesfully removed internal and known public IPs..."

# Let's count how many IPs we added
$counter = 0

# Let's see if the IPs are blacklisted in 80+ blacklist websites
$newips = $newips | ForEach-Object { 
    $IPValues = Search-BlackList -IP $_
    LogWrite "Searching blacklists for IP: $_"
    
    # If it is listed in 3 or more sites, add it to the main IP file
    if ( $IPValues.islisted.Count -ge 3 ) {
       $counter = $counter+1
       add-content -path $BaseFile -value $IPValues.IP[0] 
       LogWrite "Found in "$IPValues.islisted.Count" blacklists IP: "$IPValues.IP[0]
       LogWrite "Adding to block list IP: "$IPValues.IP[0]
    
    } else {
       LogWrite "Not found in  blacklists IP: "$IPValues.IP[0]
    }
}

if ($counter -gt 0) {

    # Let's send an email for funsies if the number of IPs are greater than 0
    Send-MailMessage -from "sswsysadmins@ssw.com.au" -to "sswsysadmins@ssw.com.au" -Subject "SSW.Firewall - New IPs added to Blacklist Feed" -Body "We just added $counter Malicious IPs to our Blacklist. <br> <br> You can find a log file with more information at $LogFile1 <br> <br> This was done as per https://sswcom.sharepoint.com/:w:/g/SysAdmin/EY-FBWPIsolKn0_x_5XXl7YBc9KyoHalLZA6Mfk9cQlqGQ?e=vtZFJb " -SmtpServer "mail.ssw.com.au" -bodyashtml
}

LogWrite "New Malicious IPs added to the list: "$counter
LogWrite "Finishing Malicious IP routine..."
