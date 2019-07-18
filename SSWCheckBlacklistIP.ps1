<# SSWCheckBlacklistIP - PS Script to Add Malicious IPs Automatically to Blacklist File
 # Created by Kiki Biancatti for SSW
 #>

Param(

[Parameter(Position=0,Mandatory=$true)]
[string] $File,
[Parameter(Position=1,Mandatory=$true)]
[string] $BaseFile,
[Parameter(Position=2,Mandatory=$true)]
[string] $LogFile

)

# Let's create a log so we can see what is happening
Function LogWrite
{
   $username = $env:USERNAME
   
   $PcName = $env:computername

   $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
   $Line = "$Stamp $PcName $Username $args"

   Add-content $Logfile -value $Line
   Write-Host $Line
}

LogWrite "Starting new Malicious IP routine..."
LogWrite "Logs for this script can be found in $LogFile"

# Install the PSBlackList Checker that gives the main functionality of checking the IPs in the blacklist
Install-Module -Name PSBlackListChecker

# Now import the module
Import-Module PSBlackListChecker

# Let's import the base list of IPs already being blocked
$BaseIPs = get-content $BaseFile 
LogWrite "Current block list found in $BaseFile"
LogWrite "Succesfully imported current block list..."

# Let's import the new IPs from a file
$IPList = import-csv $File
LogWrite "New IP list found in $File"
LogWrite "Succesfully imported new IPs to be checked..."

# Let's remove the duplicate IPs we just imported
$IPList = $IPList | sort IpAddress -unique
LogWrite "Succesfully removed new malicious duplicate IPs..."

# Let's compare it with the current IP list and get rid of the ones we already have
$newips = $IPList | WHERE-OBJECT { $BaseIPs -notcontains $_.IpAddress }
LogWrite "Succesfully removed IPs we already had in our block list..."

# Let's see if there are any internal ones and get rid of those
$newips = $newips | where-object { ($_.IpAddress -NotLike "192.168.*") -and ($_.IpAddress -NotLike "10.100.*") -and ($_.IpAddress -ne "220.233.130.70") -and ($_.IpAddress -NotLike "220.233.152.16*") -and ($_.IpAddress -NotLike "220.233.152.17*") -and ($_.IpAddress -Notlike "220.233.148.2*") }
LogWrite "Succesfully removed internal and known public IPs..."

# Let's count how many IPs we added
$counter = 0

# Let's create an array to store all the users that got attacked by blacklisted IPs
$AttackedUsers = @()

# Let's see if the IPs are blacklisted in 80+ blacklist websites
$newips = $newips | ForEach-Object { 
    $IPValues = Search-BlackList -IP $_.IpAddress
    LogWrite "Searching blacklists for IP: "$_.IpAddress
    
    # If it is listed in 3 or more sites, add it to the main IP file
    if ( $IPValues.islisted.Count -ge 3 ) {
       $counter += 1
       $AttackedUsers += $_.UserID
       add-content -path $BaseFile -value $IPValues.IP[0] 
       LogWrite "Found in "$IPValues.islisted.Count" blacklists IP: "$IPValues.IP[0]
       LogWrite "Adding to block list IP: "$IPValues.IP[0]
    
    } else {
       LogWrite "Not found in  blacklists IP: "$IPValues.IP[0]
    }
}

# Let's properly format the array of users as HTML for the email
$AttackedUsers = $AttackedUsers | group | Select Count, Name | ConvertTo-Html

# Let's create the HTML body of the email
$bodyhtml = "We just added $counter Malicious IPs to our Blacklist. You can review the number of IPs that got blocked from each user at the end of this email. <br> <br> You can find a log file with more information at <a href=$LogFile> $LogFile </a> <br> This was done as per <a href=https://sswcom.sharepoint.com/:w:/g/SysAdmin/EY-FBWPIsolKn0_x_5XXl7YBc9KyoHalLZA6Mfk9cQlqGQ?e=vtZFJb> https://sswcom.sharepoint.com/:w:/g/SysAdmin/EY-FBWPIsolKn0_x_5XXl7YBc9KyoHalLZA6Mfk9cQlqGQ?e=vtZFJb </a> <br> <br>"

# Let's give it a signature
$bodyhtml += "Powered by SSW.CheckBlacklistIP"

# Let's concatenate the whole body of the email
$body = $bodyhtml + $AttackedUsers

if ($counter -gt 0) {

    # Let's send an email for funsies if the number of IPs are greater than 0
    Send-MailMessage -from "sswserverevents@ssw.com.au" -to "sswsysadmins@ssw.com.au" -Subject "SSW.Firewall - New IPs added to Blacklist Feed" -Body $body -SmtpServer "ssw-com-au.mail.protection.outlook.com" -bodyashtml
}

LogWrite "New Malicious IPs added to the list: "$counter
LogWrite "Finishing Malicious IP routine..."
