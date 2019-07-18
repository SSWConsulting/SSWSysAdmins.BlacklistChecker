<# EventViewerSearchExtranetLockouts - PS Script to Harvest Malicious IPs Automatically 
 # Created by Kiki Biancatti for SSW
 #>

Param(

[Parameter(Position=0,Mandatory=$true)]
[string] $File,
[Parameter(Position=1,Mandatory=$true)]
[string] $LogFile

)

# Let's create the credentials for using with CredSSP
$key = get-content "C:\DataWhatsUp\MaliciousIPChecker\key.txt"
$username = get-content "C:\DataWhatsUp\MaliciousIPChecker\usercreds.txt"
$password = get-content "C:\DataWhatsUp\MaliciousIPChecker\creds.txt" | ConvertTo-SecureString -Key $key


$cred = New-Object System.Management.Automation.PSCredential($username,$password)

# Let's invoke the command on SYDADFSP01 
Invoke-Command -ComputerName SYDADFSP01 -Authentication CREDSSP -Credential $cred -ScriptBlock {

# Let's create some logs so we can see what is happening
Function LogWrite
{
   $username = $env:USERNAME
   
   $PcName = $env:computername

   $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
   $Line = "$Stamp $PcName $Username $args"

   Add-content $Using:Logfile -value $Line
   Write-Host $Line
}

$events = Get-WinEvent -FilterHashtable @{Logname='Security';Id=1210}
$events2 = ($events | select Message,TimeCreated -ExpandProperty Message)

$info = @()

$events2 | foreach {

    $IpAddresses = ((($_.Message.Split('<') | Select-String "IpAddress"))[0].tostring()).substring(10)

    $ForwardedIpAddress = (($_.Message.Split('<') | Select-String "ForwardedIpAddress")[0].tostring()).substring(19).Trim()

    $UserId = ($_.Message.Split('<') | Select-String "Userid>")[0].tostring().substring(7).Trim()



        $ActivityIDstart = (($_.Message.Split('<') | Select-String "Activity ID:").tostring().indexof("Activity ID:"))                                                                                     

        $ActivityIDend = (($_.Message.Split('<') | Select-String "Activity ID:").tostring().indexof("Additional Data"))       

    $ActivityIDlength = $ActivityIDend - $ActivityIDstart 

    $ActivityID = (($_.Message.Split('<') | Select-String "Activity ID:").tostring().substring($ActivityIDstart,$ActivityIDlength)).Trim().Replace("Activity ID: ","")

    $Server = ($_.Message.Split('<') | Select-String "Server")[0].tostring().substring(7).Trim()

    $FailureType = ($_.Message.Split('<') | Select-String "FailureType")[0].tostring().substring(12).Trim()

    $AuditType = ($_.Message.Split('<') | Select-String "AuditType")[0].tostring().substring(10).Trim()



$Fail = New-object -TypeName PSObject

add-member -inputobject $Fail -membertype noteproperty -name "TimeStamp" -value $_.TimeCreated

add-member -inputobject $Fail -membertype noteproperty -name "IPaddress" -value $IpAddresses

add-member -inputobject $Fail -membertype noteproperty -name "ForwardedIpAddress" -value $ForwardedIpAddress

add-member -inputobject $Fail -membertype noteproperty -name "UserId" -value $UserId

add-member -inputobject $Fail -membertype noteproperty -name "ActivityID" -value $ActivityID

add-member -inputobject $Fail -membertype noteproperty -name "Server" -value $Server

add-member -inputobject $Fail -membertype noteproperty -name "FailureType" -value $FailureType

add-member -inputobject $Fail -membertype noteproperty -name "AuditType" -value $AuditType



$info +=$Fail

}

$info | Select IPAddress,Server,UserID,TImeStamp | Sort-Object TimeStamp | export-csv $Using:File

LogWrite "Succesfully created new Malicious IP list in $Using:File"
}
