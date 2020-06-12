<#
.DESCRIPTION
Script that harvests malicious IP addresses from Windows Event Viewer in ADFS server.

.NOTES
Created by Kaique "Kiki" Biancatti for SSW.
#>

# Importing the configuration file
$config = Import-PowerShellDataFile $PSScriptRoot\Config.PSD1

# Building variables
$LogFile = $config.LogFile
$LogModuleLocation = $config.LogModuleLocation
$NewMaliciousIPFile = $config.NewMaliciousIPFile
$CredKey = "$PSScriptRoot\$($config.CredKey)"
$CredUser = "$PSScriptRoot\$($config.CredUser)"
$CredPass = "$PSScriptRoot\$($config.CredPass)"
$AdfsServer = $config.AdfsServer

# Importing the SSW Write-Log module
Import-Module -Name $LogModuleLocation

<#
.SYNOPSIS
Harvests malicious IP addresses from Windows Event Viewer in ADFS server.

.DESCRIPTION
Harvests malicious IP addresses from Windows Event Viewer in ADFS server.
Searches for a specific event ID and exports the IP, user and timestamp to a .csv file.

.PARAMETER NewMaliciousIPFile
The .csv file to be exported to.

.PARAMETER LogFile
The logfile to be used when logging.

.PARAMETER CredKey
The encrypted key to the password file.

.PARAMETER CredUser
The file where the username is present.

.PARAMETER CredPass
The encrypted file where the password is present.

.PARAMETER AdfsServer
The ADFS server name.

.EXAMPLE
Export-ExtranetLockouts -NewMaliciousIPFile $NewMaliciousIPFile -LogFile $LogFile -CredKey $CredKey -CredUser $CredUser -CredPass $CredPass -AdfsServer $AdfsServer
#>
function Export-ExtranetLockouts {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        $NewMaliciousIPFile,
        [Parameter(Position = 1, Mandatory = $true)]
        $LogFile,
        [Parameter(Position = 2, Mandatory = $true)]
        $CredKey,
        [Parameter(Position = 3, Mandatory = $true)]
        $CredUser,
        [Parameter(Position = 4, Mandatory = $true)]
        $CredPass,
        [Parameter(Position = 5, Mandatory = $true)]
        $AdfsServer
    )

    try {
        # Let's create the credentials for using with CredSSP
        $key = get-content $CredKey
        $username = get-content $CredUser
        $password = get-content $CredPass | ConvertTo-SecureString -Key $key
        $cred = New-Object System.Management.Automation.PSCredential($username, $password)

        Write-Log -File $LogFile -Message "Successfully imported user credentials from $CredKey, $CredUser and $CredPass..."

    }
    catch {
        $RecentError = $Error[0]
        Write-Log -File $LogFile -Message "ERROR on importing user creds - $RecentError"
    }

    Invoke-Command -ComputerName $AdfsServer -Authentication CREDSSP -Credential $cred -ArgumentList $LogModuleLocation, $LogFile, $NewMaliciousIPFile, $AdfsServer -ScriptBlock {
        try {
            $LogModuleLocation = $args[0]
            $LogFile = $args[1]
            $NewMaliciousIPFile = $args[2]
            $AdfsServer = $args[3]
            
            # Importing the SSW Write-Log module
            Import-Module -Name $LogModuleLocation
    
            $events = Get-WinEvent -FilterHashtable @{Logname = 'Security'; Id = 1210 }
            $events2 = ($events | select Message, TimeCreated -ExpandProperty Message)
    
            $info = @()
    
            $events2 | foreach {
    
                $IpAddresses = ((($_.Message.Split('<') | Select-String "IpAddress"))[0].tostring()).substring(10)    
                $ForwardedIpAddress = (($_.Message.Split('<') | Select-String "ForwardedIpAddress")[0].tostring()).substring(19).Trim()    
                $UserId = ($_.Message.Split('<') | Select-String "Userid>")[0].tostring().substring(7).Trim()
    
                $ActivityIDstart = (($_.Message.Split('<') | Select-String "Activity ID:").tostring().indexof("Activity ID:"))                                                                                         
                $ActivityIDend = (($_.Message.Split('<') | Select-String "Activity ID:").tostring().indexof("Additional Data"))           
                $ActivityIDlength = $ActivityIDend - $ActivityIDstart     
                $ActivityID = (($_.Message.Split('<') | Select-String "Activity ID:").tostring().substring($ActivityIDstart, $ActivityIDlength)).Trim().Replace("Activity ID: ", "")    
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
        
                $info += $Fail    
            }    
            $info | Select IPAddress, Server, UserID, TImeStamp | Sort-Object TimeStamp | export-csv $NewMaliciousIPFile   
            Write-Log -File $LogFile -Message "Succesfully created new Malicious IP list in $NewMaliciousIPFile..."

        }
        catch {
            $RecentError = $Error[0]
            Write-Log -File $LogFile -Message "ERROR on exporting extranet lockout events from $AdfsServer - $RecentError"
        }
    }
}

# Let's run the commands
Export-ExtranetLockouts -NewMaliciousIPFile $NewMaliciousIPFile -LogFile $LogFile -CredKey $CredKey -CredUser $CredUser -CredPass $CredPass -AdfsServer $AdfsServer
