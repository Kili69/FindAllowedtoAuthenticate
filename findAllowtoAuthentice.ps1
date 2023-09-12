<#
Script Info

Author: Andreas Lucas [MSFT]
Download: 

Disclaimer:
This sample script is not supported under any Microsoft standard support program or service. 
The sample script is provided AS IS without warranty of any kind. Microsoft further disclaims 
all implied warranties including, without limitation, any implied warranties of merchantability 
or of fitness for a particular purpose. The entire risk arising out of the use or performance of 
the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, 
or anyone else involved in the creation, production, or delivery of the scripts be liable for any 
damages whatsoever (including, without limitation, damages for loss of business profits, business 
interruption, loss of business information, or other pecuniary loss) arising out of the use of or 
inability to use the sample scripts or documentation, even if Microsoft has been advised of the 
possibility of such damages
#>
<#
.Synopsis
    This script searches for computer objects with "Allow-to-Authenticte" from trusting domains 

.DESCRIPTION
    This script searches for "Allow-to-authenticate" ACE for foreign identities on computer objects in the current domain.     

.EXAMPLE
    .\findAllowtoAuthenticate.ps1

.INPUTS
    -OU if the script searches only in a dedicated OU
    -ReportFile is the name of the CSV result file
.OUTPUTS
   CSV file
.NOTES
    
    Version Tracking
    0.1.20230901
        - First internal release
    0.1.20230905
        - show the current nummer ob the computer
    0.1.20230907
        - show the CSV file path 
        - addtional output
    0.1.20230911
        - Now is looks for remote users which indirect get the "allow-to-authenticate" due group nesting
#>
param(
    # alternate configuration file name
    [Parameter(Mandatory = $false)]
    [String]$OU = "",
    [Parameter(Mandatory = $false)]
    [String]$ReportFile = ".\Report.csv",
    [Parameter(Mandatory = $false)]
    [string]$LogFile = ".\findAllowedToauthenticate.log"
)

#region constantes
$ScriptVersion = "2023091106"
#GUID Active Directory Allowed-to-authenticate
$AllowToAuthenticateGuid = "68b1d179-0d15-4d4f-ab71-46152e79a7bc"
#Named for Built in users. This value can change if your AD is localized
$BuiltIn = "BUILTIN"
#Well-know SIDs. This will indicate this is not a trusted domain
$WknSID = "S-1-5-32-"
#the local NT Authority can be ignored
$NtAuth = "NT AUTHORITY"
#To avoid call the Get-ADDomain CMDlet several times, the domain information is stored in this variable
$Domain = Get-ADdomain
#endregion

#region LogFile preparation
Function write-scriptlog {
    Param(
        # error level
        [Parameter(Mandatory = $true)]
        [String] $LogLevel,
        [Parameter(Mandatory = $true)]
        [String] $Message
    )
    Add-Content $LogFile "$((get-date).tostring("yyyyMMdd-hh:mm:ss")) -$logLevel - $Message"
}
#endregion


#if the OU parameter is not used, the script analyzed the entire AD
if ($OU -eq ""){
    $OU= $Domain.DistinguishedName
}
else {
    #Validate the path exists
    if (!(Test-Path -Path "AD:$OU")){
        Write-Host "OU $OU does not exist"
        exit
    }
}
write-scriptlog -LogLevel "info" -Message "script started on $OU"
#All results wil be collected in this array
$RemoteAccess = @()
#Count the computer object with foreigen AD objects in the ACL
$ComputerCounter = 0
#Enuerate the domain local groups where foreign users are member of
$GroupWithForeignMembers = @()
#search for all computers in the OU and below
Write-Host "Script $ScriptVersion started at $(Get-Date) "
try{
    
    Foreach ($ForeignPrincipal in Get-ADObject -Filter {(ObjectClass -eq "foreignSecurityPrincipal") -and (Name -like "S-1-5-21*")} -Properties MemberOf){
        Foreach ($MemberOf in $ForeignPrincipal.MemberOf){
            $ForeignADObject = New-Object psObject
            $ForeignADObject | Add-Member NoteProperty -Name "GroupName" -Value "$((Get-ADDomain).NetBiosName)\$((Get-ADObject -Filter {DistinguishedName -eq $MemberOf} -Properties CN).CN)"
            $ForeignADObject | Add-Member NoteProperty -Name "Reference" -Value $ForeignPrincipal
            $GroupWithForeignMembers += $ForeignADObject
        }
    }
    Write-Host "Found $($GroupWithForeignMembers.count) groups who contains foreign members in local groups"
    $ADMembers = Get-ADComputer -Filter {(OperatingSystem -like '*Windows Server*') -and (Enabled -eq $True)} -Searchbase $OU -SearchScope Subtree
    Write-Host "Found $($ADMembers.Count) computers to analyzed"
}
catch {
    write-scriptlog -LogLevel "Err" -Message "unable to collect computer object - $($_.ScriptStackTrace)"
    break
}


#It's time to analyze all collected computer object. 
For ($i=0; $i -lt $ADMembers.Count;$i++){
    #calculate the current progress and show the progress 
    $completed = ($i*100/$ADMembers.count) 
    Write-Progress -Activity "Analyze computer" -Status " $i Computers $($ADMembers.Count) analyzed" -PercentComplete $completed

    try{
        #collect the ACL of the computer
        $Acl = Get-Acl -Path "AD:$($ADMembers[$i].DistinguishedName)" | Select-Object -ExpandProperty access  
        Foreach ($Ace in $ACl){
            #searching for Allowed-to-Authenticate and Full control
            if (($Ace.ObjectType -eq $AllowToAuthenticateGuid) -or ($Ace.ActiveDirectoryRights -eq "GenericAll")){
                #exclude well-known-SID, builtin identities, NT Authority and unresolveable SID from the current domain
                if (($Ace.IdentityReference -notlike "$WknSID*") -and`
                    ($Ace.IdentityReference -notlike "$BuiltIn\*") -and`
                    ($Ace.IdentityReference -notlike "$NTAuth\*") -and`
                    ($Ace.IdentityReference -notlike "$($Domain.DomainSid)*")
                ){
                    #if the ACE shows a foreigen domain create a new entry
                    if ($Ace.IdentityReference -notlike "$($Domain.NetBIOSName)\*"){
                        $NewComputer2Add = New-Object psObject
                        $NewComputer2Add | Add-Member NoteProperty -Name "Computer"  -Value $ADMembers[$i].DistinguishedName
                        $NewComputer2Add | Add-Member NoteProperty -Name "Identity"  -Value $Ace.IdentityReference
                        $NewComputer2Add | Add-Member NoteProperty -Name "Reference" -Value $Ace.IdentityReference
                        $RemoteAccess += $NewComputer2Add
                    } else {
                        #on any local ACE check if they are in the list with nexted foreign groups
                        foreach ($Group in $GroupWithForeignMembers){
                            if ($Ace.IdentityReference -eq "$($Group.GroupName)"){
                                $NewComputer2Add = New-Object psObject
                                $NewComputer2Add | Add-Member NoteProperty -Name "Computer" -Value $ADMembers[$i].DistinguishedName
                                $NewComputer2Add | Add-Member NoteProperty -Name "Identity" -Value $Ace.IdentityReference
                                $NewComputer2Add | Add-Member NoteProperty -Name "Reference" -Value $Group.Reference
                                $RemoteAccess += $NewComputer2Add
                            }
                        }
                    }
                }
            }
        }
    }
    catch{
        write-scriptlog -LogLevel "err" -Message "A error occurs on $($ADMembers[$i].DistinguishedName) - $($_.ScriptStackTrace)"
        Write-Host "A error occurs on number $i $($ADMembers[$i].DistinguishedName ) $($_.ScriptStackTrace)" -ForegroundColor Red
    }
}
Write-Progress -Completed -Activity "Analyze computer"
$RemoteAccess | Export-Csv -Path $ReportFile -Force -NoTypeInformation
Write-Host "Found $($RemoteAccess.Count) ACL entries on $($ADMembers.count) computers"
Write-Host "please check $ReportFile"
