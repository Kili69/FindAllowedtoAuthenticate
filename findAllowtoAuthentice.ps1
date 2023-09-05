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
#GUID Active Directory Allowed-to-authenticate
$AllowToAuthenticateGuid = "68b1d179-0d15-4d4f-ab71-46152e79a7bc"
#GUID Full access
$FullAccess = "00000000-0000-0000-0000-000000000000"
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
#search for all computers in the OU and below
try{
$ADMembers = Get-ADComputer -Filter "OperatingSyetem -like '*Windows Server*' -and Enabled -eq 'True'" -Searchbase $OU -SearchScope Subtree
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
    # More details on the next command
    #GEt-acl -Path "AD:$($ADMembers[$i].DistinguishedName)" | => collect the ACL from the computer object
    #Select-Object -ExpandProperty access | => extend the ACE for the detail analysis
    #Where-Object {(($_.ObjectType -eq $AllowToAuthenticateGuid) -or ($_.ObjectType -eq $FullAccess) )` => search only for ACE with "allow-to-authenticate" or full access
    #     -and ($_.IdentityReference -notlike "$($Domain.NetBiosName)\*")` => Ignore any local user 
    #     -and ($_.IdentityReference -notlike "$WknSID*") `                => Ignore well known Domain SIDs
    #     -and ($_.IdentityReference -notlike "$BuiltIn\*")`               => Ignore Built-IN AD object
    #     -and ($_.IdentityReference -notlike "$NTAuth\*")`                => Ignore the local NT Authority
    #     -and ($_.IdentityReference -notlike "$($Domain.DomainSID)*")} |  => Ignore unknown local deleted objects 
    try{
        $Acl = GEt-acl -Path "AD:$($ADMembers[$i].DistinguishedName)" | 
        Select-Object -ExpandProperty access | 
        Where-Object {(($_.ObjectType -eq $AllowToAuthenticateGuid) -or ($_.ObjectType -eq $FullAccess) )`
             -and ($_.IdentityReference -notlike "$($Domain.NetBiosName)\*")`
             -and ($_.IdentityReference -notlike "$WknSID*") `
             -and ($_.IdentityReference -notlike "$BuiltIn\*")`
             -and ($_.IdentityReference -notlike "$NTAuth\*")`
             -and ($_.IdentityReference -notlike "$($Domain.DomainSID)*")} |
        Select-Object @{name = "Computer";expression={$ADMembers[$i].DistinguishedName}},
                      @{name = "RemoteUser";expression={$_.IdentityReference}}
        #Only add objects with foreign ACE
        if ($null -ne $acl){
            $RemoteAccess +=($Acl)
            $ComputerCounter++
        }
    }
    catch{
        write-scriptlog -LogLevel "err" -Message "A error occurs on $($ADMembers[$i].DistinguishedName) - $($_.ScriptStackTrace)"
        Write-Host "A error occurs on number $i $($ADMembers[$i].DistinguishedName ) $($_.ScriptStackTrace)" -ForegroundColor Red
    }
}
Write-Progress -Completed -Activity "Analyze computer"
$RemoteAccess | Export-Csv -Path $ReportFile -Force
Write-Host "Found $($RemoteAccess.Count) enties on $ComputerCounter"
