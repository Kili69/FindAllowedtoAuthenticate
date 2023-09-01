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
#>
param(
    # alternate configuration file name
    [Parameter(Mandatory = $false)]
    [String]$OU,
    [Parameter(Mandatory = $false)]
    [String]$ReportFile = ".\Report.csv"
)

#const
#GUID Active Directory Allowed-to-authenticate
$AllowToAuthenticateGuid = "68b1d179-0d15-4d4f-ab71-46152e79a7bc"

$Domain = Get-ADdomain

if ($null -eq $OU){
    $OU= $Domain.DistinguishedName
}
$RemoteAccess = @{}

$ADMembers = GetADcomputer -Filer * -Searchbase $OU
$RemoteAccess = @{}


For ($i=0; $i -lt $ADMembers.Count;$i++){
    $completed = ($i*100/$ADMembers.count)
    Write-Progress -Activity "Analyze computer" -Status " Computers $($ADMembers.Count) analyzed" -PercentComplete $completed
    $Acl = GEt-acl -Path "AD:$($Computer.DistinguishedName)" | 
    Select-Object -ExpandProperty access | 
    Where-Object {($_.ObjectType -eq $AllowToAuthenticateGuid) -and ($_.IdentityReference -like "$($Domain.NetBiosName))\*")} |
    Select-Object @{name = "Computer";expression={$Server}},
                  @{name = "RemoteUser";expression={$_.IdentityReference}}
    $RemoteAccess += $Acl
}
$RemoteAccess