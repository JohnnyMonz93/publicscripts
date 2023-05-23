
#Install Graph
if(Get-Module -ListAvailable -Name Microsoft.Graph) {
    Write-Host "Microsoft.Graph Module Exists Moving On!"
}
else {
    Write-Host "Microsoft.Graph Does Not Exist Installing!!"
    Install-Module Microsoft.Graph -Scope CurrentUser -Force
}

#Connect
Connect-MgGraph -Scopes AppRoleAssignment.ReadWrite.All -ContextScope Process
Select-MgProfile Beta

#Get Managed Identity
$ManagedIdentityApp = (Get-MgServicePrincipal -all) |  Out-GridView -PassThru -Title "Choose Managed Identity"


#Get App ID
$AppID = Get-MgServicePrincipal -all | Where-Object -FilterScript {$_.PublisherName -EQ 'Microsoft Services'} | Out-GridView -PassThru -Title "Choose App ID"

$arrayOfAppRoles = @()

#Get App Roles
$arrayOfAppRoles += ($AppID.AppRoles | Select-Object DisplayName).DisplayName |  Out-GridView -PassThru -Title "You Can Choose Multiple App Roles Just Hold CTRL and Right Click Multiple Values"


#Loop Through chosen App Roles and apply to Managed Identity
foreach ($appRole in $arrayOfAppRoles){

$AppPermission = $AppID.AppRoles | Where-Object {$_.DisplayName -eq $appRole}

$AppRoleAssignment = @{
"PrincipalId" = $ManagedIdentityApp.Id
"ResourceId" = $AppID.Id
"AppRoleId" = $AppPermission.Id
}

Write-Host "Applying" $AppPermission.Description "To The Managed Identity" $ManagedIdentityApp.DisplayName
New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityApp.Id -BodyParameter $AppRoleAssignment

}
