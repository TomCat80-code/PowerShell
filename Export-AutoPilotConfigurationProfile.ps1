Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module WindowsAutopilotIntune -MinimumVersion 5.4.0 -Force
Install-Module Microsoft.Graph.Groups -Force
Install-Module Microsoft.Graph.Authentication -Force
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Force

Import-Module WindowsAutopilotIntune -MinimumVersion 5.4
Import-Module Microsoft.Graph.Groups
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Identity.DirectoryManagement

Connect-MgGraph -Scopes "Device.ReadWrite.All", "DeviceManagementManagedDevices.ReadWrite.All", "DeviceManagementServiceConfig.ReadWrite.All", "Domain.ReadWrite.All", "Group.ReadWrite.All", "GroupMember.ReadWrite.All", "User.Read"
$AutopilotProfile = Get-AutopilotProfile
$targetDirectory = "C:\Autopilot"
$AutopilotProfile | ForEach-Object {
    New-Item -ItemType Directory -Path "$targetDirectory\$($_.displayName)"
    $_ | ConvertTo-AutopilotConfigurationJSON | Set-Content -Encoding Ascii "$targetDirectory\$($_.displayName)\AutopilotConfigurationFile.json"
}