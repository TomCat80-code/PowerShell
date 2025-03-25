#Requires -Version 5
<#
.SYNOPSIS

.DESCRIPTION
  Upload a SharePoint file of complete folder without using any SharePoint modules.
  
.PARAMETER
  None

.INPUTS
  None

.OUTPUTS
  None

.NOTES
  Script:				Invoke-SPOFileUpload.ps1
  Version:				1.0
  Template:				IME_PSTemplateScript.ps1
  Template Version:		1.2
  Company:				
  Author:				Tom van Beest
  Creation Date:		25-03-2025  
  Source(s):			
  Release notes:		Version 1.0 - Initial published version.

.LINK

.EXAMPLE
  .\Invoke-SPOFileUpload.ps1

REQUIRED
  Create a new Entra ID Service Principal
    Add the Group.Read.All and Sites.Selected Application permissions -> Add specific site permissions for for the Service principal

USAGE
  Make the relevant changes to the variables in the [Declarations] section to reflect the execution evironment of the script.
  
  Information to be provided is:
	Script Version	for 	$dScriptVersion 	Should correspond with Version in the .NOTES section
	Script Name 	for 	$dScriptName		Should correspond with the actual file name (WITHOUT FILE EXTENSION) and Script (WITHOUT FILE EXTENSION) in the .NOTES section
	Customer Name	for		$dCustomerName		The full name of the customer
	Customer Abbr.	for		$dCustomerShortName	A three or four character alpanumeric (common) abbreviation of the customer
  
IMPORTANT: Please test the script using PsExec first and check for errors before deploying it through IME!

DISCLAIMER
  THIS CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" 
  WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, 
  INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. 

  This script is provided "AS IS" with no warranties, and confers no rights. 
#>

#---------------------------------------------------------[Initializations]--------------------------------------------------------

$exitCode = 0

#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Script Version
$dScriptVersion = "1.0"
$dScriptName = "Invoke-SPOFileUpload"

#Customer Specific Information
$dCustomerName = "< Customer Name >"
$dCustomerShortName = "< Customer Prefix >"

#Directories

#Log File Information

# Script Specific
$dTenantName = "< tenant name >.onmicrosoft.com"
$dClientId = "< Client Id / App Id >"
$dClientSecret = "< Client Secret >"
$dSPOSiteGroupId = "< SharePoint Group Id >"
$dTokenRequestUri = "https://login.microsoftonline.com/$dTenantName/oauth2/v2.0/token"

#-----------------------------------------------------------[Functions]------------------------------------------------------------

Function Get-AuthToken {
    Param
    (
        [Parameter(Mandatory=$true)][string]$TokenRequestUri,
        [Parameter(Mandatory=$true)][string]$ClientId,
        [Parameter(Mandatory=$true)][string]$ClientSecret
    )

    $TokenRequestBody = @{
        Grant_Type    = 'client_credentials'
        Scope         = 'https://graph.microsoft.com/.default'
        Client_Id     = $ClientId
        Client_Secret = $ClientSecret
    }
    $TokenResponse = Invoke-RestMethod -Uri $TokenRequestUri -Method POST -Body $TokenRequestBody -ErrorAction Stop
    $TokenResponse
}

Function New-SPOFileUpload {
    Param
    (
        [Parameter(Mandatory=$true,ParameterSetName="FileUploadType")][string]$FileToUpload,
        [Parameter(Mandatory=$true,ParameterSetName="FolderUploadType")][string]$FolderToUpload,
        [Parameter(Mandatory=$true)][string]$SPOSiteGroupId,
        [Parameter(Mandatory=$true)][hashtable]$AuthHeader
    )

    $SPOSiteUri = "https://graph.microsoft.com/v1.0/groups/$SPOSiteGroupId/sites/root"
    $SPOSiteId = (Invoke-RestMethod -Method GET -Headers $AuthHeader -Uri $SPOSiteUri).id

    If (-not [string]::IsNullOrEmpty($FolderToUpload)) {
        $Files = Get-ChildItem -Path $FolderToUpload -Recurse -File
        Foreach ($FileEntry in $Files) {
            $FilePath = $FileEntry.FullName
            $FileName = $FileEntry.Name
            $FileFolderPath = $FileEntry.DirectoryName
            $FileDrive = $FileEntry.PSDrive.Root
            
            $SPOSiteDrivesUri = "https://graph.microsoft.com/v1.0/sites/$SPOSiteId/drives"
            $SPOSiteDrives = Invoke-RestMethod -Method GET -Headers $AuthHeader -Uri $SPOSiteDrivesUri
            $SPOSiteDocumentsDriveId = ($SPOSiteDrives.value | Where-Object {$_.name -eq 'Documents'}).id

            $SPOFolderPath = ($FileFolderPath).Replace($FileDrive,"").Replace("\","/")
            $SPOFolderPath
            $SPOCreateUploadSessionUri = "https://graph.microsoft.com/v1.0/drives/$SPOSiteDocumentsDriveId/root:/$SPOFolderPath/$($Filename):/createUploadSession"
            $SPOCreateUploadSessionUri
            $SPOUploadSessionUri = (Invoke-RestMethod -Method POST -Headers $AuthHeader -Uri $SPOCreateUploadSessionUri).uploadUrl
            
            $FileChunkSize = 1024000
            $FileChunkPosition = 0
            $File = New-Object System.IO.FileInfo($FilePath)
            $FileReader = [System.IO.File]::OpenRead($FilePath)
            $FileBuffer = New-Object -TypeName Byte[] -ArgumentList $FileChunkSize
            
            $FileUploadCompleted = $false
            While (!$FileUploadCompleted) {
                $CurrentFileChunk = $FileReader.Read($FileBuffer, 0, $FileBuffer.Length)
                $FileOutput = $FileBuffer
                If ($CurrentFileChunk -ne $FileBuffer.Length) {
                    $FileUploadCompleted = $true
                    $FileOutput = New-Object -TypeName Byte[] -ArgumentList $CurrentFileChunk
                    [Array]::Copy($FileBuffer, $FileOutput, $CurrentFileChunk)
                }
                $FileUploadHeader = @{
                    'Content-Range' = "bytes $FileChunkPosition-$($FileChunkPosition + $FileOutput.Length - 1)/$($File.Length)"
                }
                $FileChunkPosition = $FileChunkPosition + $FileOutput.Length
                Invoke-RestMethod -Method PUT -Uri $SPOUploadSessionUri -Body $FileOutput -Headers $FileUploadHeader
            }
            $FileReader.Close()
        }
    }

    If (-not [string]::IsNullOrEmpty($FileToUpload)) {
        $FileInput = Get-Item -Path $FileToUpload
        $FilePath = $FileInput.FullName
        $FileName = $FileInput.Name
        
        $SPOSiteDrivesUri = "https://graph.microsoft.com/v1.0/sites/$SPOSiteId/drives"
        $SPOSiteDrives = Invoke-RestMethod -Method GET -Headers $AuthHeader -Uri $SPOSiteDrivesUri
        $SPOSiteDocumentsDriveId = ($SPOSiteDrives.value | Where-Object {$_.name -eq 'Documents'}).id
        
        $SPOCreateUploadSessionUri = "https://graph.microsoft.com/v1.0/drives/$SPOSiteDocumentsDriveId/root:/$($Filename):/createUploadSession"
        $SPOUploadSessionUri = (Invoke-RestMethod -Method POST -Headers $AuthHeader -Uri $SPOCreateUploadSessionUri).uploadUrl
        
        $FileChunkSize = 1024000
        $FileChunkPosition = 0
        $File = New-Object System.IO.FileInfo($FilePath)
        $FileReader = [System.IO.File]::OpenRead($FilePath)
        $FileBuffer = New-Object -TypeName Byte[] -ArgumentList $FileChunkSize
        
        $FileUploadCompleted = $false
        While (!$FileUploadCompleted) {
            $CurrentFileChunk = $FileReader.Read($FileBuffer, 0, $FileBuffer.Length)
            $FileOutput = $FileBuffer
            If ($CurrentFileChunk -ne $FileBuffer.Length) {
                $FileUploadCompleted = $true
                $FileOutput = New-Object -TypeName Byte[] -ArgumentList $CurrentFileChunk
                [Array]::Copy($FileBuffer, $FileOutput, $CurrentFileChunk)
            }
            $FileUploadHeader = @{
                'Content-Range' = "bytes $FileChunkPosition-$($FileChunkPosition + $FileOutput.Length - 1)/$($File.Length)"
            }
            $FileChunkPosition = $FileChunkPosition + $FileOutput.Length
            Invoke-RestMethod -Method PUT -Uri $SPOUploadSessionUri -Body $FileOutput -Headers $FileUploadHeader
        }
        $FileReader.Close()
    }
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

$dTokenResponse = Get-AuthToken -TokenRequestUri $dTokenRequestUri -ClientId $dClientId -ClientSecret $dClientSecret
$dAuthHeader = @{
    "Authorization" = "Bearer $($dTokenResponse.access_token)"
    "Content-Type"  = "application/json"
}

# Example Usage
# $dFolderToUpload = "C:\Intune"
# $dFileToUpload = "C:\Intune\TestUpload.txt"

New-SPOFileUpload -FolderToUpload $dFolderToUpload -SPOSiteGroupId $dSPOSiteGroupId -AuthHeader $dAuthHeader

Exit $exitCode
