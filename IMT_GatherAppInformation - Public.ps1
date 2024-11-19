#Requires -Version 5
#Requires -Modules Microsoft.Graph.Intune
#Requires -RunAsAdministrator
<#
.SYNOPSIS

.DESCRIPTION
  
.PARAMETER
  None

.INPUTS
  None

.OUTPUTS
  None

.NOTES
  Script:				IMT_GatherAppInformation.ps1
  Version:				1.0
  Template:				IME_PSTemplateScript.ps1
  Template Version:		1.0
  Company:				
  Author:				Tom van Beest
  Creation Date:		15-11-2024
  Source(s):			https://oliverkieselbach.com/2022/03/30/ime-debugging-and-intune-win32-app-decoding-part-2/
                        
  Release notes:		Version 1.0 - Initial published version.

.LINK
  https://github.com/TomCat80-code

.EXAMPLE
  None

REQUIRED  DeviceManagementApps.ReadWrite.All
  Group.Read.All

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

#---------------------------------------------------------[Initializations]------------------------------------------------------------

$exitCode = 0

#----------------------------------------------------------[Declarations]--------------------------------------------------------------

#Script Version
$dScriptVersion = "1.0"
$dScriptName = "IMT_GatherAppInformation"

#Customer SpecIfic Information
$dCustomerName = "<CustomerFullName>"
$dCustomerShortName = "<CustomerAbbreviation"

#Directories
$dCustomerDir = "$Env:ProgramData\$dCustomerShortName"
$dCustomerSavedDir = "$dCustomerDir\Saved"
$dCustomerScriptsDir = "$dCustomerDir\Scripts"
$dCustomerTempDir = "$dCustomerDir\Temp"
$dCustomerWorkingDir = "$dCustomerDir\Working"

#Log File Information
$dLogPath = "$dCustomerDir\Logging"
$dLogTime = Get-Date -Format "yyyy-MM-dd-HHmmss"
$dLogName = "$dScriptName`_$dLogTime.log"
$dLogFile = Join-Path -Path $dLogPath -ChildPath $dLogName
$dLogMaxAge = 30

# Script SpecIfic
$dEntraIDTentantID = "<Entra ID Tenant ID"
$dEntraIDMSGraphAppID = "<Entra ID Custom App with permissions>"
$dEntraIDIMBGroupPrefix = "<Group Prefix>"
$dEntraIDIMBProcessingGroupName = "<Processing Group Name"

$dASA = "azsaintune"
$dASATableServiceEndpoint = "https://$dASA.table.core.windows.net"
$dASATableName = "IMBIntuneApps"
$dASASASToken = "?sp=<SASToken>"
$dASASASTokenExpiryRegEx = (([regex]::Matches($dASASASToken, '(se=\d\d\d\d+-\d+-\d\d.\d\d+:\d+:+\d\d.)')).Value).Replace("se=","")
$dASASASTokenExpiryDate = Get-Date $dASASASTokenExpiryRegEx
$dPropertyConversionTable = @()$dPropertyConversionTable += New-Object -TypeName psobject -Property @{IntuneProperty="Id"; TableProperty="PartitionKey"}$dPropertyConversionTable += New-Object -TypeName psobject -Property @{IntuneProperty="displayName"; TableProperty="RowKey"}
$dPropertyConversionTable += New-Object -TypeName psobject -Property @{IntuneProperty="fileName"; TableProperty="FileName"}
$dPropertyConversionTable += New-Object -TypeName psobject -Property @{IntuneProperty="createdDateTime"; TableProperty="IntuneCreatedDateTime"}$dPropertyConversionTable += New-Object -TypeName psobject -Property @{IntuneProperty="lastModifiedDateTime"; TableProperty="IntuneLastModifiedDateTime"}$dPropertyConversionTable += New-Object -TypeName psobject -Property @{IntuneProperty="installExperience.runAsAccount"; TableProperty="InstallContext"}$dPropertyConversionTable += New-Object -TypeName psobject -Property @{IntuneProperty="installCommandLine"; TableProperty="InstallCommandLine"}$dPropertyConversionTable += New-Object -TypeName psobject -Property @{IntuneProperty="committedContentVersion"; TableProperty="CommittedContentVersion"}$dPropertyConversionTable += New-Object -TypeName psobject -Property @{IntuneProperty="rules"; TableProperty="DetectionRules"}$dPropertyConversionTable += New-Object -TypeName psobject -Property @{IntuneProperty="displayName"; TableProperty="Assignments"}
#-----------------------------------------------------------[Functions]----------------------------------------------------------------

Function ChangeIMELogLevel($Level = 'Verbose') {
    Try {
        $IMEConfigPath = Join-Path ${env:ProgramFiles(x86)} "Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe.config"
        $IMEConfig = [xml](Get-Content -Path $IMEConfigPath -Encoding UTF8)
        
        If ($IMEConfig.configuration.'system.diagnostics'.sources.source.switchValue -ne $Level) {
            $IMEConfig.configuration.'system.diagnostics'.sources.source.SetAttribute('switchValue', $Level)
            $IMEConfig.Save($IMEConfigPath)

            # restarting IME to activate new logging level
            Restart-Service -Name IntuneManagementExtension

            Write-Host "SUCCESS: IME log level changed to [$Level]"
        }
        Else {
            Write-Host "IME log level already set to [$Level]"
        }
    }
    Catch {
        Write-Host "ERROR: IME log level could not be changed to [$Level]"
    }
}

Function DecryptIMEAppInfo($base64string) {
    [System.Reflection.Assembly]::LoadWithPartialName("System.Security") | Out-Null

    $content = [Convert]::FromBase64String($base64string)
    $envelopedCms = New-Object Security.Cryptography.Pkcs.EnvelopedCms
    $certCollection = New-Object System.Security.Cryptography.X509CertIficates.X509CertIficate2Collection
    $envelopedCms.Decode($content)
    $envelopedCms.Decrypt($certCollection)

    $utf8content = [text.encoding]::UTF8.getstring($envelopedCms.ContentInfo.Content)

    return $utf8content
}

Function Get-AzureTableRow {
    [CmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)][string]$Endpoint,
        [parameter(Mandatory=$true)][string]$SharedAccessSignature,
        [parameter(Mandatory=$true)][string]$Table,
        [parameter(Mandatory=$false)][string]$FilterDefinition
    )
    $Headers = @{
        "x-ms-date"=(Get-Date -Format r)
        "x-ms-version"="2016-05-31"
        "Accept-Charset"="UTF-8"
        "DataServiceVersion"="3.0;NetFx"
        "MaxDataServiceVersion"="3.0;NetFx"
        "Accept"="application/json;odata=nometadata"
    };
    If ($FilterDefinition -like $null) {
        $URI = ($Endpoint + "/" + $Table + $SharedAccessSignature)
    }
    Else {
        $URI = ($Endpoint + "/" + $Table + $SharedAccessSignature + "&`$filter=($FilterDefinition)")
    }
    $TableRow = Invoke-RestMethod -Method Get -Uri $URI -Headers $Headers -ContentType "application/json"
    $TableRow.Value
}

Function Insert-AzureTableRow {
    [CmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)][string]$Endpoint,
        [parameter(Mandatory=$true)][string]$SharedAccessSignature,
        [parameter(Mandatory=$true)][string]$Table,
        [parameter(Mandatory=$true)][hashtable]$TableData
    )
    $Headers = @{
        "x-ms-date"=(Get-Date -Format r)
        "x-ms-version"="2016-05-31"
        "Accept-Charset"="UTF-8"
        "DataServiceVersion"="3.0;NetFx"
        "MaxDataServiceVersion"="3.0;NetFx"
        "Accept"="application/json;odata=nometadata"
    };
    $URI = ($Endpoint + "/" + $Table + "/" + $SharedAccessSignature)
    $Body = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $TableData))
    Invoke-RestMethod -Method Post -Uri $URI -Headers $Headers -Body $Body -ContentType "application/json"
}

Function Update-AzureTableRow {
    [CmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)][string]$Endpoint,
        [parameter(Mandatory=$true)][string]$SharedAccessSignature,
        [parameter(Mandatory=$true)][string]$Table,
        [parameter(Mandatory=$true)][string]$PartitionKey,
        [parameter(Mandatory=$true)][string]$RowKey,
        [parameter(Mandatory=$true)][hashtable]$TableData
    )
    $Headers = @{
        "x-ms-date"=(Get-Date -Format r)
        "x-ms-version"="2016-05-31"
        "Accept-Charset"="UTF-8"
        "DataServiceVersion"="3.0;NetFx"
        "MaxDataServiceVersion"="3.0;NetFx"
        "Accept"="application/json;odata=nometadata"
    };
    $Resource = "$Table(PartitionKey='$PartitionKey',RowKey='$RowKey')"
	$URI = ($Endpoint + "/" + $Resource + $SharedAccessSignature)
    $Body = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $TableData))
    Invoke-RestMethod -Method Put -Uri $URI -Headers $Headers -Body $Body -ContentType "application/json"
}

Function Delete-AzureTableRow {
    [CmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)][string]$Endpoint,
        [parameter(Mandatory=$true)][string]$SharedAccessSignature,
        [parameter(Mandatory=$true)][string]$Table,
        [parameter(Mandatory=$true)][string]$PartitionKey,
        [parameter(Mandatory=$true)][string]$RowKey
    )
    $Headers = @{
        "x-ms-date"=(Get-Date -Format r)
        "x-ms-version"="2016-05-31"
        "Accept-Charset"="UTF-8"
        "DataServiceVersion"="3.0;NetFx"
        "MaxDataServiceVersion"="3.0;NetFx"
        "Accept"="application/json;odata=nometadata"
        "If-Match"="*"
    };
    $Resource = "$Table(PartitionKey='$PartitionKey',RowKey='$RowKey')"
	$URI = ($Endpoint + "/" + $Resource + $SharedAccessSignature)
    Invoke-RestMethod -Method Delete -Uri $URI -Headers $Headers -ContentType "application/json"
}

#--------------------------------------------------------[PrepareDirectories]----------------------------------------------------------

$dCustomerDirs = $dCustomerDir,$dCustomerSavedDir,$dCustomerScriptsDir,$dCustomerTempDir,$dCustomerWorkingDir

Foreach ($dDir in $dCustomerDirs) {
	If (!(Test-Path -Path $dDir)) {
		Try {
			New-Item -Path $dDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
			Write-Host "Succesfully created the directory $($dDir)."
		}
		Catch {
			Write-Error "Failed to create directory $($dDir). Exit code ($LastExitCode). Exception: $($_.Exception.Message)" -Category OperationStopped
		}
	}
	Else {
		Write-Host "Directory $($dDir) already existed."
	}
}

#--------------------------------------------------------[RemoveOldLogging]------------------------------------------------------------

$dLogsToRemove = Get-ChildItem $dLogPath -Filter *.log | Where LastWriteTime -lt (Get-Date).AddDays(-1 * $dLogMaxAge)
  
If ($dLogsToRemove.Count -gt 0) { 
    ForEach ($dLog in $dLogsToRemove) {
		Get-Item $dLogPath\$dLog | Remove-Item
    }
}

#-----------------------------------------------------------[Execution]----------------------------------------------------------------

#Start Logging
Start-Transcript -Path $dLogFile | Out-Null

#Script Execution Elements

Write-Warning "The access token will expire at ($dASASASTokenExpiryDate)"

If ($dMSGraphAppID -ne $dEntraIDMSGraphAppID) {
    $dMSGraphAppID = (Update-MSGraphEnvironment -AppId $dEntraIDMSGraphAppID).AppId
}

If ($dMSGraphTenantID -ne $dEntraIDTentantID) {
    $dMSGraphTenantID = (Connect-MSGraph).TenantId
} 

$dIMELogPath = Join-Path $Env:ProgramData "Microsoft\IntuneManagementExtension\Logs"
$dIMELogs = (Get-ChildItem -Path $dIMELogPath | Where-Object {$_.Name -match "IntuneManagementExtension" -and $_.Name -match ".log"}).VersionInfo.FileName
$dStringToSearch = "<![LOG[Response from Intune = {".ToLower()
$dStringDateTime = "}]LOG]!><time=".ToLower()
$dLineCount = 0

$dAppsMaintainCCCVState = @()

# Intune Management Extension Logfiles processing
#Clear
Write-Output ""
Write-Output "----------------------------------------------------------------------------------------------------------------------------------------------------------------"
Write-Output " Step 1. Process applications detected in Intune Management Extension logging"
Write-Output "----------------------------------------------------------------------------------------------------------------------------------------------------------------"
Get-Content $dIMELogs | ForEach-Object {
    $dLineCount++        
    If ($dNextLine) {
        # Retrieve the correct entry (with "decryptinfo" in the string) to determine app information
        If ($_.ToString().ToLower().Contains("decryptinfo") -And -Not  $_.ToString().ToLower().Contains("outbound data:")) {
            $dIMELogEntry = "{$($_.ToString().TrimStart())}" | ConvertFrom-Json
            $dIMEResponsePayload = ($dIMELogEntry.ResponsePayload | ConvertFrom-Json)
            $dIMEAppInfo = ($dIMEResponsePayload.ContentInfo | ConvertFrom-Json)
            $dIMEAppDecryptInfo = DecryptIMEAppInfo(([xml]$($dIMEResponsePayload.DecryptInfo)).EncryptedMessage.EncryptedContent) | ConvertFrom-Json
            # Get app information from Intune based on the app ID found in the IME $dAppDecryptInfolog entry.
            $dIntuneApplicationData = 
                Try {
                    Get-IntuneMobileApp -mobileAppId $($dIMEResponsePayload.ApplicationID)
                }
                Catch {
                    $null
                }
            # Get assigned groups from Intune and retrieve group names
            $dIntuneAssignmentData = 
                If ($dIntuneApplicationData -ne $null) {
                    Get-IntuneMobileAppAssignment -mobileAppId $($dIMEResponsePayload.ApplicationID)
                }
                Else {
                    Write-Verbose "INFO: Application with ID `"$($dIMEResponsePayload.ApplicationID)`" was found in the logging though no reference can be found in Intune. Skipping..."
                }
            $dAssignmentGroupIds = $($dIntuneAssignmentData.target).groupId
            $dAssignmentGroupNames = @()
            $dAssignmentGroupNames = 
                Foreach ($dAssignmentGroupId in $dAssignmentGroupIds) {
                    (Get-Groups -groupId $dAssignmentGroupId | Where-Object {$_.displayName -match $dEntraIDIMBGroupPrefix}).displayName
                }
            
            # Build app information variables
            $dDisplayName =$($dIntuneApplicationData.displayName)
            $dIntuneAppId = $($dIMEResponsePayload.ApplicationID)
            $dFilename = $($dIntuneApplicationData.fileName)
            $dURL = $($dIMEAppInfo.UploadLocation).Replace("http","https")
            $dKey = $($dIMEAppDecryptInfo.EncryptionKey)
            $dIV =  $($dIMEAppDecryptInfo.IV)
            $dContext = $($dIntuneApplicationData.installExperience.runAsAccount)
            $dCreatedDateTime = $($dIntuneApplicationData.createdDateTime)
            $dLastModifiedDateTime =  $($dIntuneApplicationData.lastModifiedDateTime)
            $dInstallCommandLine = $($dIntuneApplicationData.installCommandLine)
            $dCommittedContentVersion = $($dIntuneApplicationData.committedContentVersion)
            $dreturnCodes = $($dIntuneApplicationData.returnCodes)
            
            $dNextLine = $false
            $dFoundAtLine = $dLineCount
        }
    }
    If ($_.ToString().ToLower().StartsWith($dStringToSearch) -eq $true) {
        $dNextLine = $true
    }
    If ($dLineCount -eq $dFoundAtLine+1 -and $dNextLine -eq $false -and $dContext -match "System") {
        # Perform required conversions for the variables
        $dIMELogEntryDateTimeStamp = ($_).replace("}]LOG]!>","").replace("=","`":").replace(" ",",`"").replace("<","`"").replace(">","")
        $dIMELogEntryDateTimeStamp = "{$($dIMELogEntryDateTimeStamp.ToString().TrimStart())}" | ConvertFrom-Json
        $dIMELogEntryDate = [regex]::Replace($($dIMELogEntryDateTimeStamp.date) ,'(\d+)-(\d+)', '$2-$1')
        $dIMELogEntryDateTime = Get-Date "$dIMELogEntryDate $($dIMELogEntryDateTimeStamp.time)" -Format "dd-MM-yyyy HH:mm:ss"
        $dDateFirstFound = $dIMELogEntryDateTime
        If ($($dIntuneApplicationData.createdDateTime).Kind -cmatch "Utc") {
            $dCreatedDateTime = Get-Date $($dCreatedDateTime).AddHours(1) -Format "dd-MM-yyyy HH:mm:ss"
        }
        Else {
            $dCreatedDateTime = Get-Date $dCreatedDateTime -Format "dd-MM-yyyy HH:mm:ss"
        }
        If ($($dIntuneApplicationData.lastModifiedDateTime).Kind -cmatch "Utc") {
            $dLastModifiedDateTime = Get-Date $($dLastModifiedDateTime).AddHours(1) -Format "dd-MM-yyyy HH:mm:ss"
        }
        Else {
            $dLastModifiedDateTime = Get-Date $dLastModifiedDateTime -Format "dd-MM-yyyy HH:mm:ss"
        }
        $dDetectionRules = $($dIntuneApplicationData.rules) | ConvertTo-Json
        $dAssignmentGroupNames = $dAssignmentGroupNames | ConvertTo-Json

        # Build Azure Storage Table data
        $dTableData = [Ordered]@{            "PartitionKey" = "$dIntuneAppId"            "RowKey" = "$dDisplayName"            "FirstProcessedDateTime" = "$dDateFirstFound"            "LastProcessedDateTime" = "$dDateFirstFound"            "IntuneCreatedDateTime" = "$dCreatedDateTime"            "IntuneLastModifiedDateTime" = "$dLastModifiedDateTime"            "FileName" = "$dFilename"
            "DownloadURL" = "$dURL"
            "EncryptionKey" = "$dKey"
            "EncryptionIV" = "$dIV"
            "InstallContext" = "$dContext"
            "InstallCommandLine" = "$dInstallCommandLine"
            "CommittedContentVersion" = "$dCommittedContentVersion"
            "DetectionRules" = "$dDetectionRules"
            "Assignments" = "$dAssignmentGroupNames"        }
        
        # Detect existing record in Azure Storage Table and compare values for properties
        $dExistingRecord = Get-AzureTableRow -Endpoint $dASATableServiceEndpoint -SharedAccessSignature $dASASASToken -Table $dASATableName -FilterDefinition "PartitionKey eq '$($dTableData.PartitionKey)'"
        $dExistingRecordChanges = $false
        Foreach ($dProperty in $($dExistingRecord.PSObject).Properties) {
            If ($dProperty.Name -ne "Timestamp") {         
                $dPropertyName = $($dProperty.Name)
                $dExistingPropertyValue = $($dProperty.Value)
                
                $dNewPropertyValue = $dTableData.$dPropertyName
                If ($dExistingPropertyValue -ne $dNewPropertyValue) {
                    $dExistingRecordChanges = $true
                }
                
                If ($dProperty.Name -eq "CommittedContentVersion") {
                    If ($dNewPropertyValue -gt $dExistingPropertyValue -and $($dTableData.DownloadURL) -match $($dExistingRecord.DownloadURL)) {
                        Write-Warning "A new file was uploaded for application `"$($dTableData.RowKey) with ID `"$($dTableData.PartitionKey)`" but was not processed!"
                        $dProcessingGroupId = (Get-Groups -Filter "displayName eq '$dEntraIDIMBProcessingGroupName'").id                    
                        If ($($dIntuneAssignmentData.target.groupId) -match "$dProcessingGroupId") {
                            Write-Output "INFO: The processing group is already assigned."
                        }
                        Else {
                            $dAssign = Read-Host -Prompt "QUESTION: The processing group is not assigned (anymore)! Would you like the application to be assigned for processing? Y/N"
                            If ($dAssign -eq "Y") {
                                Try {
                                    $dTarget = New-DeviceAndAppManagementAssignmentTargetObject -groupAssignmentTarget -groupId $dProcessingGroupId
                                    New-IntuneMobileAppAssignment -mobileAppId $($dTableData.PartitionKey) -intent required -target $dTarget
                                    Write-Output "Succesfully added the processing group to the application."
                                }
                                Catch {
                                    Write-Error "An error occured while trying to add the processing group to the application!"
                                }
                            }
                        }
                        $dTableData.CommittedContentVersion = $($dExistingRecord.CommittedContentVersion)
                        $dAppsMaintainCCCVState += New-Object -TypeName psobject -Property @{AppId="$($dTableData.PartitionKey)"; Maintain=$true}
                    }
                }
            }
        }

        # Initial entry insertion in Azure Storage Table
        If ($dExistingRecord -eq $null) {
            Try {
                Insert-AzureTableRow -Endpoint $dASATableServiceEndpoint -SharedAccessSignature $dASASASToken -Table $dASATableName -TableData $dTableData | Out-Null
                Write-Output "INFO: Succesfully added application `"$($dTableData.RowKey)`" with ID `"$($dTableData.PartitionKey)`"."
            }
            Catch {
                Write-Error "An error occured while trying to add application `"$($dTableData.RowKey)`" with ID `"$($dTableData.PartitionKey)`"."
            }
        }

        # Detect application changes and maintain FirstProcessedDateTime
        ElseIf ($dExistingRecordChanges -eq $true) {
            # Process only if LastProcessedDateTime is later than the existing table entry
            If ($dTableData.FirstProcessedDateTime -gt $($dExistingRecord.LastProcessedDateTime)) {
                $dTableData.LastProcessedDateTime = $($dTableData.FirstProcessedDateTime)
                $dTableData.FirstProcessedDateTime = $($dExistingRecord.FirstProcessedDateTime)
                
                # If the application name is changed and a new application file was uploaded a delete action for the table entry is required
                If ($($dExistingRecord.RowKey) -ne $($dTableData.RowKey)) {
                    Try { 
                        Delete-AzureTableRow -Endpoint $dASATableServiceEndpoint -SharedAccessSignature $dASASASToken -Table $dASATableName -PartitionKey $($dExistingRecord.PartitionKey) -RowKey $($dExistingRecord.RowKey)
                        Insert-AzureTableRow -Endpoint $dASATableServiceEndpoint -SharedAccessSignature $dASASASToken -Table $dASATableName -TableData $($dTableData) | Out-Null
                        Write-Output "INFO: Succesfully updated application `"$($dTableData.RowKey)`" with ID `"$($dTableData.PartitionKey)`"."
                    }
                    Catch {
                        Write-Error "An error occured while trying to update application `"$($dTableData.RowKey)`" with ID `"$($dTableData.PartitionKey)`"."
                    }
                }
                
                # If a new application file was uploaded update the table entry
                Else {
                    Try {
                        Update-AzureTableRow -Endpoint $dASATableServiceEndpoint -SharedAccessSignature $dASASASToken -Table $dASATableName -PartitionKey $($dTableData.PartitionKey) -RowKey $($dTableData.RowKey) -TableData $dTableData
                        Write-Output "INFO: Succesfully updated application `"$($dTableData.RowKey)`" with ID `"$($dTableData.PartitionKey)`"."
                    }
                    Catch {
                        Write-Error "An error occured while trying to update application `"$($dTableData.RowKey)`" with ID `"$($dTableData.PartitionKey)`"."
                    }
                }
            }
        }
    }
}

# Review all existing applications in the Azure Storage Table and detect changes in Intune
Write-Output ""
Write-Output "----------------------------------------------------------------------------------------------------------------------------------------------------------------"
Write-Output " Step 2. Detect changes for processed applications in Intune"
Write-Output "----------------------------------------------------------------------------------------------------------------------------------------------------------------"
$dImageBuilderApps = Get-AzureTableRow -Endpoint $dASATableServiceEndpoint -SharedAccessSignature $dASASASToken -Table $dASATableName
Foreach ($dImageBuilderApp in $dImageBuilderApps) {
    $dIntuneAppData = $null
    Try {
        $dIntuneAppData = Get-IntuneMobileApp -mobileAppId $($dImageBuilderApp.PartitionKey)
    }
    Catch {
    }
    If ($dIntuneAppData -ne $null) {
    
        # Find Intune property updates and build the table entries
        $dTableData = [Ordered]@{
            "PartitionKey" = "$($dImageBuilderApp.PartitionKey)"            "RowKey" = "$($dImageBuilderApp.RowKey)"
        }

        $dIntuneAppChanges = $false
        $dIntuneAppPropertiesChanged = @()

        
        $dMaintainCommittedContentVersion = ($dAppsMaintainCCCVState | Where-Object {$_.AppId -match $($dTableData.PartitionKey)}).Maintain
        If ($dIntuneAppData -ne $null) {
            Foreach ($dProperty in $dPropertyConversionTable) {
                $dIntuneProperty = $($dProperty.IntuneProperty)
                $dTableProperty = $($dProperty.TableProperty)
                $dIntunePropertyValue = $dIntuneAppData.$dIntuneProperty
                $dTablePropertyValue = $dImageBuilderApp.$dTableProperty
                If ($dIntunePropertyValue -ne $null -and ($dIntunePropertyValue.GetType()).Name -eq "Object[]") {
                    $dIntunePropertyValue = $dIntunePropertyValue | ConvertTo-Json
                }
                If ($dIntunePropertyValue -ne $null -and ($dIntunePropertyValue.GetType()).Name -eq "DateTime") {
                    If ($dIntunePropertyValue.Kind -cmatch "Utc") {
                        $dIntunePropertyValue = Get-Date $($dIntunePropertyValue).AddHours(1) -Format "dd-MM-yyyy HH:mm:ss"
                    }
                    Else {
                        $dIntunePropertyValue = Get-Date $dIntunePropertyValue -Format "dd-MM-yyyy HH:mm:ss"
                    }
                    $dTablePropertyValue = Get-Date $dTablePropertyValue -Format "dd-MM-yyyy HH:mm:ss"
                }
                If ($dTableProperty -match "CommittedContentVersion" -and $dMaintainCommittedContentVersion -eq $true) {
                    $dIntunePropertyValue = $dTablePropertyValue
                }
                If ($dTableProperty -eq "InstallContext") {
                    $dIntunePropertyValue = $($dIntuneAppData.installExperience).runAsAccount
                }
                If ($dTableProperty -eq "Assignments") {
                    $dIntuneAssignmentData = Get-IntuneMobileAppAssignment -mobileAppId $($dImageBuilderApp.PartitionKey)
                    $dAssignmentGroupIds = $($dIntuneAssignmentData.target).groupId
                    $dAssignmentGroupNames = @()
                    $dAssignmentGroupNames = 
                        Foreach ($dAssignmentGroupId in $dAssignmentGroupIds) {
                            (Get-Groups -groupId $dAssignmentGroupId | Where-Object {$_.displayName -match $dEntraIDIMBGroupPrefix}).displayName 
                        }
                    $dIntunePropertyValue = $dAssignmentGroupNames | ConvertTo-Json
                }
                If ($dIntunePropertyValue -eq $dTablePropertyValue) {
                    $dTableData.$dTableProperty = $dImageBuilderApp.$dTableProperty
                }
                ElseIf ($dTableProperty -notmatch "CommittedContentVersion" -and $dMaintainCommittedContentVersion -ne $true) {
                    $dTableData.$dTableProperty = $($dIntunePropertyValue)    
                    $dIntuneAppChanges = $true
                    $dIntuneAppPropertiesChanged += "$dTableProperty"
                }
            }

            # Maintain (for step 2) non-detectable properties as the log file is not being processed
            If ($dIntuneAppChanges -eq $true) {
                $dTableData.FirstProcessedDateTime = $($dImageBuilderApp.FirstProcessedDateTime)                $dTableData.LastProcessedDateTime = $($dImageBuilderApp.LastProcessedDateTime)
                $dTableData.DownloadURL = $($dImageBuilderApp.DownloadURL)
                $dTableData.EncryptionKey = $($dImageBuilderApp.EncryptionKey)
                $dTableData.EncryptionIV = $($dImageBuilderApp.EncryptionIV)
                Write-Output "INFO: Application `"$($dImageBuilderApp.RowKey)`" was changed."
                Write-Output "INFO: Properties changed : $dIntuneAppPropertiesChanged"
                
                # If the application name is changed a delete action for the table entry is required
                If ($($dImageBuilderApp.RowKey) -ne $($dTableData.RowKey)) {
                    Delete-AzureTableRow -Endpoint $dASATableServiceEndpoint -SharedAccessSignature $dASASASToken -Table $dASATableName -PartitionKey $($dImageBuilderApp.PartitionKey) -RowKey $($dImageBuilderApp.RowKey)
                    Insert-AzureTableRow -Endpoint $dASATableServiceEndpoint -SharedAccessSignature $dASASASToken -Table $dASATableName -TableData $($dTableData) | Out-Null
                }
                # Normal table entry update operation
                Else {
                    Update-AzureTableRow -Endpoint $dASATableServiceEndpoint -SharedAccessSignature $dASASASToken -Table $dASATableName -PartitionKey $($dTableData.PartitionKey) -RowKey $($dTableData.RowKey) -TableData $($dTableData)   
                }
            }
        }
    }
    # Delete applications which are no longer found in Intune
    Else {
        Write-Warning "The application `"$($dImageBuilderApp.RowKey)`" seems no longer to exist in Intune. Please verify!"
        $dContinue = Read-Host -Prompt "QUESTION: Would you like to delete this application from the storage table? Y/N"
        If ($dContinue -eq "Y") {
            Try {
                Delete-AzureTableRow -Endpoint $dASATableServiceEndpoint -SharedAccessSignature $dASASASToken -Table $dASATableName -PartitionKey $($dImageBuilderApp.PartitionKey) -RowKey $($dImageBuilderApp.RowKey)
                Write-Output "INFO: Application `"$($dImageBuilderApp.RowKey)`" with ID `"$($dImageBuilderApp.PartitionKey)`" has succesfully been deleted."
            }
            Catch {
                Write-Error "An error occured while trying to delete application `"$($dImageBuilderApp.RowKey)`" with ID `"$($dImageBuilderApp.PartitionKey)`"."
            }
        }
    }
}

# Detect Intune application(s) not yet processed
Write-Output ""
Write-Output "----------------------------------------------------------------------------------------------------------------------------------------------------------------"
Write-Output " Step 3. Detect unprocessed applications in Intune"
Write-Output "----------------------------------------------------------------------------------------------------------------------------------------------------------------"
$dIntuneApps = Get-IntuneMobileApp | Where-Object {$_.'@odata.type' -match "#microsoft.graph.win32LobApp"}
$dImageBuilderApps = Get-AzureTableRow -Endpoint $dASATableServiceEndpoint -SharedAccessSignature $dASASASToken -Table $dASATableName
$dProcessingGroupId = (Get-Groups -Filter "displayName eq '$dEntraIDIMBProcessingGroupName'").id
Foreach ($dIntuneApp in $dIntuneApps) {
    If ($dImageBuilderApps.PartitionKey -notcontains $dIntuneApp.Id) {
        $dIntuneAppAssignments = Get-IntuneMobileAppAssignment -mobileAppId $dIntuneApp.id
        $dAssignmentGroupNames = @()
        $dAssignmentGroupNames = 
        Foreach ($dAssignmentGroupId in $($dIntuneAppAssignments.target).groupId) {
            (Get-Groups -groupId $dAssignmentGroupId).displayName
        }
        If ($dAssignmentGroupNames -match $dEntraIDIMBGroupPrefix) {
            $dIntuneAppCreatedDate = Get-Date $($dIntuneApp.createdDateTime) -Format "dd-MM-yyyy HH:mm:ss"
            If ($($dIntuneApp.createdDateTime).Kind -cmatch "Utc") {
                $dIntuneAppCreatedDate = Get-Date $($dIntuneApp.createdDateTime).AddHours(1) -Format "dd-MM-yyyy HH:mm:ss"
            }
            Else {
                $dIntuneAppCreatedDate = Get-Date $($dIntuneApp.createdDateTime) -Format "dd-MM-yyyy HH:mm:ss"
            }
            Write-Warning "Application `"$($dIntuneApp.displayName)`" created at `"$dIntuneAppCreatedDate`" and is assigned to an IMB team though was not processed yet!"
            
            If ($dAssignmentGroupNames -match "$dEntraIDIMBProcessingGroupName") {
                Write-Output "INFO: The processing group is already assigned."
            }
            Else {
                $dAssign = Read-Host -Prompt "QUESTION: The processing group is not assigned! Would you like the application to be assigned for processing? Y/N"
                If ($dAssign -eq "Y") {
                    
                    Try {
                        $dTarget = New-DeviceAndAppManagementAssignmentTargetObject -groupAssignmentTarget -groupId $dProcessingGroupId
                        New-IntuneMobileAppAssignment -mobileAppId $($dIntuneApp.id) -intent required -target $dTarget
                        Write-Output "Succesfully added the processing group to the application."
                    }
                    Catch {
                        Write-Error "An error occured while trying to add the processing group to the application!"
                    }
                }
            }
        }
    }
}

#Stop Logging
Stop-Transcript | Out-Null

Exit $exitCode