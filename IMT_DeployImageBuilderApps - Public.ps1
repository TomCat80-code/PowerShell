#Requires -Version 5
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
  Script:				IMB_DeployImageBuilderApps.ps1
  Version:			    1.0
  Template:				IME_PSTemplateScript.ps1
  Template Version:		1.2
  Company:				
  Author:				Tom van Beest
  Creation Date:		11-11-2024
  Source(s):
  Release notes:		Version 1.0 - Initial published version.

.LINK
  None

.EXAMPLE
  .\IMB_DeployImageBuilderApps.ps1 -Team "ABC"

REQUIRED
  None

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

Param
    (
        [parameter(Mandatory=$true)][string]$Team
    )

$exitCode = 0

Function Get-PSScriptRoot {
    $ScriptRoot = ""
    Try {
        $ScriptRoot = Get-Variable -Name PSScriptRoot -ValueOnly -ErrorAction Stop
    }
    Catch {
        $ScriptRoot = Split-Path $dcript:MyInvocation.MyCommand.Path
    }
    Write-Output $ScriptRoot
}

#----------------------------------------------------------[Declarations]--------------------------------------------------------------

#Script Version
$dScriptVersion = "1.0"
$dScriptName = "IMB_DeployImageBuilderApps"

#Customer Specific Information
$dCustomerName = "<CustomerFullName>"
$dCustomerShortName = "<CustomerAbbreviation"

#Log File Information
$dTempPath = "$PSScriptRoot\Temp"

#Script Specific
$dEntraIDTenant = "<Entra ID Tenant Name>"
$dEntraIDTenantDomain = "$dEntraIDTenant.onmicrosoft.com"
$dEntraIDTenantId = "<Entra ID Tenant ID>"
$dEntraIDIMBGroupPrefix = "<Group Prefix>"

$dStorageAccount = "<Azure Storage Account Name>"
$dTableServiceEndpoint = "https://$dStorageAccount.table.core.windows.net"

$dStorageAccountSASToken = "?sp=<SASToken>"
$dStorageAccountTableName = "IMBIntuneApps"

$dDecoderURL = "https://github.com/okieselbach/Intune/raw/refs/heads/master/IntuneWinAppUtilDecoder/IntuneWinAppUtilDecoder/bin/Release/IntuneWinAppUtilDecoder.zip"
$dDecoderZIPFileName = Split-Path -Path $dDecoderURL -Leaf
$dDecoderFileName = $dDecoderZIPFileName.Replace(".zip",".exe")
$dDecoderFileHash = "27D6593589318FF59099D2B9E159CDCBAE6261442B47090AC4A78D5AB1D2F25D"

#-----------------------------------------------------------[Functions]----------------------------------------------------------------

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

#--------------------------------------------------------[PrepareDirectories]----------------------------------------------------------

$dScriptDirs = $dTempPath

Foreach ($dDir in $dScriptDirs) {
    If (!(Test-Path -Path $dDir)) {
    	Try {
    		New-Item -Path $dDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    		Write-Output "Succesfully created the directory $($dDir)."
    	}
    	Catch {
    		Write-Error "Failed to create directory $($dDir). Exit code ($LastExitCode). Exception: $($_.Exception.Message)" -Category OperationStopped
    	}
    }
    Else {
    	Write-Output "Directory $($dDir) already existed."
    }
}

#-----------------------------------------------------------[Execution]----------------------------------------------------------------

#Script Execution Elements

$dAppsList = Get-AzureTableRow -Endpoint $dTableServiceEndpoint -SharedAccessSignature $dStorageAccountSASToken -Table $dStorageAccountTableName
#$dAppsList = Get-AzureTableRow -Endpoint $dTableServiceEndpoint -SharedAccessSignature $dStorageAccountSASToken -Table $dStorageAccountTableName -FilterDefinition "Assignments eq '$Team'" 

If ($dAppsList -ne $null) {

    $dTeams = ($dAppsList.Assignments | ConvertFrom-Json).Replace($dEntraIDIMBGroupPrefix,"") | Sort-Object -Unique
    
    $dProcessingPath = "$env:SystemDrive\IntuneApps"
    $dDecoderPath = "$dProcessingPath\IntuneWinAppUtilDecoder"
    If (!(Test-Path $dDecoderPath)) {
        New-Item -ItemType Directory -Path $dDecoderPath -Force
    }
    
    $dAppsDownloadPath = "$dProcessingPath\DownloadAndDecode"
    If (!(Test-Path $dAppsDownloadPath)) {
        New-Item -ItemType Directory -Path $dAppsDownloadPath -Force
    }
    Else {
        Remove-Item -Path $dAppsDownloadPath\* -Force
    }
    
    $dDecoderZIPFilePath = "$dDecoderPath\$dDecoderZIPFileName"
    $dDecoderFilePath = "$dDecoderPath\$dDecoderFileName"
    If (!(Test-Path $dDecoderFilePath)) {
        Invoke-WebRequest -Uri $dDecoderURL -OutFile $dDecoderZIPFilePath -UseBasicParsing
        If (Test-Path $dDecoderZIPFilePath) {
            Expand-Archive $dDecoderZIPFilePath -DestinationPath $dDecoderPath -Force
        }
    }
    
    $dDecoderDownloadFileHash = (Get-FileHash -Path $dDecoderFilePath).Hash
    If ($dDecoderDownloadFileHash -ne $dDecoderFileHash) {
        Write-Error "Incorrect File Hash for the Decoder!"
        Exit -1
    }
    
    $dAppDeploymentCount = 0
    Foreach ($dApp in $dAppsList) {        If ($dApp.InstallContext -eq "system" -and $dApp.Assignments -match $Team) {            $dAppPath = Join-Path $dAppsDownloadPath $($dApp.FileName)            $dDecoderArguments = "`"$($dApp.DownloadURL)`" /Key:$($dApp.EncryptionKey) /IV:$($dApp.EncryptionIV) /FilePath:`"$dAppPath`""
            $dDecoderProcess = Start-Process -NoNewWindow -FilePath $dDecoderFilePath -ArgumentList $dDecoderArguments -PassThru -Wait
            If ($dDecoderProcess.ExitCode -ne 0) {
                Write-Error "And error occured while download and decoding `"$($dAppsList.Rowkey)`"."
                Exit -1
            }
            $dAppDeploymentCount++
        }
    }
    
    $dAppsExtractPath = "$dProcessingPath\Extracted"
    If (!(Test-Path $dAppsExtractPath)) {
        New-Item -ItemType Directory -Path $dAppsExtractPath -Force
    }
    Else {
        Remove-Item -Path $dAppsExtractPath\* -Recurse -Force
    }
    
    $dDownloadedApps = Get-Item -Path "$dAppsDownloadPath\*" | Where-Object {$_.Name -match ".zip"}
    If ($dDownloadedApps.Count -eq $dAppDeploymentCount) {
        Foreach ($dDeployApp in $dDownloadedApps) {
            $dDownloadedAppZipPath = Join-Path $dAppsDownloadPath $($dDeployApp.Name)
            $dExtractedAppPath = Join-Path $dAppsExtractPath $($dDeployApp.Name.Replace(".decoded","").Replace(".zip",""))
            Expand-Archive -Path $dDownloadedAppZipPath -DestinationPath $dExtractedAppPath -Force
        }
    }
    
    $dDeployableApps = Get-Item -Path "$dAppsExtractPath\*" #| Where-Object {$_.Name -eq "npp.8.7.1.Installer.x64"}
    Foreach ($dApp in $dDeployableApps) {
        # Check application install state based on Intune detection rule(s)
        $dAppDetectionRules = ($dAppsList | Where-Object {$_.FileName -match ($($dApp.Name).Replace("intunewin",""))}).DetectionRules | ConvertFrom-Json
        $dAppInstalled = $false
        #Foreach ($dAppDetectionRule in $dAppDetectionRules) {
        #    # Registry rule type
        #    If ($dAppDetectionRule.'@odata.type' -match "#microsoft.graph.win32LobAppRegistryRule") {
        #        Write-Output "Registry rule"
        #        $dPathToCheck = "Registry::$($dAppDetectionRule.keyPath)"
        #        If ($dAppDetectionRule.operationType -match "exists") {
        #            $dPathCheck = Get-ItemProperty -Path $dPathToCheck -Name $($dAppDetectionRule.valueName) -ErrorAction SilentlyContinue
        #        }
        #        If ($dPathCheck -ne $null) {
        #            $dAppInstalled = $true
        #        }
        #    }
        #    # File System rule type
        #    ElseIf ($dAppDetectionRule.'@odata.type' -match "#microsoft.graph.win32LobAppFileSystemRule") {
        #        Write-Output "File System rule"
        #        $dPathToCheck = $($dAppDetectionRule.path)        #        If ($dPathToCheck -contains "%") {        #            $dOSPathVariable = ($dPathToCheck.Split("%")) | Select -Skip 1 -First 1        #            $dDirectoryPath = "`$Env:$dOSPathVariable"
        #            If ($dAppDetectionRule.operationType -match "exists") {
        #            $dPathCheck = Get-ChildItem -Path "$dDirectoryPath"
        #        }
        #        If ($dAppDetectionRule.operationType -match "version") {
        #         
        #
        #        If ($dPathCheck -ne $null) {
        #            $dAppInstalled = $true
        #        }
        #
        #    }
        #    # MSI detecton rule type
        #    ElseIf ($dAppDetectionRule.'@odata.type' -match "#microsoft.graph.win32LobAppFileSystemRule") {
        #        Write-Output "File System rule"
        #    }
        #}
        #
        # Install application if not detected
        If ($dAppInstalled -eq $false) {
            Write-Output "Installing $dApp"
            $dAppFileName = $dApp.Name + ".intunewin"
            $dAppInstallCommandLine = ($dAppsList | Where-Object {$_.FileName -eq $dAppFileName}).InstallCommandLine
            $dAppInstallCommand = (Invoke-Expression ".{`$args} $dAppInstallCommandLine") | Select-Object -First 1
            $dAppInstallCommandPath = Join-Path $($dApp.FullName) $dAppInstallCommand
            $dAppInstallArguments = (Invoke-Expression ".{`$args} $dAppInstallCommandLine") | Select-Object -Skip 1
            If ($dAppInstallCommand -match "Deploy-Application.exe" -or $dAppInstallCommand -match "Install_Software_UserContext.ps1" -or $dAppInstallCommand -match "Deploy-Application.ps1") {
                $dAppInstallCommandPath = Join-Path $($dApp.FullName) "Deploy-Application.exe"
                $dAppInstall = Start-Process -NoNewWindow -FilePath $dAppInstallCommandPath -ArgumentList "-DeployMode 'Silent'" -WorkingDirectory $($dApp.FullName) -PassThru -Wait
            }
            ElseIf ($dAppInstallArguments -eq $null) {
                $dAppInstall = Start-Process -NoNewWindow -FilePath $dAppInstallCommandPath -WorkingDirectory $($dApp.FullName) -PassThru -Wait
            }
            Else {
                $dAppInstall = Start-Process -NoNewWindow -FilePath $dAppInstallCommandPath -ArgumentList $dAppInstallArguments -WorkingDirectory $($dApp.FullName) -PassThru -Wait
            }
            If ($dAppInstall.ExitCode -ne 0) {
                Write-Error "An error occured while trying to install the App. The exitcode is $($dAppInstall.ExitCode)"
                Exit -1
            }
            Else {
                Exit 0
            }
        }
    }
}
Else {
    Write-Error "No applications found in Azure Storage Table or a connection issue has occured. Please check the Azure Storage Table!"
}

#Remove-Item -Path $dTempPath -Recurse -Force

Exit $exitCode