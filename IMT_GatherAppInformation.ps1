#Requires -RunAsAdministrator
#Requires -Version 5
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
  Creation Date:		06-11-2024
  Source(s):			https://oliverkieselbach.com/2022/03/30/ime-debugging-and-intune-win32-app-decoding-part-2/
  Release notes:		Version 1.0 - Initial published version.

.LINK
  https://github.com/TomCat80-code

.EXAMPLE
  <An example execution of the script. Repeat this attribute for more than one example>

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

$exitCode = 0

#----------------------------------------------------------[Declarations]--------------------------------------------------------------

#Script Version
$dScriptVersion = "1.0"
$dScriptName = "IMT_GatherAppInformation"

#Customer SpecIfic Information
$dCustomerName = "<CUSTOMERNAME>"
$dCustomerShortName = "<CUSTOMERSHORTNAME"

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


#-----------------------------------------------------------[Functions]----------------------------------------------------------------

Function PrepareSideCarAgentLogLevel($dlevel = 'Verbose') {
    Try {
        $dIMEConfigPath = Join-Path ${env:ProgramFiles(x86)} "Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe.config"
        $dIMEConfig = [xml](Get-Content -Path $dIMEConfigPath -Encoding UTF8)
        
        If ($dIMEConfig.configuration.'system.diagnostics'.sources.source.switchValue -ne $dlevel) {
            $dIMEConfig.configuration.'system.diagnostics'.sources.source.SetAttribute('switchValue', $dlevel)
            $dIMEConfig.Save($dIMEConfigPath)

            # restarting IME to activate new logging level
            Restart-Service -Name IntuneManagementExtension

            Write-Host "SUCCESS: IME log level changed to [$dlevel]"
        }
        Else {
            Write-Host "IME log level already set to [$dlevel]"
        }
    }
    Catch {
        Write-Host "ERROR: IME log level could not be changed to [$dlevel]"
    }
}

Function Decrypt($base64string) {
    [System.Reflection.Assembly]::LoadWithPartialName("System.Security") | Out-Null

    $content = [Convert]::FromBase64String($base64string)
    $envelopedCms = New-Object Security.Cryptography.Pkcs.EnvelopedCms
    $certCollection = New-Object System.Security.Cryptography.X509CertIficates.X509CertIficate2Collection
    $envelopedCms.Decode($content)
    $envelopedCms.Decrypt($certCollection)

    $utf8content = [text.encoding]::UTF8.getstring($envelopedCms.ContentInfo.Content)

    return $utf8content
}

Function ExtractIntuneAppDetailsFromLogFile() {
    $dIMELogPath = Join-Path $env:ProgramData "Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log"
    $stringToSearch = "<![LOG[Response from Intune = {".ToLower()

    Get-Content $dIMELogPath | ForEach-Object {
        If ($nextLine) {
            If ($_.ToString().ToLower().Contains("decryptinfo") -And -Not  $_.ToString().ToLower().Contains("outbound data:"))
            {
                Try {
                    $reply = "{$($_.ToString().TrimStart())}" | ConvertFrom-Json
                
                    $responsePayload = ($reply.ResponsePayload | ConvertFrom-Json)
                    $contentInfo = ($responsePayload.ContentInfo | ConvertFrom-Json)
                    $decryptInfo = Decrypt(([xml]$responsePayload.DecryptInfo).EncryptedMessage.EncryptedContent) | ConvertFrom-Json

                    "ApplicationID : $($contentInfo.ApplicationID)"
                    "URL: $($contentInfo.UploadLocation)"
                    "Key: $($decryptInfo.EncryptionKey)"
                    "IV:  $($decryptInfo.IV)"

                    If ($RunDownloadAndExtract) {
                        $targetPath = Join-Path $TargetDirectory "$($responsePayload.ApplicationId).intunewin"
                        .\IntuneWinAppUtilDecoder.exe `"$($contentInfo.UploadLocation)`" /key:$($decryptInfo.EncryptionKey) /iv:$($decryptInfo.IV) /filePath:`"$targetPath`"
                    }

                    $nextLine = $false
                }
                Catch {
                    Write-Host "Probably no 'Verbose' logging turned on. Run script with '-EnableVerboseLogging' parameter to enable verbose logging for IME"
                }
            }
        }
        If ($_.ToString().ToLower().StartsWith($stringToSearch) -eq $true) {
            $nextLine = $true
        }
    }
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

#--------------------------------------------------------[RemoveOldLogging]----------------------------------------------------------

$dLogsToRemove = Get-ChildItem $dLogPath -Filter *.log | Where LastWriteTime -lt (Get-Date).AddDays(-1 * $dLogMaxAge)
  
If ($dLogsToRemove.Count -gt 0) { 
    ForEach ($dLog in $dLogsToRemove) {
		Get-Item $dLogPath\$dLog | Remove-Item
    }
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

#Start Logging
Start-Transcript -Path $dLogFile | Out-Null

#Script Execution Elements

if ($EnableVerboseLogging) {
    PrepareSideCarAgentLogLevel('Verbose')
}
elseif ($DisableVerboseLogging) {
    PrepareSideCarAgentLogLevel('Information')
}
else {
    ExtractIntuneAppDetailsFromLogFile
}

#Stop Logging
Stop-Transcript | Out-Null

Exit $exitCode