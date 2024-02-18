#Requires -Version 5
<#
.SYNOPSIS
  Enable Hyper-V for Windows 10

.DESCRIPTION
  Microsoft Intune Platform Script - Enable the optional Windows 10 feature "Hyper-V" without requiring local administrator permissions.
  
.PARAMETER
  None

.INPUTS
  None

.OUTPUTS
  None

.NOTES
  Script:				IPS_Device_EnableVirtualization.ps1
  Version:				1.0
  Template:				IME_PSTemplateScript.ps1
  Template Version:		1.0
  Company:				
  Author:				Tom van Beest
  Creation Date:		18-02-2024
  Source(s):			
  Release notes:		Version 1.0 - Initial published version.

.LINK
  https://github.com/TomCat80-code

.EXAMPLE
  <An example execution of the script. Repeat this attribute for more than one example>

REQUIRED
  <File Name><File Ext.>		<Location>							<Purpose>						
  <File Name><File Ext.>		<Location>							<Purpose>

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
$dScriptName = "IPS_Device_EnableVirtualization"

#Customer Specific Information
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

# Script Specific
$dSupportedModel = "N/A"
$dSupportedOSEdition = "Microsoft Windows 10 Enterprise"
$dMinimalOSBuildNumber = "18363"
$dMinimalRAM = "8"
$dAZSAURL = "<AZSAURL>"
$dAZSABlobPath = $dScriptName
$dAZSASASToken = "<AZSASTOKEN>"
$dHPBiosUtility = "BiosConfigUtility64.exe"
$dHPVTREPSET = "<HPREPSETNAMEFILENAME>"
$dCustomerADDomain = "<ADDOMAINNAME>"

#-----------------------------------------------------------[Functions]----------------------------------------------------------------

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
$dHyperVFeature = (Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online)
$dComputerSystem = (Get-WmiObject -Class Win32_ComputerSystem)
$dComputerSystemName = $dComputerSystem.Name
$dComputerSystemDomain = $dComputerSystem.Domain
$dComputerSystemUser = $dComputerSystem.UserName
$dComputerSystemManufacturer = $dComputerSystem.Manufacturer
$dComputerSystemModel = $dComputerSystem.Model
$dLoggedOnUser = $dComputerSystemUser -replace "$dCustomerADDomain","" -replace "\\",""
$dLocalGroups = Get-WmiObject Win32_Group
$dLocalGroupNames = $dLocalGroups.Name
$dProcessor = (Get-WmiObject -Class Win32_Processor)
$dOperatingSystem = (Get-WmiObject -Class Win32_OperatingSystem)
$dOperatingSystemCaption = $dOperatingSystem.Caption
$dOperatingSystemBuildNumber = $dOperatingSystem.BuildNumber
$dPhysicalRAM = (Get-WmiObject -Class Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | % {[Math]::Round(($_.sum / 1GB),2)})
$dScheduledTaskInfo = (Get-ScheduledTaskInfo -TaskName $dScriptName -ErrorAction Ignore)
$dScheduledTaskTriggerDelay = New-TimeSpan -Minutes 1
$dScheduledTaskTrigger = New-JobTrigger -AtStartup -RandomDelay $dScheduledTaskTriggerDelay
$dScheduledTaskUser = "SYSTEM"
$dScheduledTaskScriptName = "$dScriptName`_Task.ps1"
$dScheduledTaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ex bypass -file `"$dCustomerScriptsDir\$dScheduledTaskScriptName`""
$dScheduledTaskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit 1:00 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -StartWhenAvailable -RunOnlyIfNetworkAvailable -DisallowDemandStart
$dScheduledTaskScriptContent = @"
`$exitCode = 0

`$dTaskName = "IME_Device_EnableVirtualization"
`$dScriptName = "IME_Device_EnableVirtualization_Task"

#Log File Information
`$dLogPath = "$dCustomerDir\Logging"
`$dLogTime = Get-Date -Format "yyyy-MM-dd-HHmmss"
`$dLogName = "`$dScriptName``_`$dLogTime.log"
`$dLogFile = Join-Path -Path `$dLogPath -ChildPath `$dLogName
`$dHyperVFeatureAvailable = (Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online)

#Start Logging
Start-Transcript -Path `$dLogFile | Out-Null

Try { 
    If (`$dHyperVFeatureAvailable.State -eq "Disabled") {
        Write-Output "Installing Hyper-V."
		`$dHyperVFeatureInstall = (Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -All -NoRestart -WarningAction SilentlyContinue)
		If (`$dHyperVFeatureInstall.RestartNeeded) {
			Invoke-Command -ScriptBlock {msg.exe $dLoggedOnUser "BELANGRIJK!

Herstart de computer om de installatie van Hyper-V te voltooien!"}
			Add-LocalGroupMember -Group "Hyper-V-administrators" -Member "$dComputerSystemUser" -ErrorAction SilentlyContinue
			Write-Output "Hyper-V installation succesfully completed. Restart required."
			}
		Else {
			Add-LocalGroupMember -Group "Hyper-V-administrators" -Member "$dComputerSystemUser" -ErrorAction SilentlyContinue
			Invoke-Command -ScriptBlock {msg.exe $dLoggedOnUser "Hyper-V is klaar voor gebruik."}
			Write-Output "Hyper-V installation succesfully completed. Restart not required."
		}
	}
	Else {
		Add-LocalGroupMember -Group "Hyper-V-administrators" -Member "$dComputerSystemUser" -ErrorAction SilentlyContinue
		Write-Output "Hyper-V was already installed."
	}
}
Catch {
    Write-Error "Failed to install Hyper-V." -Category OperationStopped
}

#Stop Logging
Stop-Transcript | Out-Null

Exit `$exitCode
"@

If (Get-ScheduledTask -TaskName $dScriptName -ErrorAction Ignore) {
    If ($dScheduledTaskInfo.LastTaskResult -eq 267011) {
        Write-Error "The scheduled task $dScriptName has not yet run at system startup." -Category OperationStopped
        Stop-Transcript | Out-Null
        Exit $exitCode
    }
}
If ($dHyperVFeature.State -eq "Enabled") {
	Write-Output "Hyper-V is already installed." 
        If (Get-ScheduledTask -TaskName $dScriptName -ErrorAction Ignore) {
            Unregister-ScheduledTask -TaskName $dScriptName -Confirm:$false
            Write-Output "Scheduled Task $dScriptName has been removed."
        }
        If (Get-Item -Path $dCustomerScriptsDir\$dScheduledTaskScriptName -ErrorAction Ignore) {
            Remove-Item -Path $dCustomerScriptsDir\$dScheduledTaskScriptName
            Write-Output "Script File $dScheduledTaskScriptName has been removed."
        }
    Stop-Transcript | Out-Null
	Exit $exitCode
}
If ($dSupportedModel -notcontains $dComputerSystem.Model) {
    Write-Error "A $dComputerSystemManufacturer $dComputerSystemModel is not in the Supported Model list." -Category OperationStopped
    Stop-Transcript | Out-Null
	Exit $exitCode = -1
}
ElseIf ($dSupportedOSEdition -notcontains $dOperatingSystem.Caption) {
    Write-Error "$dOperatingSystemCaption is not in the supported Operating System Edition list." -Category OperationStopped
    Stop-Transcript | Out-Null
	Exit $exitCode = -1
}
ElseIf ($dMinimalOSBuildNumber -lt $dOperatingSystem.BuildNumber) {
    Write-Error "$dOperatingSystemCaption Build $dOperatingSystemBuildNumber is not supported." -Category OperationStopped
    Stop-Transcript | Out-Null
	Exit $exitCode = -1
}
<#
ElseIf ($dComputerSystem.HypervisorPresent) { 
	Write-Error "Another Hypervisor is installed or this is a Virtual Machine." -Category OperationStopped
    Stop-Transcript | Out-Null
	Exit $exitCode = -1
}
#>
<#
ElseIf (!($dProcessor.VMMonitorModeExtensions)) {
	Write-Error "This processor does not support hardware-assisted virtualization. Hyper-V cannot be installed on a device without this technology!" -Category OperationStopped
    Stop-Transcript | Out-Null
	Exit $exitCode = -1
}
#>
<#
ElseIf (!($dProcessor.SecondLevelAddressTranslationExtensions)) {
	Write-Error "The required hardware-assisted virtualization technology ""Second Level Address Translation"" (SLAT) is not available. Hyper-V cannot be installed on a device without this technology!" -Category OperationStopped
    Stop-Transcript | Out-Null
	Exit $exitCode = -1
}
#>
ElseIf (!($dOperatingSystem.DataExecutionPrevention_Available)) {
	Write-Error "The required Data Execution Prevention technology (DEP) is not available. Hyper-V cannot be installed on a device without this technology!" -Category OperationStopped
    Stop-Transcript | Out-Null
	Exit $exitCode = -1
}
ElseIf ($dPhysicalRAM -lt $dMinimalRAM) {
	Write-Error "$dPhysicalRAM GB is insufficient for the installation of Hyper-V, a minimum of $dMinimalRAM GB is required." -Category OperationStopped
	Stop-Transcript | Out-Null
	Exit $exitCode = -1
}
# Beginning of Hewlett-Packard device configuration
ElseIf ($dComputerSystem.Manufacturer -eq "HP" -or $dComputerSystem.Manufacturer -eq "Hewlett-Packard") {
    Try {
	    Write-Output "Download of files in progress."
	    Invoke-WebRequest "$dAZSAURL/$dAZSABlobPath/$dHPBiosUtility$dAZSASASToken" -OutFile $dCustomerWorkingDir\$dHPBiosUtility
        Write-Output "Download 1 of 3 completed. File location: $dCustomerWorkingDir\$dHPBiosUtility"
        Remove-Item -Path $dCustomerWorkingDir\$dComputerSystemModel.bin -Force -ErrorAction SilentlyContinue
        Invoke-WebRequest "$dAZSAURL/$dAZSABlobPath/$dComputerSystemModel.bin$dAZSASASToken" -OutFile $dCustomerWorkingDir\$dComputerSystemModel.bin
        Write-Output "Download 2 of 3 completed. File location: $dCustomerWorkingDir\$dComputerSystemModel.bin"
        Invoke-WebRequest "$dAZSAURL/$dAZSABlobPath/$dHPVTREPSET$dAZSASASToken" -OutFile $dCustomerWorkingDir\$dHPVTREPSET
        Write-Output "Download 3 of 3 completed. File location: $dCustomerWorkingDir\$dHPVTREPSET"
    }
    Catch {
        Write-Error "Download of files could not be completed." -Category OperationStopped
        Stop-Transcript | Out-Null
	    Exit $exitCode = -1
    }
    Try {
	    If (($dLocalGroupNames -contains "Gebruikers")) {
		    $dAR = New-Object System.Security.AccessControl.FileSystemAccessRule("Gebruikers","ReadandExecute","Deny")
            Write-Output "The Access Rule will be set for group (Gebruikers)."
	    }
	    ElseIf (($dLocalGroupNames -contains "Users")) {
		    $dAR = New-Object System.Security.AccessControl.FileSystemAccessRule("Users","ReadandExecute","Deny")
		    Write-Output "The Access Rule will be set for group (Users)."
	    }
    }
    Catch {
        Write-Error -Message "Could not find the local users group." -Category OperationStopped
        Stop-Transcript | Out-Null
        Exit $exitCode = -1
    } 
    $dAclFile = "$dCustomerWorkingDir\$dComputerSystemModel.bin"
    Try {
	    If ((Test-Path -Path $dAclFile)) {
		    $dAcl = Get-Acl $dAclFile
		    $dAcl.SetAccessRule($dAR)
		    Set-Acl $dAclFile $dAcl -ErrorAction Stop
		    Write-Output "Succesfully set the ACL for $dAclFile."
	    }
    }
    Catch {
        Remove-Item -Path $dCustomerWorkingDir\$dComputerSystemModel.bin -Force
        Write-Error "Could not set the ACL on $dAclFile. File has been removed." -Category OperationStopped
        Exit $exitCode = -1
    }
    Try {
        $dProcessPath = "$dCustomerWorkingDir\BiosConfigUtility64.exe"
        $dProcessArguments = ' /Set:"' + $dCustomerWorkingDir + '\HP VTx-d.REPSET" /CurSetupPasswordFile:"' + $dCustomerWorkingDir + '\' + $dComputerSystemModel + '.bin"'
        $dProcessOutputLog = "$dLogPath\$dScriptName`_BIOS_Log_$dLogTime.txt"
        $dProcessErrorLog = "$dLogPath\$dScriptName`_BIOS_Error_$dLogTime.txt"
        Start-Process -FilePath $dProcessPath -ArgumentList $dProcessArguments -Wait -RedirectStandardOutput $dProcessOutputLog -RedirectStandardError $dProcessErrorLog
        Write-Output "Succesfully configured the BIOS. A restart is required!"
    }
    Catch {
        Write-Error "Could not configure BIOS." -Category OperationStopped
    }
    Try {
	    Remove-Item -Path $dCustomerWorkingDir\$dHPBiosUtility -Force -ErrorAction SilentlyContinue
        Write-Output "Deleted: $dCustomerWorkingDir\$dHPBiosUtility"
        Remove-Item -Path $dCustomerWorkingDir\$dComputerSystemModel.bin -Force -ErrorAction SilentlyContinue
        Write-Output "Deleted: $dCustomerWorkingDir\$dComputerSystemModel.bin"
        Remove-Item -Path $dCustomerWorkingDir\$dHPVTREPSET -Force -ErrorAction SilentlyContinue
        Write-Output "Deleted: $dCustomerWorkingDir\$dHPVTREPSET"
    }
    Catch {
        Write-Error "Could not delete the Working files."
    }
    Try {
        Out-File -FilePath $dCustomerScriptsDir\$dScheduledTaskScriptName -Encoding unicode -Force -InputObject $dScheduledTaskScriptContent
        Register-ScheduledTask -TaskName $dScriptName -Trigger $dScheduledTaskTrigger -Settings $dScheduledTaskSettings -User $dScheduledTaskUser -RunLevel Highest -Action $dScheduledTaskAction -Force
        Write-Output "Successfully created the scheduled task $dScriptName."
    }
    Catch {
        Write-Error "Could not create scheduled task $dScriptName." -Category OperationStopped
    }

Invoke-Command -ScriptBlock {msg.exe $dLoggedOnUser "IMPORTANT!

To complete the installation please reboot the system in order to let the new BIOS settings take effect!"}
}
# End of Hewlett-Packard device configuration

Write-Error "Hyper-V installation not yet completed." -Category OperationStopped

#Stop Logging
Stop-Transcript | Out-Null

Exit $exitCode