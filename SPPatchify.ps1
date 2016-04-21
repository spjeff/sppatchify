<#
.SYNOPSIS
	SharePoint Central Admin - View active services across entire farm. No more select machine drop down dance!
.DESCRIPTION
	Apply CU patch to entire farm from one PowerShell console.
	
	NOTE - must run local to a SharePoint server under account with farm admin rights.

	Comments and suggestions always welcome!  spjeff@spjeff.com or @spjeff
.NOTES
	File Name		: SPPatchify.ps1
	Author			: Jeff Jones - @spjeff
	Version			: 0.1
	Last Modified	: 04-21-2015
.LINK
	http://www.github.com/spjeff/sppatchify
#>

# Plugin
Add-PSSnapIn Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null

#region binary EXE
Function CopyEXE($action) {
	Write-Host "===== $action EXE =====" -Fore Yellow

	# Loop servers
	$counter = 0
	foreach ($server in $servers) {
		# Progress
		$addr = $server.Address
		Write-Progress -Activity "Copy EXE to " -Status $addr -PercentComplete (($counter/$servers.Count)*100)
		$counter++
		
		# Skip current machine
		if ($addr -ne $env:computername) {
			if ($action -eq "Copy") {
				# Copy
				$files = Get-ChildItem ".\media\*.*"
				foreach ($file in $files) {
					$name = $file.Name
					$dest = "\\$addr\C$\SPPatchify\media"
					mkdir $dest -Force -ErrorAction SilentlyContinue | Out-Null
					mkdir $dest.replace("media","log") -Force -ErrorAction SilentlyContinue | Out-Null
					ROBOCOPY "media" $dest /Z /W:0 /R:0 /XX
				}
			} else {
				# Delete
				del "\\$addr\C$\SPPatchify\media\*.*" -confirm:$false
			}
			
		}
	}
	Write-Progress -Activity "Completed" -Completed
}

Function StartEXE() {
	Write-Host "===== StartEXE =====" -Fore Yellow
	
	# Build CMD
	$files = Get-ChildItem ".\media\*.exe"
	if ($files -is [System.Array]) {
		$name = $files[0].Name
	} else {
		$name = $files.Name
	}
	$global:patchName = $name.replace(".exe","")
	$cmd = "Start-Process 'C:\SPPatchify\media\$name' -ArgumentList '/quiet /forcerestart /log:""C:\SPPatchify\log\$name.log""' -PassThru -NoNewWindow"
	LoopRemoteCmd "Run EXE on " $cmd
}

Function WaitEXE() {
	Write-Host "===== WaitEXE =====" -Fore Yellow
	
	# Wait for reboot
	Write-Host "Wait 30 sec..."
	Sleep 30
			
	# Verify machines online
	$counter = 0
	foreach ($server in $servers) {
		# Progress
		$addr = $server.Address
		Write-Progress -Activity "Waiting for " -Status $addr -PercentComplete (($counter/$servers.Count)*100)
		$counter++
		
		# Remote Posh
		$when = Get-Date
		Write-Host "`nEXE started on $addr at $when " -NoNewLine
		do {
			$proc = Get-Process -Name $global:patchName -Computer $addr -ErrorAction SilentlyContinue
			Sleep 2
			Write-Host "."  -NoNewLine
		} while ($proc)
	}
}

Function WaitReboot() {
	Write-Host "===== WaitReboot =====" -Fore Yellow
	
	# Wait for reboot
	Write-Host "Wait 30 sec..."
	Sleep 30
			
	# Verify machines online
	$counter = 0
	foreach ($server in $servers) {
		# Progress
		$addr = $server.Address
		Write-Progress -Activity "Waiting for " -Status $addr -PercentComplete (($counter/$servers.Count)*100)
		$counter++
		
		# Remote Posh
		while (!$remote) {
			$remote = New-PSSession -ComputerName $addr
		}
	}
	Get-PSSession | Remove-PSSession
}
#endregion

#region SP Config Wizard
Function LoopRemoteCmd($msg, $cmd) {
	# Loop servers
	$counter = 0
	foreach ($server in $servers) {
		# Script block
		if ($cmd.GetType().Name -eq "String") {
			if ($env:computername -eq $server.Address) {
				$runCmd = $cmd -replace "forcerestart","norestart"
			} else {
				$runCmd = $cmd
			}
			$sb = [ScriptBlock]::Create("$runCmd")
		} else {
			$sb = $cmd
		}
	
		# Progress
		$addr = $server.Address
		$prct =  [Math]::Round(($counter/$servers.Count)*100)
		Write-Progress -Activity $msg -Status "$addr ($prct %)" -PercentComplete $prct
		$counter++
		
		# Remote Posh
		$remote = New-PSSession -ComputerName $addr -Authentication CredSSP -Credential $global:cred
		Write-Host ">> invoke on $addr" -Fore Green
		foreach ($s in $sb) {
			$s.ToString()
			Invoke-Command -Session $remote -ScriptBlock $s
		}
		Write-Host "<< complete on $addr" -Fore Green
	}
	Get-PSSession | Remove-PSSession
	Write-Progress -Activity "Completed" -Completed	
}

Function ChangeDC() {
	Write-Host "===== ChangeDC OFF =====" -Fore Yellow

	# Distributed Cache
	$sb = {
		Use-CacheCluster
		Get-AFCacheClusterHealth -ErrorAction SilentlyContinue
		$computer = [System.Net.Dns]::GetHostByName($env:computername).HostName
		$counter = 0
		$maxLoops = 60
		
		$cache = Get-CacheHost |? {$_.HostName -eq $computer}
		if ($cache) {
			do {
				try {
				# Wait for graceful stop
				$hostInfo = Stop-CacheHost -Graceful -CachePort 22233 -HostName $computer -ErrorAction SilentlyContinue
				Write-Host $computer $hostInfo.Status
				Sleep 5
				$counter++
				} catch {break}
			} while ($hostInfo -and $hostInfo.Status -ne "Down" -and $counter -lt $maxLoops)
			
			# Force stop
			Add-PSSnapIn Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null
			Stop-SPDistributedCacheServiceInstance
		}
	}
	LoopRemoteCmd "Stop Distributed Cache on " $sb
}

Function ChangeServices($state) {
	Write-Host "===== ChangeServices $state =====" -Fore Yellow
	
	# Logic core
	if ($state) {
		$action = "START"
		$sb = {
			@("IISAdmin","SPTimerV4") |% {
				if (Get-Service $_) {
					Set-Service -Name $_ -StartupType Automatic -ErrorAction SilentlyContinue
					Start-Service $_ -ErrorAction SilentlyContinue
				}
			}
			@("OSearch15","SPSearchHostController") |% {
				Start-Service $_ -ErrorAction SilentlyContinue
			}
			Start-Process 'iisreset.exe' -ArgumentList '/start' -Wait -PassThru -NoNewWindow | Out-Null
		}
	} else {
		$action = "STOP"
		$sb = {
			Start-Process 'iisreset.exe' -ArgumentList '/stop' -Wait -PassThru -NoNewWindow | Out-Null
			@("IISAdmin","SPTimerV4") |% {
				if (Get-Service $_) {
					Set-Service -Name $_ -StartupType Disabled -ErrorAction SilentlyContinue
					Stop-Service $_ -ErrorAction SilentlyContinue
				}
			}
			@("OSearch15","SPSearchHostController") |% {
				Stop-Service $_ -ErrorAction SilentlyContinue
			}
		}
	}
	
	# Search Crawler
	Write-Host "$action search crawler ..."
	try {
		$ssa = Get-SPEenterpriseSearchServiceApplication 
		if ($state) {
			$ssa.resume()
		} else {
			$ssa.pause()
		}
	} catch {}
	
	LoopRemoteCmd "$action services on " $sb
}

Function RunConfigWizard() {
	# Shared
	$shared = {
		Add-PSSnapIn Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null
		$ver = (Get-SPFarm).BuildVersion.Major;
		$psconfig = "C:\Program Files\Common Files\microsoft shared\Web Server Extensions\$ver\BIN\psconfig.exe"
		$options = "-cmd upgrade -inplace b2b -wait -cmd applicationcontent -install -cmd installfeatures -cmd secureresources"
	}
	
	# Save B2B shortcut
	$b2b = {
		$file = $psconfig.replace("psconfig.exe","psconfigb2b.cmd")
		if (!(Test-Path $file)) {
			"psconfig.exe $options" | Out-File $file -Force
		}
	}
	LoopRemoteCmd "Save B2B shortcut on " @($shared,$b2b)
	
	# Run Config Wizard
	$wiz = {
		& "$psconfig" $options
	}
	LoopRemoteCmd "Run Config Wizard on " @($shared,$wiz)
}

Function ChangeContent($state) {
	Write-Host "===== ContentDB $state =====" -Fore Yellow

	if (!$state) {
		# Remove content
		$dbs = Get-SPContentDatabase
		if ($dbs) {
			
			$dbs |% {$wa = $_.WebApplication.Url; $_ | Select Name,NormalizedDataSource,{$wa}} | Export-Csv "contentdbs-$when.csv"
			$dbs |% {
				$_.Name
				Dismount-SPContentDatabase $_ -Confirm:$false
			}
		}
	} else {
		# Add content
		$dbs = Import-Csv "contentdbs-$when.csv"
		# Loop databases
		$counter = 0
		$dbs |% {
			$name = $_.Name
			$name
			
			# Progress
			$prct =  [Math]::Round(($counter/$dbs.Count)*100)
			Write-Progress -Activity "Add database" -Status "$name ($prct %)" -PercentComplete $prct
			$counter++
		
			Mount-SPContentDatabase -WebApplication $_."`$wa" -Name $name -DatabaseServer $_.NormalizedDataSource | Out-Null
		}
	}
}
#endregion

#region general
Function EnablePS() {
	$ssp = Get-WSManCredSSP
	if ($ssp[0] -eq "The machine is not configured to allow delegating fresh credentials.") {
		# Enable remote PowerShell over CredSSP authentication
		Enable-WSManCredSSP -DelegateComputer * -Role Client -Force
		Restart-Service WinRM
	}
}

Function ReadIISPW {
	Write-Host "===== Read IIS PW =====" -Fore Yellow

	# Current user (ex: Farm Account)
	$domain = $env:userdomain
	$user = $env:username
	Write-Host "Logged in as $domain\$user"
	
	# Attempt to detect password from IIS Pool (if current user is local admin and farm account)
	$appPools = Get-CimInstance -Namespace "root/MicrosoftIISv2" -ClassName "IIsApplicationPoolSetting" -Property Name, WAMUserName, WAMUserPass | Select-Object WAMUserName, WAMUserPass
	foreach ($pool in $appPools) {	
		if ($pool.WAMUserName -like "*$user") {
			Write-Host "Found - "$pool.WAMUserName
			$pass = $pool.WAMUserPass
			if ($pass) {
				break
			}
		}
	}
	
	# Prompt for password
	if (!$pass) {
		$sec = Read-Host "Enter password: " -AsSecureString
	} else {
		$sec = $pass | ConvertTo-SecureString -AsPlainText -Force
	}
	$global:cred = New-Object System.Management.Automation.PSCredential -ArgumentList "$domain\$user",$sec
}

Function DisplayCA() {
	# version table
	(Get-SPFarm).BuildVersion
	$ver = (Get-SPFarm).BuildVersion.Major;
	
	$sb = {
		[System.Diagnostics.FileVersionInfo]::GetVersionInfo("C:\Program Files\Common Files\microsoft shared\Web Server Extensions\$ver\ISAPI\Microsoft.SharePoint.dll") | select FileVersion,@{N='PC'; E={$env:computername}}
	}
	LoopRemoteCmd "Get file version on " $sb
	
	# open Central Admin
	$ca = (Get-SPWebApplication -IncludeCentralAdministration) |? {$_.IsAdministrationWebApplication}
	$pages = @("PatchStatus.aspx","UpgradeStatus.aspx","FarmServers.aspx")
	$pages |% {start ($ca.Url + "_admin/" + $_)}
}

Function IISStart() {
	$sb = {
		net start w3svc
		Get-ChildItem IIS:\AppPools |% {$n=$_.Name; Start-WebAppPool $n}
		Get-WebSite | Start-WebSite
	}
	LoopRemoteCmd "Start IIS on " $sb
}
#endregion

Function Main() {
	# Start time
	$start = Get-Date
	$when = $start.ToString("yyyy-MM-dd-hh-mm-ss")
	$logFile = "log\$($MyInvocation.MyCommand)-$when.txt"
	Start-Transcript $logFile

	# Local farm
	(Get-SPFarm).BuildVersion
	$servers = Get-SPServer |? {$_.Role -ne "Invalid"}
	
	# Core steps
	EnablePS
 	ReadIISPW
	CopyEXE "Copy"
	ChangeDC
	ChangeServices $false
	StartEXE
	WaitEXE
	WaitReboot
	ChangeContent $false
	ChangeServices $true
	RunConfigWizard
	ChangeContent $true
	CopyEXE "Remove"
	IISStart
	DisplayCA
	
	# Run duration
	Write-Host "===== DONE =====" -Fore Yellow
	$th = [Math]::Round(((Get-Date) - $start).TotalHours,2)
	Write-Host "Duration Total Hours: $th" -Fore Yellow
	Stop-Transcript
}

Main