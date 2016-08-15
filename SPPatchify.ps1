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
	Version			: 0.33
	Last Modified	: 08-15-2016
.LINK
	Source Code
	http://www.github.com/spjeff/sppatchify
	https://www.spjeff.com/2016/05/16/sppatchify-cu-patch-entire-farm-from-one-script/
	
	Patch Notes
	http://sharepointupdates.com
#>

[CmdletBinding()]
param (
	[Parameter(Mandatory=$False, ValueFromPipeline=$false, HelpMessage='Use -d to execute Media Download only.  No farm change.  Prep step for real patching later.')]
	[Alias("d")]
	[switch]$downloadMediaOnly,

	[Parameter(Mandatory=$False, ValueFromPipeline=$false, HelpMessage='Use -c to copy \media\ across all peer machines.  No farm change.  Prep step for real patching later.')]
	[Alias("c")]
	[switch]$copyMediaOnly,

	[Parameter(Mandatory=$False, ValueFromPipeline=$false, HelpMessage='Use -v to show farm version info.  READ ONLY, NO SYSTEM CHANGES.')]
	[Alias("v")]
	[switch]$showVersion,	
	
	[Parameter(Mandatory=$False, ValueFromPipeline=$false, HelpMessage='Use -p to execute Phase Two after local reboot.')]
	[Alias("p")]
	[switch]$phaseTwo
)

# Plugin
Add-PSSnapIn Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null

# Version
$host.ui.RawUI.WindowTitle = "SPPatchify v0.33"
$rootCmd = $MyInvocation.MyCommand.Definition
$root = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$stages = @("CopyEXE","StopSvc","RunEXE","StartSvc","ProdLocal","ConfigWiz")

#region binary EXE
Function CopyEXE($action) {
	Write-Host "===== $action EXE ===== $(Get-Date)" -Fore "Yellow"
	
	# Remote UNC
	$char = $root.ToCharArray()
	if ($char[1] -eq ':') {
		$char[1] = '$'
	}
	$remoteRoot = -join $char

	# Loop servers
	$coll = newStatus("CopyEXE")
	$counter = 0
	foreach ($server in $global:servers) {
		# Progress
		$addr = $server.Address
		$prct = [Math]::Round(($counter/$global:servers.Count)*100)
		Write-Progress -Activity "Copy EXE ($prct %)" -Status $addr -PercentComplete $prct
		$counter++
		
		# GUI In Progress
		($coll |? {$_.Server -eq $server.Address}).CopyEXE = 1
		displayStatus $coll
		
		# Skip current machine
		if ($addr -ne $env:computername) {
			if ($action -eq "Copy") {
				# Copy
				$files = Get-ChildItem "$root\media\*.*"
				foreach ($file in $files) {
					$name = $file.Name
					$dest = "\\$addr\$remoteRoot\media"
					mkdir $dest -Force -ErrorAction SilentlyContinue | Out-Null
					mkdir $dest.replace("media","log") -Force -ErrorAction SilentlyContinue | Out-Null
					ROBOCOPY "media" $dest /J /Z /W:0 /R:0 /XX
				}
			} else {
				# Delete
				Remove-Item "\\$addr\$remoteRoot\media\*.*" -confirm:$false
			}
		}
		
		# GUI Done
		($coll |? {$_.Server -eq $server.Address}).CopyEXE = 2
		displayStatus $coll
	}
	Write-Progress -Activity "Completed" -Completed
}

Function RunEXE() {
	Write-Host "===== RunEXE ===== $(Get-Date)" -Fore "Yellow"
	
	# Build CMD
	$ver = (Get-SPFarm).BuildVersion.Major
	$files = Get-ChildItem "$root\media\*.exe" | sort Name
	foreach ($f in $files) {
		$name = $f.Name
		$patchName = $name.replace(".exe","")
		$cmd = "Start-Process '$root\media\$name' -ArgumentList '/quiet /forcerestart /log:""$root\log\$name.log""' -PassThru"
		if ($ver -eq 16) {
			$cmd = $cmd.replace("forcerestart","norestart")
		}
		LoopRemoteCmd "Run EXE on " $cmd
		WaitEXE $patchName
	}
	
	# Reboot
	if ($ver -eq 16) {
		foreach ($server in $global:servers) {
			if ($server.Address -ne $env:computername) {
				Restart-Computer -ComputerName $server.Address
			}
		}
	}
}

Function WaitEXE($patchName) {
	Write-Host "===== WaitEXE ===== $(Get-Date)" -Fore "Yellow"
	
	# Wait for reboot
	Write-Host "Wait 60 sec..."
	Start-Sleep 60

	# Verify machines online
	$counter = 0
	foreach ($server in $global:servers) {	
		# Progress
		$addr = $server.Address
		$prct =  [Math]::Round(($counter/$global:servers.Count)*100)
		Write-Progress -Activity "Wait EXE ($prct %)" -Status $addr -PercentComplete $prct
		$counter++
		
		# Remote Posh
		$when = Get-Date
		Write-Host "`nEXE monitor started on $addr at $when " -NoNewLine
		do {
			# Monitor EXE process
			$proc = Get-Process -Name $patchName -Computer $addr -ErrorAction SilentlyContinue
			Write-Host "." -NoNewLine
			Start-Sleep 5
			
			# Count MSPLOG files
			$cmd = "`$f=Get-ChildItem ""$root\log\*MSPLOG*"";`$c=`$f.count;`$l=(`$f|sort last -desc|select -first 1).LastWriteTime;`$s=`$env:computername;New-Object -TypeName PSObject -Prop (@{""Server""=`$s;""Count""=`$c;""LastWriteTime""=`$l})"
			$sb = [Scriptblock]::Create($cmd)
			$msp = Invoke-Command -Session (Get-PSSession) -ScriptBlock $sb
			$msp = $msp | select Server,Count,LastWriteTime | sort LastWriteTime, Server -desc
			
			# HTML view
			$coll = newStatus("RunEXE")
			($coll |? {$_.Server -eq $addr}).RunEXE = 1
			displayStatus $coll $false $false $msp
		} while ($proc)
	}
}

Function WaitReboot() {
	Write-Host "`n===== WaitReboot ===== $(Get-Date)" -Fore "Yellow"
	
	# Wait for reboot
	Write-Host "Wait 60 sec..."
	Start-Sleep 60
	
	#Clean up
	Get-PSSession | Remove-PSSession
	
	# Verify machines online
	$counter = 0
	foreach ($server in $global:servers) {
		# Progress
		$addr = $server.Address
		$prct =  [Math]::Round(($counter/$global:servers.Count)*100)
		Write-Progress -Activity "Waiting for machine ($prct %)" -Status $addr -PercentComplete $prct
		$counter++
		
		# Remote Posh
		do {
			$remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication CredSSP -ErrorAction SilentlyContinue
			if (!$remote) {
				$remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Negotiate -ErrorAction SilentlyContinue
			}
			Write-Host "."  -NoNewLine
			Start-Sleep 5
		} while (!$remote)
	}
	
	#Clean up
	Get-PSSession | Remove-PSSession
}

Function LocalReboot() {
	# product install status
	

	# create Regkey
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\" -Name RunOnce -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name SPPatchify -Value "PowerShell $root\SPPatchify.ps1 -PhaseTwo" -ErrorAction SilentlyContinue | Out-Null
	
	# Reboot
	Write-Host "`n ===== REBOOT LOCAL ===== $(Get-Date)"
	$th = [Math]::Round(((Get-Date) - $start).TotalHours, 2)
	Write-Host "Duration Total Hours: $th" -Fore "Yellow"
	Stop-Transcript
	Start-Sleep 5
	Restart-Computer -Force
	Exit
}
#endregion

#region SP Config Wizard
Function LoopRemoteCmd($msg, $cmd) {
	#Clean up
	Get-PSSession | Remove-PSSession
	
	#GUI
	switch -wildcard ($msg) {
		"STOP services on*" {
			$stage = "StopSvc"
			break;
		}
		"START services on*" {
			$stage = "StartSvc"
			break;
		}
		"Run EXE on*" {
			$stage = "RunEXE"
			break;
		}
		"Product local*" {
			$stage = "ProdLocal"
			break;
		}
		"Run Config Wizard on*" {
			$stage = "ConfigWiz"
			break;
		}
	}
	if ($stage) {
		$coll = newStatus($stage)
	}
	
	# Loop servers
	$counter = 0
	foreach ($server in $global:servers) {

		# Script block
		if ($cmd.GetType().Name -eq "String") {
			if ($env:computername -eq $server.Address) {
				$runCmd = $cmd -replace "forcerestart","norestart"
			} else {
				$runCmd = $cmd
			}
			$sb = [ScriptBlock]::Create($runCmd)
		} else {
			$sb = $cmd
		}
	
		# Progress
		$addr = $server.Address
		$prct =  [Math]::Round(($counter/$global:servers.Count)*100)
		Write-Progress -Activity $msg -Status "$addr ($prct %)" -PercentComplete $prct
		$counter++
		
		# GUI - In Progress
		if ($stage) {
			($coll |? {$_.Server -eq $server.Address})."$stage" = 1
			displayStatus $coll
		}
		
		# Remote Posh
		$remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication CredSSP -ErrorAction SilentlyContinue
		if (!$remote) {
			$remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Negotiate -ErrorAction SilentlyContinue
		}
		Start-Sleep 3
		
		# Invoke
		Write-Host ">> invoke on $addr" -Fore "Green"
		foreach ($s in $sb) {
			Write-Host $s.ToString()
			Invoke-Command -Session $remote -ScriptBlock $s
		}
		Write-Host "<< complete on $addr" -Fore "Green"
		
		# GUI - Done
		if ($stage) {
			($coll |? {$_.Server -eq $server.Address})."$stage" = 2
			displayStatus $coll
		}
	}
	Write-Progress -Activity "Completed" -Completed	
}

Function ChangeDC() {
	Write-Host "===== ChangeDC OFF ===== $(Get-Date)" -Fore "Yellow"

	# Distributed Cache
	$sb = {
		try {
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
						Start-Sleep 5
						$counter++
					} catch {
						break
					}
				} while ($hostInfo -and $hostInfo.Status -ne "Down" -and $counter -lt $maxLoops)
				
				# Force stop
				Add-PSSnapIn Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null
				Stop-SPDistributedCacheServiceInstance
			}
		} catch {}
	}
	LoopRemoteCmd "Stop Distributed Cache on " $sb
}

Function ChangeServices($state) {
	Write-Host "===== ChangeServices $state ===== $(Get-Date)" -Fore "Yellow"
	
	# Logic core
	if ($state) {
		$action = "START"
		$sb = {
			@("IISAdmin","SPTimerV4","SQLBrowser","Schedule") |% {
				if (Get-Service $_ -ErrorAction SilentlyContinue) {
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
			@("IISAdmin","SPTimerV4","SQLBrowser","Schedule") |% {
				if (Get-Service $_ -ErrorAction SilentlyContinue) {
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
		$ver = (Get-SPFarm).BuildVersion.Major
		$psconfig = "C:\Program Files\Common Files\microsoft shared\Web Server Extensions\$ver\BIN\psconfig.exe"
	}
	
	# Save B2B shortcut
	$b2b = {
		$file = $psconfig.replace("psconfig.exe", "psconfigb2b.cmd")
		if (!(Test-Path $file)) {
			"psconfig.exe $options" | Out-File $file -Force
		}
	}
	LoopRemoteCmd "Save B2B shortcut on " @($shared,$b2b)
	
	# Run Config Wizard
	$wiz = {
		& "$psconfig" -cmd "upgrade" -inplace "b2b" -wait -cmd "applicationcontent" -install -cmd "installfeatures" -cmd "secureresources"
	}
	LoopRemoteCmd "Run Config Wizard on " @($shared,$wiz)
}

Function ChangeContent($state) {
	Write-Host "===== ContentDB $state ===== $(Get-Date)" -Fore "Yellow"

	if (!$state) {
		# Remove content
		$dbs = Get-SPContentDatabase
		if ($dbs) {
			$dbs |% {$wa = $_.WebApplication.Url; $_ | select Name,NormalizedDataSource,@{n="WebApp";e={$wa}}} | Export-Csv "$root\log\contentdbs-$when.csv"
			$dbs |% {
				"$($_.Name),$($_.NormalizedDataSource)"
				Dismount-SPContentDatabase $_ -Confirm:$false
			}
		}
	} else {
		# Add content
		$dbs = Import-Csv "$root\log\contentdbs-$when.csv"
		# Loop databases
		$counter = 0
		$dbs |% {
			$name = $_.Name
			$name
			
			# Progress
			$prct =  [Math]::Round(($counter/$dbs.Count)*100)
			Write-Progress -Activity "Add database" -Status "$name ($prct %)" -PercentComplete $prct
			$counter++
		
			Mount-SPContentDatabase -WebApplication $_.WebApp -Name $name -DatabaseServer $_.NormalizedDataSource | Out-Null
		}
	}
}
#endregion

#region general
Function EnablePSRemoting() {
	$ssp = Get-WSManCredSSP
	if ($ssp[0] -match "not configured to allow delegating") {
		# Enable remote PowerShell over CredSSP authentication
		Enable-WSManCredSSP -DelegateComputer * -Role Client -Force
		Restart-Service WinRM
	}
}

Function ReadIISPW {
	Write-Host "===== Read IIS PW ===== $(Get-Date)" -Fore "Yellow"

	# Current user (ex: Farm Account)
	$domain = $env:userdomain
	$user = $env:username
	Write-Host "Logged in as $domain\$user"
	
	# Start IISAdmin if needed
	$iisadmin = Get-Service IISADMIN
	if ($iisadmin.Status -ne "Running") {
		#set Automatic and Start
		Set-Service -Name IISADMIN -StartupType Automatic -ErrorAction SilentlyContinue
		Start-Service IISADMIN -ErrorAction SilentlyContinue
	}
	
	# Attempt to detect password from IIS Pool (if current user is local admin and farm account)
	Import-Module WebAdministration -ErrorAction SilentlyContinue | Out-Null
	$m = Get-Module WebAdministration
	if ($m) {
		#PowerShell ver 2.0+ IIS technique
		$appPools = Get-ChildItem "IIS:\AppPools\"
		foreach ($pool in $appPools) {	
			if ($pool.processModel.userName -like "*$user") {
				Write-Host "Found - "$pool.processModel.userName
				$pass = $pool.processModel.password
				if ($pass) {
					break
				}
			}
		}
	} else {
		#PowerShell ver 3.0+ WMI technique
		$appPools = Get-CimInstance -Namespace "root/MicrosoftIISv2" -ClassName "IIsApplicationPoolSetting" -Property Name, WAMUserName, WAMUserPass | select WAMUserName, WAMUserPass
		foreach ($pool in $appPools) {	
			if ($pool.WAMUserName -like "*$user") {
				Write-Host "Found - "$pool.WAMUserName
				$pass = $pool.WAMUserPass
				if ($pass) {
					break
				}
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
	# version DLL File
	$sb = {
		Add-PSSnapIn Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null;
		$ver = (Get-SPFarm).BuildVersion.Major;
		[System.Diagnostics.FileVersionInfo]::GetVersionInfo("C:\Program Files\Common Files\microsoft shared\Web Server Extensions\$ver\ISAPI\Microsoft.SharePoint.dll") | select FileVersion,@{N='PC'; E={$env:computername}}
	}
	LoopRemoteCmd "Get file version on " $sb
	
	# display Version
	DisplayVersion
	
	# open Central Admin
	$ca = (Get-SPWebApplication -IncludeCentralAdministration) |? {$_.IsAdministrationWebApplication}
	$pages = @("PatchStatus.aspx","UpgradeStatus.aspx","FarmServers.aspx")
	$pages |% {Start-Process ($ca.Url + "_admin/" + $_)}
}
Function DisplayVersion() {
	# version Max Patch
	$maxv = 0
	$f = Get-SPFarm
	$p = Get-SPProduct
	foreach ($u in $p.PatchableUnitDisplayNames) {
		$n = $u
		$v = ($p.GetPatchableUnitInfoByDisplayName($n).patches | sort version -desc)[0].version
		if (!$maxv) {$maxv = $v}
		if ($v -gt $maxv) {$maxv = $v}
	}
	Write-Host "Max Product = $maxv"
	Write-Host "Farm Build  = $($f.BuildVersion)"
}
Function IISStart() {
	# start IIS pools and sites
	$sb = {
		Import-Module WebAdministration

		# IISAdmin
		$iisadmin = Get-Service "IISADMIN"
		if ($iisadmin) {
			Set-Service -Name $iisadmin -StartupType Automatic -ErrorAction SilentlyContinue
			Start-Service $iisadmin -ErrorAction SilentlyContinue
		}

		# W3WP
		Start-Service w3svc | Out-Null
		Get-ChildItem "IIS:\AppPools\" |% {$n=$_.Name; Start-WebAppPool $n | Out-Null}
		Get-WebSite | Start-WebSite | Out-Null
	}
	LoopRemoteCmd "Start IIS on " $sb
}

Function ProductLocal() {
	# Sync local SKU binary to config DB
	$sb = {
		Add-PSSnapIn Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null
		Get-SPProduct -Local
	}
	LoopRemoteCmd "Product local SKU on " $sb
	
	# Display server upgrade
	Write-Host "Farm Servers - Upgrade Status " -Fore "Yellow"
	(Get-SPProduct).Servers | Select Servername,InstallStatus | Sort Servername | ft -a
}

Function UpgradeContent() {
	Write-Host "===== Upgrade Content Databases ===== $(Get-Date)" -Fore "Yellow"
	
	# Tracking table - assign DB to server
	$maxWorkers = 4
	$track = @()
	$dbs = Get-SPContentDatabase
	$i = 0
	foreach ($db in $dbs) {
		# Assign to SPServer
		$mod = $i % $global:servers.count
		$pc = $global:servers[$mod].Address
		
		# Collect
		$obj = New-Object -TypeName PSObject -Prop (@{"Name"=$db.Name;"Id"=$db.Id;"UpgradePC"=$pc;"JID"=0;"Status"="New"})
		$track += $obj
		$i++
	}
	$track | Format-Table -Auto
	
	# GUI - servers done
	$coll = newStatus("done")
	displayStatus $coll

	# Clean up
	Get-PSSession | Remove-PSSession
	Get-Job | Remove-Job
	
	# Open sessions
	foreach ($server in $global:servers) {
		$addr = $server.Address
		$remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication CredSSP -ErrorAction SilentlyContinue
		if (!$remote) {
			$remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Negotiate -ErrorAction SilentlyContinue 
		}
	}

	# Monitor and Run loop
	do {
		# Get latest PID status
		$active = $track |? {$_.Status -eq "InProgress"}
		foreach ($db in $active) {
			# Monitor remote server job
			if ($db.JID) {
				$job = Get-Job $db.JID
				if ($job.State -eq "Completed") {
					# Update DB tracking
					$db.Status = "Completed"
				} elseif ($job.State -eq "Failed") {
					# Update DB tracking
					$db.Status = "Failed"
				} else {
					Write-host "-" -NoNewline
				}
			}
		}
		
		# Ensure workers are active
		foreach ($server in $global:servers) {
			# Count active workers per server
			$active = $track |? {$_.Status -eq "InProgress" -and $_.UpgradePC -eq $server.Address}
			if ($active.count -lt $maxWorkers) {
			
				# Choose next available DB
				$avail = $track |? {$_.Status -eq "New" -and $_.UpgradePC -eq $server.Address}
				if ($avail) {
					if ($avail -is [array]) {
						$row = $avail[0]
					} else {
						$row = $avail
					}
				
					# Kick off new worker
					$id = $row.Id
					$name = $row.Name
					$remoteStr = "`$cmd = New-Object System.Diagnostics.ProcessStartInfo; "+
						"`$cmd.FileName = 'powershell.exe'; "+
						"`$internal = Add-PSSnapin Microsoft.SharePoint.Powershell -ErrorAction SilentlyContinue | Out-Null; Upgrade-SPContentDatabase -Id $id -Confirm:`$false; "+
						"`$cmd.Arguments = '-NoProfile -Command ""$internal""'; "+
						"[System.Diagnostics.Process]::Start(`$cmd);"
					
					# Run on remote server
					$remoteCmd = [Scriptblock]::Create($remoteStr) 
					$pc = $server.Address
					Write-Host $pc -Fore "Green"
					Get-PSSession | Format-Table -AutoSize
					$session = Get-PSSession |? {$_.ComputerName -like "$pc*"}
					$result = Invoke-Command $remoteCmd -Session $session -AsJob
					
					# Update DB tracking
					$row.JID = $result.Id
					$row.Status = "InProgress"
				}
				
				# Progress
				$counter = ($track |? {$_.Status -eq "Completed"}).Count
				$prct = [Math]::Round(($counter/$track.Count)*100)
				Write-Progress -Activity "Upgrade database" -Status "$name ($prct %)" -PercentComplete $prct
				$track | Format-Table -AutoSize
				
				# GUI
				$msg = "Upgrading Content DB: $name ($prct %) - $counter of $($track.Count)"
				displayStatus $coll ($prct*3) $msg
				Start-Sleep 3
			}
		}

		# Latest counter
		$remain = $track |? {$_.status -ne "Completed" -and $_.status -ne "Failed"}
	} while ($remain)
	Write-Host "===== Upgrade Content Databases DONE ===== $(Get-Date)"
	$track | group status | Format-Table -AutoSize
	$track | Format-Table -AutoSize
	
	# GUI
	$msg = "Upgrade Content DB Complete (100 %)"
	displayStatus $coll (100*3) $msg
	
	# Clean up
	Get-PSSession | Remove-PSSession
	Get-Job | Remove-Job
}

Function ShowMenu($prod) {
	# Choices
	$csv = Import-Csv "$root\SPPatchify-Download-CU.csv"
	$choices = $csv |? {$_.Product -eq $prod} | sort Year,Month -Desc | select Year,Month -Unique

	# Menu
	Write-Host "Download CU Media to \media\ - $prod" -Fore "Yellow"
	Write-Host "---------"
	$menu = @()
	$i = 0
	$choices |% {
		$n = (getMonth($_.Month)) + " " + ($_.Year)
		$menu += $n
		if ($i -eq 0) {
			$default = $n
			$n += "[default] <=="
			Write-Host "$i $n" -Fore "Green"
		} else {
			Write-Host "$i $n"
		}
		$i++
	}

	# Return
	$sel = Read-Host "Select month. Press [enter] for default"
	if (!$sel) {
		$sel = $default
	} else {
		$sel = $menu[$sel]
	}
	$global:selmonth = $sel
} 

Function GetMonth($mo) {
	try {
		$mo = (Get-Culture).DateTimeFormat.GetAbbreviatedMonthName($mo)
	} catch {
		return $mo
	}
	return $mo
}

Function GetMonthInt($name) {
	1..12 |% {
		if ($name -eq (Get-Culture).DateTimeFormat.GetAbbreviatedMonthName($_)) {
			return $_
		}
	}
}

Function PatchMenu() {
	# Ensure folder
	mkdir "$root\media" -ErrorAction SilentlyContinue | Out-Null

	# Skip if we already have media
	$files = Get-ChildItem "$root\media\*.exe"
	if ($files) {
		Write-Host "Using EXE files found in \media\.  `nTo trigger download GUI first delete these files and run script again."		
		$files | Format-Table -Auto
		Break
	}

	# Download CSV of patch URLs
	$source = "https://raw.githubusercontent.com/spjeff/sppatchify/master/SPPatchify-Download-CU.csv"
	$local = "$root\SPPatchify-Download-CU.csv"
	$wc = New-Object System.Net.Webclient
	$dest = $local.Replace(".csv","-temp.csv")
	$wc.DownloadFile($source, $dest)
	
	# Overwrite if downloaded OK
	if (Test-Path $dest) {
		Copy-Item $dest $local -Force
		Remove-Item $dest
	}
	$csv = Import-Csv $local
	
	# SKU - SharePoint or Project?
	$sku = "SP"
	$ver = "15"
	if (Get-Command Get-SPFarm -ErrorAction SilentlyContinue) {
		$ver = (Get-SPFarm).BuildVersion.Major
	}
	if (Get-Command Get-SPProjectWebInstance -ErrorAction SilentlyContinue) {
		if ($ver -ne 16) {
			$sku = "PROJ"
		}
	}
	$prod = "$sku$ver"
	Write-Host "Product = $prod"
	ShowMenu $prod

	# Halt if Farm is PROJ and media is not
	$files = Get-ChildItem "$root\media\*prj*.exe"
	if ($sku -eq "PROJ" -and !$files) {
		Write-Host "HALT - have Project Server farm and \media\ folder missing PRJ.  Download correct media and try again." -Fore Red
		Stop-Transcript
		Exit
	}
	
	# Halt if have multiple EXE and not SP2016
	$files = Get-ChildItem "$root\media\*.exe"
	if ($files -is [System.Array] -and $ver -ne 16) {
		# HALT - multiple EXE found - require clean up before continuing
		$files | Format-Table -AutoSize
		Write-Host "HALT - Multiple EXEs found. Clean up \media\ folder and try again." -Fore Red
		Stop-Transcript
		Exit
	}
	
	# Filter CSV for selected CU month
	Write-Host "SELECTED = $($global:selmonth)" -Fore "Yellow"
	$year = $global:selmonth.Split(" ")[1]
	$month = GetMonthInt $global:selmonth.Split(" ")[0]
	$patchFiles = $csv |? {$_.Year -eq $year -and $_.Month -eq $month -and $_.Product -eq "$sku$ver"}
	$patchFiles | Format-Table -Auto
	
	# Download patch files
	$bits = (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue)
	foreach ($file in $patchFiles) {
		# Parameters
		$splits = $file.URL.Split("/")
		$name = $splits[$splits.Count - 1]
		$dest = "$root\media\$name"

		if (Test-Path $dest) {
			Write-Host "Found $name"
		} else {
			Write-Host "Downloading $name"
			if ($bits) {
				# pefer BITS
				 Write-Host "BITS $dest"
				Start-BitsTransfer -Source $file.URL -Destination $dest
			} else {
				# Dot Net
				Write-Host "WebClient $dest"
				(New-Object System.Net.WebClient).DownloadFile($file.URL, $dest)
			}
		}
	}
}

Function DetectAdmin() {
	$wid = [System.Security.Principal.WindowsIdentity]::GetCurrent()
	$prp = New-Object System.Security.Principal.WindowsPrincipal($wid)
	$adm = [System.Security.Principal.WindowsBuiltInRole]::Administrator
	$IsAdmin = $prp.IsInRole($adm)
	if (!$IsAdmin) {
		(Get-Host).UI.RawUI.Backgroundcolor = "DarkRed"
		Clear-Host
		Write-Host "===== SPPatchify - Not Running as Administrator =====`nStarting an elevated PowerShell window...`n"
		$arguments = "& '" + $rootCmd + "' -p"
		$arguments
		Start-Process powershell -Verb runAs -ArgumentList $arguments
		Break
	}
}
#endregion

#region GUI status window
function newStatus($currentStage) { 
	# servers (rows)
	$coll = @()
	$servers = Get-SPServer |? {$_.Role -ne "Invalid"} | sort Name
	foreach ($server in $servers) {
		$row = New-Object -TypeName PSObject -Property @{Server=$server.Name; Role=$server.Role}
		$coll += $row
	}

	# stages (cols)
	foreach ($row in $coll) {
		$i = $stages.IndexOf($currentStage)
		if ($currentStage -eq "done") {$i = $stages.count}
		foreach ($s in $stages) {
			if ($stages.IndexOf($s) -lt $i) {$v = 2} else {$v = 0}
			$row | Add-Member -MemberType NoteProperty -Name $s -Value $v
		}
	}
	return $coll
}

function displayStatus($coll, $px, $msg, $msp) {
	# percent
	$c = 0
	foreach ($row in $coll) {
		foreach ($col in $stages) {
			if ($row."$col" -eq 2) {
				$c++
			}
		}
	}
	$total = $coll.count * $stages.count
	$prct = [Math]::Round(($c / $total) * 100)
	
	# progress bar
$foot = "<div style='text-align:right'>{0}</div>" -f (Get-Date)
if ($px) {
$foot += @"
<br/>
<b>{0}</b>
<div style='width:300px;border:1px solid black'>
<div style='width:{1}px;height:20px;background-color:blue;'></div>
</div>
"@ -f $msg,$px
$prct = $px/3
}

	# generate HTML
	$file = "$root\sppatchify-status.html"
	$meta = "<meta http-equiv='refresh' content='5'><title>SPPatchify ($prct %)</title>"
	
	# MSPLOG second table
	if ($msp) {
		$foot = ($msp | ConvertTo-Html -Fragment) + $foot
	}

	# colors
	$html = $coll | ConvertTo-Html -Head $meta -PostContent $foot
	$html = $html.replace("<table","<table border=0 cellpadding=6 cellspacing=0")
	$html = $html.replace("<td>0</td>","<td style='background-color:lightgray'>Not Started</td>")
	$html = $html.replace("<td>1</td>","<td style='background-color:yellow'>In Progress</td>")
	$html = $html.replace("<td>2</td>","<td style='background-color:lightgreen'>Complete</td>")
	$html | Out-File $file -Force -Confirm:$false

	launchIE $file
}

function launchIE($file) {
	# web browser
	$ieproc = (Get-Process -Name iexplore -ErrorAction SilentlyContinue)| Where-Object {$_.MainWindowHandle -eq $global:HWND}
	if (!$ieproc) {
		$global:ie = new-object -comobject InternetExplorer.Application
		$global:ie.visible = $true
		$global:ie.top = 200; $global:ie.width = 800; $global:ie.height = 500 ; $global:ie.Left = 100
		$global:HWND =  $global:ie.HWND
	}
	try {
		$global:ie.navigate($file)
	} catch {}
}
#endregion

function Main() {
	# download media
	if ($downloadMediaOnly) {
		PatchMenu
		Exit
	}
	
	# display version
	if ($showVersion) {
		DisplayVersion
		Exit
	}
	
	# Start time
	$start = Get-Date
	$when = $start.ToString("yyyy-MM-dd-hh-mm-ss")
	$logFile = "$root\log\SPPatchify-$when.txt"
	mkdir "$root\log" -ErrorAction SilentlyContinue | Out-Null
	Start-Transcript $logFile
		
	# Params
	$msg = "=== PARAMS ==="
	$msg +=	"download = $downloadMediaOnly"
	$msg +=	"copy = $copyMediaOnly"
	$msg +=	"version = $showVersion"
	$msg +=	"phaseTwo = $phaseTwo"
	$c = (Get-SPContentDatabase).Count
	Write-Host "Content Databases Online: $c"

	# Local farm servers
	$global:servers = Get-SPServer |? {$_.Role -ne "Invalid"} | sort Address

	# Core steps
	if (!$phaseTwo) {
		if ($copyMediaOnly) {
			# CMD switch -C (copy media only)
			CopyEXE "Copy"
		} else {
			# Phase One - patch EXE
			PatchMenu
			EnablePSRemoting
			ReadIISPW
			CopyEXE "Copy"
			ChangeDC
			ChangeServices $false
			IISStart
			RunEXE
			WaitReboot
			ProductLocal
			LocalReboot
		}
	} else {
		# CMD switch -P (phase two) - SP Config Wizard
		DetectAdmin
		ReadIISPW
		ChangeContent $false
		ChangeServices $true
		ProductLocal
		RunConfigWizard
		ChangeContent $true
		UpgradeContent
		CopyEXE "Remove"
		IISStart
		DisplayCA
	}
	
	# Run duration
	Write-Host "===== DONE ===== $(Get-Date)" -Fore "Yellow"
	$th = [Math]::Round(((Get-Date) - $start).TotalHours, 2)
	Write-Host "Duration Hours: $th" -Fore "Yellow"
	$c = (Get-SPContentDatabase).Count
	Write-Host "Content Databases Online: $c"
	
	# Add both Phase one and two
	$regHive = "HKCU:\Software"
	$regKey = "SPPatchify"
	$regName = "PhaseOneTotalHours"
	if (!$phaseTwo) {
		# create Regkey
		New-Item -Path $regHive -Name "$regKey" -ErrorAction SilentlyContinue | Out-Null
		New-ItemProperty -Path "$regHive\$regKey" -Name "$regName" -Value $th -ErrorAction SilentlyContinue | Out-Null
	} else {
		$thKey = Get-ItemProperty -Path "$regHive\$regKey" -ErrorAction SilentlyContinue
		if ($thKey) {
			$h = [double]($thKey."$regName")
			$h += $th
		}
		Write-Host "TOTAL Hours (Phase One and Two): $h" -Fore "Yellow"
		Remove-Item -Path "$regHive\$regKey" -ErrorAction SilentlyContinue | Out-Null
	}
	
	# Cleanup
	Remove-Item "$root\sppatchify-status.html" -Force -ErrorAction SilentlyContinue | Out-Null
	Stop-Transcript
}
Main