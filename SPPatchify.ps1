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
	Version			: 0.18
	Last Modified	: 06-29-2016
.LINK
	Source Code
	http://www.github.com/spjeff/sppatchify
	https://www.spjeff.com/2016/05/16/sppatchify-cu-patch-entire-farm-from-one-script/
	
	Patch Notes
	http://sharepointupdates.com
#>

[CmdletBinding()]
param (
	[Parameter(Mandatory=$False, Position=0, ValueFromPipeline=$false, HelpMessage='Use -c to copy \media\ across all peer machines.  No farm change.  Prep step for real patching later.')]
	[Alias("c")]
	[switch]$copyOnly,
	
	[Parameter(Mandatory=$False, Position=1, ValueFromPipeline=$false, HelpMessage='Use -d to execute Media Download only.  No farm change.  Prep step for real patching later.')]
	[Alias("d")]
	[switch]$downloadOnly,
	
	[Parameter(Mandatory=$False, Position=2, ValueFromPipeline=$false, HelpMessage='Use -p to execute Phase Two after local reboot.')]
	[Alias("p")]
	[switch]$phaseTwo
)

# Version
$host.ui.RawUI.WindowTitle = "SPPatchify v0.18"

# Plugin
Add-PSSnapIn Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null
$root = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition

#region binary EXE
Function CopyEXE($action) {
	Write-Host "===== $action EXE ===== $(Get-Date)" -Fore Yellow
	
	# Remote UNC
	$char = $root.ToCharArray()
	if ($char[1] -eq ':') {
		$char[1] = '$'
	}
	$remoteRoot = -join $char

	# Loop servers
	$counter = 0
	foreach ($server in $servers) {
		# Progress
		$addr = $server.Address
		$prct = [Math]::Round(($counter/$servers.Count)*100)
		Write-Progress -Activity "Copy EXE ($prct %)" -Status $addr -PercentComplete $prct
		$counter++
		
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
					ROBOCOPY "media" $dest /Z /W:0 /R:0 /XX /XN /XO
				}
			} else {
				# Delete
				del "\\$addr\$remoteRoot\media\*.*" -confirm:$false
			}
		}
	}
	Write-Progress -Activity "Completed" -Completed
}

Function StartEXE() {
	Write-Host "===== StartEXE ===== $(Get-Date)" -Fore Yellow
	
	# Build CMD
	$files = Get-ChildItem "$root\media\*.exe"
	$name = $files[0].Name
	$global:patchName = $name.replace(".exe","")
	$cmd = "Start-Process '$root\media\$name' -ArgumentList '/quiet /forcerestart /log:""$root\log\$name.log""' -PassThru"
	LoopRemoteCmd "Run EXE on " $cmd
}

Function WaitEXE() {
	Write-Host "===== WaitEXE ===== $(Get-Date)" -Fore Yellow
	
	# Wait for reboot
	Write-Host "Wait 30 sec..."
	Start-Sleep 30

	# Verify machines online
	$counter = 0
	foreach ($server in $servers) {	
		# Progress
		$addr = $server.Address
		$prct =  [Math]::Round(($counter/$servers.Count)*100)
		Write-Progress -Activity "Waiting for EXE ($prct %)" -Status $addr -PercentComplete $prct
		$counter++
		
		# Remote Posh
		$when = Get-Date
		Write-Host "`nEXE started on $addr at $when " -NoNewLine
		do {
			# Monitor EXE process
			$proc = Get-Process -Name $global:patchName -Computer $addr -ErrorAction SilentlyContinue
			Write-Host "."  -NoNewLine
			Start-Sleep 3
		} while ($proc)
	}
}

Function WaitReboot() {
	Write-Host "===== WaitReboot ===== $(Get-Date)" -Fore Yellow
	
	# Wait for reboot
	Write-Host "Wait 30 sec..."
	Start-Sleep 30
	
	# Verify machines online
	$counter = 0
	foreach ($server in $servers) {
		# Progress
		$addr = $server.Address
		$prct =  [Math]::Round(($counter/$servers.Count)*100)
		Write-Progress -Activity "Waiting for machine ($prct %)" -Status $addr -PercentComplete $prct
		$counter++
		
		# Remote Posh
		while (!$remote) {
			$remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication CredSSP 
			Write-Host "."  -NoNewLine
			Start-Sleep 3
		}
	}
	Get-PSSession | Remove-PSSession
}

Function LocalReboot() {
	# create Regkey
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\" -Name RunOnce -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name SPPatchify -Value "PowerShell $root\SPPatchify.ps1 -PhaseTwo" -ErrorAction SilentlyContinue | Out-Null
	
	# Reboot
	Write-Host " - REBOOTING - "
	$th = [Math]::Round(((Get-Date) - $start).TotalHours, 2)
	Write-Host "Duration Total Hours: $th" -Fore Yellow
	Stop-Transcript
	Start-Sleep 5
	Restart-Computer -Force
	Exit
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
			$sb = [ScriptBlock]::Create($runCmd)
		} else {
			$sb = $cmd
		}
	
		# Progress
		$addr = $server.Address
		$prct =  [Math]::Round(($counter/$servers.Count)*100)
		Write-Progress -Activity $msg -Status "$addr ($prct %)" -PercentComplete $prct
		$counter++
		
		# Remote Posh
		$remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication CredSSP
        Start-Sleep 3
		Write-Host ">> invoke on $addr" -Fore Green
		foreach ($s in $sb) {
			Write-Host $s.ToString()
			Invoke-Command -Session $remote -ScriptBlock $s
		}
		Write-Host "<< complete on $addr" -Fore Green
	}
	Write-Progress -Activity "Completed" -Completed	
}

Function ChangeDC() {
	Write-Host "===== ChangeDC OFF ===== $(Get-Date)" -Fore Yellow

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
	Write-Host "===== ChangeServices $state ===== $(Get-Date)" -Fore Yellow
	
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
	Write-Host "===== ContentDB $state ===== $(Get-Date)" -Fore Yellow

	if (!$state) {
		# Remove content
		$dbs = Get-SPContentDatabase
		if ($dbs) {
			$dbs |% {$wa = $_.WebApplication.Url; $_ | Select Name,NormalizedDataSource,{$wa}} | Export-Csv "$root\log\contentdbs-$when.csv"
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
		
			Mount-SPContentDatabase -WebApplication $_."`$wa" -Name $name -DatabaseServer $_.NormalizedDataSource | Out-Null
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
	Write-Host "===== Read IIS PW ===== $(Get-Date)" -Fore Yellow

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
	# version DLL File
	$sb = {
		Add-PSSnapIn Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null;
		$ver = (Get-SPFarm).BuildVersion.Major;
		[System.Diagnostics.FileVersionInfo]::GetVersionInfo("C:\Program Files\Common Files\microsoft shared\Web Server Extensions\$ver\ISAPI\Microsoft.SharePoint.dll") | select FileVersion,@{N='PC'; E={$env:computername}}
	}
	LoopRemoteCmd "Get file version on " $sb
	
	# version Max Patch
	$maxv = 0
	$f = Get-SPFarm
	$p = Get-SPProduct
	foreach ($u in $p.PatchableUnitDisplayNames) {
		$n = $_
		$v = ($p.GetPatchableUnitInfoByDisplayName($n).patches | sort version -desc)[0].version
		if (!$maxv) {$maxv = $v}
		if ($v -gt $maxv) {$maxv = $v}
	}
	Write-Host "SKU Product Max Ver = $maxv"
	Write-Host "SKU Farm Ver = $($f.BuildVersion)"
	
	# open Central Admin
	$ca = (Get-SPWebApplication -IncludeCentralAdministration) |? {$_.IsAdministrationWebApplication}
	$pages = @("PatchStatus.aspx","UpgradeStatus.aspx","FarmServers.aspx")
	$pages |% {start ($ca.Url + "_admin/" + $_)}
}

Function IISStart() {
	# start IIS pools and sites
	$sb = {
        Import-Module WebAdministration

        # IISAdmin
        $iisadmin = Get-Service IISADMIN
        if ($iisadmin) {
			Set-Service -Name $iisadmin -StartupType Automatic -ErrorAction SilentlyContinue
			Start-Service $iisadmin -ErrorAction SilentlyContinue
		}

        # W3WP
		Start-Service w3svc | Out-Null
		Get-ChildItem IIS:\AppPools |% {$n=$_.Name; Start-WebAppPool $n | Out-Null}
		Get-WebSite | Start-WebSite | Out-Null
	}
	LoopRemoteCmd "Start IIS on " $sb
}

Function ProductLocal() {
    # sync local SKU binary to config DB
	$sb = {
        Add-PSSnapIn Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null
        Get-SPProduct -Local
	}
	LoopRemoteCmd "Product local SKU on " $sb
}

Function UpgradeContent() {
	Write-Host "===== Upgrade Content Databases ===== $(Get-Date)" -Fore Yellow
	
	# Tracking table - assign DB to server
	$maxWorkers = 4
	$track = @()
	$servers = Get-SPServer |? {$_.Role -eq "Application"}
	$dbs = Get-SPContentDatabase
	$i = 0
	foreach ($db in $dbs) {
		# Assign to SPServer
		$mod = $i % $servers.count
		$pc = $servers[$mod].Address
		
		# Collect
		$obj = New-Object -TypeName PSObject -Prop (@{"Name"=$db.Name;"Id"=$db.Id;"UpgradePC"=$pc;"JID"=0;"Status"="New"})
		$track += $obj
		$i++
	}
	$track |ft -a

	# Clean up
	Get-PSSession | Remove-PSSession
	Get-Job | Remove-Job
	
	# Open sessions
	foreach ($server in $servers) {
		New-PSSession -ComputerName $server.Address -Credential $global:cred -Authentication CredSSP | Out-Null
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
		foreach ($server in $servers) {
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
					Write-Host $pc -fore green
					Get-PSSession | ft -a
					$session = Get-PSSession |? {$_.ComputerName -like "$pc*"}
					$result = Invoke-Command $remoteCmd -Session $session -AsJob
					$result
					
					# Update DB tracking
					$row.JID = $result.Id
					$row.Status = "InProgress"
				}
				
				# Progress
				$counter = ($track |? {$_.Status -eq "Completed"}).Count
				$prct = [Math]::Round(($counter/$track.Count)*100)
				Write-Progress -Activity "Upgrade database" -Status "$name ($prct %)" -PercentComplete $prct
				$track | ft -a
				Sleep 1
			}
		}

		# Latest counter
		$remain = $track |? {$_.status -ne "Completed" -and $_.status -ne "Failed"}
	} while ($remain)
	Write-Host "===== Upgrade Content Databases DONE ====="
	$track | group status | ft -a
	$track | ft -a
	
	# Clean up
	Get-PSSession | Remove-PSSession
	Get-Job | Remove-Job
}

Function ShowForm() {
	# Load DLL
	[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
	$local = "$root\SPPatchify-Download-CU.csv"
	$csv = Import-Csv $local

	# WinForm
	$form = New-Object System.Windows.Forms.Form
	$form.Text = 'Select Month'
	$form.Size = New-Object System.Drawing.Size(260,180)
	$form.MaximizeBox = $false
	$form.MinimizeBox = $false
	$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle

	# Label
	$lbl = New-Object System.Windows.Forms.Label
	$lbl.Text = "SharePoint month to download. `nPatch files be saved to \media\ folder."
	$lbl.Top = 10
	$lbl.Left = 10
	$lbl.Width = 220
	$form.Controls.Add($lbl)

	# Drop Down
	$selMonth = New-Object System.Windows.Forms.ComboBox
	foreach ($c in ($csv | Sort Year,Month -Desc | Select Year,Month -Unique)) {
		$row = $c.Year + " " + (Get-Culture).DateTimeFormat.GetAbbreviatedMonthName($c.Month)
		if (!$text) {$text = $row}
		$selMonth.Items.add($row) | Out-Null
	}
	$selMonth.Top = 60
	$selMonth.Left = 10
	$selMonth.DropDownStyle  = [System.Windows.Forms.ComboBoxStyle]::DropDownList
	$selMonth.Text = $text
	$form.Controls.Add($selMonth)

	# Button
	$btnOK = New-Object System.Windows.Forms.Button
	$btnOK.Text = "OK"
	$btnOK.Top = 60
	$btnOK.Left = 160
	$btnOK.Width = 80
	$form.Controls.Add($btnOK)

	# Event Handlers
	Function ClickBtnOK() {
		$global:selmonth = $selMonth.Text 
		$form.Close()
	}
	$btnOK.Add_Click({ClickBtnOK})

	# Display form
	$res = $form.ShowDialog()
}

Function GetMonthInt($name) {
	1..12 |% {
		if ($name -eq (Get-Culture).DateTimeFormat.GetAbbreviatedMonthName($_)) {
			return $_
		}
	}
}

Function PatchMenu() {
	try {
		# Download CSV of patches
		$source = "https://raw.githubusercontent.com/spjeff/sppatchify/master/SPPatchify-Download-CU.csv"
		$local = "$root\SPPatchify-Download-CU.csv"
		$wc = New-Object System.Net.Webclient
		$dest = $local.Replace(".csv","-temp.csv")
		$wc.DownloadFile($source, $dest)
		
		# Overwrite if downloaded OK
		Copy-Item $dest $local -Force
		$csv = Import-Csv $local
		
		# Prompt for user choice
		$ver = (Get-SPFarm).BuildVersion.Major
		$ver = "15"
		ShowForm
		
		# SKU scope
		if (Get-Command Get-SPProjectWebInstance -ErrorAction SilentlyContinue) {
			$sku = "PROJ"
		} else {
			$sku = "SP"
		}
		Write-Host "SKU = $sku"
		
		# Warn if Farm is PROJ and media is not
		$files = Get-ChildItem "$root\media\*prj*.exe"
		if ($sku -eq "PROJ" -and !$files) {
			Write-Host "HALT - have Project Server farm and \media\ folder missing PRJ.  Download correct media and try again." -Fore Red
			Stop-Transcript
			Exit
		}
		
		# Halt if have multiple EXE
		$files = Get-ChildItem "$root\media\*.exe"
		if ($files -is [System.Array]) {
			# HALT - multiple EXE found - require clean up before continuing
			$files | Format-Table -AutoSize
			Write-Host "HALT - Multiple EXEs found. Clean up \media\ folder and try again." -Fore Red
			Stop-Transcript
			Exit
		}
		
		# Filter CSV for file names
		$year = $global:selmonth.Split(" ")[0]
		$month = GetMonthInt $global:selmonth.Split(" ")[1]
		$patchFiles = $csv |? {$_.Year -eq $year -and $_.Month -eq $month -and $_.Product -eq "$sku$ver"}
		$patchFiles | ft -a
		
		# Download patch media
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
	} catch {
		# Error downloading
		Write-Host "Error - Unable to download.  Please verify proxy server and Internet connection." -Fore Red
	}
}

Function DownloadMedia() {
	# Already have media?  Then skip
	$files = Get-ChildItem "$root\media\*.exe"
	if (!$files)	 {
		# Download media
		PatchMenu
	} else {
		Write-Host "Using EXE files found in \media\.  `nTo trigger download GUI first delete these files and run script again."		
		$files |Format-Table -Auto
	}
}
#endregion

Function Main() {
	# Start time
	$start = Get-Date
	$when = $start.ToString("yyyy-MM-dd-hh-mm-ss")
	$logFile = "$root\log\SPPatchify-$when.txt"
	mkdir "$root\log" -ErrorAction SilentlyContinue | Out-Null
	Start-Transcript $logFile
	
	# Params
	Write-Host "copyOnly = $copyOnly"
	Write-Host "phaseTwo = $phaseTwo"

	# Local farm
	(Get-SPFarm).BuildVersion
	$servers = Get-SPServer |? {$_.Role -ne "Invalid"} | Sort Address

	# Core steps
	if (!$phaseTwo) {
		if ($downloadOnly) {
			# CMD switch -D (download only)
			PatchMenu
		} else {
			if ($copyOnly) {
				# CMD switch -C (copy only)
				CopyEXE "Copy"
			} else {
				# Phase One - patch EXE
				DownloadMedia
				EnablePSRemoting
				ReadIISPW
				CopyEXE "Copy"
				ChangeDC
				ChangeServices $false
				IISStart
				StartEXE
				WaitEXE
				WaitReboot
				LocalReboot
			}
		}
	} else {
		# CMD switch -P (phase two) - SP Config Wizard
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
	Write-Host "===== DONE ===== $(Get-Date)" -Fore Yellow
	$th = [Math]::Round(((Get-Date) - $start).TotalHours, 2)
	Write-Host "Duration Hours: $th" -Fore Yellow
	
	# Add both Phase one and two
	$regHive = "HKCU:\Software"
	$regKey = "SPPatchify"
	$regName = "PhaseOneTotalHours"
	if (!$phaseTwo) {
		# create Regkey
		New-Item -Path $regHive -Name "$regKey" -ErrorAction SilentlyContinue | Out-Null
		New-ItemProperty -Path "$regHive\$regKey" -Name "$regName" -Value $th -ErrorAction SilentlyContinue | Out-Null
	} else {
		$h = [double]((Get-ItemProperty -Path "$regHive\$regKey")."$regName")
		$h += $th
		Write-Host "TOTAL Hours (Phase One and Two): $h" -Fore Yellow
		Remove-Item -Path "$regHive\$regKey" -ErrorAction SilentlyContinue | Out-Null
	}
	
	Stop-Transcript
}

Main