Function CopyEXE($servers) {
	# Loop servers
	$counter = 0
	foreach ($server in $servers) {
		# Progress
		Write-Progress -Activity "Copy EXE to " -Status $server -PercentComplete (($counter/$servers.Count)*100)
		$counter++
		
		# Copy
		$files = Get-ChildItem ".\SPPatchify\*.*"
		foreach ($file in $files) {
			$name = $file.Name
			$dest = "\\$server\C$\SPPatchify"
			mkdir $dest -Force -ErrorAction SilentlyContinue | Out-Null
			Copy-Item $file.FullName "$dest\$name"
		}
	}
	Write-Progress -Activity "Completed" -Completed
}

Function StartEXE($servers) {
	# Build CMD
	$files = Get-ChildItem ".\SPPatchify\*.exe"
	if ($files -is [System.Array]) {
		$name = $files[0].Name
	} else {
		$name = $files.Name
	}
	$cmd = "C:\SPPatchify\$name /quiet /passive /forcerestart /log:""C:\SPPatchify\$name.log"""
	LoopRemoteCmd "Run EXE on " $cmd
}

Function WaitReboot($servers) {
	# Wait for reboot
	$counter = 0
	foreach ($server in $servers) {
		# Progress
		Write-Progress -Activity "Waiting for " -Status $server -PercentComplete (($counter/$servers.Count)*100)
		$counter++
		
		# Remote Posh
		while (!$remote) {
			$remote = New-PSSession -ComputerName $server
			Sleep 30
			Write-Host "Wait 30 sec..."
		}
	}
}

Function ChangeServices($state) {			
	# Logic core
	if ($state) {
		$scriptBlock = {
			Set-Service -Name IISAdmin -StartupType Automatic
			Set-Service -Name SPTimerV4 -StartupType Automatic
			Start-Service IISAdmin
			Start-Service SPTimerV4
			Start-Process 'iisreset.exe' -ArgumentList '/start' -Wait -PassThru -NoNewWindow
		}
	} else {
		$scriptBlock = {
			Start-Process 'iisreset.exe' -ArgumentList '/stop' -Wait -PassThru -NoNewWindow
			Set-Service -Name IISAdmin -StartupType Disabled
			Set-Service -Name SPTimerV4 -StartupType Disabled
			Stop-Service IISAdmin
			Stop-Service SPTimerV4
		}
	}
	LoopRemoteCmd "$action services on " $scriptBlock
}

Function RunConfigWizard($servers) {
	# Build CMD
	$configWizard = "$cmd = 'psconfig.exe -cmd upgrade -inplace b2b -wait -cmd applicationcontent -install -cmd installfeatures -cmd secureresources'; $p = Start-Process $cmd -Wait -PassThru -NoNewWindow"
	LoopRemoteCmd "Run Config Wizard on " $configWizard
}

Function LoopRemoteCmd($msg, $cmd) {
	# Script block
	if ($cmd.GetType().Name -eq "String") {
		$sb = [scriptblock]::Create("$cmd")
	} else {
		$sb = $cmd
	}

	# Loop servers
	$counter = 0
	foreach ($server in $global:servers) {
		# Progress
		Write-Progress -Activity $msg -Status $server -PercentComplete (($counter/$servers.Count)*100)
		$counter++
		
		# Remote Posh
		$remote = New-PSSession -ComputerName $server
		Invoke-Command -Session $remote -ScriptBlock $sb
	}
	Write-Progress -Activity "Completed" -Completed	
}

Function Main() {
	# Local farm scope
	$global:servers = Get-SPServer |? {$_.Role -ne "Invalid"}

	# Steps
	CopyEXE $servers
	ChangeServices $servers $false
	StartEXE $servers
	WaitReboot $servers
	RunConfigWizard $servers
	ChangeServices $servers $true
}