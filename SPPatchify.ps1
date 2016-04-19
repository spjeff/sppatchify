Add-PSSnapIn Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null

Function CopyEXE() {
	# Loop servers
	$counter = 0
	foreach ($server in $servers) {
		# Progress
		$addr = $server.Address
		Write-Progress -Activity "Copy EXE to " -Status $addr -PercentComplete (($counter/$servers.Count)*100)
		$counter++
		
		# Skip current machine
		if ($addr -ne $env:computername) {
			# Copy
			$files = Get-ChildItem ".\media\*.*"
			foreach ($file in $files) {
				$name = $file.Name
				$dest = "\\$addr\C$\SPPatchify\media"
				mkdir $dest -Force -ErrorAction SilentlyContinue | Out-Null
				ROBOCOPY "media" $dest /Z /W:0 /R:0 /XX
			}
		}
	}
	Write-Progress -Activity "Completed" -Completed
}

Function StartEXE() {
	# Build CMD
	$files = Get-ChildItem ".\media\*.exe"
	if ($files -is [System.Array]) {
		$name = $files[0].Name
	} else {
		$name = $files.Name
	}
	$cmd = "C:\SPPatchify\media\$name /quiet /passive /forcerestart /log:""C:\SPPatchify\$name.log"""
	LoopRemoteCmd "Run EXE on " $cmd
}

Function WaitReboot() {
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

Function ChangeServices($state) {
	# Logic core
	if ($state) {
		$action = "START"
		$scriptBlock = {
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
		$scriptBlock = {
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
	$ssa = get-spenterprisesearchserviceapplication 
	if ($state) {
		$ssa.resume()
	} else {
		$ssa.pause()
	}
	
	LoopRemoteCmd "$action services on " $scriptBlock
}

Function RunConfigWizard() {
	# Build CMD
	$ver = (Get-SPFarm).BuildVersion.Major;
	#REM $configWizard = """C:\Program Files\Common Files\microsoft shared\Web Server Extensions\$ver\BIN\psconfig.exe"" -cmd upgrade -inplace b2b -wait -cmd applicationcontent -install -cmd installfeatures -cmd secureresources}"
	$configWizard = "& 'C:\Program Files\Common Files\microsoft shared\Web Server Extensions\$ver\BIN\psconfig.exe' -cmd upgrade -inplace b2b -wait"
	#REM $configWizard = "C:\Progra~1\Common~1\micro~1\Web Server Extensions\$ver\BIN\psconfig.exe -cmd upgrade -inplace b2b -wait"
	LoopRemoteCmd "Run Config Wizard on " $configWizard
}

Function LoopRemoteCmd($msg, $cmd) {


	# Loop servers
	$counter = 0
	foreach ($server in $servers) {
		# Script block
		if ($cmd.GetType().Name -eq "String") {
			if ($env:computername -eq $server.Address) {
				$cmd = $cmd -replace "forcerestart","norestart"
			}
			$sb = [ScriptBlock]::Create("$cmd")
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
		$sb.ToString()
		Invoke-Command -Session $remote -ScriptBlock $sb
		Write-Host "<< complete on $addr" -Fore Green
	}
	Get-PSSession | Remove-PSSession
	Write-Progress -Activity "Completed" -Completed	
}

Function ChangeContent($state) {
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
		
			Mount-SPContentDatabase -WebApplication $_."`$wa" -Name $name -DatabaseServer $_.NormalizedDataSource
		}
	}
}

Function ReadIISPW {
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

Function Main() {
	# Transcript and start time

	# Local farm scope
	$servers = Get-SPServer |? {$_.Role -ne "Invalid"}
	$when = (Get-Date).ToString("yyyy-MM-dd-hh-mm-ss")
	
	# Steps
	Write-Host "===== Read IIS PW =====" -Fore Yellow
	ReadIISPW
	
	# Steps
	Write-Host "===== CopyEXE =====" -Fore Yellow
	CopyEXE
	
	Write-Host "===== ChangeServices OFF =====" -Fore Yellow
	ChangeServices $false
	
	Write-Host "===== StartEXE =====" -Fore Yellow
	StartEXE
	
	Write-Host "===== WaitReboot =====" -Fore Yellow
	WaitReboot
	
	Write-Host "===== ContentDB OFF =====" -Fore Yellow
	ChangeContent $false
	
	Write-Host "===== RunConfigWizard =====" -Fore Yellow
	RunConfigWizard
	
	Write-Host "===== ContentDB ON =====" -Fore Yellow
	ChangeContent $true
	
	Write-Host "===== ChangeServices ON =====" -Fore Yellow
	ChangeServices $true
	
	Write-Host "===== DONE =====" -Fore Yellow
	
	# Run duration time
}

Main