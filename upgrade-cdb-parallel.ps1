# Tracking table - assign DB to server
$maxWorkers = 2
$servers = @("srv1", "srv2", "srv3", "srv4")
$track = @()
$dbs = 1..20
$i = 0
$dbs |% {
	$name = "db$_"
	$mod = $i % $servers.count
	$pc = $servers[$mod]
	$obj = New-Object -TypeName PSObject -Prop (@{"DBName"=$name;"UpgradePC"=$pc;"PID"=0;"Status"=0})
	$track += $obj
	$i++
}


# Monitor and Run loop
$remain = ($track |? {$_.Status -eq 0}).count
while ($remain -gt 0) {
	$active = $track |? {$_.Status -eq 1}
	foreach ($db in $active) {
		# Monitor remote server PID
		$proc = get-process -id $db.PID -computername $db.UpgradePC
		if (!$proc) {
			# Update DB tracking - Complete [2]
			$db.Status = 2
		}
	}
	
	# Ensure workers are active
	foreach ($server in $servers) {
		# Count active workers per server - In Progress [1]
		$active = $track |? {$_.Status -eq 1 -and $_.UpgradePC -eq $server}
		$session = New-PSSession -ComputerName $server -Credential $c
		if ($active.count -lt $maxWorkers) {
		
			# Choose next available DB - Not Started [0]
			$avail = $track |? {$_.Status -eq 0 -and $_.UpgradePC -eq $server}
			if ($avail) {
			
				# Kick off new worker
				$availName = $avail[0].DBName
				$remoteCmd = {
				
					# Define command
					$sb = {
						sleep 5
						get-service | out-file "c:\temp\out-$availName.txt"
					}
					
					# Define process
					$cmd = New-Object System.Diagnostics.ProcessStartInfo
					$cmd.FileName = "powershell.exe"
					$cmd.Arguments = "-noprofile -command $sb"
					[System.Diagnostics.Process]::Start($cmd)
				}
				
				# Run on remote server
				$result = Invoke-Command $remoteCmd -Session $session
				
				# Update DB tracking - In Progress [1]
				$avail[0].PID = $result.Id
				$avail[0].Status = 1
			}
		}
	}

	# Latest counter
	Sleep 1
	$remain = ($track |? {$_.status -eq 0}).count
}