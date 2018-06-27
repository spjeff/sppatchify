<#
.SYNOPSIS
	SharePoint Central Admin - View active services across entire farm. No more select machine drop down dance!
.DESCRIPTION
	Apply CU patch to entire farm from one PowerShell console.
	
	NOTE - must run local to a SharePoint server under account with farm admin rights.

	Comments and suggestions always welcome!  spjeff@spjeff.com or @spjeff
.NOTES
	File Namespace	: SPPatchify.ps1
	Author			: Jeff Jones - @spjeff
	Version			: 0.105
	Last Modified	: 06-27-2018
.LINK
	Source Code
	http://www.github.com/spjeff/sppatchify
	https://www.spjeff.com/2016/05/16/sppatchify-cu-patch-entire-farm-from-one-script/
	
	Patch Notes
	http://sharepointupdates.com
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $False, ValueFromPipeline = $false, HelpMessage = 'Use -d -downloadMediaOnly to execute Media Download only.  No farm changes.  Prep step for real patching later.')]
    [Alias("d")]
    [switch]$downloadMediaOnly,
    [string]$downloadVersion,

    [Parameter(Mandatory = $False, ValueFromPipeline = $false, HelpMessage = 'Use -c -copyMediaOnly to copy \media\ across all peer machines.  No farm changes.  Prep step for real patching later.')]
    [Alias("c")]
    [switch]$copyMediaOnly,

    [Parameter(Mandatory = $False, ValueFromPipeline = $false, HelpMessage = 'Use -v -showVersion to show farm version info.  READ ONLY, NO SYSTEM CHANGES.')]
    [Alias("v")]
    [switch]$showVersion,	
	
    [Parameter(Mandatory = $False, ValueFromPipeline = $false, HelpMessage = 'Use -phaseOneBinary to execute Phase One only (run binary)')]
    [switch]$phaseOneBinary,

    [Parameter(Mandatory = $False, ValueFromPipeline = $false, HelpMessage = 'Use -phaseTwo to execute Phase Two after local reboot.')]
    [switch]$phaseTwo,

    [Parameter(Mandatory = $False, ValueFromPipeline = $false, HelpMessage = 'Use -phaseThree to execute Phase Three attach and upgrade content.')]
    [switch]$phaseThree,
	
    [Parameter(Mandatory = $False, ValueFromPipeline = $false, HelpMessage = 'Use -o -onlineContent to keep content databases online.  Avoids Dismount/Mount.  NOTE - Will substantially increase patching duration for farms with more user content.')]
    [Alias("o")]
    [switch]$onlineContent,

    [Parameter(Mandatory = $False, ValueFromPipeline = $false, HelpMessage = 'Use -remoteSessionPort to open PSSession (remoting) with custom port number.')]
    [string]$remoteSessionPort,

    [Parameter(Mandatory = $False, ValueFromPipeline = $false, HelpMessage = 'Use -remoteSessionSSL to open PSSession (remoting) with SSL encryption.')]
    [switch]$remoteSessionSSL,

    [Parameter(Mandatory = $False, ValueFromPipeline = $false, HelpMessage = 'Use -test to open Remote PS Session and verify connectivity all farm members.')]
    [switch]$testRemotePowershell,

    [Parameter(Mandatory = $False, ValueFromPipeline = $false, HelpMessage = 'Use -skipProductLocal to run Phase One binary without Get-SPProduct -Local.')]
    [switch]$skipProductLocal
)

# Plugin
Add-PSSnapIn Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null
Import-Module WebAdministration -ErrorAction SilentlyContinue | Out-Null

# Version
if ($phaseTwo) {
    $phase = "-phaseTwo"
}
if ($phaseThree) {
    $phase = "-phaseThree"
}
$host.ui.RawUI.WindowTitle = "SPPatchify v0.99 $phase"
$rootCmd = $MyInvocation.MyCommand.Definition
$root = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$stages = @("CopyEXE", "StopSvc", "RunEXE", "StartSvc", "ProdLocal", "ConfigWiz")

# Remote UNC
$char = $root.ToCharArray()
if ($char[1] -eq ':') {
    $char[1] = '$'
}
$remoteRoot = -join $char

#region binary EXE
function CopyEXE($action) {
    Write-Host "===== $action EXE ===== $(Get-Date)" -Fore "Yellow"
	
    # Clear old session
    Get-Job | Remove-Job
    Get-PSSession | Remove-PSSession

    # Start Jobs
    foreach ($server in $global:servers) {
        $addr = $server.Address
        if ($addr -ne $env:computername) {
            # Dynamic command
			$dest = "\\$addr\$remoteRoot\media"
			mkdir $dest -Force -ErrorAction SilentlyContinue | Out-Null;
            ROBOCOPY ""$root\media"" ""$dest"" /Z /MIR /W:0 /R:0
        }
    }

    # Watch Jobs
    Start-Sleep 5
    $coll = newStatus("CopyEXE")
    $coll | Format-Table -AutoSize

    $counter = 0
    do {
        foreach ($server in $global:servers) {
            # Progress
            if (Get-Job) {
                $prct = [Math]::Round(($counter / (Get-Job).Count) * 100)
                if ($prct) {
                    Write-Progress -Activity "Copy EXE ($prct %) $(Get-Date)" -Status $addr -PercentComplete $prct -ErrorAction SilentlyContinue
                }
            }
			
            # GUI In Progress
            ($coll |Where-Object {$_.Server -eq $server.Address}).CopyEXE = 1
            displayStatus $coll
			
            # Check Job Status
            foreach ($job in Get-Job) {
                Get-Job | Format-Table -AutoSize
                if ($job.State -ne "Running") {
                    # GUI Done
                    $addr = $job.Command.Split(";")[0].Replace("#", "")
                    ($coll | Where-Object {$_.Server -eq $addr}).CopyEXE = 2
                    displayStatus $coll
                }
            }
			
        }
        Start-Sleep 5
        $pending = Get-Job |Where-Object {$_.State -eq "Running" -or $_.State -eq "NotStarted"}
        $counter = (Get-Job).Count - $pending.Count
    }
    while ($pending)

    # Complete
    Get-Job | Format-Table -a
    $coll | ForEach-Object {$_.CopyEXE = 2}
    displayStatus $coll
    Write-Progress -Activity "Completed $(Get-Date)" -Completed
}

function SafetyInstallRequired() {
    # Display server upgrade
    Write-Host "Farm Servers - Upgrade Status " -Fore "Yellow"
    (Get-SPProduct).Servers | Select-Object Servername, InstallStatus | Sort-Object Servername | Format-Table -AutoSize
	
    $halt = (Get-SPProduct).Servers |Where-Object {$_.InstallStatus -eq "InstallRequired"}
    if ($halt) {
        $halt | Format-Table -AutoSize
        Write-Host "HALT - MEDIA ERROR - Install on servers" -Fore Red
        Exit
    }
}

function SafetyEXE() {
    Write-Host "===== SafetyEXE ===== $(Get-Date)" -Fore "Yellow"

    # Count number of files.   Must be 3 for SP2013 (major ver 15)

    # Build CMD
    $ver = (Get-SPFarm).BuildVersion.Major
    if ($ver -eq 15) {
        foreach ($server in $global:servers) {
            $addr = $server.Address
            $c = (Get-ChildItem "\\$addr\$remoteRoot\media").Count
            if ($c -ne 3) {
                $halt = $true
                Write-Host "HALT - MEDIA ERROR - Expected 3 files on \\$addr\$remoteRoot\media" -Fore Red
            }
        }

        # Halt
        if ($halt) {
            Exit
        }
    }
}

function RunEXE() {
    Write-Host "===== RunEXE ===== $(Get-Date)" -Fore "Yellow"
    $coll = newStatus("RunEXE")
    displayStatus $coll
    
    # Remove MSPLOG
    LoopRemoteCmd "Remove MSPLOG on " "Remove-Item '$root\log\*MSPLOG*' -Confirm:`$false -ErrorAction SilentlyContinue"
	
    # Remove MSPLOG
    LoopRemoteCmd "Unblock EXE on " "gci '$root\media\*' | Unblock-File -Confirm:`$false -ErrorAction SilentlyContinue"
	
    # Build CMD
    $files = Get-ChildItem "$root\media\*.exe" | Sort-Object Name
    foreach ($f in $files) {
        # Display patch name
        $name = $f.Name
        Write-Host $name -Fore Yellow
        $patchName = $name.replace(".exe", "")
        $cmd = "$root\media\$name"
        $params = "/passive /forcerestart /log:""$root\log\$name.log"""
        $taskName = "SPPatchify"

        # Loop - Run Task Scheduler
        foreach ($server in $global:servers) {
            # Local PC - No reboot
            if ($server.Address -eq $env:computername) {
                $params = $params.Replace("forcerestart", "norestart")
            }

            # Remove SCHTASK if found
            $addr = $server.Address
            $found = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue -CimSession $addr
            if ($found) {
                $found | Unregister-ScheduledTask -Confirm:$false -CimSession $addr
            }

            # New SCHTASK parameters
            $user = "System"
            $folder = Split-Path $f
            $a = New-ScheduledTaskAction -Execute $cmd -Argument $params -WorkingDirectory $folder -CimSession $addr
            $p = New-ScheduledTaskPrincipal -RunLevel Highest -UserId $user -LogonType S4U

            # Create SCHTASK
            Write-Host "Register and start SCHTASK - $addr - $cmd" -Fore Green
            Register-ScheduledTask -TaskName $taskName -Action $a -Principal $p
            Start-ScheduledTask -TaskName $taskName -CimSession $addr
        }
            
        # Loop - Wait and check status
        foreach ($server in $global:servers) {
            $addr = $server.Address
            Write-Host "Monitor SCHTASK - $addr " -Fore Yellow
            do {
                Write-Host "." -NoNewLine
                Start-Sleep 5
                $state = $null
                $job = Get-ScheduledTask -TaskName $taskName -CimSession $addr
                if ($job) {
                    $state = $job.State
                }
            } while ($state -eq "Running")
        }
    }
	
    # SharePoint 2016 Force Reboot
    if ($ver -eq 16) {
        foreach ($server in $global:servers) {
            if ($server.Address -ne $env:computername) {
                Write-Host "Reboot $($server.Address)" -Fore Yellow
                Restart-Computer -ComputerName $server.Address
            }
        }
    }
}

function WaitEXE($patchName) {
    Write-Host "===== WaitEXE ===== $(Get-Date)" -Fore "Yellow"
	
    # Wait for reboot
    Write-Host "Wait 60 sec..."
    Start-Sleep 60

    # Verify machines online
    $counter = 0
    if ($global:servers) {
        foreach ($server in $global:servers) {	
            # Progress
            $addr = $server.Address
            $prct = [Math]::Round(($counter / $global:servers.Count) * 100)
            if ($prct) {
                Write-Progress -Activity "Wait EXE ($prct %) $(Get-Date)" -Status $addr -PercentComplete $prct
            }
            $counter++
            
            # Remote Posh
            Write-Host "`nEXE monitor started on $addr at $(Get-Date) " -NoNewLine
            do {
                # Monitor EXE process
                $proc = Get-Process -Name $patchName -Computer $addr -ErrorAction SilentlyContinue
                Write-Host "." -NoNewLine
                Start-Sleep 5

                # Measure EXE
                $stats = $proc | Select-Object Id, HandleCount, WorkingSet, PrivateMemorySize
                
                # Count MSPLOG files
                $cmd = "`$f=Get-ChildItem ""$root\log\*MSPLOG*"";`$c=`$f.count;`$l=(`$f|sort last -desc|select -first 1).LastWriteTime;`$s=`$env:computername;New-Object -TypeName PSObject -Prop (@{""Server""=`$s;""Count""=`$c;""LastWriteTime""=`$l})"
                $sb = [Scriptblock]::Create($cmd)
                $result = Invoke-Command -Session (Get-PSSession) -ScriptBlock $sb
                $msp = $result | Select-Object Server, @{n = "MSPCount"; e = {$_.Count}}, LastWriteTime | Sort-Object LastWriteTime, Server -Desc
                
                # HTML view
                $coll = newStatus("RunEXE")
                ($coll |Where-Object {$_.Server -eq $addr}).RunEXE = 1
                displayStatus $coll $false $false $msp $stats
            }
            while ($proc)
        }
    }
}

function WaitReboot() {
    Write-Host "`n===== WaitReboot ===== $(Get-Date)" -Fore "Yellow"
	
    # Wait for farm peer machines to reboot
    Write-Host "Wait 60 sec..."
    Start-Sleep 60
	
    # Clean up
    Get-PSSession | Remove-PSSession
	
    # Verify machines online
    $counter = 0
    foreach ($server in $global:servers) {
        # Progress
        $addr = $server.Address
        Write-Host $addr -Fore Yellow
        if ($addr -ne $env:COMPUTERNAME) {
            $prct = [Math]::Round(($counter / $global:servers.Count) * 100)
            if ($prct) {
                Write-Progress -Activity "Waiting for machine ($prct %) $(Get-Date)" -Status $addr -PercentComplete $prct
            }
            $counter++
		
            # Remote PowerShell session
            do {
                # Dynamic open PSSession
                if ($remoteSessionPort -and $remoteSessionSSL) {
                    $remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Credssp -Port $remoteSessionPort -UseSSL
                }
                elseif ($remoteSessionPort) {
                    $remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Credssp -Port $remoteSessionPort
                }
                elseif ($remoteSessionSSL) {
                    $remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Credssp -UseSSL
                }
                else {
                    $remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Credssp
                }


                # Display
                Write-Host "."  -NoNewLine
                Start-Sleep 5
            }
            while (!$remote)
        }
    }
	
    # Clean up
    Get-PSSession | Remove-PSSession
}

function LocalReboot() {
    # Create Regkey
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\" -Name "RunOnce" -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "SPPatchify" -Value "PowerShell -executionpolicy unrestricted -file ""$root\SPPatchify.ps1"" -PhaseTwo" -ErrorAction SilentlyContinue | Out-Null
	
    # Reboot
    Write-Host "`n ===== REBOOT LOCAL ===== $(Get-Date)"
    $th = [Math]::Round(((Get-Date) - $start).TotalHours, 2)
    Write-Host "Duration Total Hours: $th" -Fore "Yellow"
    Stop-Transcript
    Start-Sleep 5
    Restart-Computer -Force
    Exit
}
function LaunchPhaseThree() {
    # Launch script in new windows for Phase Three - Add Content
    Start-Process "powershell.exe" -ArgumentList "$root\SPPatchify.ps1 -PhaseThree"
}
function CalcDuration() {
    Write-Host "===== DONE ===== $(Get-Date)" -Fore "Yellow"
    $totalHours = [Math]::Round(((Get-Date) - $start).TotalHours, 2)
    Write-Host "Duration Hours: $totalHours" -Fore "Yellow"
    $c = (Get-SPContentDatabase).Count
    Write-Host "Content Databases Online: $c"
	
    # Add both Phase one and two
    $regHive = "HKCU:\Software"
    $regKey = "SPPatchify"
    if (!$phaseTwo) {
        # Create Regkey
        New-Item -Path $regHive -Name "$regKey" -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path "$regHive\$regKey" -Name "PhaseOneTotalHours" -Value $totalHours -ErrorAction SilentlyContinue | Out-Null
    }
    else {
        # Read Regkey
        $key = Get-ItemProperty -Path "$regHive\PhaseOneTotalHours" -ErrorAction SilentlyContinue
        if ($key) {
            $totalHours += [double]($key."PhaseOneTotalHours")
        }
        Write-Host "TOTAL Hours (Phase One and Two): $totalHours" -Fore "Yellow"
        Remove-Item -Path "$regHive\$regKey" -ErrorAction SilentlyContinue | Out-Null
    }
}
function FinalCleanUp() {
    # Loop - Run Task Scheduler
    foreach ($server in $global:servers) {
        $addr = $server.Address
        $found = Get-ScheduledTask -TaskName "SPPatchify" -ErrorAction SilentlyContinue -CimSession $addr
        if ($found) {
            $found | Unregister-ScheduledTask -Confirm:$false -CimSession $addr
        }
    }
    Remove-Item "$root\sppatchify-status.html" -Confirm:$false -Force -ErrorAction SilentlyContinue | Out-Null
    Stop-Transcript
    CloseIE
}
#endregion

#region SP Config Wizard
function LoopRemotePatch($msg, $cmd, $params) {
    if (!$cmd) {
        return
    }

    # Clean up
    Get-PSSession | Remove-PSSession
	
    # GUI
    $stage = "RunEXE"
    if ($stage) {
        $coll = newStatus($stage)
    }
	
    # Loop servers
    $counter = 0
    foreach ($server in $global:servers) {
        # Overwrite restart parameter
        $ver = (Get-SPFarm).BuildVersion.Major
        if ($ver -eq 16 -or $env:computername -eq $server.Address) {
            $cmd = $cmd.replace("forcerestart", "norestart")
        }

        # Script block
        if ($cmd.GetType().Name -eq "String") {
            $sb = [ScriptBlock]::Create($cmd)
        }
        else {
            $sb = $cmd
        }
	
        # Progress
        $addr = $server.Address
        $prct = [Math]::Round(($counter / $global:servers.Count) * 100)
        if ($prct) {
            Write-Progress -Activity $msg -Status "$addr ($prct %) $(Get-Date)" -PercentComplete $prct
        }
        $counter++
		
        # GUI - In Progress
        if ($stage) {
            ($coll |Where-Object {$_.Server -eq $server.Address})."$stage" = 1
            displayStatus $coll
        }
		
        # Remote Posh
        Write-Host ">> invoke on $addr" -Fore "Green"
		
        # Dynamic open PSSession
        if ($remoteSessionPort -and $remoteSessionSSL) {
            $remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Credssp -Port $remoteSessionPort -UseSSL
        }
        elseif ($remoteSessionPort) {
            $remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Credssp -Port $remoteSessionPort
        }
        elseif ($remoteSessionSSL) {
            $remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Credssp -UseSSL
        }
        else {
            $remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Credssp
        }

        # Invoke
        Start-Sleep 3
        foreach ($s in $sb) {
            Write-Host $s.ToString()
            if ($remote) {
                Invoke-Command -Session $remote -ScriptBlock $s
            }
        }
        Write-Host "<< complete on $addr" -Fore "Green"
		
        # GUI - Done
        if ($stage) {
            ($coll |Where-Object {$_.Server -eq $server.Address})."$stage" = 2
            displayStatus $coll
        }
    }
    Write-Progress -Activity "Completed $(Get-Date)" -Completed	
}
function LoopRemoteCmd($msg, $cmd) {
    if (!$cmd) {
        return
    }

    # Clean up
    Get-PSSession | Remove-PSSession
	
    # GUI
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
        Write-Host $server.Address -Fore Yellow

        # Script block
        if ($cmd.GetType().Name -eq "String") {
            $sb = [ScriptBlock]::Create($cmd)
        }
        else {
            $sb = $cmd
        }
	
        # Progress
        $addr = $server.Address
        $prct = [Math]::Round(($counter / $global:servers.Count) * 100)
        if ($prct) {
            Write-Progress -Activity $msg -Status "$addr ($prct %) $(Get-Date)" -PercentComplete $prct
        }
        $counter++
		
        # GUI - In Progress
        if ($stage) {
            ($coll |Where-Object {$_.Server -eq $server.Address})."$stage" = 1
            displayStatus $coll
        }
		
        # Remote Posh
        Write-Host ">> invoke on $addr" -Fore "Green"
        
        # Dynamic open PSSesion
        if ($remoteSessionPort -and $remoteSessionSSL) {
            $remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Credssp -Port $remoteSessionPort -UseSSL
        }
        elseif ($remoteSessionPort) {
            $remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Credssp -Port $remoteSessionPort
        }
        elseif ($remoteSessionSSL) {
            $remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Credssp -UseSSL
        }
        else {
            $remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Credssp
        }

        # Merge script block array
        $mergeSb = $sb
        $mergeCmd = ""
        if ($sb -is [array]) {
            foreach ($s in $sb) {
                $mergeCmd += $s.ToString() + "`n"
            }
            $mergeSb = [Scriptblock]::Create($mergeCmd)
        }
        
        # Invoke
        Start-Sleep 3
        if ($remote) {
            Write-Host $mergeSb.ToString()
            Invoke-Command -Session $remote -ScriptBlock $mergeSb
        }
        Write-Host "<< complete on $addr" -Fore "Green"
		
        # GUI - Done
        if ($stage) {
            ($coll |Where-Object {$_.Server -eq $server.Address})."$stage" = 2
            displayStatus $coll
        }
    }
    Write-Progress -Activity "Completed $(Get-Date)" -Completed	
}

function ChangeDC() {
    Write-Host "===== ChangeDC OFF ===== $(Get-Date)" -Fore "Yellow"

    # Distributed Cache
    $sb = {
        try {
            Use-CacheCluster
            Get-AFCacheClusterHealth -ErrorAction SilentlyContinue
            $computer = [System.Net.Dns]::GetHostByName($env:computername).HostName
            $counter = 0
            $maxLoops = 60
			
            $cache = Get-CacheHost |Where-Object {$_.HostName -eq $computer}
            if ($cache) {
                do {
                    try {
                        # Wait for graceful stop
                        $hostInfo = Stop-CacheHost -Graceful -CachePort 22233 -HostName $computer -ErrorAction SilentlyContinue
                        Write-Host $computer $hostInfo.Status
                        Start-Sleep 5
                        $counter++
                    }
                    catch {
                        break
                    }
                }
                while ($hostInfo -and $hostInfo.Status -ne "Down" -and $counter -lt $maxLoops)
				
                # Force stop
                Add-PSSnapIn Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null
                Stop-SPDistributedCacheServiceInstance
            }
        }
        catch {
        }
    }
    LoopRemoteCmd "Stop Distributed Cache on " $sb
}

function ChangeServices($state) {
    Write-Host "===== ChangeServices $state ===== $(Get-Date)" -Fore "Yellow"
    $ver = (Get-SPFarm).BuildVersion.Major
	
    # Logic core
    if ($state) {
        $action = "START"
        $sb = {
            @("SPAdminV4", "SPTimerV4", "SQLBrowser", "Schedule", "SPInsights") | ForEach-Object {
                if (Get-Service $_ -ErrorAction SilentlyContinue) {
                    Set-Service -Name $_ -StartupType Automatic -ErrorAction SilentlyContinue
                    Start-Service $_ -ErrorAction SilentlyContinue
                }
            }
            @("OSearch$ver", "SPSearchHostController") | ForEach-Object {
                Start-Service $_ -ErrorAction SilentlyContinue
            }
            Start-Process 'iisreset.exe' -ArgumentList '/start' -Wait -PassThru -NoNewWindow | Out-Null
        }
    }
    else {
        $action = "STOP"
        $sb = {
            Start-Process 'iisreset.exe' -ArgumentList '/stop' -Wait -PassThru -NoNewWindow | Out-Null
            @("SPAdminV4", "SPTimerV4", "SQLBrowser", "Schedule", "SPInsights") | ForEach-Object {
                if (Get-Service $_ -ErrorAction SilentlyContinue) {
                    Set-Service -Name $_ -StartupType Disabled -ErrorAction SilentlyContinue
                    Stop-Service $_ -ErrorAction SilentlyContinue
                }
            }
            @("OSearch$ver", "SPSearchHostController") | ForEach-Object {
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
        }
        else {
            $ssa.pause()
        }
    }
    catch {
    }
	
    LoopRemoteCmd "$action services on " $sb
}

function RunConfigWizard() {
    Write-Host "===== RunConfigWizard =====" -Fore Yellow

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
            "psconfig.exe -cmd upgrade -inplace b2b -force" | Out-File $file -Force
        }
    }
    LoopRemoteCmd "Save B2B shortcut on " @($shared, $b2b)
	
    # Run Config Wizard - https://blogs.technet.microsoft.com/stefan_gossner/2015/08/20/why-i-prefer-psconfigui-exe-over-psconfig-exe/
    $wiz = {
        & "$psconfig" -cmd "upgrade" -inplace "b2b" -wait -cmd "applicationcontent" -install -cmd "installfeatures" -cmd "secureresources" -cmd "services" -install
    }
    LoopRemoteCmd "Run Config Wizard on " @($shared, $wiz)
}

function ChangeContent($state) {
    Write-Host "===== ContentDB $state ===== $(Get-Date)" -Fore "Yellow"
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SharePoint") | Out-Null

    if (!$state) {
        # Remove content
        $dbs = Get-SPContentDatabase
        if ($dbs) {
            $dbs | ForEach-Object {$wa = $_.WebApplication.Url; $_ | Select-Object Name, NormalizedDataSource, @{n = "WebApp"; e = {$wa}}} | Export-Csv "$root\log\contentdbs-$when.csv" -NoTypeInformation
            $dbs | ForEach-Object {
                "$($_.Name),$($_.NormalizedDataSource)"
                Dismount-SPContentDatabase $_ -Confirm:$false
            }
        }
    }
    else {
        # Add content
        $files = Get-ChildItem "$root\log\contentdbs-*.csv" | Sort-Object LastAccessTime -Desc
        if ($files -is [Array]) {
            $files = $files[0]
        }
		
        # Loop databases
        if ($files) {
            Write-Host "Content DB - Mount from CSV $($files.Fullname)" -Fore Yellow
            $dbs = Import-Csv $files.Fullname
            $counter = 0
            if ($dbs) {
                $dbs | Where-Object {
                    $name = $_.Name
                    $name
                
                    # Progress
                    $prct = [Math]::Round(($counter / $dbs.Count) * 100)
                    if ($prct) {
                        Write-Progress -Activity "Add database" -Status "$name ($prct %) $(Get-Date)" -PercentComplete $prct
                    }
                    $counter++
            
                    $wa = [Microsoft.SharePoint.Administration.SPWebApplication]::Lookup($_.WebApp)
                    if ($wa) {
                        Mount-SPContentDatabase -WebApplication $wa -Name $name -DatabaseServer $_.NormalizedDataSource | Out-Null
                    }
                }
            }
        }
        else {
            Write-Host "Content DB - CSV not found" -Fore Yellow
        }
    }
}
#endregion

#region general
function EnablePSRemoting() {
    $ssp = Get-WSManCredSSP
    if ($ssp[0] -match "not configured to allow delegating") {
        # Enable remote PowerShell over CredSSP authentication
        Enable-WSManCredSSP -DelegateComputer * -Role Client -Force
        Restart-Service WinRM
    }
}

function ReadIISPW {
    Write-Host "===== Read IIS PW ===== $(Get-Date)" -Fore "Yellow"

    # Current user (ex: Farm Account)
    $domain = $env:userdomain
    $user = $env:username
    Write-Host "Logged in as $domain\$user"
	
    # Start IISAdmin if needed
    $iisadmin = Get-Service IISADMIN
    if ($iisadmin.Status -ne "Running") {
        # Set Automatic and Start
        Set-Service -Name IISADMIN -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service IISADMIN -ErrorAction SilentlyContinue
    }
	
    # Attempt to detect password from IIS Pool (if current user is local admin and farm account)
    Import-Module WebAdministration -ErrorAction SilentlyContinue | Out-Null
    $m = Get-Module WebAdministration
    if ($m) {
        # PowerShell ver 2.0+ IIS technique
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
    }
    else {
        # PowerShell ver 3.0+ WMI technique
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
    }

    # Prompt for password
    if (!$pass) {
        $sec = Read-Host "Enter password: " -AsSecureString
    }
    else {
        $sec = $pass | ConvertTo-SecureString -AsPlainText -Force
    }

    # Save global
    $global:username = $user
    $global:userpass = $pass
    $global:cred = New-Object System.Management.Automation.PSCredential -ArgumentList "$domain\$user", $sec
}

function DisplayCA() {
    # Version DLL File
    $sb = {
        Add-PSSnapIn Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null;
        $ver = (Get-SPFarm).BuildVersion.Major;
        [System.Diagnostics.FileVersionInfo]::GetVersionInfo("C:\Program Files\Common Files\microsoft shared\Web Server Extensions\$ver\ISAPI\Microsoft.SharePoint.dll") | Select-Object FileVersion, @{N = 'PC'; E = {$env:computername}}
    }
    LoopRemoteCmd "Get file version on " $sb
	
    # Display Version
    DisplayVersion
	
    # Open Central Admin
    $ca = (Get-SPWebApplication -IncludeCentralAdministration) | Where-Object {$_.IsAdministrationWebApplication -eq $true}
    $pages = @("PatchStatus.aspx", "UpgradeStatus.aspx", "FarmServers.aspx")
    $pages | ForEach-Object {Start-Process ($ca.Url + "_admin/" + $_)}
}
function DisplayVersion() {
    # Version Max Patch
    $maxv = 0
    $f = Get-SPFarm
    $p = Get-SPProduct
    foreach ($u in $p.PatchableUnitDisplayNames) {
        $n = $u
        $v = ($p.GetPatchableUnitInfoByDisplayName($n).patches | Sort-Object version -desc)[0].version
        if (!$maxv) {
            $maxv = $v
        }
        if ($v -gt $maxv) {
            $maxv = $v
        }
    }

    # Display data
    if ($maxv -eq $f.BuildVersion) {
        Write-Host "Max Product = $maxv" -Fore Green
        Write-Host "Farm Build  = $($f.BuildVersion)" -Fore Green
    } else {
        Write-Host "Max Product = $maxv" -Fore Yellow
        Write-Host "Farm Build  = $($f.BuildVersion)" -Fore Yellow
    }

    # Server status table
    (Get-SPProduct).Servers | Select-Object Servername, InstallStatus | Sort-Object Servername | Format-Table -AutoSize
}
function IISStart() {
    # Start IIS pools and sites
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
        Get-ChildItem "IIS:\AppPools\" | ForEach-Object {$n = $_.Name; Start-WebAppPool $n | Out-Null}
        Get-WebSite | Start-WebSite | Out-Null
    }
    LoopRemoteCmd "Start IIS on " $sb
}

function ProductLocal() {
    # Sync local SKU binary to config DB
    $sb = {
        Add-PSSnapIn Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null
        Get-SPProduct -Local
    }
    LoopRemoteCmd "Product local SKU on " $sb
	
    # Display server upgrade
    Write-Host "Farm Servers - Upgrade Status " -Fore "Yellow"
    (Get-SPProduct).Servers | Select-Object Servername, InstallStatus | Sort-Object Servername | Format-Table -AutoSize
}

function UpgradeContent() {
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
        $obj = New-Object -TypeName PSObject -Prop (@{"Name" = $db.Name; "Id" = $db.Id; "UpgradePC" = $pc; "JID" = 0; "Status" = "New"})
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
        
        # Dynamic open PSSesion
        if ($remoteSessionPort -and $remoteSessionSSL) {
            $remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Credssp -Port $remoteSessionPort -UseSSL
        }
        elseif ($remoteSessionPort) {
            $remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Credssp -Port $remoteSessionPort
        }
        elseif ($remoteSessionSSL) {
            $remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Credssp -UseSSL
        }
        else {
            $remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Credssp
        }
    }

    # Monitor and Run loop
    do {
        # Get latest PID status
        $active = $track |Where-Object {$_.Status -eq "InProgress"}
        foreach ($db in $active) {
            # Monitor remote server job
            if ($db.JID) {
                $job = Get-Job $db.JID
                if ($job.State -eq "Completed") {
                    # Update DB tracking
                    $db.Status = "Completed"
                }
                elseif ($job.State -eq "Failed") {
                    # Update DB tracking
                    $db.Status = "Failed"
                }
                else {
                    Write-host "-" -NoNewline
                }
            }
        }
		
        # Ensure workers are active
        foreach ($server in $global:servers) {
            # Count active workers per server
            $active = $track |Where-Object {$_.Status -eq "InProgress" -and $_.UpgradePC -eq $server.Address}
            if ($active.count -lt $maxWorkers) {
			
                # Choose next available DB
                $avail = $track |Where-Object {$_.Status -eq "New" -and $_.UpgradePC -eq $server.Address}
                if ($avail) {
                    if ($avail -is [array]) {
                        $row = $avail[0]
                    }
                    else {
                        $row = $avail
                    }
				
                    # Kick off new worker
                    $id = $row.Id
                    $name = $row.Name
                    $remoteStr = "`$cmd = New-Object System.Diagnostics.ProcessStartInfo; " + 
                    "`$cmd.FileName = 'powershell.exe'; " + 
                    "`$internal = Add-PSSnapin Microsoft.SharePoint.Powershell -ErrorAction SilentlyContinue | Out-Null; Upgrade-SPContentDatabase -Id $id -Confirm:`$false; " + 
                    "`$cmd.Arguments = '-NoProfile -Command ""$internal""'; " + 
                    "[System.Diagnostics.Process]::Start(`$cmd);"
					
                    # Run on remote server
                    $remoteCmd = [Scriptblock]::Create($remoteStr) 
                    $pc = $server.Address
                    Write-Host $pc -Fore "Green"
                    Get-PSSession | Format-Table -AutoSize
                    $session = Get-PSSession |Where-Object {$_.ComputerName -like "$pc*"}
                    if (!$session) {
                        # Dynamic open PSSession
                        if ($remoteSessionPort -and $remoteSessionSSL) {
                            $session = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Credssp -Port $remoteSessionPort -UseSSL
                        }
                        elseif ($remoteSessionPort) {
                            $session = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Credssp -Port $remoteSessionPort
                        }
                        elseif ($remoteSessionSSL) {
                            $session = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Credssp -UseSSL
                        }
                        else {
                            $session = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Credssp
                        }
                    }
                    $result = Invoke-Command $remoteCmd -Session $session -AsJob
					
                    # Update DB tracking
                    $row.JID = $result.Id
                    $row.Status = "InProgress"
                }
				
                # Progress
                $counter = ($track |Where-Object {$_.Status -eq "Completed"}).Count
                $prct = 0
                if ($track) {
                    $prct = [Math]::Round(($counter / $track.Count) * 100)
                }
                if ($prct) {
                    Write-Progress -Activity "Upgrade database" -Status "$name ($prct %) $(Get-Date)" -PercentComplete $prct
                }
                $track | Format-Table -AutoSize
				
                # GUI
                $msg = "Upgrading Content DB: $name ($prct %) - $counter of $($track.Count)"
                displayStatus $coll ($prct * 3) $msg
                Start-Sleep 3
            }
        }

        # Latest counter
        $remain = $track |Where-Object {$_.status -ne "Completed" -and $_.status -ne "Failed"}
    }
    while ($remain)
    Write-Host "===== Upgrade Content Databases DONE ===== $(Get-Date)"
    $track | Group-Object status | Format-Table -AutoSize
    $track | Format-Table -AutoSize
	
    # GUI
    $msg = "Upgrade Content DB Complete (100 %)"
    displayStatus $coll (100 * 3) $msg
	
    # Clean up
    Get-PSSession | Remove-PSSession
    Get-Job | Remove-Job
}

function ShowMenu($prod) {
    # Choices
    $csv = Import-Csv "$root\SPPatchify-Download-CU.csv" | Select-Object -Property @{n = 'MonthInt'; e = {[int]$_.Month}}, *
    $choices = $csv |Where-Object {$_.Product -eq $prod} | Sort-Object Year, MonthInt -Desc | Select-Object Year, Month -Unique

    # Menu
    Write-Host "Download CU Media to \media\ - $prod" -Fore "Yellow"
    Write-Host "---------"
    $menu = @()
    $i = 0
    $choices | ForEach-Object {
        $n = (getMonth($_.Month)) + " " + ($_.Year)
        $menu += $n
        if ($i -eq 0) {
            $default = $n
            $n += "[default] <=="
            Write-Host "$i $n" -Fore "Green"
        }
        else {
            Write-Host "$i $n"
        }
        $i++
    }

    # Return
    $sel = Read-Host "Select month. Press [enter] for default"
    if (!$sel) {
        $sel = $default
    }
    else {
        $sel = $menu[$sel]
    }
    $global:selmonth = $sel
} 

function GetMonth($mo) {
    # Convert integer to three letter month name
    try {
        $mo = (Get-Culture).DateTimeFormat.GetAbbreviatedMonthName($mo)
    }
    catch {
        return $mo
    }
    return $mo
}

function GetMonthInt($name) {
    # Convert three letter month name to integer
    1 .. 12 | ForEach-Object {
        if ($name -eq (Get-Culture).DateTimeFormat.GetAbbreviatedMonthName($_)) {
            return $_
        }
    }
}
function PatchRemoval() {
    # Remove patch media
    $files = Get-ChildItem "$root\media\*.exe" 
    $files | Format-Table -AutoSize
    $files | Remove-Item -Confirm:$false -Force
}
function PatchMenu() {
    # Ensure folder
    mkdir "$root\media" -ErrorAction SilentlyContinue | Out-Null

    # Skip if we already have media
    $files = Get-ChildItem "$root\media\*.exe"
    if ($files) {
        Write-Host "Using EXE found in \media\.`nTo trigger download GUI first delete \media\ folder and run script again."		
        $files | Format-Table -Auto
        Return
    }

    # Download CSV of patch URLs
    $source = "https://raw.githubusercontent.com/spjeff/sppatchify/master/SPPatchify-Download-CU.csv"
    $local = "$root\SPPatchify-Download-CU.csv"
    $wc = New-Object System.Net.Webclient
    $dest = $local.Replace(".csv", "-temp.csv")
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
    if ($downloadVersion) {
        $ver = $downloadVersion
    }
    if (Get-Command Get-SPFarm -ErrorAction SilentlyContinue) {
        # Local farm
        $farm = Get-SPFarm -ErrorAction SilentlyContinue
        if ($farm) {
            $ver = $farm.BuildVersion.Major
            $sppl = (Get-SPProduct -Local) |Where-Object {$_.ProductName -like "*Microsoft Project*"}
            if ($sppl) {
                if ($ver -ne 16) {
                    $sku = "PROJ"
                }
            }
        }
        else {
            # Detect binary folder - fallback if not joined to farm
            $detect16 = Get-ChildItem "C:\Program Files\Common Files\microsoft shared\Web Server Extensions\16"
            if ($detect16) {
                $ver = "16"
            }
        }
    }

    # Product and menu
    $prod = "$sku$ver"
    Write-Host "Product = $prod"
    ShowMenu $prod
	
    # Filter CSV for selected CU month
    Write-Host "SELECTED = $($global:selmonth)" -Fore "Yellow"
    $year = $global:selmonth.Split(" ")[1]
    $month = GetMonthInt $global:selmonth.Split(" ")[0]
    $patchFiles = $csv |Where-Object {$_.Year -eq $year -and $_.Month -eq $month -and $_.Product -eq "$sku$ver"}
    $patchFiles | Format-Table -Auto
	
    # Download patch files
    $bits = (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue)
    foreach ($file in $patchFiles) {
        # Parameters
        $splits = $file.URL.Split("/")
        $name = $splits[$splits.Count - 1]
        $dest = "$root\media\$name"

        # Download file if missing
        if (Test-Path $dest) {
            Write-Host "Found $name"
        }
        else {
            Write-Host "Downloading $name"
            if ($bits) {
                # pefer BITS
                Write-Host "BITS $dest"
                Start-BitsTransfer -Source $file.URL -Destination $dest
            }
            else {
                # Dot Net
                Write-Host "WebClient $dest"
                (New-Object System.Net.WebClient).DownloadFile($file.URL, $dest)
            }
        }
    }

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
}

function DetectAdmin() {
    # Are we running as local Administrator
    $wid = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $prp = New-Object System.Security.Principal.WindowsPrincipal($wid)
    $adm = [System.Security.Principal.WindowsBuiltInRole]::Administrator
    $IsAdmin = $prp.IsInRole($adm)
    if (!$IsAdmin) {
        (Get-Host).UI.RawUI.Backgroundcolor = "DarkRed"
        Clear-Host
        Write-Host "===== SPPatchify - Not Running as Administrator =====`nStarting an elevated PowerShell window...`n"
        $arguments = "& '" + $rootCmd + "' -phaseTwo"
        $arguments
        Start-Process powershell -Verb runAs -ArgumentList $arguments
        Break
    }
}

function SaveServiceInst() {
    # Save config to CSV
    $sos = Get-SPServiceInstance |Where-Object {$_.Status -eq "Online"} | Select-Object Id, TypeName, @{n = "Server"; e = {$_.Server.Address}}
    $sos | Export-Csv "$root\log\sos-before.csv" -Force -NoTypeInformation
}

function StartServiceInst() {
    # Restore config from CSV
    $sos = Import-Csv "$root\log\sos-before.csv"
    if ($sos) {
        foreach ($row in $sos) {
            $si = Get-SPServiceInstance $row.Id
            if ($si) {
                if ($si.Status -ne "Online") {
                    $row | Format-Table -AutoSize
                    Write-Host "Starting ... " -Fore Green
                    if ($si.TypeName -ne "User Profile Synchronization Service") {
                        # UPS needs password input to start via Central Admin GUI
                        $si.Provision()
                    }
                    if ($si.TypeName -eq "Distributed Cache") {
                        # Special command to initialize
                        Add-SPDistributedCacheServiceInstance
                        $si.Provision()
                    }
                    Write-Host "OK"
                }
            }
        }
    }
}
#endregion

#region GUI status window
function newStatus($currentStage) { 
    # Servers (rows)
    $coll = @()
    foreach ($server in $global:servers) {
        $row = New-Object -TypeName PSObject -Property @{Server = $server.Name; Role = $server.Role}
        $coll += $row
    }

    # Stages (cols)
    foreach ($row in $coll) {
        $i = $stages.IndexOf($currentStage)
        if ($currentStage -eq "done") {
            $i = $stages.count
        }
        foreach ($s in $stages) {
            if ($stages.IndexOf($s) -lt $i) {
                $v = 2
            }
            else {
                $v = 0
            }
            $row | Add-Member -MemberType NoteProperty -Name $s -Value $v
        }
    }
    return $coll
}

function displayStatus($coll, $px, $msg, $msp, $stats) {
    # Percent display
    $c = 0
    foreach ($row in $coll) {
        foreach ($col in $stages) {
            if ($row."$col" -eq 2) {
                $c++
            }
        }
    }
    $rowCount = $coll.count
    if (!$rowCount) {
        $rowCount = 1
    }
    $total = $rowCount * $stages.count
    $prct = [Math]::Round(($c / $total) * 100)
	
    # Progress bar
    $foot = "<div style='text-align:right'>{0}</div>" -f (Get-Date)
    if ($px) {
        $foot += @"
<br/>
<b>{0}</b>
<div style='width:300px;border:1px solid black'>
<div style='width:{1}px;height:20px;background-color:blue;'></div>
</div>
"@ -f $msg, $px
        $prct = $px / 3
    }

    # Generate HTML
    $file = "$root\sppatchify-status.html"
    $meta = "<meta http-equiv='refresh' content='5'><title>SPPatchify ($prct %)</title>"

    # Measure EXE
    if ($stats) {
        $foot = ($stats | ConvertTo-Html -Fragment) + $foot
    }
	
    # MSPLOG second table
    if ($msp) {
        $foot = ($msp | ConvertTo-Html -Fragment) + $foot
    }

    # HTML Footer and Color
    $html = $coll | ConvertTo-Html -Head $meta -PostContent $foot
    $html = $html.replace("<table", "<table border=0 cellpadding=6 cellspacing=0")
    $html = $html.replace("<td>0</td>", "<td style='background-color:lightgray'>Not Started</td>")
    $html = $html.replace("<td>1</td>", "<td style='background-color:yellow'>In Progress</td>")
    $html = $html.replace("<td>2</td>", "<td style='background-color:lightgreen'>Complete</td>")
    try {
        $html | Out-File $file -Force -Confirm:$false -ErrorAction SilentlyContinue
    }
    catch {}

    launchIE $file
}

function LaunchIE($file) {
    # Navigate Web browser
    $ieproc = (Get-Process -Name iexplore -ErrorAction SilentlyContinue)| Where-Object {$_.MainWindowHandle -eq $global:HWND}
    if (!$ieproc) {
        $global:ie = New-Object -COMObject InternetExplorer.Application
        $global:ie.visible = $true
        $global:ie.top = 200; $global:ie.width = 800; $global:ie.height = 500 ; $global:ie.Left = 100
        $global:HWND = $global:ie.HWND
    }
    try {
        $global:ie.navigate($file)
    }
    catch {
    }
}
function CloseIE() {
    # Close Web browser
    $ieproc = (Get-Process -Name iexplore -ErrorAction SilentlyContinue)| Where-Object {$_.MainWindowHandle -eq $global:HWND}
    $ieproc | Stop-Process
}
#endregion

function PreflightCheck() {
    try {
        Write-Host "Check Remote PowerShell " -Fore Green
        # Start Jobs
        foreach ($server in $global:servers) {
            $addr = $server.Address
            if ($addr -ne $env:computername) {
				            # Dynamic open PSSession
                if ($remoteSessionPort -and $remoteSessionSSL) {
                    $remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Credssp -Port $remoteSessionPort -UseSSL
                }
                elseif ($remoteSessionPort) {
                    $remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Credssp -Port $remoteSessionPort
                }
                elseif ($remoteSessionSSL) {
                    $remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Credssp -UseSSL
                }
                else {
                    $remote = New-PSSession -ComputerName $addr -Credential $global:cred -Authentication Credssp
                }
            }
        }
        Write-Host "Succeess" -Fore Green
        return $true
    }
    catch {
        throw 'Not able to connect to one or more computers in the farm. Please make sure you have run run Enable-PSRemoting and Enable-WSManCredSSP -Role Server'
    }
}

function ClearCacheIni() {  

    Write-Host "Clear CACHE.INI " -Fore Green
    # Get the local farm instance
    $farm = Get-SPServer | Where-Object {($_.Role -ne "Invalid")}

    # Stop the SharePoint Timer Service on each server in the farm
    ChangeSPTimer $farm $false

    # Delete all xml files from cache config folder on each server in the farm
    DeleteXmlCache $farm

    # Start the SharePoint Timer Service on each server in the farm
    ChangeSPTimer $farm $true
    Write-Host "Succeess" -Fore Green
}

function LaunchPhaseThree() {
    Start-Process "powershell.exe" -ArgumentList "$scriptFile -phaseThree"
}


# Stops the SharePoint Timer Service on each server in the SharePoint Farm.
function ChangeSPTimer($farm, $state) {
    # Constants
    $timer = "SPTimerV4"
    $timerInstance = "Microsoft SharePoint Foundation Timer"  

    # Iterate through each server in the farm, and each service in each server
    foreach ($server in $farm) {
        foreach ($instance in $server.ServiceInstances) {
            # If the server has the timer service then stop the service
            if ($instance.TypeName -eq $timerInstance) {
                # Display
                $addr = $server.Address
                if ($state) {
                    $change = "Running"
                } else {
                    $change = "Stopped"
                }

                Write-Host -Foregroundcolor DarkGray -NoNewline "$timer service on server: "
                Write-Host -Foregroundcolor Gray $addr

                # Change
                $svc = Get-Service -ComputerName $addr -Name $timer
                $svc | Set-Service -StartupType Automatic
                if ($state) {
                    $svc | Start-Service
                } else {
                    $svc | Stop-Service
                }

                # Wait for service stop/start
                WaitSPTimer $addr $timer $change $state
                break;
            }
        }
    }
}


# Waits for the service on the server to reach the required service state.
function WaitSPTimer($addr, $service, $change, $state) {
    Write-Host -foregroundcolor DarkGray -NoNewLine "Waiting for $service to change to $change on server $addr"

    do {
        Start-Sleep 3
        Write-Host -Foregroundcolor DarkGray -NoNewLine "."

        # Change
        $svc = Get-Service -ComputerName $addr -Name $timer
        $svc | Set-Service -StartupType Automatic
        if ($state) {
            $svc | Start-Service
        } else {
            $svc | Stop-Service
        }
        
    }
    while ($svc.Status -ne $change)
    Write-Host -Foregroundcolor DarkGray -NoNewLine " Service is "
    Write-Host -Foregroundcolor Gray $change
}


# Removes all xml files recursive on an UNC path
function DeleteXmlCache($farm) {
    Write-Host -foregroundcolor DarkGray "Delete xml files"

    # Iterate through each server in the farm, and each service in each server
    foreach ($server in $farm) {
        foreach ($instance in $server.ServiceInstances) {
            # If the server has the timer service delete the XML files from the config cache
            if ($instance.TypeName -eq $timerServiceInstanceName) {
                [string]$serverName = $server.Name

                Write-Host -foregroundcolor DarkGray -NoNewline "Deleting xml files from config cache on server: "
                Write-Host -foregroundcolor Gray $serverName

                # Remove all xml files recursive on an UNC path
                $path = "\\" + $serverName + "\c$\ProgramData\Microsoft\SharePoint\Config\*-*\*.xml"
                Remove-Item -path $path -Force

                # 1 = refresh all cache settings
                $path = "\\" + $serverName + "\c$\ProgramData\Microsoft\SharePoint\Config\*-*\cache.ini"
                Set-Content -path $path -Value "1"

                break
            }
        }
    }
}

function TestRemotePowershell() {
    # Prepare
    Get-PSSession | Remove-PSSession -ErrorAction SilentlyContinue | Out-Null
    ReadIISPW

    # Connect
    $farm = Get-SPServer |Where-Object {($_.Role -ne "Invalid")}
    foreach ($f in $farm) {
        New-PSSession -ComputerName $f.Address -Authentication Credssp -Credential $global:cred
    }

    # Display
    Get-PSSession | ft -AutoSize
    if ($farm.Count -eq (Get-PSSession).Count) {
        $color = "Green"
    } else {
        $color = "Red"
    }
    Write-Host "Farm Servers : $($farm.Count)" -Fore $color
    Write-Host "Sessions     : $((Get-PSSession).Count)" -Fore $color
}

function Main() {
    # Test PowerShell
    if ($testRemotePowershell) {
        TestRemotePowershell
        Exit
    }

    # Download media
    if ($downloadMediaOnly) {
        PatchRemoval
        PatchMenu
        Exit
    }
	
    # Display version
    if ($showVersion) {
        DisplayVersion
        Exit
    }
	
    # Start LOG
    $start = Get-Date
    $when = $start.ToString("yyyy-MM-dd-hh-mm-ss")
    $logFile = "$root\log\SPPatchify-$when.txt"
    mkdir "$root\log" -ErrorAction SilentlyContinue | Out-Null
    Start-Transcript $logFile

    # Version
    "SPPatchify version 0.99 last modified 06-20-2018"
	
    # Parameters
    $msg = "=== PARAMS === $(Get-Date)"
    $msg +=	"download = $downloadMediaOnly"
    $msg +=	"copy = $copyMediaOnly"
    $msg +=	"version = $showVersion"
    $msg +=	"phaseTwo = $phaseTwo"
    Write-Host "Content Databases Online: $((Get-SPContentDatabase).Count)"

    # Local farm servers
    $global:servers = Get-SPServer |Where-Object {$_.Role -ne "Invalid"} | Sort-Object Address
    Write-Host "Servers Online: $($global:servers).Count"

    # Halt if no servers detected
    if (($global:servers).Count -eq 0) {
        Write-Host "HALT - POWERSHELL ERROR - No SharePoint servers detected.  Close this window and run from new window." -Fore Red
        Exit        
    }
    
    # Read IIS Password
    ReadIISPW    
    if (-not (PreflightCheck)) {
        return
    }    

    # Prepare \LOG\ folder
    LoopRemoteCmd "Create log directory on" "mkdir '$root\log' -ErrorAction SilentlyContinue | Out-Null"

    # Core steps
    if (!$phaseTwo -and !$phaseThree) {
        if ($copyMediaOnly) {
            # Copy media only (switch -C)            
            CopyEXE "Copy"
        }
        else {
            # Phase One - Binary EXE
            PatchMenu
            EnablePSRemoting
            ClearCacheIni
            CopyEXE "Copy"
            SafetyEXE
            SaveServiceInst
            ChangeServices $true
            ProductLocal
            ChangeDC
            ChangeServices $false
            IISStart
            RunEXE
            WaitReboot
            if (!$skipProductLocal) {
                ProductLocal
            }
            if (!$phaseOneBinary) {
                # Reboot and queue Phase two
                LocalReboot
            }
        }
    }
    # Phase Two - SP Config Wizard
    if ($phaseTwo) {
        SafetyInstallRequired
        DetectAdmin        
        if (!$onlineContent) {
            ChangeContent $false
        }
        ChangeServices $true
        ProductLocal
        RunConfigWizard
        # Launch new window - Phase Three
        LaunchPhaseThree
    }
    # Phase Three - Add Content
    if ($phaseThree) {
        if (!$onlineContent) {
            ChangeContent $true
        }
        UpgradeContent
        IISStart
        StartServiceInst
        DisplayCA
    }
	
    # Calculate Duration and Run Cleanup
    CalcDuration
    FinalCleanUp
    Write-Host "DONE"
}
Main