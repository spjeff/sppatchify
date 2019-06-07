# This Script will install the CU Faster
# Keep This Script and Required Files in Same Folder.

Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null

# This Script will install the CU Faster
#Keep This Script and Required Files in Same Folder.

###########################
##Ensure Patch is Present##
###########################
$patchfile = Get-ChildItem | Where-Object { $_.Extension -eq ".exe" } 
if (!$patchfile) {
    Write-Host "Unable to retrieve the file.  Exiting Script" -ForegroundColor "Red"
    Return
}

########################
##Stop Search Services##
########################
##Checking Search services##
$srchctr = 1 
$srch4srvctr = 1 
$srch5srvctr = 1

$ver = (Get-SPFarm).BuildVersion.Major              # Get the version number for Osearch 14,15,16,19)
$srv4 = Get-Service "OSearch$ver" 
$srv5 = Get-Service "SPSearchHostController"

If (($srv4.status -eq "Running") -or ($srv5.status -eq "Running")) {
    Write-Host "Choose 1 to Pause Search Service Application" -ForegroundColor Cyan
    Write-Host "Choose 2 to leave Search Service Application running" -ForegroundColor Cyan
    $searchappresult = Read-Host "Press 1 or 2 and hit enter"
    Write-Host

    if ($searchappresult -eq 1) {
        $srchctr = 2
        Write-Host "Pausing the Search Service Application" -ForegroundColor Yellow
        Write-Host "This could take a few minutes" -ForegroundColor Yellow
        $ssa = get-spenterprisesearchserviceapplication
        $ssa.pause()
    }
    elseif ($searchappresult -eq 2) {
        Write-Host "Continuing without pausing the Search Service Application"
    }
    else {
        Write-Host "Run the script again and choose option 1 or 2" -ForegroundColor Red
        Write-Host "Exiting Script" -ForegroundColor Red
        Return 
    } 
}

Write-Host "Stopping Search Services if they are running" -ForegroundColor Yellow
if ($srv4.status -eq "Running") { 
    $srch4srvctr = 2 
    Set-Service -Name "OSearch$srv" -StartupType Disabled 
    $srv4.stop() 
}

if ($srv5.status -eq "Running") {
    $srch5srvctr = 2
    Set-service "SPSearchHostController" -StartupType Disabled
    $srv5.stop()
}

do {
    $srv6 = get-service "SPSearchHostController"
    if ($srv6.status -eq "Stopped") {
        $yes = 1
    }
    Start-Sleep -Seconds 10
}
until ($yes -eq 1)

Write-Host "Search Services are stopped" -ForegroundColor Green 
Write-Host

#######################
##Stop Other Services##
#######################
Set-Service -Name "IISADMIN" -StartupType Disabled
Set-Service -Name "SPTimerV4" -StartupType Disabled
Write-Host "Gracefully stopping IIS W3WP Processes" -ForegroundColor Yellow
Write-Host
iisreset -stop -noforce
Write-Host "Stopping Services" -ForegroundColor Yellow
Write-Host

$srv2 = get-service "SPTimerV4" 
if ($srv2.status -eq "Running") {
  $srv2.stop()
}

Write-Host "Services are Stopped" -ForegroundColor Green
Write-Host 
Write-Host

##################
##Start patching##
##################
Write-Host "Patching now keep this PowerShell window open" -ForegroundColor Magenta
Write-Host
$starttime = Get-Date
$filename = $patchfile.Basename

Start-Process $filename PACKAGE.BYPASS.DETECTION.CHECK=1
Start-Sleep -seconds 20 
$proc = Get-Process $filename
$proc.WaitForExit()

$finishtime = Get-Date
Write-Host
Write-Host "Patch installation complete" -ForegroundColor Green
Write-Host 

##################
##Start Services##
##################
Write-Host "Starting Services Backup" -ForegroundColor Yellow
Set-Service -Name "SPTimerV4" -StartupType Automatic 
Set-Service -Name "IISADMIN" -StartupType Automatic

##Grabbing local server and starting services##


$srv2 = Get-Service "SPTimerV4"
$srv2.start()
$srv3 = Get-Service "IISADMIN"
$srv3.start()
$srv4 = Get-Service "OSearch$srv"
$srv5 = Get-Service "SPSearchHostController"

###Ensuring Search Services were stopped by script before Starting" 
if ($srch4srvctr -eq 2) {
    set-service -Name "OSearch$srv" -StartupType Automatic
    $srv4.start()
}
if ($srch5srvctr -eq 2) {
    Set-service "SPSearchHostController" -StartupType Automatic
    $srv5.start()
}

###Resuming Search Service Application if paused### 
if ($srchctr -eq 2) {
    Write-Host "Resuming the Search Service Application" -ForegroundColor Yellow
    $ssa = get-spenterprisesearchserviceapplication 
    $ssa.resume()
}

Write-Host "Services are Started" -ForegroundColor Green
Write-Host
Write-Host
Write-Host "Script Duration" -ForegroundColor Yellow
Write-Host "Started: " $starttime -ForegroundColor Yellow
Write-Host "Finished: " $finishtime -ForegroundColor Yellow
Write-Host "Script Complete"