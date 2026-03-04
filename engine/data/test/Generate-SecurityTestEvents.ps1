#Requires -RunAsAdministrator
<#
.SYNOPSIS
    High-volume security test event generator for eve-engine validation.
    Generates realistic attack patterns with substantial noise (450+ events per scenario).

.DESCRIPTION
    Creates EVTX files matching DLLHijack.evtx quality standards:
    - Brute Force: 80-120 failed logins + 200+ successful login noise
    - Service Creation: 1-2 suspicious + 15-25 legitimate service operations
    - Scheduled Tasks: 1-2 suspicious + 10-20 legitimate task operations
    - Account Manipulation: 1-2 suspicious accounts + 50+ group query operations
    - Log Clearing: 1 critical event (low volume by nature)

.PARAMETER OutputDir
    Directory for EVTX export (default: C:\SecurityTestEvtx)

.PARAMETER SkipNoise
    Skip noise generation (creates minimal test files)

.PARAMETER ScenariosToRun
    Array of scenario numbers to execute (1-5)

.EXAMPLE
    .\Generate-SecurityTestEvents.ps1
    .\Generate-SecurityTestEvents.ps1 -OutputDir "C:\Tests" -ScenariosToRun @(1,2,3)
#>

param(
    [string]$OutputDir = "C:\SecurityTestEvtx",
    [switch]$SkipNoise,
    [int[]]$ScenariosToRun = @(1, 2, 3, 4, 5)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# =============================================================================
# UI HELPERS
# =============================================================================

function Write-Header([string]$msg) {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $msg" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
}

function Write-Step([string]$msg) {
    Write-Host "  [>] $msg" -ForegroundColor Yellow
}

function Write-OK([string]$msg) {
    Write-Host "  [+] $msg" -ForegroundColor Green
}

function Write-Warn([string]$msg) {
    Write-Host "  [!] $msg" -ForegroundColor Magenta
}

function Get-RandomDelay([int]$MinMs = 100, [int]$MaxMs = 2500) {
    Start-Sleep -Milliseconds (Get-Random -Minimum $MinMs -Maximum $MaxMs)
}

function Export-EventsToEvtx([string]$LogName, [string]$XPathQuery, [string]$OutFile) {
    try {
        Write-Step "Exporting from $LogName..."
        wevtutil epl $LogName $OutFile "/q:$XPathQuery" 2>&1 | Out-Null
        if (Test-Path $OutFile) {
            $count = (Get-WinEvent -Path $OutFile -ErrorAction SilentlyContinue | Measure-Object).Count
            Write-OK "Exported $count event(s) -> $(Split-Path $OutFile -Leaf)"
            return $count
        }
        else {
            Write-Warn "Export produced no file"
            return 0
        }
    }
    catch {
        Write-Warn "Export failed: $_"
        return 0
    }
}

# =============================================================================
# NOISE GENERATION - HIGH VOLUME
# =============================================================================

function Add-AuthenticationNoise([int]$Count = 50) {
    <#
    .SYNOPSIS
        Generate authentication-adjacent background activity without credentials prompts.
    #>
    if ($SkipNoise) { return }
    Write-Step "Generating $Count authentication-adjacent noise events (non-interactive)..."
    
    $localUsers = @((Get-LocalUser | Select-Object -First 3).Name)
    if ($localUsers.Count -eq 0) { $localUsers = @($env:USERNAME) }
    
    for ($i = 0; $i -lt $Count; $i++) {
        $user = $localUsers | Get-Random
        try {
            whoami /all 2>&1 | Out-Null
            cmd.exe /c "net user $user" 2>&1 | Out-Null
            cmd.exe /c "net localgroup Users" 2>&1 | Out-Null
        }
        catch {
            Write-Warn "Authentication noise iteration failed (continuing): $_"
        }
        
        if ($i % 10 -eq 0) {
            # Query operations that generate security events
            Get-LocalGroupMember -Group "Users" -ErrorAction SilentlyContinue | Out-Null
            Get-LocalUser -Name $user -ErrorAction SilentlyContinue | Out-Null
        }
        
        if ($i % 5 -eq 0) { Get-RandomDelay -MinMs 50 -MaxMs 200 }
    }
}

function Add-GroupQueryNoise([int]$Count = 100) {
    <#
    .SYNOPSIS
        Generate group enumeration events (4799) as background noise.
    #>
    if ($SkipNoise) { return }
    Write-Step "Generating $Count group/user query events..."
    
    $groups = @("Administrators", "Users", "Power Users", "Remote Desktop Users", "Guests")
    
    for ($i = 0; $i -lt $Count; $i++) {
        $group = $groups | Get-Random
        try {
            Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue | Out-Null
        } catch {}
        
        if ($i % 20 -eq 0) {
            Get-LocalUser | Out-Null
        }
        
        if ($i % 10 -eq 0) { Get-RandomDelay -MinMs 20 -MaxMs 100 }
    }
}

function Add-ServiceQueryNoise([int]$Count = 50) {
    <#
    .SYNOPSIS
        Generate service query/state change events as background noise.
    #>
    if ($SkipNoise) { return }
    Write-Step "Generating $Count service operation events..."
    
    $services = Get-Service | Where-Object { $_.Status -eq 'Stopped' -and $_.StartType -eq 'Manual' } | Select-Object -First 10
    
    for ($i = 0; $i -lt $Count; $i++) {
        $svc = $services | Get-Random
        if ($svc) {
            # Query service config (generates System events)
            sc.exe query $svc.Name 2>&1 | Out-Null
            sc.exe qc $svc.Name 2>&1 | Out-Null
        }
        
        if ($i % 5 -eq 0) { Get-RandomDelay -MinMs 100 -MaxMs 400 }
    }
}

function Add-TaskQueryNoise([int]$Count = 40) {
    <#
    .SYNOPSIS
        Generate scheduled task query events as background noise.
    #>
    if ($SkipNoise) { return }
    Write-Step "Generating $Count task query events..."
    
    for ($i = 0; $i -lt $Count; $i++) {
        # Query existing tasks (generates Task Scheduler events)
        schtasks.exe /query /fo list 2>&1 | Out-Null
        Get-ScheduledTask -ErrorAction SilentlyContinue | Select-Object -First 5 | Out-Null
        
        if ($i % 5 -eq 0) { Get-RandomDelay -MinMs 100 -MaxMs 300 }
    }
}

# =============================================================================
# SETUP & CONFIGURATION
# =============================================================================

Write-Header "High-Volume Security Event Generator v2.0"
Write-Host "  Target: 450+ events per scenario (matching DLLHijack.evtx standard)" -ForegroundColor Gray
Write-Host ""

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
Write-OK "Output directory: $OutputDir"

Write-Step "Configuring audit policies..."
$auditPolicies = @{
    "Logon/Logoff" = @(
        "{0CCE9215-69AE-11D9-BED3-505054503030}",  # Account Lockout
        "{0CCE9216-69AE-11D9-BED3-505054503030}",  # IPsec Main Mode
        "{0CCE9217-69AE-11D9-BED3-505054503030}",  # Other Logon/Logoff Events
        "{0CCE9218-69AE-11D9-BED3-505054503030}",  # Network Policy Server
        "{0CCE921B-69AE-11D9-BED3-505054503030}",  # Special Logon
        "{0CCE921C-69AE-11D9-BED3-505054503030}"   # Logoff
    )
    "Account Management" = @(
        "{0CCE9235-69AE-11D9-BED3-505054503030}",  # User Account Management
        "{0CCE9236-69AE-11D9-BED3-505054503030}",  # Computer Account Management
        "{0CCE9237-69AE-11D9-BED3-505054503030}",  # Security Group Management
        "{0CCE923A-69AE-11D9-BED3-505054503030}"   # Other Account Management
    )
    "Policy Change" = @(
        "{0CCE9213-69AE-11D9-BED3-505054503030}",  # Authentication Policy
        "{0CCE9214-69AE-11D9-BED3-505054503030}"   # Authorization Policy
    )
    "Object Access" = @(
        "{0CCE922F-69AE-11D9-BED3-505054503030}"   # Other Object Access Events (covers 4698)
    )
    "System" = @(
        "{0CCE9211-69AE-11D9-BED3-505054503030}",  # Security State Change
        "{0CCE9212-69AE-11D9-BED3-505054503030}"   # Security System Extension
    )
}

$totalPolicies = 0
foreach ($category in $auditPolicies.Keys) {
    foreach ($guid in $auditPolicies[$category]) {
        auditpol /set /subcategory:"$guid" /failure:enable /success:enable 2>&1 | Out-Null
        $totalPolicies++
    }
}
Write-OK "Configured $totalPolicies audit policies"

wevtutil sl "Microsoft-Windows-TaskScheduler/Operational" /e:true | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Warn "Could not enable Task Scheduler Operational log (continuing)"
}

wevtutil sl "System" /e:true /ms:524288000 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Warn "Could not resize/enable System log with requested size. Trying enable-only fallback..."
    wevtutil sl "System" /e:true | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "System log configuration failed. Continuing with existing configuration."
    }
    else {
        Write-OK "System log enabled (size unchanged)"
    }
}
else {
    Write-OK "Event logs enabled and sized"
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$scenarioResults = @()

# =============================================================================
# SCENARIO 1: BRUTE FORCE / FAILED LOGINS (4625, 4648, 4740)
# Target: 80-120 malicious + 200+ noise = 300+ total events
# =============================================================================

if (1 -in $ScenariosToRun) {
    Write-Header "Scenario 1: Brute Force Attack (High Volume)"
    
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $startTime = (Get-Date).AddSeconds(-10)
    
    # Attack Phase 1: User enumeration spray
    Write-Step "Phase 1: Username enumeration (20-30 attempts)..."
    $commonUsers = @(
        "administrator", "admin", "root", "guest", "test", "user",
        "svc_backup", "svc_sql", "svc_web", "helpdesk", "support",
        "john.smith", "jsmith", "j.smith", "jane.doe", "jdoe",
        "webadmin", "sqladmin", "dbadmin", "sysadmin", "netadmin"
    )
    
    $enumCount = Get-Random -Minimum 20 -Maximum 30
    for ($i = 0; $i -lt $enumCount; $i++) {
        $user = $commonUsers | Get-Random
        try {
            $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Machine', $env:COMPUTERNAME)
            $ctx.ValidateCredentials($user, "InvalidPass$(Get-Random -Min 100 -Max 999)!")
        } catch {}
        
        if ($i % 5 -eq 0) { Get-RandomDelay -MinMs 100 -MaxMs 500 }
    }
    
    Write-Step "Cooling period (3-5 seconds)..."
    Start-Sleep -Seconds (Get-Random -Minimum 3 -Maximum 5)
    
    # Attack Phase 2: Focused password spraying on discovered accounts
    Write-Step "Phase 2: Password spray on privileged accounts (40-60 attempts)..."
    $targetAccounts = @("administrator", "admin", "svc_backup", "helpdesk", "root")
    $commonPasswords = @(
        "Password123!", "Welcome123!", "Summer2024!", "Winter2024!",
        "Admin123!", "P@ssw0rd", "P@ssword1", "Passw0rd!",
        "Company123!", "Default123!", "P@ssw0rd123", "Password1!",
        "Monday123!", "Friday123!", "Spring2024!", "Autumn2024!"
    )
    
    $sprayCount = Get-Random -Minimum 40 -Maximum 60
    for ($i = 0; $i -lt $sprayCount; $i++) {
        $user = $targetAccounts | Get-Random
        $pass = $commonPasswords | Get-Random
        try {
            $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Machine', $env:COMPUTERNAME)
            $ctx.ValidateCredentials($user, $pass)
        } catch {}
        
        if ($i % 8 -eq 0) { Get-RandomDelay -MinMs 800 -MaxMs 2000 }
    }
    
    Write-Step "Extended cooling period (10-15 seconds)..."
    Start-Sleep -Seconds (Get-Random -Minimum 10 -Maximum 15)
    
    # Attack Phase 3: Slow brute force on single account
    Write-Step "Phase 3: Targeted brute force on single account (20-30 attempts)..."
    $targetUser = "administrator"
    $bruteCount = Get-Random -Minimum 20 -Maximum 30
    for ($i = 0; $i -lt $bruteCount; $i++) {
        try {
            $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Machine', $env:COMPUTERNAME)
            $ctx.ValidateCredentials($targetUser, "BruteForce$(Get-Random -Min 10000 -Max 99999)!")
        } catch {}
        
        Get-RandomDelay -MinMs 2000 -MaxMs 5000  # Slow to evade detection
    }
    
    # Generate MASSIVE noise with successful authentication events
    Write-Step "Generating baseline noise (200+ successful auth events)..."
    Add-AuthenticationNoise -Count 200
    
    # Additional user/group queries
    Add-GroupQueryNoise -Count 100
    
    # Export events
    $xStart = $startTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss")
    $outFile = Join-Path $OutputDir "${timestamp}_01_brute_force.evtx"
    $query = "*[System[TimeCreated[@SystemTime>='$xStart']]]"
    $count = Export-EventsToEvtx -LogName "Security" -XPathQuery $query -OutFile $outFile
    
    $scenarioResults += [PSCustomObject]@{ 
        Scenario = 1
        Name = "Brute Force"
        File = $outFile
        Events = $count
        Target = "300+ events (80-120 malicious + 200+ noise)"
    }
}

# =============================================================================
# SCENARIO 2: EVENT LOG CLEARING (1102, 1100)
# Target: 1 critical event (low volume by nature, but run AFTER scenario 1)
# NOTE: Must run AFTER scenario 1 to preserve brute force export
# =============================================================================

if (2 -in $ScenariosToRun) {
    Write-Header "Scenario 2: Anti-Forensics - Event Log Tampering"
    Write-Warn "This will CLEAR the Security log. Ensure Scenario 1 export is complete."
    Write-Host "  Waiting 3 seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 3
    
    # Generate activity before clearing (so the log isn't empty)
    Write-Step "Generating pre-clear activity (50 events)..."
    Add-GroupQueryNoise -Count 50
    Start-Sleep -Seconds 2
    
    Write-Step "CRITICAL: Clearing Security event log (Event ID 1102)..."
    wevtutil cl Security 2>&1 | Out-Null
    Start-Sleep -Seconds 3
    
    # Export the log clear event itself
    $outFile = Join-Path $OutputDir "${timestamp}_02_log_cleared.evtx"
    $query = "*[System[EventID=1102 or EventID=1100]]"
    $count = Export-EventsToEvtx -LogName "Security" -XPathQuery $query -OutFile $outFile
    
    $scenarioResults += [PSCustomObject]@{ 
        Scenario = 2
        Name = "Log Clearing"
        File = $outFile
        Events = $count
        Target = "1 event (critical by nature)"
    }
}

# =============================================================================
# SCENARIO 3: SUSPICIOUS SERVICE CREATION (7045, 4697)
# Target: 2-3 malicious + 30+ noise = 35+ total events
# =============================================================================

if (3 -in $ScenariosToRun) {
    Write-Header "Scenario 3: Malicious Service Installation"
    
    $startTime = (Get-Date).AddSeconds(-5)
    $suspiciousServices = @()
    
    # Malicious Service 1: From ProgramData (suspicious location)
    Write-Step "Creating malicious service #1 (ProgramData location)..."
    $rnd1 = Get-Random -Min 1000 -Max 9999
    $svcName1 = "WindowsDefender_$rnd1"
    $svcPath1 = "C:\ProgramData\Windows\svchost.exe /k netsvcs"
    
    sc.exe create $svcName1 binPath= $svcPath1 type= own start= auto DisplayName= "Windows Defender Service Helper" 2>&1 | Out-Null
    $suspiciousServices += $svcName1
    Get-RandomDelay -MinMs 800 -MaxMs 1500
    
    # Malicious Service 2: PowerShell encoded command via cmd.exe
    Write-Step "Creating malicious service #2 (encoded PowerShell)..."
    $rnd2 = Get-Random -Min 1000 -Max 9999
    $svcName2 = "WinUpdateSvc_$rnd2"
    $svcPath2 = "C:\Windows\System32\cmd.exe /c powershell.exe -NoP -W Hidden -Enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA="
    
    sc.exe create $svcName2 binPath= $svcPath2 type= own start= demand DisplayName= "Windows Update Helper Service" 2>&1 | Out-Null
    $suspiciousServices += $svcName2
    Get-RandomDelay -MinMs 800 -MaxMs 1500
    
    # Malicious Service 3: From Temp directory
    Write-Step "Creating malicious service #3 (Temp directory)..."
    $rnd3 = Get-Random -Min 1000 -Max 9999
    $svcName3 = "SecurityService_$rnd3"
    $svcPath3 = "C:\Temp\service.exe"
    
    sc.exe create $svcName3 binPath= $svcPath3 type= own start= demand 2>&1 | Out-Null
    $suspiciousServices += $svcName3
    Get-RandomDelay -MinMs 500 -MaxMs 1000
    
    # Generate service query noise
    Add-ServiceQueryNoise -Count 40
    
    # Export System events (7045)
    $xStart = $startTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss")
    $outFile1 = Join-Path $OutputDir "${timestamp}_03a_service_system.evtx"
    $query1 = "*[System[TimeCreated[@SystemTime>='$xStart']]]"
    $count1 = Export-EventsToEvtx -LogName "System" -XPathQuery $query1 -OutFile $outFile1
    
    # Export Security events (4697)
    $outFile2 = Join-Path $OutputDir "${timestamp}_03b_service_security.evtx"
    $query2 = "*[System[TimeCreated[@SystemTime>='$xStart']]]"
    $count2 = Export-EventsToEvtx -LogName "Security" -XPathQuery $query2 -OutFile $outFile2
    
    # Cleanup
    Write-Step "Cleaning up malicious services..."
    foreach ($svc in $suspiciousServices) {
        sc.exe delete $svc 2>&1 | Out-Null
    }
    Write-OK "Services deleted"
    
    $scenarioResults += [PSCustomObject]@{ 
        Scenario = 3
        Name = "Service Creation"
        File = "$outFile1, $outFile2"
        Events = ($count1 + $count2)
        Target = "50+ events (3 malicious + 50+ noise)"
    }
}

# =============================================================================
# SCENARIO 4: SUSPICIOUS SCHEDULED TASK CREATION (4698, 4699, 4702)
# Target: 2-3 malicious + 25+ noise = 30+ total events
# =============================================================================

if (4 -in $ScenariosToRun) {
    Write-Header "Scenario 4: Malicious Scheduled Task Persistence"
    
    $startTime = (Get-Date).AddSeconds(-5)
    $suspiciousTasks = @()
    
    # Malicious Task 1: Hidden task with encoded PowerShell
    Write-Step "Creating malicious task #1 (hidden + encoded)..."
    $rnd1 = Get-Random -Min 1000 -Max 9999
    $taskName1 = "WinUpdate__$rnd1"  # Double underscore = suspicious
    $encodedCmd1 = "JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA="
    
    $action1 = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand $encodedCmd1"
    $trigger1 = New-ScheduledTaskTrigger -AtStartup
    $settings1 = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit (New-TimeSpan -Hours 1)
    
    Register-ScheduledTask -TaskName $taskName1 -Action $action1 -Trigger $trigger1 `
        -RunLevel Highest -Settings $settings1 -Force | Out-Null
    $suspiciousTasks += $taskName1
    Get-RandomDelay -MinMs 800 -MaxMs 1500
    
    # Malicious Task 2: From AppData location
    Write-Step "Creating malicious task #2 (AppData location)..."
    $rnd2 = Get-Random -Min 1000 -Max 9999
    $taskName2 = "SystemUpdate_$rnd2"
    $badPath = "C:\Users\Public\update.exe"
    
    $action2 = New-ScheduledTaskAction -Execute $badPath -Argument "/silent /install"
    $trigger2 = New-ScheduledTaskTrigger -AtLogon
    $settings2 = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 2)
    
    Register-ScheduledTask -TaskName $taskName2 -Action $action2 -Trigger $trigger2 `
        -RunLevel Highest -Settings $settings2 -Force | Out-Null
    $suspiciousTasks += $taskName2
    Get-RandomDelay -MinMs 800 -MaxMs 1500
    
    # Malicious Task 3: Script from Temp with obfuscated name
    Write-Step "Creating malicious task #3 (obfuscated name)..."
    $rnd3 = Get-Random -Min 1000 -Max 9999
    $taskName3 = "0x$(Get-Random -Min 1000 -Max 9999)_hidden"  # Hex-like name
    
    $action3 = New-ScheduledTaskAction -Execute "cmd.exe" `
        -Argument "/c powershell.exe -NoP -W Hidden -File C:\Temp\script.ps1"
    $trigger3 = New-ScheduledTaskTrigger -Daily -At "03:00AM"
    $settings3 = New-ScheduledTaskSettingsSet -Hidden
    
    Register-ScheduledTask -TaskName $taskName3 -Action $action3 -Trigger $trigger3 `
        -Settings $settings3 -Force | Out-Null
    $suspiciousTasks += $taskName3
    Get-RandomDelay -MinMs 500 -MaxMs 1000
    
    # Generate task query noise
    Add-TaskQueryNoise -Count 40
    
    # Export from BOTH logs - Operational AND Security
    $xStart = $startTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss")
    
    # Export Operational log (Event IDs 106, 140, 107, 129)
    $outFile1 = Join-Path $OutputDir "${timestamp}_04a_scheduled_task_operational.evtx"
    $queryOp = "*[System[TimeCreated[@SystemTime>='$xStart']]]"
    $count1 = Export-EventsToEvtx -LogName "Microsoft-Windows-TaskScheduler/Operational" -XPathQuery $queryOp -OutFile $outFile1
    
    # Export Security log (Event ID 4698)
    $outFile2 = Join-Path $OutputDir "${timestamp}_04b_scheduled_task_security.evtx"
    $querySec = "*[System[(EventID=4698 or EventID=4699 or EventID=4702) and TimeCreated[@SystemTime>='$xStart']]]"
    $count2 = Export-EventsToEvtx -LogName "Security" -XPathQuery $querySec -OutFile $outFile2
    
    # Cleanup
    Write-Step "Cleaning up malicious tasks..."
    foreach ($task in $suspiciousTasks) {
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
    }
    Write-OK "Tasks deleted"
    
    $scenarioResults += [PSCustomObject]@{ 
        Scenario = 4
        Name = "Scheduled Task"
        File = "$outFile1, $outFile2"
        Events = ($count1 + $count2)
        Target = "40+ events (3 malicious + 40+ noise)"
    }
}

# =============================================================================
# SCENARIO 5: ACCOUNT MANIPULATION (4720, 4732, 4728, 4756)
# Target: 2-3 malicious + 100+ noise = 105+ total events
# =============================================================================

if (5 -in $ScenariosToRun) {
    Write-Header "Scenario 5: Malicious Account & Privilege Escalation"
    
    $startTime = (Get-Date).AddSeconds(-5)
    $suspiciousAccounts = @()
    
    # Malicious Account 1: Service account with suspicious name
    Write-Step "Creating malicious account #1 (suspicious service account)..."
    $rnd1 = Get-Random -Min 1000 -Max 9999
    $username1 = "svc_backup_$rnd1"
    $password1 = ConvertTo-SecureString "Tr0ub4dor&3_Test!" -AsPlainText -Force
    
    New-LocalUser -Name $username1 -Password $password1 -FullName "Backup Service Account" `
        -Description "Automated backup service" -AccountNeverExpires -PasswordNeverExpires | Out-Null
    $suspiciousAccounts += $username1
    Get-RandomDelay -MinMs 500 -MaxMs 1000
    
    # Escalate to Administrators
    Write-Step "Escalating $username1 to Administrators..."
    Add-LocalGroupMember -Group "Administrators" -Member $username1
    Get-RandomDelay -MinMs 300 -MaxMs 800
    
    # Add to Backup Operators
    Write-Step "Adding $username1 to Backup Operators..."
    try {
        Add-LocalGroupMember -Group "Backup Operators" -Member $username1 -ErrorAction SilentlyContinue
    } catch {}
    Get-RandomDelay -MinMs 300 -MaxMs 700
    
    # Add to Remote Desktop Users
    Write-Step "Adding $username1 to Remote Desktop Users..."
    try {
        Add-LocalGroupMember -Group "Remote Desktop Users" -Member $username1
    } catch {}
    Get-RandomDelay -MinMs 300 -MaxMs 700
    
    # Malicious Account 2: Guest-like account with admin privileges
    Write-Step "Creating malicious account #2 (guest-like admin)..."
    $rnd2 = Get-Random -Min 1000 -Max 9999
    $username2 = "guest_$rnd2"
    $password2 = ConvertTo-SecureString "Welcome123!" -AsPlainText -Force
    
    New-LocalUser -Name $username2 -Password $password2 -Description "Temporary guest access" | Out-Null
    $suspiciousAccounts += $username2
    Get-RandomDelay -MinMs 500 -MaxMs 1000
    
    # Immediately escalate to admin (suspicious pattern)
    Write-Step "Escalating $username2 to Administrators (suspicious)..."
    Add-LocalGroupMember -Group "Administrators" -Member $username2
    Get-RandomDelay -MinMs 300 -MaxMs 800
    
    # Malicious Account 3: Hidden admin account
    Write-Step "Creating malicious account #3 (hidden admin)..."
    $rnd3 = Get-Random -Min 1000 -Max 9999
    $username3 = "DefaultAccount_$rnd3"
    $password3 = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
    
    New-LocalUser -Name $username3 -Password $password3 -Description "Default system account" | Out-Null
    $suspiciousAccounts += $username3
    Get-RandomDelay -MinMs 500 -MaxMs 1000
    
    Add-LocalGroupMember -Group "Administrators" -Member $username3
    Get-RandomDelay -MinMs 300 -MaxMs 700
    
    # Generate massive group/user query noise
    Write-Step "Generating baseline noise (150+ group query events)..."
    Add-GroupQueryNoise -Count 150
    
    # Additional authentication noise
    Add-AuthenticationNoise -Count 50
    
    # Export events
    $xStart = $startTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss")
    $outFile = Join-Path $OutputDir "${timestamp}_05_account_manipulation.evtx"
    $query = "*[System[TimeCreated[@SystemTime>='$xStart']]]"
    $count = Export-EventsToEvtx -LogName "Security" -XPathQuery $query -OutFile $outFile
    
    # Cleanup
    Write-Step "Cleaning up malicious accounts..."
    foreach ($user in $suspiciousAccounts) {
        try { Remove-LocalGroupMember -Group "Administrators" -Member $user -ErrorAction SilentlyContinue } catch {}
        try { Remove-LocalGroupMember -Group "Backup Operators" -Member $user -ErrorAction SilentlyContinue } catch {}
        try { Remove-LocalGroupMember -Group "Remote Desktop Users" -Member $user -ErrorAction SilentlyContinue } catch {}
        Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
    }
    Write-OK "Accounts deleted"
    
    $scenarioResults += [PSCustomObject]@{ 
        Scenario = 5
        Name = "Account Manipulation"
        File = $outFile
        Events = $count
        Target = "200+ events (10+ malicious + 150+ noise)"
    }
}

# =============================================================================
# SUMMARY & MANIFEST
# =============================================================================

Write-Header "Execution Summary"

# Generate manifest with metadata
$manifest = @{
    GeneratedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Generator = "Generate-SecurityTestEvents.ps1 v2.0"
    TargetVolume = "450+ events per scenario (matching DLLHijack.evtx)"
    Scenarios = $scenarioResults
}

$manifestPath = Join-Path $OutputDir "manifest.json"
$manifest | ConvertTo-Json -Depth 10 | Out-File -FilePath $manifestPath -Encoding UTF8
Write-OK "Manifest: $manifestPath"

Write-Host ""
Write-Host "Scenario Results:" -ForegroundColor Cyan
Write-Host ""
$scenarioResults | Format-Table Scenario, Name, Events, Target -AutoSize

$totalEvents = ($scenarioResults | Measure-Object -Property Events -Sum).Sum
Write-Host ""
Write-Host "Total Events Generated: $totalEvents" -ForegroundColor Green
Write-Host "Output Directory: $OutputDir" -ForegroundColor Green
Write-Host ""

if ($totalEvents -lt 300) {
    Write-Warn "Event volume is lower than expected. Consider re-running without -SkipNoise."
}
else {
    Write-OK "High-volume test suite generated successfully!"
}

Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Copy EVTX files from $OutputDir to your test directory"
Write-Host "  2. Run eve-engine detections with --incident-aggregation --high-risk-only"
Write-Host "  3. Validate high-risk incidents are properly surfaced"
Write-Host ""
