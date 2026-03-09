#requires -RunAsAdministrator

<#
.SYNOPSIS
    WinRM Configuration Script - Simplified for WEC/WEF Log Collection (version in script)

.DESCRIPTION
    Simplified WinRM configuration script for Windows Event Collector (WEC) 
    and Windows Event Forwarding (WEF) log collection. Supports HTTP/HTTPS 
    listeners with automatic firewall and policy configuration.

.PARAMETER Action
    Action to perform: enable, status, firewall, policies, UserPermissions, help

.PARAMETER ListenerType
    Listener type: http, https (default: http)

.PARAMETER User
    User account for log collection (domain\user, user@domain.com, or localuser)

.PARAMETER Port
    Custom port (default: 5985 for HTTP, 5986 for HTTPS)

.PARAMETER ThumbPrint
    Certificate thumbprint for HTTPS (optional - will auto-detect if not provided)

.PARAMETER WecIp
    WEC server IP address (required for firewall configuration)

.PARAMETER WecHostname
    WEC server hostname (required for firewall configuration)

.PARAMETER LogPath
    Path for log files (default: .\log)

.EXAMPLE
    .\winrmconfig.ps1 -Action enable -ListenerType http -User "domain\serviceaccount"

.EXAMPLE
    .\winrmconfig.ps1 -Action enable -ListenerType https -User "domain\serviceaccount" -ThumbPrint "ABC123..."

.EXAMPLE
    .\winrmconfig.ps1 -Action firewall -WecIp "192.168.1.100" -WecHostname "wec-server"

.EXAMPLE
    .\winrmconfig.ps1 -Action UserPermissions -User "domain\serviceaccount"

.EXAMPLE
    .\winrmconfig.ps1 -Action status

.NOTES
    Author: Andre Henrique (Uniao Geek)
    Email: contato@uniaogeek.com.br
    LinkedIn: https://www.linkedin.com/in/mrhenrike
    Instagram: @uniaogeek
    Version: 2.3.2
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("Enable", "Disable", "Status", "ConfigureFirewall", "ConfigurePolicies", "CheckPermissions", "ShowAllCerts", "ExportCACert", "Report", "ShowHelp", "ShowHelpLong", "EnsureWinRM", "ReadEvents")]
    [string]$Action,
    
    [Parameter()]
    [ValidateSet("http", "https")]
    [string]$ListenerType = "http",
    
    [Parameter()]
    [string]$User,
    
    [Parameter()]
    [ValidateRange(1, 65535)]
    [int]$Port,
    
    [Parameter()]
    [string]$ThumbPrint,
    
    [Parameter()]
    [string]$WecIp,
    
    [Parameter()]
    [string]$WecHostname,
    
    [Parameter()]
    [string]$LogPath = ".\log",
    
    [Parameter()]
    [string]$ExportCertPath,
    
    [Parameter()]
    [ValidateSet("basic", "negotiate", "kerberos")]
    [string]$AuthType = "negotiate",
    
    [Parameter()]
    [ValidateSet("Error", "Warning", "Info", "Debug")]
    [string]$LogLevel = "Error",
    
    [Parameter()]
    [string]$ConfigFile = "config-sample.json",
    [Parameter()]
    [string]$IPv4Filter,
    [Parameter()]
    [string]$IPv6Filter,
    # ReadEvents: target host (default localhost)
    [Parameter()]
    [string]$TargetHost = "localhost",
    # ReadEvents: password for remote (plain; use only in lab)
    [Parameter()]
    [string]$Password,
    # ReadEvents: channel/log name (default Security)
    [Parameter()]
    [string]$Channel = "Security",
    # ReadEvents: max events to read (default 10, max 100)
    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$Count = 10,
    # ReadEvents: sort by TimeCreated asc or desc (default asc = oldest first)
    [Parameter()]
    [ValidateSet("asc", "desc")]
    [string]$SortOrder = "asc",
    # Help language: only applies to ShowHelp / ShowHelpLong (default en-US; use pt-BR for Portuguese)
    [Parameter()]
    [ValidateSet("en-US", "pt-BR")]
    [string]$Language = "en-US",
    # Report: output to screen (default) or export to file
    [Parameter()]
    [ValidateSet("Screen", "Html", "Txt")]
    [string]$ReportFormat = "Screen",
    [Parameter()]
    [string]$ReportOutputPath,
    # Skip confirmation prompts for policies/firewall when set (use in automation)
    [Parameter()]
    [switch]$NoPrompt
)

# Global variables
$ScriptVersion = "2.3.2"
$Global:RestartRequired = $false

# Required PowerShell modules with impact description per function
# (Name, Description, AffectedActions: which -Action values need this module)
$Script:RequiredModules = @(
    @{
        Name = "NetSecurity"
        MinimumVersion = "1.0.0"
        Description = "Windows Firewall management (Get-NetFirewallRule, New-NetFirewallRule, etc.)"
        AffectedActions = @("Enable", "Disable", "ConfigureFirewall", "EnsureWinRM", "Status", "Report")
        Impact = "Without NetSecurity: firewall rules cannot be listed, created or validated. Actions 'ConfigureFirewall', 'EnsureWinRM', 'Enable', 'Status' and 'Report' will fail or skip firewall steps."
    },
    @{
        Name = "Microsoft.PowerShell.LocalAccounts"
        MinimumVersion = "1.0.0"
        Description = "Local users and groups (Get-LocalUser, Get-LocalGroupMember)"
        AffectedActions = @("Enable", "CheckPermissions")
        Impact = "Without LocalAccounts: local user validation and Event Log Readers group membership checks will fail. Actions 'Enable' and 'CheckPermissions' cannot verify or add local users."
    }
)

# Fast module check: tries to import, does NOT scan all modules on disk (Get-Module -ListAvailable is slow)
function Test-RequiredModules {
    $missing = @()
    foreach ($mod in $Script:RequiredModules) {
        $loaded = Get-Module -Name $mod.Name -ErrorAction SilentlyContinue
        if (-not $loaded) {
            # Try to import (fast - uses already-cached module list in session)
            try {
                Import-Module -Name $mod.Name -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
            } catch {
                $missing += $mod
            }
        }
    }
    return $missing
}

# Check if a specific module is available (fast import attempt, used at runtime per function)
function Assert-ModuleAvailable {
    param([string]$ModuleName, [string]$FunctionContext = "")
    $loaded = Get-Module -Name $ModuleName -ErrorAction SilentlyContinue
    if ($loaded) { return $true }
    try {
        Import-Module -Name $ModuleName -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
        return $true
    } catch {
        $mod = $Script:RequiredModules | Where-Object { $_.Name -eq $ModuleName } | Select-Object -First 1
        $impact = if ($mod) { $mod.Impact } else { "This function requires module '$ModuleName'." }
        Write-Host ""
        Write-Host "  [MODULE MISSING] $ModuleName" -ForegroundColor Red
        if ($FunctionContext) { Write-Host "  Context: $FunctionContext" -ForegroundColor Yellow }
        Write-Host "  $impact" -ForegroundColor Yellow
        Write-Host "  To install: Install-Module $ModuleName -Scope CurrentUser -Force" -ForegroundColor Cyan
        Write-Host "  Note: PowerShell execution policy must allow script execution (Set-ExecutionPolicy RemoteSigned -Scope CurrentUser)" -ForegroundColor Cyan
        Write-Host ""
        return $false
    }
}

function Install-RequiredModules {
    param([array]$ModulesToInstall)
    # Check execution policy before attempting install
    $policy = Get-ExecutionPolicy -Scope CurrentUser
    if ($policy -eq "Restricted") {
        Write-Host ""
        Write-Host "  WARNING: PowerShell execution policy is 'Restricted'." -ForegroundColor Yellow
        Write-Host "  Module installation may fail. To allow: Set-ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor Cyan
        Write-Host ""
    }
    foreach ($mod in $ModulesToInstall) {
        Write-Host "  Installing: $($mod.Name)..." -ForegroundColor Cyan
        try {
            Install-Module -Name $mod.Name -MinimumVersion $mod.MinimumVersion -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Import-Module -Name $mod.Name -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
            Write-Host "  Installed and loaded: $($mod.Name)" -ForegroundColor Green
        } catch {
            Write-Host "  Failed to install $($mod.Name): $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "  Impact: $($mod.Impact)" -ForegroundColor Yellow
            Write-Host "  Manual install: Install-Module $($mod.Name) -Scope CurrentUser -Force" -ForegroundColor Cyan
        }
    }
}

# At load: fast check (import attempt, not full disk scan)
$missingModules = Test-RequiredModules
if ($missingModules.Count -gt 0) {
    Write-Host ""
    Write-Host "  [STARTUP CHECK] The following PowerShell modules are required but not available:" -ForegroundColor Yellow
    foreach ($m in $missingModules) {
        Write-Host "  - $($m.Name): $($m.Description)" -ForegroundColor Gray
        Write-Host "    Impact: $($m.Impact)" -ForegroundColor DarkYellow
        Write-Host "    Affected actions: $($m.AffectedActions -join ', ')" -ForegroundColor Gray
    }
    Write-Host ""
    $response = Read-Host "  Install missing modules now? (y/n)"
    if ($response -match '^[yY]') {
        Install-RequiredModules -ModulesToInstall $missingModules
    } else {
        Write-Host ""
        Write-Host "  Skipped. Some actions will be unavailable or partially functional:" -ForegroundColor Yellow
        foreach ($m in $missingModules) {
            Write-Host "  - $($m.Impact)" -ForegroundColor DarkYellow
        }
        Write-Host "  Install later: Install-Module $( ($missingModules | ForEach-Object { $_.Name }) -join ', ' ) -Scope CurrentUser -Force" -ForegroundColor Cyan
    }
    Write-Host ""
}

# Create log directory if it doesn't exist
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

$LogFile = Join-Path $LogPath "winrmconfig_$(Get-Date -Format 'yyyyMMdd').log"

# Enhanced logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "Info",
        [string]$Component = "Main"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [$Component] $Message"
    
    # Write to console with colors
            switch ($Level) {
        "Error" { Write-Host $Message -ForegroundColor Red }
        "Warning" { Write-Host $Message -ForegroundColor Yellow }
        "Success" { Write-Host $Message -ForegroundColor Green }
        "Info" { Write-Host $Message -ForegroundColor Cyan }
        default { Write-Host $Message }
    }
    
    # Write to log file
    Add-Content -Path $LogFile -Value $logEntry -Encoding UTF8
}

# Fast helper: get WinRM/WEC firewall rules by display name pattern (avoids full enum)
function Get-WinRMFirewallRules {
    # Query only rules matching WinRM or WEC by name — much faster than enumerating all rules
    if (-not (Assert-ModuleAvailable "NetSecurity" "Get-WinRMFirewallRules")) { return @() }
    $rules = @()
    try { $rules += Get-NetFirewallRule -DisplayName "*WinRM*" -ErrorAction SilentlyContinue } catch {}
    try { $rules += Get-NetFirewallRule -DisplayName "*WEC*" -ErrorAction SilentlyContinue } catch {}
    return $rules
}

# Check if a firewall rule already exists by protocol, port, direction
# Uses targeted query (by name pattern) instead of full enumeration for performance
function Test-FirewallRuleExistsByPortProtocol {
    param(
        [int]$LocalPort,
        [string]$Protocol = "TCP",
        [string]$Direction = "Inbound"
    )
    if (-not (Assert-ModuleAvailable "NetSecurity" "Test-FirewallRuleExistsByPortProtocol")) { return $false }
    # Query rules by name patterns first (fast), then also check all inbound rules for the port
    $candidates = @()
    try { $candidates += Get-NetFirewallRule -DisplayName "*WinRM*" -ErrorAction SilentlyContinue } catch {}
    try { $candidates += Get-NetFirewallRule -DisplayName "*WEC*" -ErrorAction SilentlyContinue } catch {}
    try { $candidates += Get-NetFirewallRule -DisplayName "*Remote Management*" -ErrorAction SilentlyContinue } catch {}
    # Also check all enabled inbound rules on the target port using port filter lookup
    try {
        $portFilters = Get-NetFirewallPortFilter -Protocol $Protocol -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq $LocalPort -or $_.LocalPort -eq "Any" }
        foreach ($pf in $portFilters) {
            try {
                $r = $pf | Get-NetFirewallRule -ErrorAction SilentlyContinue
                if ($r -and $r.Direction -eq $Direction -and $r.Enabled -ne "False") { return $true }
            } catch {}
        }
    } catch {}
    foreach ($r in $candidates) {
        if ($r.Direction -ne $Direction -or $r.Enabled -eq "False") { continue }
        try {
            $pf = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue
            if ($pf -and ($pf.LocalPort -eq $LocalPort -or $pf.LocalPort -eq "Any") -and $pf.Protocol -eq $Protocol) { return $true }
        } catch {}
    }
    return $false
}

# Add firewall rule only if no rule exists for same port/protocol/direction (validates to avoid duplicates)
function Add-FirewallRuleIfMissing {
    param([string]$DisplayName, [int]$Port, [string]$Protocol = "TCP")
    if (Test-FirewallRuleExistsByPortProtocol -LocalPort $Port -Protocol $Protocol -Direction Inbound) {
        Write-Host "  Rule already exists for $Protocol port $Port (inbound); skipping." -ForegroundColor Cyan
        return
    }
    $doCreate = $false
    if ($script:NoPrompt) { $doCreate = $true } else {
        $response = Read-Host "  No firewall rule found for $Protocol port $Port. Create rule '$DisplayName'? (y/n)"
        if ($response -match '^[yY]') { $doCreate = $true }
    }
    if ($doCreate) {
        New-NetFirewallRule -DisplayName $DisplayName -Direction Inbound -Protocol $Protocol -LocalPort $Port -Action Allow | Out-Null
        Write-Log "Firewall rule created: $DisplayName (port $Port)" "Success" "Firewall"
        Write-Host "  Rule created: $DisplayName (port $Port)" -ForegroundColor Gray
    } else { Write-Host "  Skipped." -ForegroundColor Yellow }
}

# EnsureWinRM: start service, quickconfig if needed, WSMan Basic/AllowUnencrypted/TrustedHosts, firewall 5985/5986 (consolidates fix-winrm + Enable-WindowsRemoteAccess WinRM part)
function Invoke-EnsureWinRM {
    try {
        Write-Host ""
        Write-Host ("=" * 60) -ForegroundColor Cyan
        Write-Host "ENSURE WINRM (quick fix)" -ForegroundColor Yellow
        Write-Host ("=" * 60) -ForegroundColor Cyan
        Write-Host ""

        $svc = Get-Service -Name WinRM -ErrorAction SilentlyContinue
        if (-not $svc -or $svc.Status -ne "Running") {
            Write-Host "Starting WinRM service..." -ForegroundColor Yellow
            try { Start-Service WinRM -ErrorAction Stop } catch { & winrm quickconfig -q -Force 2>&1 | Out-Null }
            Write-Log "WinRM service started" "Success" "EnsureWinRM"
        }

        $winrmReady = $false
        try { $null = Test-WSMan -ComputerName localhost -ErrorAction Stop; $winrmReady = $true } catch {}
        if (-not $winrmReady) {
            Write-Host "Configuring WinRM (quickconfig)..." -ForegroundColor Yellow
            & winrm quickconfig -q -Force 2>&1 | Out-Null
            Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction SilentlyContinue
            Write-Log "WinRM quickconfig completed" "Success" "EnsureWinRM"
        }

        Write-Host "Setting WSMan (TrustedHosts, Basic, AllowUnencrypted)..." -ForegroundColor Cyan
        Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value "*" -Force -ErrorAction SilentlyContinue
        Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true -Force -ErrorAction SilentlyContinue
        Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true -Force -ErrorAction SilentlyContinue

        # Create registry policies (GPO-style) if not present - allow Basic and unencrypted traffic in lab
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        Set-ItemProperty -Path $regPath -Name "AllowBasic" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $regPath -Name "AllowUnencrypted" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $regPath -Name "IPv4Filter" -Value "*" -Type String -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $regPath -Name "IPv6Filter" -Value "*" -Type String -Force -ErrorAction SilentlyContinue

        Add-FirewallRuleIfMissing -DisplayName "WinRM HTTP" -Port 5985
        Add-FirewallRuleIfMissing -DisplayName "WinRM HTTPS" -Port 5986

        if (-not (Get-NetTCPConnection -LocalPort 5985 -State Listen -ErrorAction SilentlyContinue)) {
            Write-Host "Restarting WinRM to activate listener..." -ForegroundColor Yellow
            Restart-Service WinRM -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        }

        if (Get-NetTCPConnection -LocalPort 5985 -State Listen -ErrorAction SilentlyContinue) {
            Write-Host "WinRM is listening on port 5985." -ForegroundColor Green
            Write-Log "EnsureWinRM completed successfully" "Success" "EnsureWinRM"
        } else {
            Write-Host "Warning: WinRM is not yet listening on 5985. Run -Action Enable -User ... to create listener." -ForegroundColor Yellow
        }
        Write-Host ""
    } catch {
        Write-Log "EnsureWinRM error: $($_.Exception.Message)" "Error" "EnsureWinRM"
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ReadEvents: connect to target (localhost or remote) and list last N events from channel (validates read access; max 100)
function Invoke-ReadEvents {
    param(
        [string]$Target,
        [string]$UserAccount,
        [string]$PasswordPlain,
        [string]$TransportType,
        [int]$PortNum,
        [string]$LogChannel,
        [int]$MaxCount,
        [string]$Order
    )
    $scriptBlock = {
        param($ch, $max, $ord)
        $events = Get-WinEvent -LogName $ch -MaxEvents $max -ErrorAction Stop
        if ($ord -eq "desc") { $events = $events | Sort-Object TimeCreated -Descending } else { $events = $events | Sort-Object TimeCreated }
        $events | ForEach-Object { [PSCustomObject]@{ TimeCreated = $_.TimeCreated; Id = $_.Id; LevelDisplayName = $_.LevelDisplayName; Message = ($_.Message -replace "`r?`n", " ") } }
    }
    if ($Target -eq "localhost" -or $Target -eq "." -or $Target -eq $env:COMPUTERNAME) {
        Write-Host "Reading local events: $LogChannel (last $MaxCount, order $Order)..." -ForegroundColor Cyan
        try {
            $result = & $scriptBlock $LogChannel $MaxCount $Order
            $result | Format-Table -AutoSize
            Write-Host "Total: $($result.Count) event(s)." -ForegroundColor Green
        } catch {
            Write-Host "Error reading events: $($_.Exception.Message)" -ForegroundColor Red
        }
        return
    }
    if (-not $UserAccount) {
        Write-Host "For remote host, -User is required. Use -Password for basic auth in lab." -ForegroundColor Red
        return
    }
    $securePass = $null
    if ($PasswordPlain) {
        $securePass = ConvertTo-SecureString $PasswordPlain -AsPlainText -Force
    } else {
        $securePass = Read-Host "Password for $UserAccount" -AsSecureString
    }
    $cred = New-Object PSCredential($UserAccount, $securePass)
    $useSSL = ($TransportType -eq "https")
    if (-not $PortNum) { $PortNum = if ($useSSL) { 5986 } else { 5985 } }
    Write-Host "Connecting to ${Target}:${PortNum} ($TransportType) as $UserAccount..." -ForegroundColor Cyan
    try {
        $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck
        $session = New-PSSession -ComputerName $Target -Port $PortNum -UseSSL:$useSSL -Credential $cred -SessionOption $sessionOption -ErrorAction Stop
        $result = Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $LogChannel, $MaxCount, $Order
        Remove-PSSession $session -ErrorAction SilentlyContinue
        $result | Format-Table -AutoSize
        Write-Host "Total: $($result.Count) event(s)." -ForegroundColor Green
    } catch {
        Write-Host "Error connecting or reading events: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Test if user exists
function Test-User {
    param([string]$Username)
    
    try {
        if ($Username -match "@") {
            # Email format - convert to domain\user
            $domain = $Username.Split("@")[1]
            $user = $Username.Split("@")[0]
            $Username = "$domain\$user"
        }
        
        # Extract username part
        $userName = $Username.Split("\")[-1]
        
        # Try local user first (requires LocalAccounts module)
        try {
            if (Assert-ModuleAvailable "Microsoft.PowerShell.LocalAccounts" "Test-User (local lookup)" 2>$null) {
                $userObj = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue
                if ($userObj) {
                    Write-Log "Found local user: $userName" "Info" "UserValidation"
                    return $true
                }
            }
        }
        catch {
            Write-Log "Local user not found: $userName" "Info" "UserValidation"
        }
        
        # Try AD user
        try {
            $userObj = Get-ADUser -Identity $Username -ErrorAction SilentlyContinue
            if ($userObj) {
                Write-Log "Found AD user: $Username" "Info" "UserValidation"
                return $true
            }
        }
        catch {
            Write-Log "AD module not available or user not found in AD" "Info" "UserValidation"
        }
        
        # Try built-in accounts
        $builtInUsers = @("Administrator", "SYSTEM", "NETWORK SERVICE", "LOCAL SERVICE")
        if ($builtInUsers -contains $userName) {
            Write-Log "Found built-in user: $userName" "Info" "UserValidation"
            return $true
        }
        
        Write-Log "User not found: $Username" "Warning" "UserValidation"
            return $false
        }
    catch {
        Write-Log "Error validating user: $($_.Exception.Message)" "Error" "UserValidation"
        return $false
    }
}

# Add user to Event Log Readers group
function Add-UserToEventLogReaders {
    param([string]$Username)
    
    try {
        $group = [ADSI]"WinNT://./Event Log Readers,group"
        $user = [ADSI]"WinNT://./$Username,user"
        $group.Add($user.PSBase.Path)
        
        Write-Log "User $Username added to Event Log Readers group" "Success" "UserManagement"
        return $true
    }
    catch {
        Write-Log "Failed to add user to Event Log Readers group: $($_.Exception.Message)" "Error" "UserManagement"
        return $false
    }
}

# Check if user is in Event Log Readers group
function Test-UserInEventLogReaders {
    param([string]$Username)
    
    try {
        $userName = $Username.Split("\")[-1]
        
        # Try to get group members using Get-LocalGroupMember
        try {
            if (-not (Assert-ModuleAvailable "Microsoft.PowerShell.LocalAccounts" "Test-UserInEventLogReaders")) {
                Write-Host "  Falling back to ADSI for group membership check..." -ForegroundColor Yellow
            }
            $members = Get-LocalGroupMember -Group "Event Log Readers" -ErrorAction SilentlyContinue
            foreach ($member in $members) {
                if ($member.Name -like "*$userName" -or $member.Name -eq $userName) {
                    return $true
                }
            }
        }
        catch {
            Write-Log "Could not enumerate Event Log Readers group members" "Info" "UserValidation"
        }
        
        # Alternative method using ADSI
        try {
            $group = [ADSI]"WinNT://./Event Log Readers,group"
            $members = $group.psbase.Invoke("Members")
            
            foreach ($member in $members) {
                $memberName = $member.GetType().InvokeMember("Name", 'GetProperty', $null, $member, $null)
                if ($memberName -eq $userName) {
                    return $true
                }
            }
        }
        catch {
            Write-Log "ADSI method failed for Event Log Readers group" "Info" "UserValidation"
        }
        
        return $false
    }
    catch {
        Write-Log "Error checking Event Log Readers group membership: $($_.Exception.Message)" "Error" "UserValidation"
        return $false
    }
}

# Configure HTTP listener
function New-HTTPListener {
    param(
        [int]$Port = 5985,
        [string]$User
    )
    
    try {
        Write-Log "Creating HTTP listener on port $Port" "Info" "Listener"
        
        # Check if listener already exists
        $existing = winrm enumerate winrm/config/listener?Address=*+Transport=HTTP 2>$null
        if ($existing) {
            Write-Log "HTTP listener already exists, updating configuration" "Info" "Listener"
        } else {
            # Create new listener
            winrm create winrm/config/Listener?Address=*+Transport=HTTP
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to create HTTP listener"
            }
        }
        
        # Configure WinRM settings
        winrm set winrm/config/service '@{AllowUnencrypted="true"}'
        winrm set winrm/config/client '@{TrustedHosts="*"}'
        
        Write-Log "HTTP listener configured successfully on port $Port" "Success" "Listener"
        return $true
    }
    catch {
        Write-Log "Error creating HTTP listener: $($_.Exception.Message)" "Error" "Listener"
        return $false
    }
}

# Configure HTTPS listener
function New-HTTPSListener {
    param(
        [int]$Port = 5986,
        [string]$ThumbPrint,
        [string]$User
    )
    
    try {
        Write-Log "Creating HTTPS listener on port $Port" "Info" "Listener"
        
        # Auto-detect certificate if not provided
        if (-not $ThumbPrint) {
            Write-Host ""
            Write-Host ("=" * 60) -ForegroundColor Cyan
            Write-Host "SELECT CERTIFICATE FOR HTTPS LISTENER" -ForegroundColor Yellow
            Write-Host ("=" * 60) -ForegroundColor Cyan
            Write-Host ""
            
            # Get all certificates with Server Authentication EKU
            $certificates = Get-ChildItem Cert:\LocalMachine\My | Where-Object { 
                $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) -and (
                    ($_.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Enhanced Key Usage" } | ForEach-Object { $_.Format($false) }) -match "Server Authentication|Autenticação do Servidor" -or
                    ($_.EnhancedKeyUsageList | Where-Object { $_.FriendlyName -eq "Server Authentication" -or $_.FriendlyName -eq "Autenticação do Servidor" -or $_.ObjectId -eq "1.3.6.1.5.5.7.3.1" })
                )
            }
            
            if (-not $certificates -or $certificates.Count -eq 0) {
                Write-Host "No valid certificates found with Server Authentication EKU." -ForegroundColor Red
                Write-Host "Please install a valid certificate or provide -ThumbPrint parameter." -ForegroundColor Yellow
                throw "No valid certificate found. Please provide -ThumbPrint parameter or install a valid certificate."
            }
            
            # Display certificates in numbered list
            Write-Host "Available certificates for HTTPS:" -ForegroundColor Green
            Write-Host ""
            
            for ($i = 0; $i -lt $certificates.Count; $i++) {
                $cert = $certificates[$i]
                $subject = if ($cert.Subject) { $cert.Subject.Split(',')[0].Trim() } else { "N/A" }
                $expiry = if ($cert.NotAfter) { $cert.NotAfter.ToString("yyyy-MM-dd") } else { "N/A" }
                
                Write-Host "  $($i + 1). Subject: " -NoNewline
                Write-Host $subject -ForegroundColor Cyan
                Write-Host "     Thumbprint: " -NoNewline
                Write-Host $cert.Thumbprint -ForegroundColor Gray
                Write-Host "     Expires: " -NoNewline
                Write-Host $expiry -ForegroundColor Gray
                Write-Host ""
            }
            
            # Get user selection
            do {
                try {
                    $selection = Read-Host "Enter certificate number (1-$($certificates.Count))"
                    $index = [int]$selection - 1
                    
                    if ($index -ge 0 -and $index -lt $certificates.Count) {
                        $selectedCert = $certificates[$index]
                        $ThumbPrint = $selectedCert.Thumbprint
                        $subject = if ($selectedCert.Subject) { $selectedCert.Subject.Split(',')[0].Trim() } else { "N/A" }
                        
                        Write-Host "Selected certificate: " -NoNewline
                        Write-Host $subject -ForegroundColor Green
                        Write-Host "Thumbprint: " -NoNewline
                        Write-Host $ThumbPrint -ForegroundColor Cyan
                        Write-Log "User selected certificate: $ThumbPrint ($subject)" "Info" "Certificate"
                        break
                    } else {
                        Write-Host "Invalid selection. Please enter a number between 1 and $($certificates.Count)." -ForegroundColor Red
                    }
                }
                catch {
                    Write-Host "Invalid input. Please enter a valid number." -ForegroundColor Red
                }
            } while ($true)
        }
        
        # Check if listener already exists
        $existing = winrm enumerate winrm/config/listener?Address=*+Transport=HTTPS 2>$null
        if ($existing) {
            Write-Log "HTTPS listener already exists, updating configuration" "Info" "Listener"
        } else {
            # Create new listener with certificate
            winrm create winrm/config/Listener?Address=*+Transport=HTTPS+Port=$Port CertificateThumbprint="$ThumbPrint"
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to create HTTPS listener"
            }
        }
        
        # Configure WinRM settings
        winrm set winrm/config/service '@{AllowUnencrypted="false"}'
        winrm set winrm/config/client '@{TrustedHosts="*"}'
        
        Write-Log "HTTPS listener configured successfully on port $Port with certificate $ThumbPrint" "Success" "Listener"
        return $true
    }
    catch {
        Write-Log "Error creating HTTPS listener: $($_.Exception.Message)" "Error" "Listener"
        return $false
    }
}

# Configure firewall rules
function Set-FirewallRules {
    param(
        [string]$WecIp,
        [string]$WecHostname,
        [string]$Type = "http",
        [int]$Port = 0
    )
    
    try {
        if (-not (Assert-ModuleAvailable "NetSecurity" "Set-FirewallRules")) {
            Write-Host "  Cannot configure firewall rules without NetSecurity module." -ForegroundColor Red
            return $false
        }
        Write-Log "Configuring firewall rules for WEC communication" "Info" "Firewall"
        
        # If specific port requested, create rule for that port only
        if ($Port -gt 0) {
            $ruleName = "WinRM-Custom-$Port-In"
            $description = "WinRM Custom Port $Port - Allow inbound connections for WEC log collection from $WecHostname ($WecIp)"
            Add-FirewallRuleIfMissing -DisplayName $ruleName -Port $Port
            Write-Log "Created firewall rule for custom port $Port" "Success" "Firewall"
            Write-Host "✓ Created firewall rule for port $Port" -ForegroundColor Green
        } else {
            # Create HTTP and HTTPS rules using Add-FirewallRuleIfMissing (validates duplicates)
            Add-FirewallRuleIfMissing -DisplayName "WinRM-HTTP-In" -Port 5985
            Add-FirewallRuleIfMissing -DisplayName "WinRM-HTTPS-In" -Port 5986
        }
        
        return $true
    }
    catch {
        Write-Log "Error configuring firewall: $($_.Exception.Message)" "Error" "Firewall"
        return $false
    }
}

# Configure WinRM policies
function Set-WinRMPolicies {
    try {
        Write-Log "Configuring WinRM policies" "Info" "Policies"
        
        Write-Host ""
        Write-Host ("=" * 60) -ForegroundColor Cyan
        Write-Host "CONFIGURE WINRM POLICIES" -ForegroundColor Yellow
        Write-Host ("=" * 60) -ForegroundColor Cyan
        Write-Host ""
        
        # Check current policies
        Write-Host "Current WinRM Policies:" -ForegroundColor Green
        $isDC = Test-DomainController
        Test-WinRMPolicies
        Test-SecurityLogAccess
        
        Write-Host ""
        Write-Host "Configuring policies..." -ForegroundColor Green
        
        # Check and configure Allow Basic Authentication (validate exists, prompt before create)
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
        $basicAuth = Get-ItemProperty -Path $regPath -Name "AllowBasic" -ErrorAction SilentlyContinue
        
        if (-not $basicAuth -or $basicAuth.AllowBasic -ne 1) {
            $doIt = $script:NoPrompt
            if (-not $doIt) { $response = Read-Host "  Allow Basic Authentication is not configured. Create/update policy? (y/n)"; $doIt = ($response -match '^[yY]') }
            if ($doIt) {
                try {
                    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                    Set-ItemProperty -Path $regPath -Name "AllowBasic" -Value 1 -Type DWord
                    Write-Host "  Allow Basic Authentication: Enabled" -ForegroundColor Green
                } catch { Write-Host "  Failed" -ForegroundColor Red }
            } else { Write-Host "  Skipped." -ForegroundColor Yellow }
        } else {
            Write-Host "  Allow Basic Authentication: Already configured" -ForegroundColor Cyan
        }
        
        # Check and configure Allow Unencrypted Traffic
        $unencrypted = Get-ItemProperty -Path $regPath -Name "AllowUnencrypted" -ErrorAction SilentlyContinue
        
        if (-not $unencrypted -or $unencrypted.AllowUnencrypted -ne 0) {
            $doIt = $script:NoPrompt
            if (-not $doIt) { $response = Read-Host "  Allow Unencrypted Traffic is not set as desired. Set to Disabled (0)? (y/n)"; $doIt = ($response -match '^[yY]') }
            if ($doIt) {
                try {
                    Set-ItemProperty -Path $regPath -Name "AllowUnencrypted" -Value 0 -Type DWord
                    Write-Host "  Allow Unencrypted Traffic: Disabled" -ForegroundColor Green
                } catch { Write-Host "  Failed" -ForegroundColor Red }
            } else { Write-Host "  Skipped." -ForegroundColor Yellow }
        } else {
            Write-Host "  Allow Unencrypted Traffic: Already configured" -ForegroundColor Cyan
        }
        
        # Check and configure Allow Remote Server Management
        $ipv4Filter = Get-ItemProperty -Path $regPath -Name "IPv4Filter" -ErrorAction SilentlyContinue
        $ipv6Filter = Get-ItemProperty -Path $regPath -Name "IPv6Filter" -ErrorAction SilentlyContinue
        
        # Use script params if provided (non-interactive/lab); otherwise ask
        $ipv4Input = $script:IPv4Filter
        $ipv6Input = $script:IPv6Filter
        if (-not $ipv4Input) { $ipv4Input = "" }
        if (-not $ipv6Input) { $ipv6Input = "" }
        if (-not $ipv4Filter -or -not $ipv6Filter -or $ipv4Filter.IPv4Filter -ne "*" -or $ipv6Filter.IPv6Filter -ne "*") {
            if (-not $ipv4Input -and -not $ipv6Input) {
                Write-Host "  Allow Remote Server Management (IPv4/IPv6 filter) is not configured." -ForegroundColor Yellow
                if ($script:NoPrompt) { $ipv4Input = "*"; $ipv6Input = "*" }
                else {
                    $response = Read-Host "  Create/update IP filters? (y/n)"
                    if ($response -notmatch '^[yY]') { Write-Host "  Skipped." -ForegroundColor Yellow }
                    else {
                        Write-Host "    Enter IPv4 filter (default: *): " -NoNewline
                        $ipv4Input = Read-Host
                        if ([string]::IsNullOrWhiteSpace($ipv4Input)) { $ipv4Input = "*" }
                        Write-Host "    Enter IPv6 filter (default: *): " -NoNewline
                        $ipv6Input = Read-Host
                        if ([string]::IsNullOrWhiteSpace($ipv6Input)) { $ipv6Input = "*" }
                    }
                }
            }
            if ([string]::IsNullOrWhiteSpace($ipv4Input)) { $ipv4Input = "*" }
            if ([string]::IsNullOrWhiteSpace($ipv6Input)) { $ipv6Input = "*" }
            
            if ($ipv4Input -or $ipv6Input) {
                $doIt = $script:NoPrompt
                if (-not $doIt) { $response = Read-Host "  Set IPv4Filter=$ipv4Input IPv6Filter=$ipv6Input? (y/n)"; $doIt = ($response -match '^[yY]') }
                if ($doIt) {
                    try {
                        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                        Set-ItemProperty -Path $regPath -Name "IPv4Filter" -Value $ipv4Input -Type String
                        Set-ItemProperty -Path $regPath -Name "IPv6Filter" -Value $ipv6Input -Type String
                        Write-Host "    IPv4 Filter: $ipv4Input" -ForegroundColor Green
                        Write-Host "    IPv6 Filter: $ipv6Input" -ForegroundColor Green
                    } catch { Write-Host "    Failed to configure IP filters" -ForegroundColor Red }
                } else { Write-Host "  Skipped." -ForegroundColor Yellow }
            }
        } else {
            Write-Host "  Allow Remote Server Management: " -NoNewline
            Write-Host "Already configured" -ForegroundColor Cyan
        }
        
        # Configure Configure Log Access - Always replace with the specified string via Registry
        $regPathEventLog = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
        $newChannelAccess = "O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;S-1-5-20)"
        $existingChannelAccess = Get-ItemProperty -Path $regPathEventLog -Name "ChannelAccess" -ErrorAction SilentlyContinue
        if (-not $existingChannelAccess -or $existingChannelAccess.ChannelAccess -ne $newChannelAccess) {
            $doIt = $script:NoPrompt
            if (-not $doIt) { $response = Read-Host "  Configure Log Access (Event Log Security) is not set. Create/update? (y/n)"; $doIt = ($response -match '^[yY]') }
            if ($doIt) {
                try {
                    if (-not (Test-Path $regPathEventLog)) { New-Item -Path $regPathEventLog -Force | Out-Null }
                    Set-ItemProperty -Path $regPathEventLog -Name "ChannelAccess" -Value $newChannelAccess -Type String
                    Restart-Service EventLog -Force -ErrorAction SilentlyContinue
                    Write-Host "  Configure Log Access: Enabled" -ForegroundColor Green
                    Write-Host "    ChannelAccess: $newChannelAccess" -ForegroundColor Cyan
                } catch { Write-Host "  Failed - $($_.Exception.Message)" -ForegroundColor Red }
            } else { Write-Host "  Skipped." -ForegroundColor Yellow }
        } else {
            Write-Host "  Configure Log Access: Already configured" -ForegroundColor Cyan
        }
        
        Write-Host ""
        Write-Host "Policy configuration completed!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Updated WinRM Policies:" -ForegroundColor Green
        $isDC = Test-DomainController | Out-Null
        Test-WinRMPolicies
        Test-SecurityLogAccess
        
        Write-Log "WinRM policies configured successfully" "Success" "Policies"
        return $true
    }
    catch {
        Write-Log "Error configuring WinRM policies: $($_.Exception.Message)" "Error" "Policies"
        return $false
    }
}

# Show all certificates available for WinRM
function Show-AllCertificates {
    try {
        Write-Log "Retrieving all certificates" "Info" "Certificates"
        
        Write-Host ""
        Write-Host ("=" * 60) -ForegroundColor Cyan
        Write-Host "AVAILABLE CERTIFICATES FOR WINRM" -ForegroundColor Yellow
        Write-Host ("=" * 60) -ForegroundColor Cyan
        Write-Host ""
        
        # Get all certificates from LocalMachine\My store
        $certificates = Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction SilentlyContinue
        
        if (-not $certificates -or $certificates.Count -eq 0) {
            Write-Host "No certificates found in LocalMachine\My store" -ForegroundColor Yellow
            Write-Host "→ Install a certificate with Server Authentication EKU to use HTTPS" -ForegroundColor Cyan
            return
        }
        
        # Separate certificates with and without Server Authentication EKU
        $serverAuthCerts = @()
        $otherCerts = @()
        
        foreach ($cert in $certificates) {
            $hasServerAuth = $false
            try {
                # Check Enhanced Key Usage extensions
                $eku = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Enhanced Key Usage" }
                if ($eku) {
                    $ekuString = $eku.Format($false)
                    if ($ekuString -match "Server Authentication" -or $ekuString -match "Autenticação do Servidor") {
                        $hasServerAuth = $true
                        $serverAuthCerts += $cert
                    } else {
                        $otherCerts += $cert
                    }
                } else {
                    # Alternative method: check EnhancedKeyUsageList property
                    $hasServerAuthEKU = $false
                    foreach ($eku in $cert.EnhancedKeyUsageList) {
                        if ($eku.FriendlyName -eq "Server Authentication" -or 
                            $eku.FriendlyName -eq "Autenticação do Servidor" -or
                            $eku.ObjectId -eq "1.3.6.1.5.5.7.3.1") {
                            $hasServerAuthEKU = $true
                            break
                        }
                    }
                    
                    if ($hasServerAuthEKU) {
                        $hasServerAuth = $true
                        $serverAuthCerts += $cert
                    } else {
                        $otherCerts += $cert
                    }
                }
            }
            catch {
                # If we can't check EKU, include in other certificates
                $otherCerts += $cert
            }
        }
        
        # Display certificates with Server Authentication EKU first
        if ($serverAuthCerts.Count -gt 0) {
            Write-Host "Certificates with Server Authentication EKU (Recommended for HTTPS):" -ForegroundColor Green
            Write-Host ""
            
            # Calculate column widths for server auth certs
            $maxSubjectLength = 0
            $maxIssuerLength = 0
            $maxThumbprintLength = 0
            $maxExpiryLength = 0
            
            foreach ($cert in $serverAuthCerts) {
                $subject = if ($cert.Subject) { $cert.Subject } else { "N/A" }
                $issuer = if ($cert.Issuer) { $cert.Issuer } else { "N/A" }
                $thumbprint = if ($cert.Thumbprint) { $cert.Thumbprint } else { "N/A" }
                $expiry = if ($cert.NotAfter) { $cert.NotAfter.ToString("yyyy-MM-dd") } else { "N/A" }
                
                if ($subject.Length -gt $maxSubjectLength) { $maxSubjectLength = $subject.Length }
                if ($issuer.Length -gt $maxIssuerLength) { $maxIssuerLength = $issuer.Length }
                if ($thumbprint.Length -gt $maxThumbprintLength) { $maxThumbprintLength = $thumbprint.Length }
                if ($expiry.Length -gt $maxExpiryLength) { $maxExpiryLength = $expiry.Length }
            }
            
            # Ensure minimum widths
            if ($maxSubjectLength -lt 20) { $maxSubjectLength = 20 }
            if ($maxIssuerLength -lt 20) { $maxIssuerLength = 20 }
            if ($maxThumbprintLength -lt 10) { $maxThumbprintLength = 10 }
            if ($maxExpiryLength -lt 10) { $maxExpiryLength = 10 }
            
            # Create table header
            $headerLine = "┌" + ("─" * ($maxSubjectLength + 2)) + "┬" + ("─" * ($maxIssuerLength + 2)) + "┬" + ("─" * ($maxThumbprintLength + 2)) + "┬" + ("─" * ($maxExpiryLength + 2)) + "┐"
            $separatorLine = "├" + ("─" * ($maxSubjectLength + 2)) + "┼" + ("─" * ($maxIssuerLength + 2)) + "┼" + ("─" * ($maxThumbprintLength + 2)) + "┼" + ("─" * ($maxExpiryLength + 2)) + "┤"
            $footerLine = "└" + ("─" * ($maxSubjectLength + 2)) + "┴" + ("─" * ($maxIssuerLength + 2)) + "┴" + ("─" * ($maxThumbprintLength + 2)) + "┴" + ("─" * ($maxExpiryLength + 2)) + "┘"
            
            Write-Host $headerLine -ForegroundColor Gray
            Write-Host "│ $("Subject".PadRight($maxSubjectLength)) │ $("Issuer".PadRight($maxIssuerLength)) │ $("Thumbprint".PadRight($maxThumbprintLength)) │ $("Expires".PadRight($maxExpiryLength)) │" -ForegroundColor Gray
            Write-Host $separatorLine -ForegroundColor Gray
            
            foreach ($cert in $serverAuthCerts) {
                $subject = if ($cert.Subject) { $cert.Subject } else { "N/A" }
                $issuer = if ($cert.Issuer) { $cert.Issuer } else { "N/A" }
                $thumbprint = if ($cert.Thumbprint) { $cert.Thumbprint } else { "N/A" }
                $expiry = if ($cert.NotAfter) { $cert.NotAfter.ToString("yyyy-MM-dd") } else { "N/A" }
                
                # Truncate long strings
                if ($subject.Length -gt 40) { $subject = $subject.Substring(0, 37) + "..." }
                if ($issuer.Length -gt 40) { $issuer = $issuer.Substring(0, 37) + "..." }
                
                Write-Host "│ $($subject.PadRight($maxSubjectLength)) │ $($issuer.PadRight($maxIssuerLength)) │ $($thumbprint.PadRight($maxThumbprintLength)) │ $($expiry.PadRight($maxExpiryLength)) │" -ForegroundColor White
            }
            
            Write-Host $footerLine -ForegroundColor Gray
            Write-Host ""
            Write-Host "Server Authentication certificates: " -NoNewline
            Write-Host $serverAuthCerts.Count -ForegroundColor Green
            Write-Host ""
        }
        
        # Display other certificates
        if ($otherCerts.Count -gt 0) {
            Write-Host "Other certificates (may not be suitable for HTTPS):" -ForegroundColor Yellow
            Write-Host ""
            
            # Calculate column widths for other certs
            $maxSubjectLength = 0
            $maxIssuerLength = 0
            $maxThumbprintLength = 0
            $maxExpiryLength = 0
            
            foreach ($cert in $otherCerts) {
                $subject = if ($cert.Subject) { $cert.Subject } else { "N/A" }
                $issuer = if ($cert.Issuer) { $cert.Issuer } else { "N/A" }
                $thumbprint = if ($cert.Thumbprint) { $cert.Thumbprint } else { "N/A" }
                $expiry = if ($cert.NotAfter) { $cert.NotAfter.ToString("yyyy-MM-dd") } else { "N/A" }
                
                if ($subject.Length -gt $maxSubjectLength) { $maxSubjectLength = $subject.Length }
                if ($issuer.Length -gt $maxIssuerLength) { $maxIssuerLength = $issuer.Length }
                if ($thumbprint.Length -gt $maxThumbprintLength) { $maxThumbprintLength = $thumbprint.Length }
                if ($expiry.Length -gt $maxExpiryLength) { $maxExpiryLength = $expiry.Length }
            }
            
            # Ensure minimum widths
            if ($maxSubjectLength -lt 20) { $maxSubjectLength = 20 }
            if ($maxIssuerLength -lt 20) { $maxIssuerLength = 20 }
            if ($maxThumbprintLength -lt 10) { $maxThumbprintLength = 10 }
            if ($maxExpiryLength -lt 10) { $maxExpiryLength = 10 }
            
            # Create table header
            $headerLine = "┌" + ("─" * ($maxSubjectLength + 2)) + "┬" + ("─" * ($maxIssuerLength + 2)) + "┬" + ("─" * ($maxThumbprintLength + 2)) + "┬" + ("─" * ($maxExpiryLength + 2)) + "┐"
            $separatorLine = "├" + ("─" * ($maxSubjectLength + 2)) + "┼" + ("─" * ($maxIssuerLength + 2)) + "┼" + ("─" * ($maxThumbprintLength + 2)) + "┼" + ("─" * ($maxExpiryLength + 2)) + "┤"
            $footerLine = "└" + ("─" * ($maxSubjectLength + 2)) + "┴" + ("─" * ($maxIssuerLength + 2)) + "┴" + ("─" * ($maxThumbprintLength + 2)) + "┴" + ("─" * ($maxExpiryLength + 2)) + "┘"
            
            Write-Host $headerLine -ForegroundColor Gray
            Write-Host "│ $("Subject".PadRight($maxSubjectLength)) │ $("Issuer".PadRight($maxIssuerLength)) │ $("Thumbprint".PadRight($maxThumbprintLength)) │ $("Expires".PadRight($maxExpiryLength)) │" -ForegroundColor Gray
            Write-Host $separatorLine -ForegroundColor Gray
            
            foreach ($cert in $otherCerts) {
                $subject = if ($cert.Subject) { $cert.Subject } else { "N/A" }
                $issuer = if ($cert.Issuer) { $cert.Issuer } else { "N/A" }
                $thumbprint = if ($cert.Thumbprint) { $cert.Thumbprint } else { "N/A" }
                $expiry = if ($cert.NotAfter) { $cert.NotAfter.ToString("yyyy-MM-dd") } else { "N/A" }
                
                # Truncate long strings
                if ($subject.Length -gt 40) { $subject = $subject.Substring(0, 37) + "..." }
                if ($issuer.Length -gt 40) { $issuer = $issuer.Substring(0, 37) + "..." }
                
                Write-Host "│ $($subject.PadRight($maxSubjectLength)) │ $($issuer.PadRight($maxIssuerLength)) │ $($thumbprint.PadRight($maxThumbprintLength)) │ $($expiry.PadRight($maxExpiryLength)) │" -ForegroundColor White
            }
            
            Write-Host $footerLine -ForegroundColor Gray
            Write-Host ""
            Write-Host "Other certificates: " -NoNewline
            Write-Host $otherCerts.Count -ForegroundColor Yellow
            Write-Host ""
        }
        
        # Summary
        Write-Host "SUMMARY:" -ForegroundColor Cyan
        Write-Host "  Total certificates: " -NoNewline
        Write-Host $certificates.Count -ForegroundColor White
        Write-Host "  Server Authentication: " -NoNewline
        Write-Host $serverAuthCerts.Count -ForegroundColor Green
        Write-Host "  Other certificates: " -NoNewline
        Write-Host $otherCerts.Count -ForegroundColor Yellow
        
        if ($serverAuthCerts.Count -eq 0) {
            Write-Host ""
            Write-Host "→ No certificates with Server Authentication EKU found" -ForegroundColor Yellow
            Write-Host "→ Install a certificate with Server Authentication EKU to use HTTPS" -ForegroundColor Cyan
        } else {
            Write-Host ""
            Write-Host "→ Use certificates with Server Authentication EKU for HTTPS listeners" -ForegroundColor Green
        }
        
        Write-Log "Certificate listing completed successfully" "Success" "Certificates"
        return $certificates
    }
    catch {
        Write-Log "Error listing certificates: $($_.Exception.Message)" "Error" "Certificates"
        Write-Host ""
        Write-Host ("=" * 60) -ForegroundColor Cyan
        Write-Host "AVAILABLE CERTIFICATES FOR WINRM" -ForegroundColor Yellow
        Write-Host ("=" * 60) -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  ✗ Error retrieving certificates: " -NoNewline
        Write-Host $_.Exception.Message -ForegroundColor Red
        return $null
    }
}

# Export CA certificate
function Export-CACertificate {
    param([string]$ExportPath)
    
    try {
        Write-Log "Exporting CA certificate to: $ExportPath" "Info" "CertificateExport"
        
        Write-Host ""
        Write-Host ("=" * 60) -ForegroundColor Cyan
        Write-Host "EXPORT CA CERTIFICATE" -ForegroundColor Yellow
        Write-Host ("=" * 60) -ForegroundColor Cyan
        Write-Host ""
        
        if (-not $ExportPath) {
            Write-Host "  ✗ Export path not specified" -ForegroundColor Red
            Write-Host "  → Use -ExportCertPath parameter to specify export location" -ForegroundColor Yellow
            return $false
        }
        
        # Get CA certificate from Trusted Root Certification Authorities
        $caCerts = Get-ChildItem -Path "Cert:\LocalMachine\Root" -ErrorAction SilentlyContinue
        
        if (-not $caCerts -or $caCerts.Count -eq 0) {
            Write-Host "  ✗ No CA certificates found in Trusted Root store" -ForegroundColor Red
            return $false
        }
        
        # Find the most relevant CA certificate (usually the one with most recent expiry)
        $selectedCert = $caCerts | Sort-Object NotAfter -Descending | Select-Object -First 1
        
        if (-not $selectedCert) {
            Write-Host "  ✗ Could not select CA certificate" -ForegroundColor Red
            return $false
        }
        
        # Export the certificate
        try {
            $exportBytes = $selectedCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            [System.IO.File]::WriteAllBytes($ExportPath, $exportBytes)
            
            Write-Host "  ✓ CA certificate exported successfully" -ForegroundColor Green
            Write-Host "  → File: " -NoNewline
            Write-Host $ExportPath -ForegroundColor Cyan
            Write-Host "  → Subject: " -NoNewline
            Write-Host $selectedCert.Subject -ForegroundColor Cyan
            Write-Host "  → Thumbprint: " -NoNewline
            Write-Host $selectedCert.Thumbprint -ForegroundColor Cyan
            
            Write-Log "CA certificate exported successfully to: $ExportPath" "Success" "CertificateExport"
            return $true
        }
        catch {
            Write-Host "  ✗ Failed to export certificate: " -NoNewline
            Write-Host $_.Exception.Message -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Log "Error exporting CA certificate: $($_.Exception.Message)" "Error" "CertificateExport"
        Write-Host ""
        Write-Host ("=" * 60) -ForegroundColor Cyan
        Write-Host "EXPORT CA CERTIFICATE" -ForegroundColor Yellow
        Write-Host ("=" * 60) -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  ✗ Error during export: " -NoNewline
        Write-Host $_.Exception.Message -ForegroundColor Red
        return $false
    }
}

# Generate comprehensive report
function Generate-Report {
    try {
        Write-Log "Generating comprehensive WinRM report" "Info" "Report"
        
        Write-Host ""
        Write-Host ("=" * 60) -ForegroundColor Cyan
        Write-Host "WINRM COMPREHENSIVE REPORT" -ForegroundColor Yellow
        Write-Host ("=" * 60) -ForegroundColor Cyan
        Write-Host ""
        
        $reportData = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            SystemInfo = @{}
            WinRMStatus = @{}
            Certificates = @{}
            FirewallRules = @{}
            Policies = @{}
            Recommendations = @()
        }
        
        # System Information (CimInstance is faster than WmiObject)
        Write-Host "Collecting system information..." -ForegroundColor Cyan
        try {
            $computerInfo = Get-CimInstance -ClassName Win32_ComputerSystem -Property Name,Domain -ErrorAction SilentlyContinue
            $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -Property Caption,Version,OSArchitecture -ErrorAction SilentlyContinue
            $reportData.SystemInfo = @{
                ComputerName = $computerInfo.Name
                Domain = $computerInfo.Domain
                OS = $osInfo.Caption
                Version = $osInfo.Version
                Architecture = $osInfo.OSArchitecture
            }
        }
        catch {
            Write-Host "  ⚠ Could not collect system information" -ForegroundColor Yellow
        }
        
        # WinRM Status
        Write-Host "Collecting WinRM status..." -ForegroundColor Cyan
        try {
            $winrmService = Get-Service -Name "WinRM" -ErrorAction SilentlyContinue
            $activeListeners = Get-ActiveListeners
            
            $reportData.WinRMStatus = @{
                ServiceStatus = $winrmService.Status
                StartType = $winrmService.StartType
                Listeners = $activeListeners
            }
        }
        catch {
            Write-Host "  ⚠ Could not collect WinRM status" -ForegroundColor Yellow
        }
        
        # Certificates
        Write-Host "Collecting certificate information..." -ForegroundColor Cyan
        try {
            $certificates = Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction SilentlyContinue
            $reportData.Certificates = @{
                Count = $certificates.Count
                Certificates = $certificates | Select-Object Subject, Issuer, Thumbprint, NotAfter
            }
        }
        catch {
            Write-Host "  ⚠ Could not collect certificate information" -ForegroundColor Yellow
        }
        
        # Firewall Rules (targeted query by name pattern - avoids full enumeration)
        Write-Host "Collecting firewall rules..." -ForegroundColor Cyan
        try {
            $firewallRules = Get-WinRMFirewallRules
            $reportData.FirewallRules = @{
                Count = $firewallRules.Count
                Rules = $firewallRules | Select-Object DisplayName, Enabled, Direction
            }
        }
        catch {
            Write-Host "  ⚠ Could not collect firewall rules" -ForegroundColor Yellow
        }
        
        # Policies
        Write-Host "Collecting WinRM policies..." -ForegroundColor Cyan
        try {
            $isDC = Test-DomainController
            $policies = Test-WinRMPolicies
            $logAccess = Test-SecurityLogAccess
            
            $reportData.Policies = @{
                DomainController = $isDC
                WinRMPolicies = $policies
                LogAccess = $logAccess
            }
        }
        catch {
            Write-Host "  ⚠ Could not collect policy information" -ForegroundColor Yellow
        }
        
        # Generate recommendations
        Write-Host "Generating recommendations..." -ForegroundColor Cyan
        $recommendations = @()
        
        if ($reportData.WinRMStatus.ServiceStatus -ne "Running") {
            $recommendations += "Start WinRM service"
        }
        
        if ($reportData.WinRMStatus.Listeners.Count -eq 0) {
            $recommendations += "Configure WinRM listeners for log collection"
        }
        
        if ($reportData.Certificates.Count -eq 0) {
            $recommendations += "Install certificates for HTTPS listeners"
        }
        
        if ($reportData.FirewallRules.Count -eq 0) {
            $recommendations += "Configure firewall rules for WinRM"
        }
        
        $reportData.Recommendations = $recommendations
        
        # Display report summary
        Write-Host ""
        Write-Host "REPORT SUMMARY:" -ForegroundColor Green
        Write-Host "  System: " -NoNewline
        Write-Host "$($reportData.SystemInfo.ComputerName) ($($reportData.SystemInfo.OS))" -ForegroundColor Cyan
        Write-Host "  WinRM Service: " -NoNewline
        Write-Host $reportData.WinRMStatus.ServiceStatus -ForegroundColor $(if ($reportData.WinRMStatus.ServiceStatus -eq "Running") { "Green" } else { "Red" })
        Write-Host "  Active Listeners: " -NoNewline
        Write-Host $reportData.WinRMStatus.Listeners.Count -ForegroundColor Cyan
        Write-Host "  Certificates: " -NoNewline
        Write-Host $reportData.Certificates.Count -ForegroundColor Cyan
        Write-Host "  Firewall Rules: " -NoNewline
        Write-Host $reportData.FirewallRules.Count -ForegroundColor Cyan
        
        if ($reportData.Recommendations.Count -gt 0) {
            Write-Host ""
            Write-Host "RECOMMENDATIONS:" -ForegroundColor Yellow
            foreach ($rec in $reportData.Recommendations) {
                Write-Host "  • $rec" -ForegroundColor Yellow
            }
        }
        
        Write-Host ""
        Write-Host "Report generation completed!" -ForegroundColor Green
        
        # Export to file if requested (ReportFormat Html/Txt and ReportOutputPath set)
        $fmt = $script:ReportFormat
        $outPath = $script:ReportOutputPath
        if ($fmt -ne "Screen" -and $outPath) {
            $outDir = Split-Path -Parent $outPath
            if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
            try {
                if ($fmt -eq "Txt") {
                    $lines = @(
                        "WinRM Configuration Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
                        "System: $($reportData.SystemInfo.ComputerName) | $($reportData.SystemInfo.OS) | $($reportData.SystemInfo.Architecture)",
                        "WinRM Service: $($reportData.WinRMStatus.ServiceStatus) | StartType: $($reportData.WinRMStatus.StartType)",
                        "Active Listeners: $($reportData.WinRMStatus.Listeners.Count)",
                        "Certificates: $($reportData.Certificates.Count)",
                        "Firewall Rules: $($reportData.FirewallRules.Count)",
                        "Domain Controller: $($reportData.Policies.DomainController)",
                        "Recommendations: $(($reportData.Recommendations) -join '; ')"
                    )
                    $lines | Out-File -FilePath $outPath -Encoding UTF8
                } elseif ($fmt -eq "Html") {
                    $html = @"
<!DOCTYPE html><html><head><meta charset='utf-8'><title>WinRM Report</title><style>body{font-family:Segoe UI,sans-serif;margin:20px;} table{border-collapse:collapse;} th,td{border:1px solid #ccc;padding:6px;} th{background:#eee;}</style></head><body>
<h1>WinRM Configuration Report</h1><p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
<h2>System</h2><p>$($reportData.SystemInfo.ComputerName) | $($reportData.SystemInfo.OS) | $($reportData.SystemInfo.Architecture)</p>
<h2>WinRM</h2><p>Service: $($reportData.WinRMStatus.ServiceStatus) | StartType: $($reportData.WinRMStatus.StartType) | Listeners: $($reportData.WinRMStatus.Listeners.Count)</p>
<h2>Certificates</h2><p>Count: $($reportData.Certificates.Count)</p>
<h2>Firewall Rules</h2><p>Count: $($reportData.FirewallRules.Count)</p>
<h2>Recommendations</h2><ul>$(( $reportData.Recommendations | ForEach-Object { "<li>$_</li>" } ) -join '')</ul>
</body></html>
"@
                    $html | Out-File -FilePath $outPath -Encoding UTF8
                }
                Write-Host "Report exported to: $outPath" -ForegroundColor Green
                Write-Log "Report exported to $outPath" "Success" "Report"
            } catch {
                Write-Host "Export failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        
        Write-Log "Comprehensive report generated successfully" "Success" "Report"
        return $reportData
    }
    catch {
        Write-Log "Error generating report: $($_.Exception.Message)" "Error" "Report"
        Write-Host ""
        Write-Host ("=" * 60) -ForegroundColor Cyan
        Write-Host "WINRM COMPREHENSIVE REPORT" -ForegroundColor Yellow
        Write-Host ("=" * 60) -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  ✗ Error generating report: " -NoNewline
        Write-Host $_.Exception.Message -ForegroundColor Red
        return $null
    }
}

# Check user permissions for WEC/WEF
function Test-UserPermissions {
    param([string]$Username)
    
    try {
        Write-Log "Checking permissions for user: $Username" "Info" "UserPermissions"
        
        if (-not (Test-User -Username $Username)) {
            Write-Log "User $Username does not exist" "Error" "UserPermissions"
            Write-Host ""
            Write-Host ("=" * 60) -ForegroundColor Cyan
            Write-Host "USER PERMISSIONS VALIDATION" -ForegroundColor Yellow
            Write-Host ("=" * 60) -ForegroundColor Cyan
            Write-Host ""
            Write-Host "  ✗ User not found: " -NoNewline
            Write-Host $Username -ForegroundColor Red
            Write-Host "  → Please verify the username and try again" -ForegroundColor Yellow
            return $false
        }
    
        Write-Host ""
        Write-Host ("=" * 60) -ForegroundColor Cyan
        Write-Host "USER PERMISSIONS VALIDATION" -ForegroundColor Yellow
        Write-Host ("=" * 60) -ForegroundColor Cyan
        Write-Host ""
        
        # Check Event Log Readers group membership
        $inEventLogReaders = Test-UserInEventLogReaders -Username $Username
        Write-Host "Event Log Readers Group:" -ForegroundColor Green
        if ($inEventLogReaders) {
            Write-Host "  ✓ User is member of Event Log Readers group" -ForegroundColor Green
        } else {
            Write-Host "  ✗ User is NOT member of Event Log Readers group" -ForegroundColor Red
            Write-Host "  → Recommendation: Add user to Event Log Readers group" -ForegroundColor Yellow
        }
        
        # Check WMI permissions
        Write-Host ""
        Write-Host "WMI Permissions:" -ForegroundColor Green
        try {
            $wmiTest = Get-CimInstance -ClassName Win32_ComputerSystem -Property Name -ErrorAction SilentlyContinue
            if ($wmiTest) {
                Write-Host "  ✓ WMI access is available" -ForegroundColor Green
            } else {
                Write-Host "  ✗ WMI access may be restricted" -ForegroundColor Red
            }
        }
        catch {
            Write-Host "  ✗ WMI access denied: $($_.Exception.Message)" -ForegroundColor Red
        }
        
        # Check WinRM access
        Write-Host ""
        Write-Host "WinRM Access:" -ForegroundColor Green
        try {
            $winrmTest = & winrm get winrm/config 2>$null
            if ($winrmTest) {
                Write-Host "  ✓ WinRM configuration accessible" -ForegroundColor Green
            } else {
                Write-Host "  ✗ WinRM configuration not accessible" -ForegroundColor Red
            }
        }
        catch {
            Write-Host "  ✗ WinRM access denied: $($_.Exception.Message)" -ForegroundColor Red
        }
        
        # Check Event Log access
        Write-Host ""
        Write-Host "Event Log Access:" -ForegroundColor Green
        try {
            $eventLogTest = Get-WinEvent -ListLog Security -MaxEvents 1 -ErrorAction SilentlyContinue
            if ($eventLogTest) {
                Write-Host "  ✓ Security event log accessible" -ForegroundColor Green
            } else {
                Write-Host "  ✗ Security event log not accessible" -ForegroundColor Red
            }
        }
        catch {
            Write-Host "  ✗ Event log access denied: $($_.Exception.Message)" -ForegroundColor Red
        }
        
        # Check specific event log permissions
        Write-Host ""
        Write-Host "Detailed Event Log Permissions:" -ForegroundColor Green
        try {
            # Check if user can read from Security log
            $securityLog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
            if ($securityLog) {
                Write-Host "  ✓ Security log is accessible for reading" -ForegroundColor Green
            }
            
            # Check if user can read from System log
            $systemLog = Get-WinEvent -ListLog System -ErrorAction SilentlyContinue
            if ($systemLog) {
                Write-Host "  ✓ System log is accessible for reading" -ForegroundColor Green
            }
            
            # Check if user can read from Application log
            $applicationLog = Get-WinEvent -ListLog Application -ErrorAction SilentlyContinue
            if ($applicationLog) {
                Write-Host "  ✓ Application log is accessible for reading" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "  ✗ Detailed event log access check failed: $($_.Exception.Message)" -ForegroundColor Red
        }
        
        # Check Registry permissions for event logs
        Write-Host ""
        Write-Host "Registry Permissions:" -ForegroundColor Green
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog"
            $regTest = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            if ($regTest) {
                Write-Host "  ✓ Event log registry access is available" -ForegroundColor Green
            } else {
                Write-Host "  ✗ Event log registry access may be restricted" -ForegroundColor Red
            }
        }
        catch {
            Write-Host "  ✗ Registry access denied: $($_.Exception.Message)" -ForegroundColor Red
        }
        
        # Summary
        Write-Host ""
        Write-Host "Summary:" -ForegroundColor Yellow
        if ($inEventLogReaders) {
            Write-Host "  ✓ User has basic permissions for WEC/WEF log collection" -ForegroundColor Green
            Write-Host "  → User can perform log collection operations" -ForegroundColor Cyan
        } else {
            Write-Host "  ✗ User needs to be added to Event Log Readers group" -ForegroundColor Red
            Write-Host "  → Run: .\winrmconfig.ps1 -Action enable -User `"$Username`"" -ForegroundColor Cyan
        }
        
        return $inEventLogReaders
    }
    catch {
        Write-Log "Error checking user permissions: $($_.Exception.Message)" "Error" "UserPermissions"
        Write-Host ""
        Write-Host ("=" * 60) -ForegroundColor Cyan
        Write-Host "USER PERMISSIONS VALIDATION" -ForegroundColor Yellow
        Write-Host ("=" * 60) -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  ✗ Error during permission check: " -NoNewline
        Write-Host $_.Exception.Message -ForegroundColor Red
        return $false
    }
}

# Get active listeners with details
function Get-ActiveListeners {
    try {
        Write-Log "Getting active WinRM listeners" "Info" "Listeners"
        
        $listeners = @()
        
        # Get all listeners
        try {
            $allListeners = & winrm enumerate winrm/config/listener 2>$null
            if ($allListeners) {
                # Parse HTTP listeners
                if ($allListeners -match "Transport = HTTP") {
                    $listeners += @{
                        Type = "HTTP"
                        Port = "5985"
                        Address = "*"
                        Transport = "HTTP"
                        Status = "Active"
                    }
                }
                
                # Parse HTTPS listeners
                if ($allListeners -match "Transport = HTTPS") {
                    $listeners += @{
                        Type = "HTTPS"
                        Port = "5986"
                        Address = "*"
                        Transport = "HTTPS"
                        Status = "Active"
                    }
                }
            }
        }
        catch {
            Write-Log "No listeners found" "Info" "Listeners"
        }
        
        return $listeners
    }
    catch {
        Write-Log "Error getting active listeners: $($_.Exception.Message)" "Error" "Listeners"
        return @()
    }
}

# Check WinRM policies via Registry
function Test-WinRMPolicies {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
    
    try {
        if (Test-Path $regPath) {
            # Allow Basic Authentication
            $basicAuth = Get-ItemProperty -Path $regPath -Name "AllowBasic" -ErrorAction SilentlyContinue
            if ($basicAuth) {
                $status = if ($basicAuth.AllowBasic -eq 1) { "Enabled" } else { "Disabled" }
                $color = if ($basicAuth.AllowBasic -eq 1) { "Green" } else { "Red" }
                Write-Host "  Allow Basic Authentication: " -NoNewline
                Write-Host $status -ForegroundColor $color
            } else {
                Write-Host "  Allow Basic Authentication: " -NoNewline
                Write-Host "Not configured" -ForegroundColor Yellow
            }
            
            # Allow Unencrypted Traffic
            $unencrypted = Get-ItemProperty -Path $regPath -Name "AllowUnencrypted" -ErrorAction SilentlyContinue
            if ($unencrypted) {
                $status = if ($unencrypted.AllowUnencrypted -eq 1) { "Enabled" } else { "Disabled" }
                $color = if ($unencrypted.AllowUnencrypted -eq 1) { "Green" } else { "Red" }
                Write-Host "  Allow Unencrypted Traffic: " -NoNewline
                Write-Host $status -ForegroundColor $color
            } else {
                Write-Host "  Allow Unencrypted Traffic: " -NoNewline
                Write-Host "Not configured" -ForegroundColor Yellow
            }
            
            # Allow Remote Server Management (verificar se tem filtros IP)
            $ipv4Filter = Get-ItemProperty -Path $regPath -Name "IPv4Filter" -ErrorAction SilentlyContinue
            $ipv6Filter = Get-ItemProperty -Path $regPath -Name "IPv6Filter" -ErrorAction SilentlyContinue
            
            if ($ipv4Filter -or $ipv6Filter) {
                $filters = @()
                if ($ipv4Filter) { $filters += "IPv4: $($ipv4Filter.IPv4Filter)" }
                if ($ipv6Filter) { $filters += "IPv6: $($ipv6Filter.IPv6Filter)" }
                Write-Host "  Allow Remote Server Management: " -NoNewline
                Write-Host "Active ($($filters -join ', '))" -ForegroundColor Green
            } else {
                Write-Host "  Allow Remote Server Management: " -NoNewline
                Write-Host "Not configured" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  Allow Basic Authentication: " -NoNewline
            Write-Host "Not configured" -ForegroundColor Yellow
            Write-Host "  Allow Unencrypted Traffic: " -NoNewline
            Write-Host "Not configured" -ForegroundColor Yellow
            Write-Host "  Allow Remote Server Management: " -NoNewline
            Write-Host "Not configured" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Error checking WinRM policies" -ForegroundColor Red
    }
}

# Check Security Log ChannelAccess
function Test-SecurityLogAccess {
    try {
        $securityLogConfig = & wevtutil gl Security 2>$null
        if ($securityLogConfig -and $securityLogConfig.Length -gt 0) {
            # Procurar por channelAccess na saída
            $channelAccessLine = $securityLogConfig | Where-Object { $_ -match "channelAccess:" }
            if ($channelAccessLine) {
                $channelAccess = ($channelAccessLine -split "channelAccess:")[1].Trim()
                
                # Verificar se contém a string necessária
                $requiredSid = "(A;;0x1;;;S-1-5-20)"
                if ($channelAccess.Contains($requiredSid)) {
                    Write-Host "  Configure Log Access: " -NoNewline
                    Write-Host "Active (ChannelAccess: $channelAccess) - OK" -ForegroundColor Green
                } else {
                    Write-Host "  Configure Log Access: " -NoNewline
                    Write-Host "Active (ChannelAccess: $channelAccess) - Needs adjustment (missing $requiredSid)" -ForegroundColor Yellow
                }
            } else {
                Write-Host "  Configure Log Access: " -NoNewline
                Write-Host "Not configured" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  Configure Log Access: " -NoNewline
            Write-Host "Not configured" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  Configure Log Access: Error checking configuration" -ForegroundColor Red
    }
}

# Check Domain Controller status (uses Get-CimInstance - faster than Get-WmiObject)
function Test-DomainController {
    try {
        $domainRole = (Get-CimInstance -ClassName Win32_ComputerSystem -Property DomainRole -ErrorAction Stop).DomainRole
        if ($domainRole -eq 4 -or $domainRole -eq 5) {
            Write-Host "  Domain Controller Check: " -NoNewline
            Write-Host "Domain Controller" -ForegroundColor Green
            return $true
        } else {
            Write-Host "  Domain Controller Check: " -NoNewline
            Write-Host "Not domain controller" -ForegroundColor Yellow
            return $false
        }
    }
    catch {
        Write-Host "  Domain Controller Check: Error checking status" -ForegroundColor Red
        return $false
    }
}

# Get system status
function Get-SystemStatus {
    param([int]$Port = 0)
    
    Write-Log "Generating system status report" "Info" "Status"
    
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "WINRM CONFIGURATION STATUS" -ForegroundColor Yellow
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host ""
    
    # Service status
    $winrmService = Get-Service -Name "WinRM" -ErrorAction SilentlyContinue
    $firewallService = Get-Service -Name "MpsSvc" -ErrorAction SilentlyContinue
    
    Write-Host "`nServices:" -ForegroundColor Green
    Write-Host "  WinRM Service: " -NoNewline
    if ($winrmService.Status -eq "Running") { Write-Host $winrmService.Status -ForegroundColor Green -NoNewline } else { Write-Host $winrmService.Status -ForegroundColor Red -NoNewline }
    Write-Host ""
    Write-Host "  WinRM Startup Mode: " -NoNewline
    if ($winrmService.StartType -eq "Automatic") { Write-Host $winrmService.StartType -ForegroundColor Blue -NoNewline } else { Write-Host $winrmService.StartType -ForegroundColor Yellow -NoNewline }
    Write-Host ""
    Write-Host "  Firewall Service: " -NoNewline
    if ($firewallService.Status -eq "Running") { Write-Host $firewallService.Status -ForegroundColor Green -NoNewline } else { Write-Host $firewallService.Status -ForegroundColor Red -NoNewline }
    Write-Host ""
    
    # Listeners (only if WinRM service is running)
    Write-Host "`nListeners:" -ForegroundColor Green
    if ($winrmService.Status -eq "Running") {
        try {
            $listeners = & winrm enumerate winrm/config/listener 2>$null
            if ($listeners) {
                # Check for HTTP listener
                Write-Host "  HTTP Listener: " -NoNewline
                if ($listeners -match "Transport = HTTP") {
                    Write-Host "Active" -ForegroundColor Green
                } else {
                    Write-Host "Inactive" -ForegroundColor Red
                }
                
                # Check for HTTPS listener
                Write-Host "  HTTPS Listener: " -NoNewline
                if ($listeners -match "Transport = HTTPS") {
                    Write-Host "Active" -ForegroundColor Green
                } else {
                    Write-Host "Inactive" -ForegroundColor Red
                }
            } else {
                Write-Host "  HTTP Listener: " -NoNewline
                Write-Host "Inactive" -ForegroundColor Red
                Write-Host "  HTTPS Listener: " -NoNewline
                Write-Host "Inactive" -ForegroundColor Red
            }
        }
        catch {
            Write-Host "  HTTP Listener: " -NoNewline
            Write-Host "Unable to enumerate" -ForegroundColor Red
            Write-Host "  HTTPS Listener: " -NoNewline
            Write-Host "Unable to enumerate" -ForegroundColor Red
        }
    } else {
        Write-Host "  HTTP Listener: " -NoNewline
        Write-Host "Inactive" -ForegroundColor Red
        Write-Host "  HTTPS Listener: " -NoNewline
        Write-Host "Inactive" -ForegroundColor Red
    }
    
    # Firewall rules (targeted query — avoids full enumeration of all rules)
    Write-Host "`nFirewall Rules:" -ForegroundColor Green
    $allWinRMRules = Get-WinRMFirewallRules
    if ($Port -gt 0) {
        $winrmRules = $allWinRMRules | Where-Object {
            try {
                $pf = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_ -ErrorAction SilentlyContinue
                $pf -and $pf.LocalPort -eq $Port
            } catch { $false }
        }
    } else {
        $winrmRules = $allWinRMRules
    }

    if ($winrmRules) {
        $maxNameLength = ($winrmRules | ForEach-Object { $_.DisplayName.Length } | Measure-Object -Maximum).Maximum
        if ($maxNameLength -lt 55) { $maxNameLength = 55 }
        $maxPortLength = 4
        $maxStatusLength = 7
        $headerLine   = "┌" + ("─" * ($maxNameLength + 2)) + "┬" + ("─" * ($maxPortLength + 2)) + "┬" + ("─" * ($maxStatusLength + 2)) + "┐"
        $separatorLine = "├" + ("─" * ($maxNameLength + 2)) + "┼" + ("─" * ($maxPortLength + 2)) + "┼" + ("─" * ($maxStatusLength + 2)) + "┤"
        $footerLine   = "└" + ("─" * ($maxNameLength + 2)) + "┴" + ("─" * ($maxPortLength + 2)) + "┴" + ("─" * ($maxStatusLength + 2)) + "┘"
        Write-Host $headerLine -ForegroundColor Gray
        Write-Host "│ $("Rule Name".PadRight($maxNameLength)) │ $("Port".PadRight($maxPortLength)) │ $("Status".PadRight($maxStatusLength)) │" -ForegroundColor Gray
        Write-Host $separatorLine -ForegroundColor Gray
        foreach ($rule in $winrmRules) {
            $portStr = "N/A"
            try {
                $pf = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                if ($pf -and $pf.LocalPort) { $portStr = $pf.LocalPort.ToString() }
            } catch {
                if ($rule.DisplayName -like "*HTTP*" -and $rule.DisplayName -notlike "*HTTPS*") { $portStr = "5985" }
                elseif ($rule.DisplayName -like "*HTTPS*") { $portStr = "5986" }
                elseif ($rule.DisplayName -match "WinRM-Custom-(\d+)-In") { $portStr = $matches[1] }
            }
            $status = if ($rule.Enabled -eq "True") { "Enabled" } else { "Disabled" }
            Write-Host "│ $($rule.DisplayName.PadRight($maxNameLength)) │ $($portStr.PadRight($maxPortLength)) │ $($status.PadRight($maxStatusLength)) │" -ForegroundColor White
        }
        Write-Host $footerLine -ForegroundColor Gray
    } else {
        if ($Port -gt 0) { Write-Host "  No WinRM firewall rules found for port $Port" -ForegroundColor Yellow }
        else { Write-Host "  No WinRM firewall rules found for default ports (5985/5986)" -ForegroundColor Yellow }
    }
    
    # WinRM Policies Check
    Write-Host "`nWinRM Policies:" -ForegroundColor Green
    $isDC = Test-DomainController
    Test-WinRMPolicies
    Test-SecurityLogAccess
    
    Write-Host ""
}

# Show simple help (en-US or pt-BR via -Language)
function Show-SimpleHelp {
    if ($Language -eq "pt-BR") {
        Write-Host ""
        Write-Host "WinRM Configuration Script v$ScriptVersion" -ForegroundColor Cyan
        Write-Host "Configuracao simplificada do WinRM para coleta de logs WEC/WEF" -ForegroundColor White
        Write-Host ""
        Write-Host "USO:" -ForegroundColor Yellow
        Write-Host "  .\winrmconfig.ps1 -Action <acao> [parametros]"
        Write-Host ""
        Write-Host "ACOES:" -ForegroundColor Yellow
        Write-Host "  Enable/Disable     - Configurar ou remover listener WinRM (HTTP/HTTPS) - EXIGE: -User"
        Write-Host "  Status             - Exibir status atual do WinRM"
        Write-Host "  ConfigureFirewall  - Gerenciar regras de firewall (interativo)"
        Write-Host "  ConfigurePolicies  - Configurar politicas WinRM"
        Write-Host "  CheckPermissions   - Verificar permissoes do usuario para WEC/WEF - EXIGE: -User"
        Write-Host "  ShowAllCerts       - Listar certificados disponiveis para WinRM"
        Write-Host "  ExportCACert       - Exportar certificado CA - EXIGE: -ExportCertPath"
        Write-Host "  Report             - Gerar relatorio completo do WinRM"
        Write-Host "  EnsureWinRM        - Ativacao rapida: iniciar WinRM, politicas, firewall 5985/5986 (sem -User)"
        Write-Host "  ReadEvents         - Listar ultimos N eventos do canal (validar leitura; max 100) - local ou -TargetHost -User -Password"
        Write-Host "  ShowHelp           - Exibir esta mensagem de ajuda"
        Write-Host "  ShowHelpLong       - Exibir ajuda detalhada com exemplos"
        Write-Host ""
        Write-Host "EXEMPLOS RAPIDOS:" -ForegroundColor Yellow
        Write-Host "  .\winrmconfig.ps1 -Action Enable -User `"domain\user`""
        Write-Host "  .\winrmconfig.ps1 -Action EnsureWinRM"
        Write-Host "  .\winrmconfig.ps1 -Action ReadEvents -TargetHost 10.254.2.241 -User opc -Password 'xxx' -Channel Security -Count 10"
        Write-Host "  .\winrmconfig.ps1 -Action Disable (selecao interativa)"
        Write-Host "  .\winrmconfig.ps1 -Action CheckPermissions -User `"domain\user`""
        Write-Host "  .\winrmconfig.ps1 -Action Status"
        Write-Host ""
        Write-Host "Ajuda em ingles (padrao): .\winrmconfig.ps1 -Action ShowHelp"
        Write-Host "Ajuda em portugues: .\winrmconfig.ps1 -Action ShowHelp -Language pt-BR"
        Write-Host "Exemplos detalhados: .\winrmconfig.ps1 -Action ShowHelpLong [-Language pt-BR]"
        Write-Host ""
        return
    }
    Write-Host ""
    Write-Host "WinRM Configuration Script v$ScriptVersion" -ForegroundColor Cyan
    Write-Host "Simplified WinRM configuration for WEC/WEF log collection" -ForegroundColor White
    Write-Host ""
    Write-Host "USAGE:" -ForegroundColor Yellow
    Write-Host "  .\winrmconfig.ps1 -Action <action> [parameters]"
    Write-Host ""
    Write-Host "ACTIONS:" -ForegroundColor Yellow
    Write-Host "  Enable/Disable     - Configure or remove WinRM listener (HTTP/HTTPS) - REQUIRES: -User"
    Write-Host "  Status             - Show current WinRM configuration status"
    Write-Host "  ConfigureFirewall  - Interactive firewall rules management for WinRM"
    Write-Host "  ConfigurePolicies  - Configure WinRM policies"
    Write-Host "  CheckPermissions   - Check user permissions for WEC/WEF - REQUIRES: -User"
    Write-Host "  ShowAllCerts       - Show all available certificates for WinRM"
    Write-Host "  ExportCACert       - Export CA certificate - REQUIRES: -ExportCertPath"
    Write-Host "  Report             - Generate comprehensive WinRM report"
    Write-Host "  EnsureWinRM        - Quick fix: start WinRM, policies, firewall 5985/5986 (no -User)"
    Write-Host "  ReadEvents         - List last N events from channel (validates read; max 100) - local or -TargetHost -User -Password"
    Write-Host "  ShowHelp           - Show this help message"
    Write-Host "  ShowHelpLong       - Show detailed help with examples"
    Write-Host ""
    Write-Host "HELP LANGUAGE: -Language en-US (default) or -Language pt-BR"
    Write-Host ""
    Write-Host "QUICK EXAMPLES:" -ForegroundColor Yellow
    Write-Host "  .\winrmconfig.ps1 -Action Enable -User `"domain\user`""
    Write-Host "  .\winrmconfig.ps1 -Action EnsureWinRM"
    Write-Host "  .\winrmconfig.ps1 -Action ReadEvents -TargetHost 10.254.2.241 -User opc -Password 'xxx' -Channel Security -Count 10"
    Write-Host "  .\winrmconfig.ps1 -Action Disable (interactive selection)"
    Write-Host "  .\winrmconfig.ps1 -Action CheckPermissions -User `"domain\user`""
    Write-Host "  .\winrmconfig.ps1 -Action Status"
    Write-Host ""
    Write-Host "For detailed examples: .\winrmconfig.ps1 -Action ShowHelpLong"
    Write-Host "For help in Portuguese: .\winrmconfig.ps1 -Action ShowHelp -Language pt-BR"
    Write-Host ""
}

# Show detailed help (en-US or pt-BR via -Language)
function Show-DetailedHelp {
    if ($Language -eq "pt-BR") {
        Write-Host ""
        Write-Host "WinRM Configuration Script v$ScriptVersion - Ajuda Detalhada" -ForegroundColor Cyan
        Write-Host "Configuracao simplificada do WinRM para coleta de logs WEC/WEF" -ForegroundColor White
        Write-Host ""
        Write-Host "USO:" -ForegroundColor Yellow
        Write-Host "  .\winrmconfig.ps1 -Action <acao> [parametros]"
        Write-Host ""
        Write-Host "ACOES:" -ForegroundColor Yellow
        Write-Host "  Enable/Disable     - Configurar ou remover listener WinRM (HTTP/HTTPS)"
        Write-Host "  Status             - Exibir status atual do WinRM"
        Write-Host "  ConfigureFirewall  - Gerenciar regras de firewall (interativo)"
        Write-Host "  ConfigurePolicies  - Configurar politicas WinRM"
        Write-Host "  CheckPermissions   - Verificar permissoes do usuario para WEC/WEF"
        Write-Host "  ShowAllCerts       - Listar certificados disponiveis para WinRM"
        Write-Host "  ExportCACert       - Exportar certificado CA"
        Write-Host "  Report             - Gerar relatorio completo do WinRM"
        Write-Host "  EnsureWinRM        - Ativacao rapida: iniciar WinRM, politicas (estilo GPO), firewall 5985/5986"
        Write-Host "  ReadEvents         - Listar ultimos N eventos (default Security, 10, asc; max 100) para validar leitura"
        Write-Host "  ShowHelp           - Exibir ajuda resumida"
        Write-Host "  ShowHelpLong       - Exibir esta ajuda detalhada"
        Write-Host ""
        Write-Host "PARAMETROS:" -ForegroundColor Yellow
        Write-Host "  -Action         Acao a executar (OBRIGATORIO)"
        Write-Host "  -ListenerType   http ou https (OPCIONAL, default: http)"
        Write-Host "  -User           Usuario para coleta de logs (OBRIGATORIO para Enable/Disable/CheckPermissions)"
        Write-Host "  -Port           Porta customizada (OPCIONAL, default: 5985 HTTP, 5986 HTTPS)"
        Write-Host "  -ThumbPrint     Thumbprint do certificado HTTPS (OPCIONAL)"
        Write-Host "  -WecIp          IP do servidor WEC (para ConfigureFirewall)"
        Write-Host "  -WecHostname    Nome do host WEC (para ConfigureFirewall)"
        Write-Host "  -LogPath        Caminho dos logs (OPCIONAL, default: .\log)"
        Write-Host "  -ExportCertPath Caminho para exportar certificado CA (OBRIGATORIO para ExportCACert)"
        Write-Host "  -AuthType       basic, negotiate, kerberos (OPCIONAL, default: negotiate)"
        Write-Host "  -LogLevel       Error, Warning, Info, Debug (OPCIONAL, default: Error)"
        Write-Host "  -ConfigFile     Arquivo de config (OPCIONAL)"
        Write-Host "  -IPv4Filter     Filtro IPv4 para ConfigurePolicies (ex: * em lab)"
        Write-Host "  -IPv6Filter     Filtro IPv6 para ConfigurePolicies"
        Write-Host "  -Language       en-US (padrao) ou pt-BR - idioma da ajuda (ShowHelp/ShowHelpLong)"
        Write-Host "  ReadEvents: -TargetHost (default localhost), -User (remoto), -Password, -ListenerType, -Port, -Channel (default Security), -Count (1-100), -SortOrder (asc/desc)"
        Write-Host ""
        Write-Host "EXEMPLOS DETALHADOS:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  # Listener HTTP"
        Write-Host "  .\winrmconfig.ps1 -Action Enable -ListenerType http -User `"domain\user`""
        Write-Host ""
        Write-Host "  # Ativacao rapida (sem -User)"
        Write-Host "  .\winrmconfig.ps1 -Action EnsureWinRM"
        Write-Host ""
        Write-Host "  # Ler ultimos 10 eventos Security (local)"
        Write-Host "  .\winrmconfig.ps1 -Action ReadEvents"
        Write-Host ""
        Write-Host "  # Ler 20 eventos Application em host remoto"
        Write-Host "  .\winrmconfig.ps1 -Action ReadEvents -TargetHost 10.254.2.241 -User opc -Password 'Senha' -Channel Application -Count 20 -SortOrder desc"
        Write-Host ""
        Write-Host "  # Desabilitar listeners (interativo)"
        Write-Host "  .\winrmconfig.ps1 -Action Disable"
        Write-Host ""
        Write-Host "  # Verificar permissoes"
        Write-Host "  .\winrmconfig.ps1 -Action CheckPermissions -User `"domain\user`""
        Write-Host ""
        Write-Host "  # Status e politicas"
        Write-Host "  .\winrmconfig.ps1 -Action Status"
        Write-Host "  .\winrmconfig.ps1 -Action ConfigurePolicies -IPv4Filter `"*`" -IPv6Filter `"*`""
        Write-Host ""
        Write-Host "RESOLUCAO DE PROBLEMAS:" -ForegroundColor Yellow
        Write-Host "  winrm get winrm/config"
        Write-Host "  winrm enumerate winrm/config/listener"
        Write-Host "  Get-NetFirewallRule -DisplayName `"*WinRM*`""
        Write-Host "  Get-LocalGroupMember -Group `"Event Log Readers`""
        Write-Host ""
        return
    }
    Write-Host ""
    Write-Host "WinRM Configuration Script v$ScriptVersion - Detailed Help" -ForegroundColor Cyan
    Write-Host "Simplified WinRM configuration for WEC/WEF log collection" -ForegroundColor White
    Write-Host ""
    Write-Host "USAGE:" -ForegroundColor Yellow
    Write-Host "  .\winrmconfig.ps1 -Action <action> [parameters]"
    Write-Host ""
    Write-Host "ACTIONS:" -ForegroundColor Yellow
    Write-Host "  Enable/Disable     - Configure or remove WinRM listener (HTTP/HTTPS)"
    Write-Host "  Status             - Show current WinRM configuration status"
    Write-Host "  ConfigureFirewall  - Interactive firewall rules management for WinRM"
    Write-Host "  ConfigurePolicies  - Configure WinRM policies"
    Write-Host "  CheckPermissions   - Check user permissions for WEC/WEF"
    Write-Host "  ShowAllCerts       - Show all available certificates for WinRM"
    Write-Host "  ExportCACert       - Export CA certificate"
    Write-Host "  Report             - Generate comprehensive WinRM report"
    Write-Host "  EnsureWinRM        - Quick fix: start WinRM, set policies (GPO-style), firewall 5985/5986"
    Write-Host "  ReadEvents         - List last N events (default Security, 10, asc; max 100) to validate read access"
    Write-Host "  ShowHelp           - Show simple help message"
    Write-Host "  ShowHelpLong       - Show this detailed help"
    Write-Host ""
    Write-Host "PARAMETERS:" -ForegroundColor Yellow
    Write-Host "  -Action         Action to perform (REQUIRED)"
    Write-Host "  -ListenerType   http or https (OPTIONAL, default: http)"
    Write-Host "  -User           User account for log collection (REQUIRED for Enable/Disable/CheckPermissions)"
    Write-Host "  -Port           Custom port (OPTIONAL, default: 5985 for HTTP, 5986 for HTTPS)"
    Write-Host "  -ThumbPrint     Certificate thumbprint for HTTPS (OPTIONAL, auto-detected if not provided)"
    Write-Host "  -WecIp          WEC server IP address (REQUIRED for ConfigureFirewall)"
    Write-Host "  -WecHostname    WEC server hostname (REQUIRED for ConfigureFirewall)"
    Write-Host "  -LogPath        Path for log files (OPTIONAL, default: .\log)"
    Write-Host "  -ExportCertPath Path to export CA certificate (REQUIRED for ExportCACert)"
    Write-Host "  -AuthType       Authentication type: basic, negotiate, kerberos (OPTIONAL, default: negotiate)"
    Write-Host "  -LogLevel       Log level: Error, Warning, Info, Debug (OPTIONAL, default: Error)"
    Write-Host "  -ConfigFile     Configuration file path (OPTIONAL, default: config-sample.json)"
    Write-Host "  -IPv4Filter     IPv4 filter for ConfigurePolicies (e.g. * for lab)"
    Write-Host "  -IPv6Filter     IPv6 filter for ConfigurePolicies"
    Write-Host "  -Language       en-US (default) or pt-BR - help language for ShowHelp/ShowHelpLong only"
    Write-Host "  ReadEvents: -TargetHost (default localhost), -User (required for remote), -Password, -ListenerType (http/https), -Port, -Channel (default Security), -Count (1-100, default 10), -SortOrder (asc/desc, default asc)"
    Write-Host ""
    Write-Host "PARAMETER VARIATIONS:" -ForegroundColor Yellow
    Write-Host "  -User formats: domain\user, user@domain.com, localuser"
    Write-Host "  -ListenerType: http (5985), https (5986)"
    Write-Host "  -Port: 1-65535"
    Write-Host ""
    Write-Host "DETAILED EXAMPLES:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  .\winrmconfig.ps1 -Action Enable -ListenerType http -User `"domain\serviceaccount`""
    Write-Host "  .\winrmconfig.ps1 -Action Enable -ListenerType https -User `"domain\serviceaccount`" -ThumbPrint `"ABC123...`""
    Write-Host "  .\winrmconfig.ps1 -Action Enable -ListenerType http -User `"domain\serviceaccount`" -Port 8080"
    Write-Host "  .\winrmconfig.ps1 -Action Disable"
    Write-Host "  .\winrmconfig.ps1 -Action Disable -User `"*`""
    Write-Host "  .\winrmconfig.ps1 -Action ConfigureFirewall"
    Write-Host "  .\winrmconfig.ps1 -Action CheckPermissions -User `"domain\serviceaccount`""
    Write-Host "  .\winrmconfig.ps1 -Action Status"
    Write-Host "  .\winrmconfig.ps1 -Action ConfigurePolicies"
    Write-Host "  .\winrmconfig.ps1 -Action ShowAllCerts"
    Write-Host "  .\winrmconfig.ps1 -Action ExportCACert -ExportCertPath `"C:\temp\ca-cert.cer`""
    Write-Host "  .\winrmconfig.ps1 -Action Report"
    Write-Host "  .\winrmconfig.ps1 -Action EnsureWinRM"
    Write-Host "  .\winrmconfig.ps1 -Action ReadEvents"
    Write-Host "  .\winrmconfig.ps1 -Action ReadEvents -TargetHost 10.254.2.241 -User opc -Password 'pwd' -Channel Application -Count 20 -SortOrder desc"
    Write-Host ""
    Write-Host "TROUBLESHOOTING:" -ForegroundColor Yellow
    Write-Host "  winrm get winrm/config"
    Write-Host "  winrm enumerate winrm/config/listener"
    Write-Host "  Get-NetFirewallRule -DisplayName `"*WinRM*`""
    Write-Host "  Get-LocalGroupMember -Group `"Event Log Readers`""
    Write-Host ""
}

# Main execution
function Main {
        Write-Host ""
    Write-Host ""
    Write-Log "WinRM Configuration Script v$ScriptVersion started" "Info" "Main"
    
    # Check for help parameters without -Action
    $allArgs = $args -join " "
    if ($allArgs -match "help|\-h|\-\-help|\-\?") {
        Show-SimpleHelp
        Write-Host ""
        Write-Host ""
        return
    }
    
    # If no action specified, show simple help
    if (-not $Action) {
        Show-SimpleHelp
        Write-Host ""
        Write-Host ""
        return
    }
    
    switch ($Action) {
        "Enable" {
            if (-not $User) {
                Write-Log "User parameter is REQUIRED for Enable action" "Error" "Main"
                Write-Host "ERROR: -User parameter is REQUIRED for Enable action" -ForegroundColor Red
                Write-Host "Example: .\winrmconfig.ps1 -Action Enable -ListenerType http -User `"domain\user`"" -ForegroundColor Yellow
                return
            }
            
            # Check and configure WinRM service
            Write-Host "Checking WinRM service status..." -ForegroundColor Cyan
            $winrmService = Get-Service -Name "WinRM" -ErrorAction SilentlyContinue
            
            if ($winrmService.Status -ne "Running") {
                Write-Host "Configuring WinRM service..." -ForegroundColor Yellow
                try {
                    # Use winrm quickconfig to properly configure WinRM
                    $quickConfigResult = & winrm quickconfig -q 2>&1
            if ($LASTEXITCODE -eq 0) {
                        Write-Host "✓ WinRM service configured and started" -ForegroundColor Green
                        Write-Log "WinRM service configured successfully" "Success" "Main"
                    } else {
                        Write-Host "ℹ WinRM quickconfig completed with warnings" -ForegroundColor Cyan
                        Write-Log "WinRM quickconfig completed with warnings" "Info" "Main"
                }
            }
        catch {
                    Write-Host "ℹ WinRM quickconfig completed with warnings: $($_.Exception.Message)" -ForegroundColor Cyan
                    Write-Log "WinRM quickconfig completed with warnings: $($_.Exception.Message)" "Warning" "Main"
                }
        } else {
                Write-Host "✓ WinRM service is already running" -ForegroundColor Green
                Write-Host "Restarting WinRM service to ensure clean state..." -ForegroundColor Cyan
                try {
                    Restart-Service -Name "WinRM" -Force -ErrorAction Stop
                    Write-Host "✓ WinRM service restarted successfully" -ForegroundColor Green
                    Write-Log "WinRM service restarted successfully" "Success" "Main"
    }
    catch {
                    Write-Host "ℹ Could not restart WinRM service: $($_.Exception.Message)" -ForegroundColor Cyan
                    Write-Log "Could not restart WinRM service: $($_.Exception.Message)" "Warning" "Main"
                }
            }
            
            # Validate user
            if (-not (Test-User -Username $User)) {
                Write-Log "User does not exist: $User" "Error" "Main"
                Write-Host "ERROR: User '$User' does not exist" -ForegroundColor Red
                return
            }
            
            # Add user to Event Log Readers group
            Add-UserToEventLogReaders -Username $User
            
            # Set default port
            if (-not $Port) {
                $Port = if ($ListenerType -eq "https") { 5986 } else { 5985 }
            }
            
            # Configure listener
            if ($ListenerType -eq "http") {
                New-HTTPListener -Port $Port -User $User
        } else {
                New-HTTPSListener -Port $Port -ThumbPrint $ThumbPrint -User $User
            }
            
            # Configure policies
            Set-WinRMPolicies
            
            Write-Log "WinRM configuration completed successfully" "Success" "Main"
            Write-Host ""
            Write-Host ""
        }
        
        "Disable" {
    Write-Host ""
            Write-Host ("=" * 60) -ForegroundColor Cyan
            Write-Host "DISABLE WINRM LISTENERS" -ForegroundColor Yellow
            Write-Host ("=" * 60) -ForegroundColor Cyan
            
            # Get active listeners
            $activeListeners = Get-ActiveListeners
            
            if ($activeListeners.Count -eq 0) {
                Write-Host "No active WinRM listeners found." -ForegroundColor Yellow
                Write-Host "Nothing to disable." -ForegroundColor Green
                Write-Host ""
        Write-Host ""
        return
    }
    
            # Show active listeners
            Write-Host "`nActive WinRM Listeners:" -ForegroundColor Green
            Write-Host "┌─────────┬──────┬─────────┬──────────┐" -ForegroundColor Gray
            Write-Host "│ Type    │ Port │ Address │ Status   │" -ForegroundColor Gray
            Write-Host "├─────────┼──────┼─────────┼──────────┤" -ForegroundColor Gray
            
            foreach ($listener in $activeListeners) {
                Write-Host "│ $($listener.Type.PadRight(7)) │ $($listener.Port.PadRight(4)) │ $($listener.Address.PadRight(7)) │ $($listener.Status.PadRight(8)) │" -ForegroundColor White
            }
            Write-Host "└─────────┴──────┴─────────┴──────────┘" -ForegroundColor Gray
            
            # If user specified, use that; otherwise show selection menu
            if ($User) {
                if ($User -eq "*") {
                    Write-Host "`nDisabling ALL WinRM listeners..." -ForegroundColor Yellow
                    $selectedListeners = $activeListeners
                } else {
                    Write-Host "`nDisabling WinRM listeners for user: $User" -ForegroundColor Yellow
                    $selectedListeners = $activeListeners
                }
            } else {
                Write-Host "`nSelect listeners to disable:" -ForegroundColor Yellow
                Write-Host "1. Disable ALL listeners" -ForegroundColor White
                Write-Host "2. Disable HTTP listener only" -ForegroundColor White
                Write-Host "3. Disable HTTPS listener only" -ForegroundColor White
                Write-Host "4. Cancel" -ForegroundColor White
                
                do {
                    $choice = Read-Host "`nEnter your choice (1-4)"
                } while ($choice -notmatch '^[1-4]$')
                
                switch ($choice) {
                    "1" {
                        $selectedListeners = $activeListeners
                        Write-Host "Disabling ALL listeners..." -ForegroundColor Yellow
                    }
                    "2" {
                        $selectedListeners = $activeListeners | Where-Object { $_.Type -eq "HTTP" }
                        Write-Host "Disabling HTTP listener..." -ForegroundColor Yellow
                    }
                    "3" {
                        $selectedListeners = $activeListeners | Where-Object { $_.Type -eq "HTTPS" }
                        Write-Host "Disabling HTTPS listener..." -ForegroundColor Yellow
                    }
                    "4" {
                        Write-Host "Operation cancelled." -ForegroundColor Yellow
                        return
                    }
                }
            }
            
            # Disable selected listeners
            foreach ($listener in $selectedListeners) {
                Write-Host "`nDisabling $($listener.Type) listener..." -ForegroundColor Yellow
                
                try {
                    if ($listener.Type -eq "HTTP") {
                        winrm delete winrm/config/listener?Address=*+Transport=HTTP 2>$null
                        Write-Host "✓ HTTP listener removed" -ForegroundColor Green
                        
                        # Remove HTTP firewall rule
                        $httpRuleRemoved = Remove-NetFirewallRule -DisplayName "WinRM-HTTP-In" -ErrorAction SilentlyContinue
                        if ($httpRuleRemoved) {
                            Write-Host "✓ HTTP firewall rule removed" -ForegroundColor Green
                        } else {
                            Write-Host "ℹ HTTP firewall rule not found" -ForegroundColor Cyan
                        }
                    }
                    elseif ($listener.Type -eq "HTTPS") {
                        winrm delete winrm/config/listener?Address=*+Transport=HTTPS 2>$null
                        Write-Host "✓ HTTPS listener removed" -ForegroundColor Green
                        
                        # Remove HTTPS firewall rule
                        $httpsRuleRemoved = Remove-NetFirewallRule -DisplayName "WinRM-HTTPS-In" -ErrorAction SilentlyContinue
                        if ($httpsRuleRemoved) {
                            Write-Host "✓ HTTPS firewall rule removed" -ForegroundColor Green
                } else {
                            Write-Host "ℹ HTTPS firewall rule not found" -ForegroundColor Cyan
                        }
                    }
                }
                catch {
                    Write-Host "ℹ $($listener.Type) listener not found or already removed" -ForegroundColor Cyan
                }
            }
            
            Write-Host "`n✓ WinRM listeners disabled successfully" -ForegroundColor Green
            
            # Check if all listeners were removed and disable WinRM service if needed
            $remainingListeners = Get-ActiveListeners
            if ($remainingListeners.Count -eq 0) {
                Write-Host "`nDisabling WinRM service (no listeners remaining)..." -ForegroundColor Yellow
                try {
                    # Stop WinRM service
                    Stop-Service -Name "WinRM" -Force -ErrorAction SilentlyContinue
                    Write-Host "✓ WinRM service stopped" -ForegroundColor Green
                    
                    # Set WinRM service to disabled
                    Set-Service -Name "WinRM" -StartupType Disabled -ErrorAction SilentlyContinue
                    Write-Host "✓ WinRM service startup set to Disabled" -ForegroundColor Green
                    
                    Write-Log "WinRM service disabled successfully" "Success" "Main"
                }
                catch {
                    Write-Host "ℹ Could not disable WinRM service: $($_.Exception.Message)" -ForegroundColor Cyan
                    Write-Log "Could not disable WinRM service: $($_.Exception.Message)" "Warning" "Main"
                }
            }
            
            Write-Log "WinRM listeners disabled successfully" "Success" "Main"
            Write-Host ""
            Write-Host ""
        }
        
        "Status" {
            Get-SystemStatus -Port $Port
            Write-Host ""
            Write-Host ""
        }
        
        "ConfigureFirewall" {
            if (-not (Assert-ModuleAvailable "NetSecurity" "ConfigureFirewall")) {
                Write-Host "  Cannot manage firewall rules without the NetSecurity module." -ForegroundColor Red
                return
            }
            Write-Host ""
            Write-Host ("=" * 60) -ForegroundColor Cyan
            Write-Host "CONFIGURE WINRM FIREWALL RULES" -ForegroundColor Yellow
            Write-Host ("=" * 60) -ForegroundColor Cyan
            
            # Get current WinRM firewall rules (targeted - fast)
            $winrmRules = Get-WinRMFirewallRules
            
            if ($winrmRules) {
                Write-Host "`nCurrent WinRM Firewall Rules:" -ForegroundColor Green
                
                # Calculate column widths
                $maxNumLength = 3  # For "Num" column
                $maxNameLength = 0
                $maxPortLength = 0
                $maxStatusLength = 0
                
                foreach ($rule in $winrmRules) {
                    $nameLength = $rule.DisplayName.Length
                    if ($nameLength -gt $maxNameLength) { $maxNameLength = $nameLength }
                    
                    $portStr = "N/A"
                    try {
                        $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                        if ($portFilter.LocalPort) {
                            $portStr = $portFilter.LocalPort.ToString()
                        }
                    }
                    catch {
                        if ($rule.DisplayName -like "*HTTP*") { $portStr = "5985" }
                        elseif ($rule.DisplayName -like "*HTTPS*") { $portStr = "5986" }
                        elseif ($rule.DisplayName -like "*Custom*") { 
                            if ($rule.DisplayName -match "WinRM-Custom-(\d+)-In") {
                                $portStr = $matches[1]
                            }
                        }
                    }
                    
                    if ($portStr.Length -gt $maxPortLength) { $maxPortLength = $portStr.Length }
                    if ($maxStatusLength -lt 7) { $maxStatusLength = 7 }
                }
                
                # Ensure minimum widths
                if ($maxNameLength -lt 55) { $maxNameLength = 55 }
                if ($maxPortLength -lt 7) { $maxPortLength = 7 }  # Increased from 4 to 7
                if ($maxStatusLength -lt 10) { $maxStatusLength = 10 }  # Increased from 7 to 10
                
                # Create table header
                $headerLine = "┌" + ("─" * ($maxNumLength + 2)) + "┬" + ("─" * ($maxNameLength + 2)) + "┬" + ("─" * ($maxPortLength + 2)) + "┬" + ("─" * ($maxStatusLength + 2)) + "┐"
                $separatorLine = "├" + ("─" * ($maxNumLength + 2)) + "┼" + ("─" * ($maxNameLength + 2)) + "┼" + ("─" * ($maxPortLength + 2)) + "┼" + ("─" * ($maxStatusLength + 2)) + "┤"
                $footerLine = "└" + ("─" * ($maxNumLength + 2)) + "┴" + ("─" * ($maxNameLength + 2)) + "┴" + ("─" * ($maxPortLength + 2)) + "┴" + ("─" * ($maxStatusLength + 2)) + "┘"
                
                Write-Host $headerLine -ForegroundColor Gray
                Write-Host "│ $("Num".PadRight($maxNumLength)) │ $("Rule Name".PadRight($maxNameLength)) │ $("Port".PadRight($maxPortLength)) │ $("Status".PadRight($maxStatusLength)) │" -ForegroundColor Gray
                Write-Host $separatorLine -ForegroundColor Gray
                
                $ruleIndex = 1
                foreach ($rule in $winrmRules) {
                    $portStr = "N/A"
                    
                    try {
                        $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                        if ($portFilter.LocalPort) {
                            $portStr = $portFilter.LocalPort.ToString()
                        }
                    }
                    catch {
                        if ($rule.DisplayName -like "*HTTP*") { $portStr = "5985" }
                        elseif ($rule.DisplayName -like "*HTTPS*") { $portStr = "5986" }
                        elseif ($rule.DisplayName -like "*Custom*") { 
                            if ($rule.DisplayName -match "WinRM-Custom-(\d+)-In") {
                                $portStr = $matches[1]
                            }
                        }
                    }
                    
                    $status = if ($rule.Enabled -eq "True") { "Enabled" } else { "Disabled" }
                    
                    Write-Host "│ $($ruleIndex.ToString().PadRight($maxNumLength)) │ $($rule.DisplayName.PadRight($maxNameLength)) │ $($portStr.PadRight($maxPortLength)) │ $($status.PadRight($maxStatusLength)) │" -ForegroundColor White
                    $ruleIndex++
                }
                Write-Host $footerLine -ForegroundColor Gray
            } else {
                Write-Host "`nNo WinRM firewall rules found." -ForegroundColor Yellow
            }
            
            # Show menu options
            Write-Host "`nFirewall Management Options:" -ForegroundColor Green
            Write-Host "1. Delete specific rule(s)" -ForegroundColor White
            Write-Host "2. Delete ALL WinRM rules" -ForegroundColor White
            Write-Host "3. Add new WinRM rule" -ForegroundColor White
            Write-Host "4. Disable specific rule(s)" -ForegroundColor White
            Write-Host "5. Disable ALL WinRM rules" -ForegroundColor White
            Write-Host "6. Exit" -ForegroundColor White
            
            do {
                $choice = Read-Host "`nEnter your choice (1-6)"
            } while ($choice -notmatch '^[1-6]$')
            
            switch ($choice) {
                "1" {
                    if ($winrmRules) {
                        Write-Host "`nEnter rule numbers to delete (comma-separated, e.g., 1,3,5):" -ForegroundColor Yellow
                        $ruleNumbers = Read-Host "Rule numbers"
                        
                        $numbers = $ruleNumbers -split "," | ForEach-Object { $_.Trim() }
                        $deletedCount = 0
                        
                        foreach ($num in $numbers) {
                            if ($num -match '^\d+$' -and [int]$num -ge 1 -and [int]$num -le $winrmRules.Count) {
                                $ruleIndex = [int]$num - 1
                                $rule = $winrmRules[$ruleIndex]
                                
                                try {
                                    Remove-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction Stop
                                    Write-Host "✓ Deleted rule: $($rule.DisplayName)" -ForegroundColor Green
                                    $deletedCount++
                                }
                                catch {
                                    Write-Host "✗ Failed to delete rule: $($rule.DisplayName)" -ForegroundColor Red
                                }
                            } else {
                                Write-Host "✗ Invalid rule number: $num" -ForegroundColor Red
                            }
                        }
                        
                        Write-Host "`nDeleted $deletedCount rule(s)" -ForegroundColor Green
                    } else {
                        Write-Host "No rules to delete." -ForegroundColor Yellow
                    }
                }
                
                "2" {
                    if ($winrmRules) {
                        Write-Host "`nDeleting ALL WinRM firewall rules..." -ForegroundColor Yellow
                        $deletedCount = 0
                        
                        foreach ($rule in $winrmRules) {
                            try {
                                Remove-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction Stop
                                Write-Host "✓ Deleted rule: $($rule.DisplayName)" -ForegroundColor Green
                                $deletedCount++
                            }
                            catch {
                                Write-Host "✗ Failed to delete rule: $($rule.DisplayName)" -ForegroundColor Red
                            }
                        }
                        
                        Write-Host "`nDeleted $deletedCount rule(s)" -ForegroundColor Green
                    } else {
                        Write-Host "No rules to delete." -ForegroundColor Yellow
                    }
                }
                
                "3" {
                    Write-Host "`nAdd New WinRM Firewall Rule:" -ForegroundColor Green
                    
                    # Get port
                    $portInput = Read-Host "Enter port number (default: 5985)"
                    if ([string]::IsNullOrWhiteSpace($portInput)) {
                        $newPort = 5985
                    } else {
                        $tempPort = 0
                        if ([int]::TryParse($portInput, [ref]$tempPort) -and $tempPort -ge 1 -and $tempPort -le 65535) {
                            $newPort = $tempPort
                        } else {
                            Write-Host "Invalid port number, using default 5985" -ForegroundColor Yellow
                            $newPort = 5985
                        }
                    }
                    
                    # Get custom title
                    $customTitle = Read-Host "Enter custom title (default: Custom Port $newPort)"
                    if ([string]::IsNullOrWhiteSpace($customTitle)) {
                        $customTitle = "Custom Port $newPort"
                    }
                    
                    # Get local IP
                    $localIp = Read-Host "Enter local IP address (default: Any)"
                    if ([string]::IsNullOrWhiteSpace($localIp)) {
                        $localIp = "Any"
                    }
                    
                    # Get remote IP
                    $remoteIp = Read-Host "Enter remote IP address (default: Any)"
                    if ([string]::IsNullOrWhiteSpace($remoteIp)) {
                        $remoteIp = "Any"
                    }
                    
                    # Get authorized user
                    $authorizedUser = Read-Host "Enter authorized user (default: Any)"
                    if ([string]::IsNullOrWhiteSpace($authorizedUser)) {
                        $authorizedUser = "Any"
                    }
                    
                    # Get protocol
                    $protocol = Read-Host "Enter protocol (TCP/UDP, default: TCP)"
                    if ([string]::IsNullOrWhiteSpace($protocol) -or $protocol -notmatch "^(TCP|UDP)$") {
                        $protocol = "TCP"
                    }
                    
                    # Create rule name with WinRM prefix
                    $ruleName = "WinRM-$customTitle"
                    $description = "WinRM $customTitle - Allow inbound connections for WEC log collection"
                    
                    # Create rule with custom parameters
                    try {
                        # Build the rule parameters
                        $ruleParams = @{
                            DisplayName = $ruleName
                            Description = $description
                            Direction = "Inbound"
                            Action = "Allow"
                            Protocol = $protocol
                            LocalPort = $newPort
                            Profile = "Any"
                            ErrorAction = "Stop"
                        }
                        
                        # Add local IP if not Any
                        if ($localIp -ne "Any") {
                            $ruleParams.LocalAddress = $localIp
                        }
                        
                        # Add remote IP if not Any
                        if ($remoteIp -ne "Any") {
                            $ruleParams.RemoteAddress = $remoteIp
                        }
                        
                        # Try to create rule with WinRM service restriction using netsh
                        $netshCommand = "netsh advfirewall firewall add rule name=`"$ruleName`" dir=in action=allow protocol=$protocol localport=$newPort"
                        
                        if ($localIp -ne "Any") {
                            $netshCommand += " localip=$localIp"
                        }
                        
                        if ($remoteIp -ne "Any") {
                            $netshCommand += " remoteip=$remoteIp"
                        }
                        
                        $netshCommand += " service=winrm description=`"$description`""
                        
                        # Execute netsh command
                        $netshResult = Invoke-Expression $netshCommand 2>&1
                        
                        if ($LASTEXITCODE -eq 0) {
                            Write-Host "✓ Created firewall rule: $ruleName" -ForegroundColor Green
                            Write-Host "  Port: $newPort" -ForegroundColor Cyan
                            Write-Host "  Protocol: $protocol" -ForegroundColor Cyan
                            Write-Host "  Local IP: $localIp" -ForegroundColor Cyan
                            Write-Host "  Remote IP: $remoteIp" -ForegroundColor Cyan
                            Write-Host "  Service: WinRM" -ForegroundColor Cyan
                            Write-Host "  Status: Enabled" -ForegroundColor Cyan
                        } else {
                            # Fallback to New-NetFirewallRule if netsh fails
                            Write-Host "Warning: Could not create rule with WinRM service restriction, using standard method..." -ForegroundColor Yellow
                            
                            New-NetFirewallRule @ruleParams | Out-Null
                            
                            # Verify rule was created
                            $createdRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                            if ($createdRule) {
                                Write-Host "✓ Created firewall rule: $ruleName" -ForegroundColor Green
                                Write-Host "  Port: $newPort" -ForegroundColor Cyan
                                Write-Host "  Protocol: $protocol" -ForegroundColor Cyan
                                Write-Host "  Local IP: $localIp" -ForegroundColor Cyan
                                Write-Host "  Remote IP: $remoteIp" -ForegroundColor Cyan
                                Write-Host "  Service: Any" -ForegroundColor Cyan
                                Write-Host "  Status: $($createdRule.Enabled)" -ForegroundColor Cyan
                            } else {
                                Write-Host "✗ Rule created but could not be verified" -ForegroundColor Yellow
                            }
                        }
                    }
                    catch {
                        Write-Host "✗ Failed to create firewall rule: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
                
                "4" {
                    if ($winrmRules) {
                        Write-Host "`nEnter rule numbers to disable (comma-separated, e.g., 1,3,5):" -ForegroundColor Yellow
                        $ruleNumbers = Read-Host "Rule numbers"
                        
                        $numbers = $ruleNumbers -split "," | ForEach-Object { $_.Trim() }
                        $disabledCount = 0
                        
                        foreach ($num in $numbers) {
                            if ($num -match '^\d+$' -and [int]$num -ge 1 -and [int]$num -le $winrmRules.Count) {
                                $ruleIndex = [int]$num - 1
                                $rule = $winrmRules[$ruleIndex]
                                
                                try {
                                    Set-NetFirewallRule -DisplayName $rule.DisplayName -Enabled False -ErrorAction Stop
                                    Write-Host "✓ Disabled rule: $($rule.DisplayName)" -ForegroundColor Green
                                    $disabledCount++
                                }
                                catch {
                                    Write-Host "✗ Failed to disable rule: $($rule.DisplayName)" -ForegroundColor Red
                                }
                            } else {
                                Write-Host "✗ Invalid rule number: $num" -ForegroundColor Red
                            }
                        }
                        
                        Write-Host "`nDisabled $disabledCount rule(s)" -ForegroundColor Green
                    } else {
                        Write-Host "No rules to disable." -ForegroundColor Yellow
                    }
                }
                
                "5" {
                    if ($winrmRules) {
                        Write-Host "`nDisabling ALL WinRM firewall rules..." -ForegroundColor Yellow
                        $disabledCount = 0
                        
                        foreach ($rule in $winrmRules) {
                            try {
                                Set-NetFirewallRule -DisplayName $rule.DisplayName -Enabled False -ErrorAction Stop
                                Write-Host "✓ Disabled rule: $($rule.DisplayName)" -ForegroundColor Green
                                $disabledCount++
                            }
                            catch {
                                Write-Host "✗ Failed to disable rule: $($rule.DisplayName)" -ForegroundColor Red
                            }
                        }
                        
                        Write-Host "`nDisabled $disabledCount rule(s)" -ForegroundColor Green
                    } else {
                        Write-Host "No rules to disable." -ForegroundColor Yellow
                    }
                }
                
                "6" {
                    Write-Host "Exiting firewall configuration." -ForegroundColor Yellow
                }
            }
            
            Write-Host ""
            Write-Host ""
        }
        
        "ConfigurePolicies" {
            $result = Set-WinRMPolicies
            Write-Host ""
            Write-Host ""
        }
        
        "CheckPermissions" {
            if (-not $User) {
                Write-Log "User parameter is REQUIRED for CheckPermissions action" "Error" "Main"
                Write-Host "ERROR: -User parameter is REQUIRED for CheckPermissions action" -ForegroundColor Red
                Write-Host "Example: .\winrmconfig.ps1 -Action CheckPermissions -User `"domain\user`"" -ForegroundColor Yellow
                return
            }
            
            Test-UserPermissions -Username $User
            Write-Host ""
            Write-Host ""
        }
        
            "ShowHelp" {
                Show-SimpleHelp
            Write-Host ""
            Write-Host ""
            }
            
            "ShowHelpLong" {
                Show-DetailedHelp
            Write-Host ""
    Write-Host ""
        }
        
        "ShowAllCerts" {
            Show-AllCertificates
            Write-Host ""
            Write-Host ""
        }
        
        "ExportCACert" {
            if (-not $ExportCertPath) {
                Write-Log "ExportCertPath parameter is REQUIRED for ExportCACert action" "Error" "Main"
                Write-Host "ERROR: -ExportCertPath parameter is REQUIRED for ExportCACert action" -ForegroundColor Red
                Write-Host "Example: .\winrmconfig.ps1 -Action ExportCACert -ExportCertPath `"C:\temp\ca-cert.cer`"" -ForegroundColor Yellow
                return
            }
            
            Export-CACertificate -ExportPath $ExportCertPath
            Write-Host ""
            Write-Host ""
        }
        
        "Report" {
            Generate-Report
            Write-Host ""
            Write-Host ""
        }

        "EnsureWinRM" {
            Invoke-EnsureWinRM
            Write-Host ""
            Write-Host ""
        }

        "ReadEvents" {
            Write-Host ""
            Write-Host ("=" * 60) -ForegroundColor Cyan
            Write-Host "READ EVENTS (validate event read access)" -ForegroundColor Yellow
            Write-Host ("=" * 60) -ForegroundColor Cyan
            Write-Host "Channel: $Channel | Count: $Count (max 100) | Sort: $SortOrder" -ForegroundColor Gray
            Write-Host "Transport: $ListenerType | Port: $(if ($Port) { $Port } else { if ($ListenerType -eq 'https') { 5986 } else { 5985 } })" -ForegroundColor Gray
            Write-Host ""
            $portRead = $Port
            if (-not $portRead) { $portRead = if ($ListenerType -eq "https") { 5986 } else { 5985 } }
            Invoke-ReadEvents -Target $TargetHost -UserAccount $User -PasswordPlain $Password -TransportType $ListenerType -PortNum $portRead -LogChannel $Channel -MaxCount $Count -Order $SortOrder
            Write-Host ""
            Write-Host ""
        }
    
    }
}

# Execute main function
Main