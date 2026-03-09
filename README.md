# WinRM Log Collector

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Windows](https://img.shields.io/badge/Windows-Server%202016+-green.svg)](https://www.microsoft.com/en-us/windows-server)
[![Version](https://img.shields.io/badge/Version-2.3.2-orange.svg)](https://github.com/Uniao-Geek/WinRM-Log-Collector/releases)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> 🇧🇷 **Leia em Português:** [README-pt-BR.md](README-pt-BR.md)

---

## Overview

**WinRM Log Collector** is a PowerShell-based solution for configuring and managing Windows Remote Management (WinRM) for log collection via Windows Event Collector (WEC) and Windows Event Forwarding (WEF).

It provides a comprehensive toolset for configuring listeners (HTTP/HTTPS), managing firewall rules with duplicate detection, enforcing GPO-style policies via registry, validating user permissions, reading remote events, and generating reports (screen, HTML, TXT).

### Key Features

- **13 Actions** — configure, monitor, validate, troubleshoot
- **HTTP and HTTPS listener** support with certificate auto-detection
- **Firewall management** — interactive, validates by port/protocol/service (not just rule name) to avoid duplicates
- **GPO-style policy configuration** — AllowBasic, AllowUnencrypted, IP filters, EventLog ChannelAccess — all with pre-check and user confirmation before creating/updating
- **Module availability check at startup** — identifies missing modules, shows impact per action, and offers to install
- **Runtime module guard** — every function that requires a module gracefully reports what is missing and what is affected
- **User and permission validation** — Event Log Readers group, WMI, WinRM access
- **Read remote/local events** — validate event log read access from any Windows host
- **Reports** — screen output, or export to HTML / TXT
- **-NoPrompt switch** — skip all confirmations for automation/scripting

---

## Requirements

| Requirement | Details |
|---|---|
| OS | Windows Server 2016+ / Windows 10+  |
| PowerShell | 5.1 or later |
| Privileges | **Administrator** (required — enforced by `#requires -RunAsAdministrator`) |
| PowerShell modules | `NetSecurity` (firewall), `Microsoft.PowerShell.LocalAccounts` (users/groups) |
| Execution Policy | `RemoteSigned` or `Bypass` at minimum |

### PowerShell Modules Impact

The script checks modules at startup (fast import attempt — not a full disk scan). If missing:

| Module | Used By | Impact if Missing |
|---|---|---|
| `NetSecurity` | ConfigureFirewall, EnsureWinRM, Enable, Status, Report | Cannot list, create or validate firewall rules |
| `Microsoft.PowerShell.LocalAccounts` | Enable, CheckPermissions | Cannot validate local users or check Event Log Readers group membership |

To install manually:
```powershell
Install-Module NetSecurity, Microsoft.PowerShell.LocalAccounts -Scope CurrentUser -Force
```

Execution policy (if restricted):
```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## Quick Start

```powershell
# Run as Administrator
# Enable WinRM with HTTP listener
.\winrmconfig.ps1 -Action Enable -User "domain\serviceaccount"

# Quick fix: start WinRM, apply basic policies, open firewall ports 5985/5986
.\winrmconfig.ps1 -Action EnsureWinRM

# Show current status
.\winrmconfig.ps1 -Action Status

# Read last 10 events from Security log (local)
.\winrmconfig.ps1 -Action ReadEvents

# Show help
.\winrmconfig.ps1 -Action ShowHelp
.\winrmconfig.ps1 -Action ShowHelpLong
```

---

## Actions Reference

### `Enable`
Configures a WinRM listener (HTTP or HTTPS), starts and restarts the WinRM service, adds the user to Event Log Readers group, and configures policies.

**Requires:** `-User`

```powershell
# HTTP listener (port 5985)
.\winrmconfig.ps1 -Action Enable -User "domain\serviceaccount"

# HTTPS listener (auto-selects certificate)
.\winrmconfig.ps1 -Action Enable -ListenerType https -User "domain\serviceaccount"

# HTTPS with specific certificate thumbprint
.\winrmconfig.ps1 -Action Enable -ListenerType https -User "domain\serviceaccount" -ThumbPrint "ABCDEF1234..."

# Custom port
.\winrmconfig.ps1 -Action Enable -User "domain\serviceaccount" -Port 8080

# Skip all confirmation prompts (automation)
.\winrmconfig.ps1 -Action Enable -User "domain\serviceaccount" -NoPrompt
```

---

### `Disable`
Removes WinRM listeners interactively or by user/type. Stops and disables the WinRM service if no listeners remain.

```powershell
# Interactive selection
.\winrmconfig.ps1 -Action Disable

# Disable all listeners for a user
.\winrmconfig.ps1 -Action Disable -User "*"
```

---

### `Status`
Shows full WinRM configuration status: service status, active listeners, firewall rules (WinRM/WEC), and current policies.

```powershell
.\winrmconfig.ps1 -Action Status

# Show firewall rules for a specific port
.\winrmconfig.ps1 -Action Status -Port 8080
```

---

### `ConfigureFirewall`
Interactive firewall rule manager for WinRM/WEC. Lists current rules, allows adding (with port, protocol, IP, service), deleting, and disabling rules.

**Before creating:** validates existence by port + protocol + direction (not just display name) to prevent duplicates.  
**When not found:** asks user confirmation before creating.

```powershell
.\winrmconfig.ps1 -Action ConfigureFirewall

# Skip confirmation prompts
.\winrmconfig.ps1 -Action ConfigureFirewall -NoPrompt
```

**What is validated before creating a rule:**
- Port (LocalPort)
- Protocol (TCP/UDP)
- Direction (Inbound)
- Enabled state

---

### `ConfigurePolicies`
Configures WinRM registry policies (GPO-style). For each policy:
1. Checks if already configured (and shows current value)
2. If not configured or differs from desired value: **asks the user** before creating/updating
3. Skips if user declines

Policies managed:
| Policy | Registry Key | Desired Value |
|---|---|---|
| Allow Basic Authentication | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowBasic` | 1 (Enabled) |
| Allow Unencrypted Traffic | `HKLM:\...\AllowUnencrypted` | 0 (Disabled) |
| IPv4/IPv6 Filter | `IPv4Filter`, `IPv6Filter` | `*` (or custom) |
| EventLog ChannelAccess | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\ChannelAccess` | SDDL with Network Service |

```powershell
.\winrmconfig.ps1 -Action ConfigurePolicies

# With specific IP filters
.\winrmconfig.ps1 -Action ConfigurePolicies -IPv4Filter "192.168.1.0/24" -IPv6Filter "*"

# Skip all confirmations
.\winrmconfig.ps1 -Action ConfigurePolicies -NoPrompt
```

---

### `EnsureWinRM`
Quick fix action: starts WinRM service, runs quickconfig if needed, sets WSMan settings (TrustedHosts, Basic auth, AllowUnencrypted), applies registry policies, and opens firewall ports 5985 and 5986.

Designed for lab/POC environments. Does NOT require `-User`.

```powershell
.\winrmconfig.ps1 -Action EnsureWinRM

# No prompts
.\winrmconfig.ps1 -Action EnsureWinRM -NoPrompt
```

---

### `CheckPermissions`
Validates user permissions for WEC/WEF log collection: Event Log Readers group membership, WMI access, WinRM accessibility, and Security/System/Application event log access.

**Requires:** `-User`

```powershell
.\winrmconfig.ps1 -Action CheckPermissions -User "domain\serviceaccount"
.\winrmconfig.ps1 -Action CheckPermissions -User "localuser"
```

---

### `ShowAllCerts`
Lists all certificates in `LocalMachine\My` store, separating those with **Server Authentication EKU** (suitable for HTTPS) from others.

```powershell
.\winrmconfig.ps1 -Action ShowAllCerts
```

---

### `ExportCACert`
Exports the most recent CA certificate from `LocalMachine\Root` store to a file.

**Requires:** `-ExportCertPath`

```powershell
.\winrmconfig.ps1 -Action ExportCACert -ExportCertPath "C:\temp\ca-cert.cer"
```

---

### `Report`
Generates a comprehensive WinRM report including: system info, WinRM service status, active listeners, certificates, firewall rules, and policies. Output can be to screen, HTML file, or TXT file.

```powershell
# Screen output (default)
.\winrmconfig.ps1 -Action Report

# Export as HTML
.\winrmconfig.ps1 -Action Report -ReportFormat Html -ReportOutputPath "C:\reports\winrm-report.html"

# Export as TXT
.\winrmconfig.ps1 -Action Report -ReportFormat Txt -ReportOutputPath "C:\reports\winrm-report.txt"
```

---

### `ReadEvents`
Reads the last N events from a Windows event log channel. Supports both local and remote hosts (via WinRM). Useful for validating read access.

```powershell
# Local Security log, last 10 events (ascending)
.\winrmconfig.ps1 -Action ReadEvents

# Last 20 Application events, descending
.\winrmconfig.ps1 -Action ReadEvents -Channel Application -Count 20 -SortOrder desc

# Remote host via HTTP
.\winrmconfig.ps1 -Action ReadEvents -TargetHost 10.254.2.241 -User "opc" -Password "mypassword" -Channel Security -Count 10

# Remote host via HTTPS
.\winrmconfig.ps1 -Action ReadEvents -TargetHost wec-server -User "domain\user" -ListenerType https -Channel Security
```

---

### `ShowHelp` / `ShowHelpLong`
Displays help in English (default) or Portuguese.

```powershell
.\winrmconfig.ps1 -Action ShowHelp
.\winrmconfig.ps1 -Action ShowHelp -Language pt-BR
.\winrmconfig.ps1 -Action ShowHelpLong
.\winrmconfig.ps1 -Action ShowHelpLong -Language pt-BR
```

---

## Parameters Reference

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `-Action` | String | Yes | — | Action to perform (see Actions above) |
| `-ListenerType` | `http`/`https` | No | `http` | WinRM listener type |
| `-User` | String | Conditional | — | User account (required for Enable, Disable, CheckPermissions) |
| `-Port` | Int (1-65535) | No | 5985/5986 | Custom port |
| `-ThumbPrint` | String | No | auto | Certificate thumbprint for HTTPS |
| `-WecIp` | String | No | — | WEC server IP (for ConfigureFirewall) |
| `-WecHostname` | String | No | — | WEC server hostname (for ConfigureFirewall) |
| `-LogPath` | String | No | `.\log` | Directory for log files |
| `-ExportCertPath` | String | Conditional | — | Path to export CA certificate |
| `-AuthType` | `basic`/`negotiate`/`kerberos` | No | `negotiate` | Authentication type |
| `-LogLevel` | `Error`/`Warning`/`Info`/`Debug` | No | `Error` | Logging verbosity |
| `-IPv4Filter` | String | No | — | IPv4 filter for ConfigurePolicies (e.g. `*`) |
| `-IPv6Filter` | String | No | — | IPv6 filter for ConfigurePolicies |
| `-TargetHost` | String | No | `localhost` | Remote host for ReadEvents |
| `-Password` | String | No | — | Password for remote ReadEvents (plain text — lab only) |
| `-Channel` | String | No | `Security` | Event log channel for ReadEvents |
| `-Count` | Int (1-100) | No | `10` | Max events to read |
| `-SortOrder` | `asc`/`desc` | No | `asc` | Sort order for ReadEvents |
| `-Language` | `en-US`/`pt-BR` | No | `en-US` | Help language (ShowHelp/ShowHelpLong only) |
| `-ReportFormat` | `Screen`/`Html`/`Txt` | No | `Screen` | Report output format |
| `-ReportOutputPath` | String | No | — | File path for HTML/TXT report export |
| `-NoPrompt` | Switch | No | — | Skip all confirmation prompts (automation mode) |

---

## Firewall Validation — How It Works

Unlike simple name-based checks, the script validates firewall rules by **port + protocol + direction + enabled state**. This prevents duplicate rules even when rule names differ across environments or are set by GPO.

**Validation flow:**
1. Query rules matching `*WinRM*`, `*WEC*`, `*Remote Management*` by display name
2. Also query all port filters matching the target port/protocol (catches any rule regardless of name)
3. If a matching rule is found → skip creation, notify user
4. If no match found → prompt user for confirmation (unless `-NoPrompt`)
5. Only then create the rule

---

## GPO / Policy Validation — How It Works

For each policy setting (registry key):

1. **Check current value** in registry
2. If already set to desired value → report as "Already configured", skip
3. If not set or different → **display current vs. desired value**, ask user "Create/update? (y/n)"
4. With `-NoPrompt` → automatically apply without asking

This prevents accidental overwrites and gives full visibility of what will change.

---

## Module Error Handling

If a required module is missing at runtime (when a specific function needs it):

```
  [MODULE MISSING] NetSecurity
  Context: ConfigureFirewall
  Without NetSecurity: firewall rules cannot be listed, created or validated. ...
  To install: Install-Module NetSecurity -Scope CurrentUser -Force
  Note: PowerShell execution policy must allow script execution ...
```

The function then returns gracefully without crashing the script.

---

## Logging

Log files are saved to `.\log\winrmconfig_YYYYMMDD.log` (configurable via `-LogPath`).

Format: `[timestamp] [Level] [Component] Message`

Log levels: `Error`, `Warning`, `Info`, `Debug`  
Default: `Error` (only errors logged to file; all output shown on screen)

---

## Troubleshooting Commands

```powershell
# Check WinRM config
winrm get winrm/config

# List listeners
winrm enumerate winrm/config/listener

# Check firewall rules (by name)
Get-NetFirewallRule -DisplayName "*WinRM*"

# Check firewall rules (by port)
Get-NetFirewallPortFilter -Protocol TCP | Where-Object { $_.LocalPort -eq 5985 } | Get-NetFirewallRule

# Check Event Log Readers group members
Get-LocalGroupMember -Group "Event Log Readers"

# Check execution policy
Get-ExecutionPolicy -List

# Test WinRM connectivity
Test-WSMan -ComputerName <hostname>
```

---

## Version History

| Version | Changes |
|---|---|
| 2.3.2 | Performance fix: replaced full firewall rule enumeration with targeted queries; replaced `Get-WmiObject` with `Get-CimInstance`; improved module check (fast import vs full disk scan); runtime module guard per function with impact description; `-NoPrompt` applied to all policy/firewall prompts |
| 2.3.1 | Added module check at startup; `-ReportFormat`/`-ReportOutputPath` for HTML/TXT export; GPO policy pre-check with user confirmation; firewall duplicate detection by port/protocol; `-NoPrompt` switch |
| 2.3.0 | Added `EnsureWinRM`, `ReadEvents` actions; `-Language` for bilingual help |
| 2.2.x | Interactive firewall manager; certificate auto-detection; detailed reporting |

---

## Author

**Andre Henrique** (Uniao Geek)  
Email: contato@uniaogeek.com.br  
LinkedIn: [linkedin.com/in/mrhenrike](https://www.linkedin.com/in/mrhenrike)  
GitHub: [github.com/Uniao-Geek](https://github.com/Uniao-Geek)

---

## License

MIT — see [LICENSE](LICENSE)
