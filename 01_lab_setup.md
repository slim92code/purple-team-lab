**English** · **[Srpski](01_lab_setup.sr.md)**

# Purple Team Home Lab — Lab Setup

**Project:** Purple LAB — SOC Analyst Level 2
**Domain:** MARVEL.LOCAL
**Goal:** SOC L2 portfolio + CV demonstration + YouTube series

---

## 1. INFRASTRUCTURE

### Network
- **Subnet:** 192.168.182.0/24
- **VMware NAT network** (host can ping all, internet via NAT)

### VM Inventory

| Machine | IP | Role | RAM | CPU |
|---|---|---|---|---|
| **HYDRA-DC** (Windows Server 2022) | 192.168.182.135 | Domain Controller, AD CS, DNS | 2GB | 2 |
| **THEPUNISHER** (Windows 10) | 192.168.182.137 | Endpoint, domain joined | 2GB | 2 |
| **SPIDERMAN** (Windows 10) | 192.168.182.138 | Endpoint, domain joined | 2GB | 2 |
| **Kali Linux** | 192.168.182.133 | Attacker | 2GB | 2 |
| **Splunk Linux** | 192.168.182.131 | SIEM | 4GB | 2 |

**Total: 12GB RAM, 10 CPU**

### Active Directory Users

| Username | Password | Group | Notes |
|---|---|---|---|
| Administrator | `P@$$w0rd!` | Domain Admins | Built-in DA |
| frankcastle (fcastle) | Password1 | **Domain Admins** | Compromised via password spray |
| peterparker (pparker) | (unknown) | Domain Users | Not cracked — Domain User only |
| SQLService | MYpassword123# | **Domain Admins**, has SPN | Kerberoasted |
| tstark | (unknown) | **Domain Admins** | — |
| Guest | - | - | Disabled |

### Cracked credentials (known)
- **fcastle:Password1** — domain user (password spray)
- **SQLService:MYpassword123#** — service account with SPN (Kerberoasting)
- **THEPUNISHER\Administrator NT hash:** `fbdcd5041c96ddbd82224270b57f11fc` (local admin)
- **frankcastle NT hash:** `64f12cddaa88057e06a81b54e73b949b`
- **SUPERMAN NT hash:** `2b576acbe6bcfda7294d6bd18041b8fe`
- **Cached MARVEL\Administrator:** `$DCC2$10240#Administrator#c7154f935b7d1ace4c1d72bd4fb7889c`
- **Cached MARVEL\fcastle:** `$DCC2$10240#fcastle#e6f48c2526bd594441d3da3723155f6f`
- **$MACHINE.ACC hash:** `d770bd67e3abc0203eff3c20cf595db2`

---

## 2. SPLUNK CONFIGURATION

### Version
- **Splunk Enterprise 10.2.0 Free** (500MB/day limit)
- **Location:** `/opt/splunk/`

### Installed Apps
- ✅ Splunk_TA_windows
- ✅ TA-microsoft-sysmon 10.6.2
- ✅ Splunk_SA_CIM 8.5.0

### Index structure
- **`main`** — all events

### Source field map (via `source` field, not `sourcetype`)

| Source | Content |
|---|---|
| `WinEventLog:Security` | Authentication, Process Creation (EC4624, 4625, 4688, 4698, 4768, 4769, 4771, 4776) |
| `WinEventLog:Microsoft-Windows-Sysmon/Operational` | Sysmon EC1, 3, 5, 8, 11, 12, 13, 22 |
| `WinEventLog:Microsoft-Windows-PowerShell/Operational` | PowerShell Script Block (EC4103, 4104) |
| `WinEventLog:Microsoft-Windows-WMI-Activity/Operational` | WMI events |
| `WinEventLog:Microsoft-Windows-TaskScheduler/Operational` | Task Scheduler events |

---

## 3. ISSUES RESOLVED DURING SETUP (key for CV)

### 3.1 Timestamp problem (VM pause/resume)

**Symptom:** Events arrive with shifted timestamps (hours/days off) after VM pause/resume

**Fix:** `/opt/splunk/etc/apps/Splunk_TA_windows/local/props.conf`
```ini
[WinEventLog:Microsoft-Windows-Sysmon/Operational]
DATETIME_CONFIG = CURRENT
MAX_TIMESTAMP_LOOKAHEAD = 128
KV_MODE = auto
SHOULD_LINEMERGE = false
```

### 3.2 Forwarder connection drops on VM resume

**Fix:** Auto-restart task on all Windows machines:
```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command Restart-Service SplunkForwarder"
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName "RestartSplunkOnBoot" -Action $action -Trigger $trigger -RunLevel Highest -Force
```

### 3.3 Sysmon errorCode=5 (Access Denied)

**Symptom:** Forwarder cannot read Sysmon log on SPIDERMAN

**Fix:**
```powershell
sc.exe config SplunkForwarder obj= "LocalSystem"
Restart-Service SplunkForwarder
```

### 3.4 Timezone offset (DST off)

**Symptom:** SPIDERMAN events one hour ahead

**Fix:**
```powershell
Set-TimeZone -Id "Central European Standard Time"
w32tm /resync /force
```

### 3.5 DC NTP configuration

```cmd
w32tm /config /syncfromflags:manual /manualpeerlist:"pool.ntp.org,0.pool.ntp.org" /reliable:YES /update
net stop W32Time
net start W32Time
w32tm /resync /force
```

### 3.6 Audit Policy "Other Object Access Events" disabled by default

**Symptom:** EC4698 (Scheduled Task Created) not logging

**Fix (with elevated privileges):**
```cmd
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

### 3.7 Forwarder on clients not sending Sysmon logs

**Fix:** Explicit inputs.conf — do not rely on defaults

### 3.8 SMB port 445 occupied by old Python process

**Symptom:** `OSError: [Errno 98] Address already in use` when starting impacket-smbserver

**Fix:**
```bash
sudo ss -tlnp | grep 445
sudo kill -9 <PID>
```

---

## 4. SYSMON CONFIGURATION

**Version:** Sysmon v15.15
**Config:** `C:\Users\frankcastle\Desktop\UF_Sysmon\sysmon-config-master\sysmonconfig-export.xml` (SwiftOnSecurity/Olaf config)
**SHA256:** `055FEBC600E6D7448CDF3812307275912927A62B1F94D0D933B64B294BC87162`

### EventCodes arriving in Splunk

| EventCode | Name | Status |
|---|---|---|
| 1 | ProcessCreate | ✅ |
| 3 | NetworkConnect (filtered) | ✅ |
| 5 | ProcessTerminate | ✅ |
| 7 | ImageLoad | ❌ Disabled in config |
| 8 | CreateRemoteThread | ✅ |
| 10 | ProcessAccess | ❌ Needs enabling for Mimikatz detection |
| 11 | FileCreate | ✅ |
| 12/13 | RegistryEvent | ✅ |
| 22 | DnsQuery | ✅ |

### Sysmon EC3 watchlist (critical for C2 detection)

Sysmon config filters network connections only for processes in the watchlist:
- `powershell.exe` ✅
- `cmd.exe` ✅
- `mshta.exe` ✅
- `certutil.exe` ✅
- `regsvr32.exe` ✅
- `rundll32.exe` ✅
- **`GlobalProtect_Update.exe`** ❌ — **NEEDS TO BE ADDED** as part of detection engineering iteration (Seg 8)

---

## 5. AUDIT POLICY COMMANDS

### HYDRA-DC (Domain Controller)

```cmd
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"SAM" /success:enable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

### THEPUNISHER, SPIDERMAN (Endpoints)

```cmd
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
```

### Command Line + PowerShell logging (all machines)

```cmd
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v "*" /t REG_SZ /d "*" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "C:\PSTranscripts" /f
```

---

## 6. FORWARDER INPUTS.CONF (all Windows machines)

**Location:** `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

```ini
[default]
host = THEPUNISHER

[WinEventLog://Security]
disabled = 0
index = main
sourcetype = WinEventLog:Security

[WinEventLog://System]
disabled = 0
index = main
sourcetype = WinEventLog:System

[WinEventLog://Application]
disabled = 0
index = main
sourcetype = WinEventLog:Application

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = main
sourcetype = WinEventLog:Microsoft-Windows-Sysmon/Operational
renderXml = false

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = main
sourcetype = WinEventLog:PowerShell

[WinEventLog://Microsoft-Windows-WMI-Activity/Operational]
disabled = 0
index = main
sourcetype = WinEventLog:WMI

[WinEventLog://Microsoft-Windows-TaskScheduler/Operational]
disabled = 0
index = main
sourcetype = WinEventLog:TaskScheduler
```

**Restart command:**
```powershell
Restart-Service SplunkForwarder
```

---

## 7. DEFENDER EXCLUSIONS (deployed via GPO)

Paths excluded from scanning (set via GPO on DC):
- `C:\Temp`
- `C:\Windows\` (entire Windows folder)
- `C:\Windows\Tasks`

**Narrative note:** Defender stays **enabled** throughout attacks. Goal is realistic detection, not disabling AV.

### Defender behavior during testing

| Tool | Defender triggered? | Result |
|---|---|---|
| Sliver implant (`GlobalProtect_Update.exe` in C:\Temp) | ❌ | Passes — in exclusion path |
| Mimikatz (`mimikatz.exe`) | ✅ Blocked | "Trojan:Win32/HackTool" |
| Mimikatz renamed (`m64.exe`) | ✅ Blocked | AMSI catches string `lsadump::dcsync` |
| SharpKatz | ❌ | Passes AV but fails with RPC error 1825 |
| Rubeus | ❌ | Passes |
| InstallUtil .NET payload | ❌ | Passes (LOLBin) |
| certutil download | ✅ Blocked | "Trojan:Win32/Ceprolad.A" on nc.exe |
| reg save SAM/SYSTEM | ❌ | Passes (legitimate Windows tool) |

---

## 8. NETWORK CONNECTIVITY MATRIX

### From Kali (192.168.182.133) to other machines

| Destination | Port 445 (SMB) | Port 135 (RPC) | Port 443 (HTTPS) | Port 88 (Kerberos) | Port 389 (LDAP) |
|---|---|---|---|---|---|
| HYDRA-DC (.135) | ❌ Blocked | ❌ Blocked | - | ✅ | ✅ |
| THEPUNISHER (.137) | ❌ Blocked | ❌ Blocked | - | - | - |
| SPIDERMAN (.138) | ❌ Blocked | ❌ Blocked | - | - | - |

### From THEPUNISHER (192.168.182.137) to DC

| Destination | Port 445 | Port 135 | Port 88 | Port 389 |
|---|---|---|---|---|
| HYDRA-DC | ✅ | ✅ | ✅ | ✅ |

**Consequence:** All impacket attacks against the DC must be executed **through Sliver shell on THEPUNISHER**, not directly from Kali.

### From Windows machines to Kali

| Destination | Port 443 (Sliver mTLS) | Port 445 (SMB share) | Port 8080 (HTTP) |
|---|---|---|---|
| Kali (192.168.182.133) | ✅ | ✅ (when smbserver is up) | ✅ (when python -m http.server is up) |

---

## 9. TOOLS USED IN THE LAB

### On Kali

```bash
# Recon & enumeration
nmap
kerbrute
netexec (nxc)
bloodhound-python
certipy-ad

# Exploitation
impacket-* (GetUserSPNs, GetNPUsers, secretsdump, smbserver, smbclient)
sliver (v1.7.1-0kali4) — C2 framework
rubeus (apt package)
mimikatz (/usr/share/windows-resources/mimikatz/x64/)
SharpKatz (downloaded from GitHub Flangvik/SharpCollection)
hashcat

# Paths
/usr/share/windows-resources/rubeus/Rubeus.exe
/usr/share/windows-resources/mimikatz/x64/mimikatz.exe
/usr/share/doc/python3-impacket/examples/
```

### Wordlists

```bash
/usr/share/wordlists/rockyou.txt
/tmp/users_clean.txt  # custom user list
```

---

## 10. PRE-FLIGHT CHECKLIST (before recording video)

### Start all VMs in order:
1. ✅ HYDRA-DC (DC must be first — DNS dependency)
2. ✅ Splunk Linux
3. ✅ THEPUNISHER
4. ✅ SPIDERMAN (as needed)
5. ✅ Kali

### After startup, verify:

```bash
# On Kali:
ping -c 2 192.168.182.135  # DC reachable
ping -c 2 192.168.182.131  # Splunk reachable
ping -c 2 192.168.182.137  # THEPUNISHER reachable
```

```powershell
# On Windows machines:
Get-Service SplunkForwarder  # Must be Running
Get-Service Sysmon64         # Must be Running
```

### Check in Splunk (Last 5 minutes):

```spl
| metadata type=hosts
| table host, recentTime
```

Must show all 3 Windows hosts with recent `recentTime`.

```spl
index=main host=THEPUNISHER 
| stats count by sourcetype
```

Must show all sourcetypes (Security, Sysmon, PowerShell).

### Time synchronization

```powershell
# On all Windows machines:
w32tm /resync /force
```

### Defender status

```powershell
Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled
# Must be True/True
```

---

## 11. VALIDATION SCRIPT

PowerShell script for quick lab readiness check:

```powershell
Write-Host "--- SOC LEVEL 2 LAB VALIDATION ---" -ForegroundColor Cyan

# 1. Lockout Policy
$lockout = net accounts | Select-String "Lockout threshold"
Write-Host "[*] Account Lockout: $lockout" -ForegroundColor Yellow

# 2. Audit Policy (Process Creation)
$audit = auditpol /get /subcategory:"Process Creation" | Select-String "Success and Failure"
if ($audit) {
    Write-Host "[+] Audit Process Creation: ENABLED" -ForegroundColor Green
} else {
    Write-Host "[-] Audit Process Creation: DISABLED" -ForegroundColor Red
}

# 3. Command Line Logging
$reg = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
if ($reg -and $reg.ProcessCreationIncludeCmdLine_Enabled -eq 1) {
    Write-Host "[+] Command Line Logging: ENABLED" -ForegroundColor Green
} else {
    Write-Host "[-] Command Line Logging: DISABLED" -ForegroundColor Red
}

# 4. Defender
$defender = Get-MpPreference
if ($defender) {
    $rt = if ($defender.DisableRealtimeMonitoring) { "OFF" } else { "ON" }
    Write-Host "[*] Defender Real-Time: $rt" -ForegroundColor Yellow
    if ($defender.ExclusionPath -contains "C:\Temp") {
        Write-Host "[+] Exclusion C:\Temp: PRESENT" -ForegroundColor Green
    }
}

# 5. Splunk Forwarder
$splunk = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
if ($splunk -and $splunk.Status -eq "Running") {
    Write-Host "[+] Splunk Forwarder: RUNNING" -ForegroundColor Green
} else {
    Write-Host "[-] Splunk Forwarder: NOT FOUND / STOPPED" -ForegroundColor Red
}

# 6. Sysmon
$sysmon = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($sysmon -and $sysmon.Status -eq "Running") {
    Write-Host "[+] Sysmon: RUNNING" -ForegroundColor Green
} else {
    Write-Host "[-] Sysmon: NOT RUNNING" -ForegroundColor Red
}

Write-Host "--- VALIDATION COMPLETE ---" -ForegroundColor Cyan
```

---

**End of Document 1**
**Next:** `02_attack_playbook.md` — all attack phases with exact commands
