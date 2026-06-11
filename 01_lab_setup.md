# Purple Team Home Lab — Lab Setup Complete

**Projekat:** Purple LAB — SOC Analyst Level 2  
**Domain:** MARVEL.LOCAL  
**Cilj:** SOC L2 portfolio + CV demonstracija + YouTube serija

---

## 1. INFRASTRUKTURA

### Mreža
- **Subnet:** 192.168.182.0/24
- **VMware NAT network** (host može pinguje sve, internet preko NAT-a)

### VM Inventory

| Mašina | IP | Uloga | RAM | CPU |
|---|---|---|---|---|
| **HYDRA-DC** (Windows Server 2022) | 192.168.182.135 | Domain Controller, AD CS, DNS | 2GB | 2 |
| **THEPUNISHER** (Windows 10) | 192.168.182.137 | Endpoint domain joined | 2GB | 2 |
| **SPIDERMAN** (Windows 10) | 192.168.182.138 | Endpoint domain joined | 2GB | 2 |
| **Kali Linux** | 192.168.182.133 | Napadač | 2GB | 2 |
| **Splunk Linux** | 192.168.182.131 | SIEM | 4GB | 2 |

**Ukupno: 12GB RAM, 10 CPU**

### Active Directory korisnici

| Username | Password | Group | Notes |
|---|---|---|---|
| Administrator | `P@$$w0rd!` | Domain Admins | **Lokalni** Administrator THEPUNISHER, ne domain Administrator |
| frankcastle | Password1 | Domain Admins | Kompromitovan kroz password spray |
| peterparker | (unknown) | Domain Users | Nije krekovan |
| SQLService | MYpassword123# | Domain Admins, ima SPN | Kerberoasted |
| tstark | (unknown) | Domain Admins | Postoji — potvrđeno preko Domain Admins membershipa |
| Guest | - | - | Disabled |

### Krekovane kredencijale (poznate)
- **fcastle:Password1** — Domain Admin (kompromitovan kroz password spray)
- **SQLService:MYpassword123#** — service account sa SPN (Kerberoasting)
- **THEPUNISHER\Administrator NT hash:** `fbdcd5041c96ddbd82224270b57f11fc` (lokalni admin)
- **frankcastle NT hash:** `64f12cddaa88057e06a81b54e73b949b`
- **SUPERMAN NT hash:** `2b576acbe6bcfda7294d6bd18041b8fe`
- **Cached MARVEL\Administrator:** `$DCC2$10240#Administrator#c7154f935b7d1ace4c1d72bd4fb7889c`
- **Cached MARVEL\fcastle:** `$DCC2$10240#fcastle#e6f48c2526bd594441d3da3723155f6f`
- **$MACHINE.ACC hash:** `d770bd67e3abc0203eff3c20cf595db2`

---

## 2. SPLUNK KONFIGURACIJA

### Verzija
- **Splunk Enterprise 10.2.0 Free** (500MB/dan limit)
- **Lokacija:** `/opt/splunk/`

### Apps instalirani
- ✅ Splunk_TA_windows
- ✅ TA-microsoft-sysmon (instaliran — ekstrahuje Image, DestinationIp, GrantedAccess…)
- ✅ Splunk_SA_CIM (za tstats CIM headlinere u Splunk pack-u)
  - **Napomena:** SPL u dokumentaciji i screenshotovima namerno koristi `rex field=Message` (pedagoški — pokazuje strukturu eventa). Deployable pak (`detections/splunk/`) koristi TA-ekstrahovana polja bez rex-a.

### Index strukturа
- **`main`** — svi eventi

### Source field map

| Source | Sadržaj |
|---|---|
| `WinEventLog:Security` | Authentication, Process Creation (EC4624, 4625, 4688, 4698, 4768, 4769, 4771, 4776) |
| `WinEventLog:Microsoft-Windows-Sysmon/Operational` | Sysmon EC1, 3, 5, 8, 11, 12, 13, 22 |
| `WinEventLog:Microsoft-Windows-PowerShell/Operational` | PowerShell Script Block (EC4103, 4104) |
| `WinEventLog:Microsoft-Windows-WMI-Activity/Operational` | WMI eventi |
| `WinEventLog:Microsoft-Windows-TaskScheduler/Operational` | Task Scheduler eventi |

---

## 3. PROBLEMI REŠENI TOKOM SETUPA (kritično za CV)

### 3.1 Timestamp problem (VM pause/resume)

**Simptom:** Eventi stižu sa pomerenim timestamp-om (sat-dana razlike) nakon pause/resume VM-a

**Fix:** `/opt/splunk/etc/apps/Splunk_TA_windows/local/props.conf`
```ini
[WinEventLog:Microsoft-Windows-Sysmon/Operational]
DATETIME_CONFIG = CURRENT
MAX_TIMESTAMP_LOOKAHEAD = 128
KV_MODE = auto
SHOULD_LINEMERGE = false
```

### 3.2 Forwarder konekcija puca pri VM resume

**Fix:** Auto-restart task na svim Windows mašinama:
```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command Restart-Service SplunkForwarder"
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName "RestartSplunkOnBoot" -Action $action -Trigger $trigger -RunLevel Highest -Force
```

### 3.3 Sysmon errorCode=5 (Access Denied)

**Simptom:** Forwarder ne može da čita Sysmon log na SPIDERMAN

**Fix:**
```powershell
sc.exe config SplunkForwarder obj= "LocalSystem"
Restart-Service SplunkForwarder
```

### 3.4 Timezone offset (DST off)

**Simptom:** SPIDERMAN eventi sat vremena unapred

**Fix:**
```powershell
Set-TimeZone -Id "Central European Standard Time"
w32tm /resync /force
```

### 3.5 DC NTP konfiguracija

```cmd
w32tm /config /syncfromflags:manual /manualpeerlist:"pool.ntp.org,0.pool.ntp.org" /reliable:YES /update
net stop W32Time
net start W32Time
w32tm /resync /force
```

### 3.6 Audit Policy "Other Object Access Events" disabled by default

**Simptom:** EC4698 (Scheduled Task Created) ne loguje se

**Fix (sa elevated privilegijama):**
```cmd
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

### 3.7 Forwarder na klijentima ne šalje Sysmon logove

**Fix:** Eksplicitan inputs.conf — ne oslanjaj se na default

### 3.8 SMB port 445 zauzet od starog Python procesa

**Simptom:** `OSError: [Errno 98] Address already in use` pri pokretanju impacket-smbserver

**Fix:**
```bash
sudo ss -tlnp | grep 445
sudo kill -9 <PID>
```

---

## 4. SYSMON KONFIGURACIJA

**Verzija:** Sysmon v15.15  
**Config:** `C:\Users\frankcastle\Desktop\UF_Sysmon\sysmon-config-master\sysmonconfig-export.xml` (SwiftOnSecurity/Olafr config)  
**SHA256:** `055FEBC600E6D7448CDF3812307275912927A62B1F94D0D933B64B294BC87162`

### EventCode-ovi koji stižu u Splunk

| EventCode | Naziv | Status |
|---|---|---|
| 1 | ProcessCreate | ✅ |
| 3 | NetworkConnect (filtrirano) | ✅ |
| 5 | ProcessTerminate | ✅ |
| 7 | ImageLoad | ❌ Disabled u config-u |
| 8 | CreateRemoteThread | ✅ |
| 10 | ProcessAccess | ❌ Treba uključiti za Mimikatz detect |
| 11 | FileCreate | ✅ |
| 12/13 | RegistryEvent | ✅ |
| 22 | DnsQuery | ✅ |

### Sysmon EC3 watchlist (bitno za C2 detekciju)

Sysmon config filtrira mrežne konekcije samo sa procesima iz watchlist-e:
- `powershell.exe` ✅
- `cmd.exe` ✅
- `mshta.exe` ✅
- `certutil.exe` ✅
- `regsvr32.exe` ✅
- `rundll32.exe` ✅
- **`GlobalProtect_Update.exe`** ❌ — **TREBA DODATI** kao deo detection engineering iteracije

---

## 5. AUDIT POLICY KOMANDE

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

### Command Line + PowerShell logging (sve mašine)

```cmd
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v "*" /t REG_SZ /d "*" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "C:\PSTranscripts" /f
```

---

## 6. FORWARDER INPUTS.CONF (sve Windows mašine)

**Lokacija:** `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

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

**Restart komanda:**
```powershell
Restart-Service SplunkForwarder
```

---

## 7. DEFENDER EXCLUSIONS (GPO postavljeno)

Putanje izuzete od skeniranja (postavljeno preko GPO na DC):
- `C:\Temp`
- `C:\Windows\` (ceo Windows folder)
- `C:\Windows\Tasks`

**Bitno za narativ:** Defender ostaje **uključen** tokom napada. Cilj je realna detekcija, ne disabling.

### Defender ponašanje tokom testiranja

| Alat | Defender reagovao? | Rezultat |
|---|---|---|
| Sliver implant (`GlobalProtect_Update.exe` u C:\Temp) | ❌ | Prolazi jer je u exclusion path-u |
| Mimikatz (`mimikatz.exe`) | ✅ Blokirao | "Trojan:Win32/HackTool" |
| Mimikatz preimenovan (`m64.exe`) | ✅ Blokirao | AMSI hvata string `lsadump::dcsync` |
| SharpKatz | ❌ | Prolazi (manje signature) ali RPC error 1825 |
| Rubeus | ❌ | Prolazi |
| InstallUtil .NET payload | ❌ | Prolazi (LOLBin) |
| certutil download | ✅ Blokirao | "Trojan:Win32/Ceprolad.A" na nc.exe |
| reg save SAM/SYSTEM | ❌ | Prolazi (legitimni Windows alat) |

---

## 8. NETWORK CONNECTIVITY MATRICA

### Iz Kali (192.168.182.133) prema ostalim

| Destinacija | Port 445 (SMB) | Port 135 (RPC) | Port 443 (HTTPS) | Port 88 (Kerberos) | Port 389 (LDAP) |
|---|---|---|---|---|---|
| HYDRA-DC (.135) | ❌ Blokiran | ❌ Blokiran | - | ✅ | ✅ |
| THEPUNISHER (.137) | ❌ Blokiran | ❌ Blokiran | - | - | - |
| SPIDERMAN (.138) | ❌ Blokiran | ❌ Blokiran | - | - | - |

### Iz THEPUNISHER (192.168.182.137) prema DC

| Destinacija | Port 445 | Port 135 | Port 88 | Port 389 |
|---|---|---|---|---|
| HYDRA-DC | ✅ | ✅ | ✅ | ✅ |

**Posledica:** Sve impacket napade prema DC-u moramo da pokrenemo **kroz Sliver shell na THEPUNISHER**, ne direktno sa Kali-ja.

### Iz Windows mašina prema Kali

| Destinacija | Port 443 (Sliver mTLS) | Port 445 (SMB share) | Port 8080 (HTTP) |
|---|---|---|---|
| Kali (192.168.182.133) | ✅ | ✅ (kad je smbserver up) | ✅ (kad je python -m http.server up) |

---

## 9. ALATI KORIŠĆENI U LABU

### Na Kali

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
SharpKatz (preuzet sa GitHub Flangvik/SharpCollection)
hashcat

# Putanje
/usr/share/windows-resources/rubeus/Rubeus.exe
/usr/share/windows-resources/mimikatz/x64/mimikatz.exe
/usr/share/doc/python3-impacket/examples/
```

### Lozinka liste

```bash
/usr/share/wordlists/rockyou.txt
/tmp/users_clean.txt  # custom lista korisnika
```

---

## 10. PRE-FLIGHT CHECKLIST (pre snimanja videa)

### Sve VM-ove upaliti redosledom:
1. ✅ HYDRA-DC (DC mora da bude prvi zbog DNS-a)
2. ✅ Splunk Linux
3. ✅ THEPUNISHER
4. ✅ SPIDERMAN (po potrebi)
5. ✅ Kali

### Posle uključivanja proveriti:

```bash
# Na Kali:
ping -c 2 192.168.182.135  # DC dostupan
ping -c 2 192.168.182.131  # Splunk dostupan
ping -c 2 192.168.182.137  # THEPUNISHER dostupan
```

```powershell
# Na Windows mašinama:
Get-Service SplunkForwarder  # Mora da bude Running
Get-Service Sysmon64         # Mora da bude Running
```

### Provera u Splunk-u (Last 5 minutes):

```spl
| metadata type=hosts
| table host, recentTime
```

Mora da pokazuje sve 3 Windows hosta sa svežim `recentTime`.

```spl
index=main host=THEPUNISHER 
| stats count by sourcetype
```

Mora da pokazuje sve sourcetype-ove (Security, Sysmon, PowerShell).

### Sat sinhronizacija

```powershell
# Na svim Windows mašinama:
w32tm /resync /force
```

### Defender status

```powershell
Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled
# Mora da bude True/True
```

---

## 11. VALIDATION SKRIPTA

PowerShell skripta za brzu proveru lab spremnosti:

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
        Write-Host "[+] Exclusion C:\Temp: PRISUTAN" -ForegroundColor Green
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

**Kraj Dokumenta 1**  
**Sledeći:** `02_attack_playbook.md` — sve napadačke faze sa tačnim komandama
