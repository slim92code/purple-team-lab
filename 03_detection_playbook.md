**English** · **[Srpski](03_detection_playbook.sr.md)**

# Purple Team Home Lab — Detection Playbook

**Project:** Purple LAB — SOC Analyst Level 2
**Goal:** Detection engineering — SPL queries, MITRE Detection Cards, Splunk dashboard panels

> **Note on query format.** The SPL queries in this document are *pedagogical* — they intentionally parse raw `Message` fields with `rex` to show event structure. **Production detections do not parse Message** — they rely on the Splunk Add-on for Windows and Sysmon Add-on, which already extract all fields (`Account_Name`, `Ticket_Encryption_Type`, `Image`, `DestinationIp`…), and high-volume detections use `tstats` over accelerated CIM data models. The deployable, CIM/TA-normalized version + vendor-agnostic Sigma rules are in `detections/` (see `detections/README.md`).

---

## TABLE OF CONTENTS

1. Detection Cards (8 phases in MITRE format)
2. Splunk Dashboard structure
3. Universal SPL queries
4. False positive tuning
5. Incident Response runbook
6. Detection coverage matrix
7. **Production Hardening Playbook (Seg 10)**

---

## DETECTION CARD #1 — RECONNAISSANCE

**MITRE Tactic:** Reconnaissance / Discovery
**MITRE Technique:** T1046 (Network Service Discovery), T1087 (Account Discovery)

### Attack description

Attacker scans the network with nmap, enumerates users via LDAP/Kerberos, identifies services and AD CS templates.

### Data Sources

- Sysmon EC3 (Network Connection)
- Windows Security EC4625 (Account Failed to Log On)
- Windows Security EC4768 (Kerberos TGT requested)

### Primary SPL Queries

**SPL 1.1 — High number of network connections from a single IP (nmap signature)**

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| rex field=Message "SourceIp:\s*(?<src_ip>[^\r\n]+)"
| rex field=Message "DestinationPort:\s*(?<dst_port>[^\r\n]+)"
| stats count dc(dst_port) as unique_ports by src_ip, host
| where count > 50 OR unique_ports > 20
| sort - count
```

**SPL 1.2 — Kerberos enumeration (kerbrute userenum)**

```spl
index=main source="WinEventLog:Security" EventCode=4768
| rex field=Message "Client Address:\s*::ffff:(?<src_ip>[^\r\n]+)"
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| stats count dc(username) as unique_users by src_ip
| where unique_users > 10
| sort - count
```

**SPL 1.3 — LDAP enumeration (BloodHound signature)**

```spl
index=main source="WinEventLog:Security" EventCode=4662
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| rex field=Message "Object Name:\s*(?<object>[^\r\n]+)"
| stats count by username, object
| where count > 100
| sort - count
```

### Result analysis

| Indicator | Normal | Suspicious |
|---|---|---|
| Connections per min | < 5 | > 50 |
| Unique ports per host | 1-3 | > 20 |
| Source IP | Internal service | Unknown workstation |
| Time | Business hours | After hours |

### False Positives

| Scenario | Explanation |
|---|---|
| Vulnerability scanner (Nessus, Qualys) | Legitimate security scan — verify with security team |
| Network monitoring (Nagios, PRTG) | Can generate similar patterns |
| Administrator nmap scan | Verify with IT |

### Tuning recommendations

- Whitelist IP addresses of legitimate scanners
- Set thresholds based on baseline
- Time-based alert — lower threshold to > 10 after hours
- Correlate with other alerts from the same source IP

### Incident Response

1. Identify source IP
2. Check if IP belongs to a known scanner (whitelist check)
3. If unknown — escalate to P2
4. Block IP on firewall
5. Review all activities from the same source IP in the last 24 hours

---

## DETECTION CARD #2 — PASSWORD SPRAYING

**MITRE Tactic:** Credential Access
**MITRE Technique:** T1110.003 (Password Spraying)

### Attack description

Attacker attempts the same password against multiple user accounts via Kerberos pre-auth requests. Goal — find an account with a default/weak password without triggering the lockout policy.

### Data Sources

- Windows Security EC4771 (Kerberos pre-auth failed)
- Windows Security EC4768 (TGT requested — success)
- Windows Security EC4625 (NTLM auth failed)

### Primary SPL Queries

**SPL 2.1 — Password spray detection (multiple users from the same IP in a short window)**

```spl
index=main source="WinEventLog:Security" EventCode=4771
| rex field=Message "Client Address:\s*::ffff:(?<src_ip>[^\r\n]+)"
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| bucket _time span=5m
| stats dc(username) as unique_users count by _time, src_ip
| where unique_users >= 3
| sort - _time
```

**SPL 2.2 — Spray success identification (4771 followed by 4768)**

```spl
index=main source="WinEventLog:Security" (EventCode=4771 OR EventCode=4768)
| rex field=Message "Client Address:\s*::ffff:(?<src_ip>[^\r\n]+)"
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| transaction src_ip maxspan=10m
| where eventcount > 5 AND match(EventCode, "4768")
| table _time, src_ip, username, EventCode
```

**SPL 2.3 — Timeline for detection dashboard**

```spl
index=main source="WinEventLog:Security" EventCode=4771 earliest=-24h
| rex field=Message "Client Address:\s*::ffff:(?<src_ip>[^\r\n]+)"
| timechart span=5m count by src_ip
```

### Result analysis

| Indicator | Normal | Suspicious |
|---|---|---|
| Failed logons per user | < 3 per hour | > 5 in 5 min |
| Unique users from same IP | 1-2 | > 3 |
| Source IP | User's workstation | Unknown or Linux IP |
| Pattern | Sporadic | Sequential |

### False Positives

| Scenario | Explanation |
|---|---|
| Service account with wrong password | Configuration not updated |
| User's script (e.g., RDP retry) | Rare occurrences |
| Mobile sync client | Outlook, ActiveSync timeout retries |

### Tuning

- Exclude known service accounts from analysis
- Especially monitor activities after hours
- Correlate with EC4625 (NTLM) for a complete picture

### Incident Response

1. Identify the successfully compromised account (4771 → 4768)
2. **Urgently:** reset the password of that account
3. Review all activities of the account after compromise
4. Force re-authentication for all active sessions
5. Block source IP

---

## DETECTION CARD #3 — EXECUTION (LOLBins / InstallUtil)

**MITRE Tactic:** Defense Evasion / Execution
**MITRE Technique:** T1218.004 (InstallUtil)

### Attack description

Attacker executes a payload through a Microsoft-signed binary (`InstallUtil.exe`) instead of directly via `powershell.exe`. Bypasses application control policies that trust Microsoft binaries.

### Data Sources

- Windows Security EC4688 (Process Created)
- Sysmon EC1 (Process Create)
- Sysmon EC11 (File Create)

### Primary SPL Queries

**SPL 3.1 — InstallUtil execution detection**

```spl
index=main source="WinEventLog:Security" EventCode=4688
| rex field=Message "New Process Name:\s*(?<process>[^\r\n]+)"
| rex field=Message "Process Command Line:\s*(?<cmdline>[^\r\n]+)"
| rex field=Message "Creator Process Name:\s*(?<parent>[^\r\n]+)"
| search process="*InstallUtil.exe*"
| table _time, host, parent, process, cmdline
| sort - _time
```

**SPL 3.2 — InstallUtil spawns suspicious children**

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| rex field=Message "ParentImage:\s*(?<parent>[^\r\n]+)"
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| rex field=Message "CommandLine:\s*(?<cmdline>[^\r\n]+)"
| search parent="*InstallUtil.exe*"
| table _time, host, parent, process, cmdline
| sort - _time
```

**SPL 3.3 — Suspicious DLL files in C:\Temp**

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| rex field=Message "TargetFilename:\s*(?<filename>[^\r\n]+)"
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| search filename="C:\\Temp*.dll" OR filename="C:\\Temp*.exe"
| table _time, host, process, filename
```

### Analysis

| Indicator | Normal | Suspicious |
|---|---|---|
| InstallUtil parent | msiexec, svchost | cmd.exe, powershell.exe |
| InstallUtil child | none | cmd.exe, whoami.exe |
| DLL path | Program Files | C:\Temp, C:\Users\*\Downloads |
| Flag `/U` (uninstall) | Rare | Frequent (LOLBin signature) |

### False Positives

| Scenario | Explanation |
|---|---|
| Visual Studio development | Build processes legitimately use InstallUtil |
| .NET application setup | Software installation |

### Tuning

- Whitelist InstallUtil parent processes (msiexec, setup.exe)
- Alert only on DLL/EXE from user-writable paths
- Correlate with Defender SmartScreen events

### Incident Response

1. Identify which DLL/EXE was executed
2. Hash & VirusTotal lookup
3. Isolate host
4. Memory dump before attempting to stop the process
5. Identify the delivery vector

---

## DETECTION CARD #4 — KERBEROASTING

**MITRE Tactic:** Credential Access
**MITRE Technique:** T1558.003 (Kerberoasting)

### Attack description

Attacker seeks TGS tickets for accounts with SPNs (service accounts). RC4 encryption in the TGS response is crackable offline. Goal — obtain the hash of a service account that often has privileged permissions.

### Data Sources

- Windows Security EC4769 (Kerberos service ticket requested)

### Primary SPL Queries

**SPL 4.1 — Kerberoasting (RC4 encryption type)**

```spl
index=main source="WinEventLog:Security" EventCode=4769
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| rex field=Message "Service Name:\s*(?<service>[^\r\n]+)"
| rex field=Message "Ticket Encryption Type:\s*(?<enc_type>[^\r\n]+)"
| rex field=Message "Client Address:\s*::ffff:(?<src_ip>[^\r\n]+)"
| where enc_type="0x17"
| search NOT service="krbtgt" NOT service="*$"
| table _time, host, src_ip, username, service, enc_type
| sort - _time
```

**SPL 4.2 — Multiple TGS requests in a short period (mass kerberoasting)**

```spl
index=main source="WinEventLog:Security" EventCode=4769
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| rex field=Message "Service Name:\s*(?<service>[^\r\n]+)"
| rex field=Message "Ticket Encryption Type:\s*(?<enc_type>[^\r\n]+)"
| where enc_type="0x17"
| bucket _time span=5m
| stats dc(service) as unique_services by _time, username
| where unique_services > 3
```

### Analysis

| Indicator | Normal | Suspicious |
|---|---|---|
| Encryption type | 0x12 (AES256), 0x11 (AES128) | **0x17 (RC4-HMAC)** |
| Service requests per user | 1-3 (legitimate applications) | > 5 (mass roasting) |
| Service target | krbtgt, machine accounts | User accounts with SPN |
| Source | DC, application server | User workstation |

### False Positives

| Scenario | Explanation |
|---|---|
| Legacy application with RC4 | Old SQL Server, custom application |
| MS Office with SPN | Rare but possible |

### Tuning

- Whitelist legacy applications
- Special attention to accounts with "admincount=1" property
- Migrate to AES encryption (msDS-SupportedEncryptionTypes)

### Incident Response

1. Identify which service account's TGS was requested
2. **Urgently:** rotate the password of the service account
3. Set AES encryption for the account
4. Review account permissions (Domain Admin? local Admin?)
5. Consider gMSA (Group Managed Service Account) migration

---

## DETECTION CARD #5 — LATERAL MOVEMENT (C2 Implant)

**MITRE Tactic:** Command and Control
**MITRE Technique:** T1071.001 (Web Protocols), T1572 (Protocol Tunneling)

### Attack description

Attacker launches a C2 implant (Sliver, Cobalt Strike, Metasploit) that establishes an mTLS/HTTPS connection to the attacker's server. All subsequent commands go through that channel.

### Data Sources

- Sysmon EC1 (Process Create)
- Sysmon EC3 (Network Connection)
- Sysmon EC11 (File Create)
- Sysmon EC22 (DNS Query)

### Primary SPL Queries

**SPL 5.1 — Processes from C:\Temp making network connections**

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| rex field=Message "DestinationIp:\s*(?<dst_ip>[^\r\n]+)"
| rex field=Message "DestinationPort:\s*(?<dst_port>[^\r\n]+)"
| search process="C:\\Temp\\*" OR process="C:\\Users\\*\\AppData\\*" OR process="C:\\ProgramData\\*"
| stats count by host, process, dst_ip, dst_port
| sort - count
```

**SPL 5.2 — Beaconing pattern (regular intervals)**

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 dst_port=443
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| rex field=Message "DestinationIp:\s*(?<dst_ip>[^\r\n]+)"
| eval connect_time=_time
| sort 0 process, dst_ip, _time
| streamstats current=f last(connect_time) as prev_connect by process, dst_ip
| eval interval=connect_time-prev_connect
| where interval > 10 AND interval < 300
| stats avg(interval) as avg_interval stdev(interval) as stdev_interval count by host, process, dst_ip
| where count > 5 AND stdev_interval < 30
| sort - count
```

**SPL 5.3 — Internal IP destinations (not internet)**

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| rex field=Message "DestinationIp:\s*(?<dst_ip>[^\r\n]+)"
| rex field=Message "DestinationPort:\s*(?<dst_port>[^\r\n]+)"
| search dst_ip="192.168.182.*" dst_port="443"
| search NOT process="*svchost*" NOT process="*chrome*" NOT process="*firefox*"
| table _time, host, process, dst_ip, dst_port
| sort - _time
```

### Analysis

| Indicator | Normal | Suspicious |
|---|---|---|
| Process path | Program Files, System32 | C:\Temp, AppData, ProgramData |
| Destination IP | Public Microsoft/Google | Internal IP that isn't DC or a known server |
| Connection interval | Random | Regular (60s + jitter) |
| Connection duration | Short or long-lived legit | Periodic short bursts |

### False Positives

| Scenario | Explanation |
|---|---|
| OneDrive sync | OneDrive goes to Microsoft IPs (52.x.x.x, 150.171.x.x) |
| Windows Update | svchost.exe, port 443 to windowsupdate.com |
| Browser auto-update | Chrome/Firefox update mechanisms |

### Tuning recommendations

**KEY:** Add to Sysmon NetworkConnect watchlist:

```xml
<NetworkConnect onmatch="include">
  <Image condition="contains">\Temp\</Image>
  <Image condition="contains">\AppData\</Image>
  <Image condition="contains">\ProgramData\</Image>
  <Rule groupRelation="and">
    <DestinationPort condition="is">443</DestinationPort>
    <DestinationIp condition="begin with">192.168.</DestinationIp>
  </Rule>
</NetworkConnect>
```

### Incident Response

1. **Urgently:** isolate the compromised host (network)
2. Memory dump
3. Analyze process tree
4. Identify the C2 server
5. Block C2 IP on perimeter firewall
6. Review whether C2 spread to other hosts

---

## DETECTION CARD #6 — CREDENTIAL DUMPING

**MITRE Tactic:** Credential Access
**MITRE Technique:** T1003.002 (SAM), T1003.005 (Cached Credentials), T1003.006 (DCSync)

### Attack description

Attacker extracts local and cached domain credentials via `reg save` of SAM/SYSTEM/SECURITY hives, or attempts DCSync against the DC.

### Data Sources

- Windows Security EC4688 (Process Created)
- Sysmon EC1 (Process Create)
- Sysmon EC11 (File Create — hive files)
- Windows Defender Operational log

### Primary SPL Queries

**SPL 6.1 — Registry hive dump detection**

```spl
index=main source="WinEventLog:Security" EventCode=4688
| rex field=Message "Process Command Line:\s*(?<cmdline>[^\r\n]+)"
| rex field=Message "New Process Name:\s*(?<process>[^\r\n]+)"
| search process="*reg.exe*" cmdline="*save*" (cmdline="*SAM*" OR cmdline="*SYSTEM*" OR cmdline="*SECURITY*")
| table _time, host, process, cmdline
| sort - _time
```

**SPL 6.2 — Suspicious hive files in non-Windows locations**

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| rex field=Message "TargetFilename:\s*(?<filename>[^\r\n]+)"
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| search filename="*.hive" OR filename="*sam*.save*" OR filename="*system*.save*"
| search NOT filename="C:\\Windows\\System32*"
| table _time, host, process, filename
```

**SPL 6.3 — Mimikatz / SharpKatz detection (Defender blocks)**

```spl
index=main source="WinEventLog:Microsoft-Windows-Windows Defender/Operational" 
  (EventCode=1116 OR EventCode=1117)
| rex field=Message "Name:\s*(?<threat>[^\r\n]+)"
| rex field=Message "Path:\s*(?<path>[^\r\n]+)"
| table _time, host, threat, path
```

**SPL 6.4 — DCSync detection (replication traffic from non-DC)**

```spl
index=main source="WinEventLog:Security" EventCode=4662
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| rex field=Message "Properties:\s*(?<properties>[^\r\n]+)"
| search properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"
| search NOT username="*$"
| table _time, host, username, properties
```

GUIDs are:
- `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` = DS-Replication-Get-Changes
- `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` = DS-Replication-Get-Changes-All
- `89e95b76-444d-4c62-991a-0facbeda640c` = DS-Replication-Get-Changes-In-Filtered-Set

**SPL 6.5 — LSASS access (Mimikatz signature)**

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
| rex field=Message "TargetImage:\s*(?<target>[^\r\n]+)"
| rex field=Message "SourceImage:\s*(?<source>[^\r\n]+)"
| rex field=Message "GrantedAccess:\s*(?<access>[^\r\n]+)"
| search target="*lsass.exe*"
| search access="0x1010" OR access="0x1410" OR access="0x143A"
| table _time, host, source, target, access
```

### Analysis

| Indicator | Normal | Suspicious |
|---|---|---|
| reg.exe save | Backup tools | Combination SAM+SYSTEM+SECURITY |
| Hive file location | C:\Windows\System32\config | C:\Temp, C:\Users\Public |
| LSASS access | csrss.exe, wininit.exe | Processes from user space |
| DCSync source | DC machine account | User account |

### False Positives

| Scenario | Explanation |
|---|---|
| Backup software | Veeam, BackupExec legitimately use reg save |
| System administrator | Manual backup before upgrade |
| Forensics tools | Versioned evidence collection |

### Tuning

- Whitelist backup software service accounts
- Alert only on SAM + SYSTEM + SECURITY combination in a short timeframe
- DCSync alert is high-fidelity — always investigate

### Incident Response

1. **Critical alert** — DCSync or Mimikatz signature = potential Domain Admin compromise
2. Host isolation immediately
3. Force krbtgt password reset (TWICE, not once)
4. Reset all privileged accounts
5. Forensic memory analysis
6. Threat hunt — other hosts with the same IOCs

---

## DETECTION CARD #7 — PERSISTENCE (Scheduled Task)

**MITRE Tactic:** Persistence
**MITRE Technique:** T1053.005 (Scheduled Task/Job)

### Attack description

Attacker creates a scheduled task that executes malware at logon or on a schedule, running as SYSTEM. The implant remains active after reboot.

### Data Sources

- Windows Security EC4698 (Scheduled Task Created)
- Windows Security EC4702 (Scheduled Task Updated)
- Windows TaskScheduler EC106 (Task registered)
- Sysmon EC11 (File Create in C:\Windows\System32\Tasks)

### Primary SPL Queries

**SPL 7.1 — Scheduled task creation (master query)**

```spl
index=main source="WinEventLog:Security" EventCode=4698
| rex field=Message "Task Name:\s*(?<taskname>[^\r\n]+)"
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| rex field=Message "<Command>(?<command>[^<]+)</Command>"
| rex field=Message "<UserId>(?<runas>[^<]+)</UserId>"
| rex field=Message "<LogonTrigger>" 
| table _time, host, username, taskname, command, runas
| sort - _time
```

**SPL 7.2 — Task created from suspicious binary path**

```spl
index=main source="WinEventLog:Security" EventCode=4698
| rex field=Message "Task Name:\s*(?<taskname>[^\r\n]+)"
| rex field=Message "<Command>(?<command>[^<]+)</Command>"
| search command="C:\\Temp*" OR command="C:\\Users*" OR command="C:\\ProgramData*"
| table _time, host, taskname, command
| sort - _time
```

**SPL 7.3 — Task running as SYSTEM (S-1-5-18)**

```spl
index=main source="WinEventLog:Security" EventCode=4698
| rex field=Message "Task Name:\s*(?<taskname>[^\r\n]+)"
| rex field=Message "Account Name:\s*(?<creator>[^\r\n]+)"
| rex field=Message "<UserId>(?<runas>[^<]+)</UserId>"
| search runas="S-1-5-18"
| search NOT creator="*$" NOT creator="SYSTEM"
| table _time, host, creator, taskname, runas
| sort - _time
```

**SPL 7.4 — Sysmon FileCreate in Tasks folder**

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| rex field=Message "TargetFilename:\s*(?<filename>[^\r\n]+)"
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| search filename="C:\\Windows\\System32\\Tasks\\*"
| search NOT process="*svchost*" NOT process="*MsMpEng*"
| table _time, host, process, filename
```

### Analysis

| Indicator | Normal | Suspicious |
|---|---|---|
| Task creator | SYSTEM, Administrator | User account |
| Task command path | Program Files, System32 | C:\Temp, AppData |
| Run As | The user who created it | SYSTEM (escalation) |
| Trigger | Scheduled time | LogonTrigger, BootTrigger |
| Task name | Descriptive | Mimicry of legitimate (WindowsUpdate*, Adobe*) |

### False Positives

| Scenario | Explanation |
|---|---|
| Software installation | Many installers create tasks |
| Group Policy preference | Domain policy task deployment |
| Backup software | Schedule jobs |

### Tuning

- Whitelist known enterprise software task names
- Alert on combination user creator + SYSTEM runas + suspicious path
- Correlate with file create events (Sysmon EC11)

### Incident Response

1. Identify task command and runas
2. Disable task (don't delete — preserve evidence)
3. Hash check command binary
4. Identify creator account
5. Review other tasks created by the same account
6. Sweep for the same task name on other hosts

---

## DETECTION CARD #8 — C2 + EXFILTRATION

**MITRE Tactic:** Command and Control / Exfiltration
**MITRE Technique:** T1071.001 (Web Protocols), T1041 (Exfiltration Over C2 Channel)

### Attack description

Persistent C2 channel via HTTPS/mTLS (Sliver, Cobalt Strike). All commands, file uploads, and exfiltration go through the same encrypted channel.

### Data Sources

- Sysmon EC3 (Network Connection)
- Sysmon EC22 (DNS Query)
- Firewall logs (perimeter)

### Primary SPL Queries

**SPL 8.1 — C2 beaconing pattern detection**

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| rex field=Message "DestinationIp:\s*(?<dst_ip>[^\r\n]+)"
| rex field=Message "DestinationPort:\s*(?<dst_port>[^\r\n]+)"
| where dst_port=443 OR dst_port=80
| bucket _time span=1m
| stats count by _time, host, process, dst_ip
| eventstats avg(count) as avg_count stdev(count) as stdev_count by process, dst_ip
| where avg_count > 0.5 AND stdev_count < 1
```

**SPL 8.2 — Long-running connections from user-space binaries**

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

**SPL 8.3 — Suspicious DNS queries (DGA pattern)**

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22
| rex field=Message "QueryName:\s*(?<query>[^\r\n]+)"
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| eval query_len=len(query)
| where query_len > 30
| stats count by host, process, query
| sort - count
```

**SPL 8.4 — File create followed by network connection (staging)**

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" 
  (EventCode=11 OR EventCode=3)
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| rex field=Message "TargetFilename:\s*(?<filename>[^\r\n]+)"
| rex field=Message "DestinationIp:\s*(?<dst_ip>[^\r\n]+)"
| eval activity=if(EventCode=11, "FILE_CREATE", "NETWORK_CONN")
| transaction host process maxspan=5m
| where eventcount > 5
| table _time, host, process, activity, filename, dst_ip
```

### Analysis

| Indicator | Normal | Suspicious |
|---|---|---|
| Connection interval | Random | Regular (heartbeat) |
| Destination | CDN, public services | Single IP held over time |
| Process | Browser, system services | User-writable path binary |
| TLS SNI | Matches destination | Doesn't match or empty |

### False Positives

| Scenario | Explanation |
|---|---|
| OneDrive sync (Microsoft IPs) | 52.x.x.x, 150.171.x.x |
| Windows Update | windowsupdate.microsoft.com |
| Antivirus updates | Defender update channels |
| Telemetry (Microsoft, Adobe, browser) | Regular small requests |

### Tuning

- Maintain allowlist of legitimate cloud services (Microsoft, Google, Adobe IP ranges)
- Threshold based on baseline traffic patterns
- Investigate based on **combination** of indicators, not individual ones

### Incident Response

1. **Urgently isolate** the compromised host
2. Capture network traffic (PCAP)
3. Identify the C2 destination
4. Block on perimeter firewall and DNS
5. Threat intel lookup for the destination
6. Sweep the network for the same IOC

---

## SPLUNK DASHBOARD STRUCTURE

### Dashboard 1 — "Purple Lab — Attack Overview"

**Panel 1.1 — Single Value: Active Alerts (Last 24h)**

```spl
index=main source="WinEventLog:Security" (EventCode=4771 OR EventCode=4769 OR EventCode=4698 OR EventCode=4688) earliest=-24h
| stats count
```

**Panel 1.2 — Timechart: Attacks by Phase**

```spl
index=main source="WinEventLog:Security" earliest=-24h
| eval phase=case(
    EventCode=4771 OR EventCode=4768, "1-Password_Spray",
    EventCode=4769, "2-Kerberoasting",
    match('Process Command Line', "InstallUtil"), "3-LOLBin",
    match('Process Command Line', "reg.*save.*SAM"), "4-Cred_Dump",
    EventCode=4698, "5-Persistence",
    true(), "Other"
)
| where phase != "Other"
| timechart span=15m count by phase
```

**Panel 1.3 — Table: Top 10 Suspicious Activities**

```spl
index=main source="WinEventLog:Security" EventCode=4688
| rex field=Message "Process Command Line:\s*(?<cmdline>[^\r\n]+)"
| search cmdline="*mimikatz*" OR cmdline="*reg.*save*" OR cmdline="*InstallUtil*" OR cmdline="*schtasks*" OR cmdline="*certutil*"
| stats count by host, cmdline
| sort - count
| head 10
```

---

## UNIVERSAL SPL QUERIES (CHEAT SHEET)

### Top Failed Logons

```spl
index=main source="WinEventLog:Security" EventCode=4625
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| stats count by username, host
| sort - count
```

### LOLBins across all machines

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

### Suspicious File Creates

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| rex field=Message "TargetFilename:\s*(?<filename>[^\r\n]+)"
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| search (filename="C:\\Temp\\*.exe" OR filename="C:\\Temp\\*.dll" OR filename="*\\Tasks\\*")
| search NOT process="*Defender*" AND NOT process="*OneDrive*"
| table _time, host, process, filename
```

---

## INCIDENT RESPONSE RUNBOOK

### Priority levels

| Level | Definition | Response time |
|---|---|---|
| **P1 — Critical** | Domain compromise potential, active C2, credential theft | < 15 min |
| **P2 — High** | Privilege escalation, lateral movement, persistence | < 1 hour |
| **P3 — Medium** | Suspicious activity, recon, failed exploitation | < 4 hours |
| **P4 — Low** | Anomalies without clear malicious intent | < 24 hours |

### Generic IR process

**1. Detect & Triage (0-15 min)**
- Alert assessment
- Initial classification (P1-P4)
- Notify on-call team
- Document timeline start

**2. Investigate (15 min - 4 hours)**
- Correlate alerts
- Pull related logs (Splunk searches)
- Identify scope (which hosts, which accounts)
- Memory dump if possible

**3. Contain (parallel with investigate)**
- Network isolation of compromised host
- Disable affected accounts
- Block C2 IP/domain
- Preserve evidence

**4. Eradicate**
- Remove malware
- Reset credentials
- Patch vulnerabilities
- Validate clean state

**5. Recover**
- Restore from clean backup if needed
- Re-enable services
- Monitor for re-infection

**6. Lessons Learned**
- Post-incident review
- Update detection logic
- Train team
- Update runbook

---

## DETECTION COVERAGE MATRIX

| MITRE Technique | Detection Source | SPL Status | False Positive Risk |
|---|---|---|---|
| T1046 (Net Service Discovery) | Sysmon EC3 | ✅ High | Medium |
| T1087 (Account Discovery) | Sec EC4768 | ✅ High | Low |
| T1110.003 (Password Spray) | Sec EC4771 | ✅ Excellent | Low |
| T1558.003 (Kerberoasting) | Sec EC4769 | ✅ Excellent | Low |
| T1218.004 (InstallUtil) | Sec EC4688 | ✅ High | Medium |
| T1071.001 (Web Protocols C2) | Sysmon EC3 | ⚠️ Medium (needs tuning) | High |
| T1003.002 (SAM dump) | Sec EC4688 | ✅ Excellent | Low |
| T1003.006 (DCSync) | Sec EC4662 | ✅ High | Low |
| T1053.005 (Scheduled Task) | Sec EC4698 | ✅ Excellent | Medium |
| T1041 (Exfil over C2) | Sysmon EC3 | ⚠️ Medium | High |

---

## PRODUCTION HARDENING PLAYBOOK (Segment 10)

**Goal:** "Before/After Detection Engineering" — for each attack from Phases 1-8, define a hardening fix + re-run SPL query that proves the attack now fails or is detected at a new layer.

**Central point:** Hardening ≠ Detection. Prevention reduces the attack surface, but the surface never reaches zero. Detection remains the *safety net* for everything that slips through the prevention layer.

---

### Hardening Fix #1 — Phase 2 Password Spray

**Prevention controls:**
- Fine-Grained Password Policy (min 14 chars, complexity enabled)
- Account Lockout Threshold = 5
- Lockout Duration = 30 minutes
- Lockout Observation Window = 30 minutes

**Re-run SPL — verify lockout:**

```spl
index=main source="WinEventLog:Security" EventCode=4740
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| rex field=Message "Caller Computer Name:\s*(?<src_host>[^\r\n]+)"
| table _time, username, src_host
| sort - _time
```

**SPL for low-and-slow detection (bypass attempt):**

```spl
index=main source="WinEventLog:Security" EventCode=4771 earliest=-7d
| rex field=Message "Client Address:\s*::ffff:(?<src_ip>[^\r\n]+)"
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| bucket _time span=1h
| stats dc(username) as unique_users count by _time, src_ip
| where unique_users > 5
| sort - _time
```

> An attacker who waits 35 minutes between attempts per user bypasses lockout, but creates a distinct multi-user pattern over longer time.

---

### Hardening Fix #2 — Phase 4 Kerberoasting

**Prevention controls:**
- `msDS-SupportedEncryptionTypes` = 24 (AES128 + AES256) for all service accounts
- Service account password ≥ 20 chars random
- Description, info, comment fields cleaned of password leaks
- gMSA migration (long-term recommendation)

**Re-run SPL — RC4 now an anomaly:**

```spl
index=main source="WinEventLog:Security" EventCode=4769
| rex field=Message "Ticket Encryption Type:\s*(?<enc_type>[^\r\n]+)"
| rex field=Message "Service Name:\s*(?<service>[^\r\n]+)"
| where enc_type="0x17"
| stats count by service, enc_type
```

> After AES enforcement, every 0x17 (RC4) event is an anomaly. The alert threshold flips — RC4 now *must* alert because it shouldn't exist.

---

### Hardening Fix #3 — Phase 5 Sliver Execution

**Prevention controls:**
- AppLocker Deny rules for C:\Temp, C:\Users\*\AppData\Local\Temp, C:\Users\Public
- AppLocker service (AppIDSvc) on Automatic + Started
- GPO deployment via central policy
- WDAC as next step for high-security tier

**Re-run SPL — AppLocker Block events:**

```spl
index=main source="WinEventLog:Microsoft-Windows-AppLocker/EXE and DLL" EventCode=8004
| rex field=Message "(?<blocked_path>C:\\\\[^\s]+\.exe)"
| rex field=Message "User:\s*(?<user>[^\r\n]+)"
| table _time, user, blocked_path
| sort - _time
```

**SPL for bypass attempts (signed LOLBin abuse):**

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| rex field=Message "ParentImage:\s*(?<parent>[^\r\n]+)"
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| rex field=Message "CommandLine:\s*(?<cmdline>[^\r\n]+)"
| search process="*InstallUtil*" OR process="*MSBuild*" OR process="*regsvr32*"
| search cmdline="*\\Temp\\*" OR cmdline="*\\AppData\\*"
| table _time, parent, process, cmdline
```

> AppLocker blocks direct execution from user paths, but signed LOLBin can load payloads from those paths. Detection layer catches the combination.

---

### Hardening Fix #4 — Phase 8 mTLS C2 Beacon

**Prevention controls:**
- Sysmon NetworkConnect include rule for C:\Temp, C:\Users, C:\ProgramData
- Sysmon include rule for LOLBin binaries
- Sysmon config deploy via GPO startup script (NETLOGON share)
- Version control in Git with tags (v2.1-purple)

**Re-run SPL — beaconing detection:**

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| rex field=Message "DestinationIp:\s*(?<dst_ip>[^\r\n]+)"
| rex field=Message "DestinationPort:\s*(?<dst_port>[^\r\n]+)"
| search process="*\\Temp\\*" OR process="*\\Users\\*"
| stats count by process, dst_ip, dst_port
| where count > 5
| sort - count
```

**SPL for beacon interval anomaly (jitter analysis):**

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| rex field=Message "DestinationIp:\s*(?<dst_ip>[^\r\n]+)"
| search process="*\\Temp\\*"
| streamstats current=f window=1 values(_time) as prev_time by process, dst_ip
| eval interval=_time-prev_time
| stats avg(interval) as avg_interval, stdev(interval) as jitter, count by process, dst_ip
| where avg_interval > 30 AND avg_interval < 300 AND jitter < 10
```

> Regular intervals with small jitter = beaconing signature. Sliver default is 60s ± 30%.

---

### Hardening Coverage Matrix

| Phase | Attack | Prevention Layer | Detection Layer | Status |
|---|---|---|---|---|
| 1 | Recon (nmap, kerbrute) | Network segmentation | EC4768 fail code 0x6 alert | Detection only |
| 2 | Password Spray | FGPP + lockout | EC4740 + multi-user 4771 | Both |
| 3 | LOLBin Execution | AppLocker + WDAC | EC4688 + Sysmon EC1 chain | Both |
| 4 | Kerberoasting | AES + strong password + gMSA | EC4769 RC4 anomaly | Both |
| 5 | Sliver Execution | AppLocker Deny C:\Temp | EC8004 + Sysmon EC1 | Both |
| 6 | Credential Dumping | Defender + Credential Guard | Sysmon EC11 SAM dump | Both |
| 7 | Persistence | Restricted local admin | EC4698 + Sysmon EC11 Tasks | Detection primary |
| 8 | mTLS C2 Beacon | Egress filter + TLS inspection (NDR) | Sysmon EC3 + JA3 fingerprint | Detection primary |

---

### Closing Insight — Mature SOC Mindset

**L1 thinking:** "We have Splunk and Defender, we're covered."

**L2 thinking:** "Prevention + Detection layer + Detection-as-Code + MITRE ATT&CK coverage + false positive tuning."

**L3 thinking:** "Threat model → attack paths → which attacks are realistic → prevention investment vs detection investment optimization."

Defense in Depth means an attacker must bypass multiple layers. But no single layer is bulletproof. Detection remains the *safety net* for everything prevention lets through. That is the difference between an SOC analyst who thinks about tools and one who thinks about methodology.

---
