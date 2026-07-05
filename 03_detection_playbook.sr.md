**[English](03_detection_playbook.md)** · **Srpski**
# Purple Team Home Lab — Detection Playbook

**Projekat:** Purple LAB — SOC Analyst Level 2  
**Cilj:** Detection engineering — SPL upiti, MITRE Detection Cards, Splunk dashboard panels

> **Napomena o formi upita.** SPL upiti u ovom dokumentu su *pedagoški* — namerno ručno
> parsiraju sirovi `Message` sa `rex` da bi se videla struktura eventa. **Produkcijske
> detekcije ne parsiraju Message** — oslanjaju se na Splunk Add-on for Windows i Add-on for
> Sysmon koji već ekstrahuju sva polja (`Account_Name`, `Ticket_Encryption_Type`, `Image`,
> `DestinationIp`…), a high-volume detekcije idu kroz `tstats` nad akcelerovanim CIM data
> modelima. Deployable, CIM/TA-normalizovana verzija + vendor-agnostic Sigma pravila su u
> `detections/` (vidi `detections/README.md`).

---

## SADRŽAJ

1. Detection Cards (8 faza po MITRE formatu)
2. Splunk Dashboard struktura
3. Univerzalni SPL upiti
4. False positive tuning
5. Incident Response runbook
6. Detection coverage matrica
7. **Production Hardening Playbook (Seg 10)**

---

## DETECTION CARD #1 — RECONNAISSANCE

**MITRE Tactic:** Reconnaissance / Discovery  
**MITRE Technique:** T1046 (Network Service Discovery), T1087 (Account Discovery)

### Opis napada

Napadač skenira mrežu nmap-om, enumerira korisnike kroz LDAP/Kerberos, identifikuje servise i AD CS šablone.

### Data Sources

- Sysmon EC3 (Network Connection)
- Windows Security EC4625 (Account Failed to Log On)
- Windows Security EC4768 (Kerberos TGT requested)

### Primarni SPL Upiti

**SPL 1.1 — Visok broj mrežnih konekcija sa jednog IP-a (nmap signature)**

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| rex field=Message "SourceIp:\s*(?<src_ip>[^\r\n]+)"
| rex field=Message "DestinationPort:\s*(?<dst_port>[^\r\n]+)"
| stats count dc(dst_port) as unique_ports by src_ip, host
| where count > 50 OR unique_ports > 20
| sort - count
```

**SPL 1.2 — Kerberos enumeracija (kerbrute userenum)**

```spl
index=main source="WinEventLog:Security" EventCode=4768
| rex field=Message "Client Address:\s*::ffff:(?<src_ip>[^\r\n]+)"
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| stats count dc(username) as unique_users by src_ip
| where unique_users > 10
| sort - count
```

**SPL 1.3 — LDAP enumeracija (BloodHound signature)**

```spl
index=main source="WinEventLog:Security" EventCode=4662
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| rex field=Message "Object Name:\s*(?<object>[^\r\n]+)"
| stats count by username, object
| where count > 100
| sort - count
```

### Analiza rezultata

| Pokazatelj | Normalno | Sumnjivo |
|---|---|---|
| Konekcije u 1 min | < 5 | > 50 |
| Različiti portovi po hostu | 1-3 | > 20 |
| Source IP | Interni servisni | Nepoznat workstation |
| Vreme | Radno vreme | Van radnog vremena |

### False Positives

| Scenario | Objašnjenje |
|---|---|
| Vulnerability scanner (Nessus, Qualys) | Legitimni security scan — verifikuj sa security timom |
| Network monitoring (Nagios, PRTG) | Mogu generisati slične patterne |
| Administrator nmap scan | Verifikuj sa IT |

### Tuning preporuke

- Whitelist IP adrese legitimnih skenera
- Threshold podesiti na osnovu baseline-a
- Time-based alert — van radnog vremena snizi threshold na > 10
- Korelacija sa ostalim alertima istog source IP-a

### Incident Response

1. Identifikovati source IP
2. Proveriti da li IP pripada poznatom skeneru (whitelist check)
3. Ako nepoznat — eskalirati P2
4. Blokirati IP na firewall-u
5. Pregledati sve aktivnosti istog source IP-a u poslednjih 24h

---

## DETECTION CARD #2 — PASSWORD SPRAYING

**MITRE Tactic:** Credential Access  
**MITRE Technique:** T1110.003 (Password Spraying)

### Opis napada

Napadač pokušava istu lozinku na više korisničkih naloga kroz Kerberos pre-auth zahteve. Cilj — pronaći nalog sa default/slabom lozinkom bez aktiviranja lockout polise.

### Data Sources

- Windows Security EC4771 (Kerberos pre-auth failed)
- Windows Security EC4768 (TGT requested — uspeh)
- Windows Security EC4625 (NTLM auth failed)

### Primarni SPL Upiti

**SPL 2.1 — Password Spray detection (više korisnika sa istog IP-a u kratkom periodu)**

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

**SPL 2.3 — Timeline za detection dashboard**

```spl
index=main source="WinEventLog:Security" EventCode=4771 earliest=-24h
| rex field=Message "Client Address:\s*::ffff:(?<src_ip>[^\r\n]+)"
| timechart span=5m count by src_ip
```

### Analiza rezultata

| Pokazatelj | Normalno | Sumnjivo |
|---|---|---|
| Failed logons po useru | < 3 u sat | > 5 u 5 min |
| Različiti useri sa istog IP | 1-2 | > 3 |
| Source IP | Workstation usera | Nepoznat ili Linux IP |
| Pattern | Sporadično | Sekvencijalno |

### False Positives

| Scenario | Objašnjenje |
|---|---|
| Servisni nalog sa pogrešnom lozinkom | Konfiguracija nije ažurirana |
| User-ov skenarski (npr. RDP retry) | Retke pojave |
| Mobile sync klijent | Outlook, ActiveSync timeout retries |

### Tuning

- Isključi poznate servisne naloge iz analize
- Posebno pratiti aktivnosti van radnog vremena
- Korelacija sa 4625 (NTLM) za kompletnu sliku

### Incident Response

1. Identifikovati uspešno kompromitovan nalog (4771 → 4768)
2. **Hitno:** resetovati lozinku tog naloga
3. Pregledati sve aktivnosti naloga nakon kompromisa
4. Force re-authentication za sve aktivne sesije
5. Blokirati source IP

---

## DETECTION CARD #3 — EXECUTION (LOLBins / InstallUtil)

**MITRE Tactic:** Defense Evasion / Execution  
**MITRE Technique:** T1218.004 (InstallUtil)

### Opis napada

Napadač pokreće payload kroz Microsoft signed binary `InstallUtil.exe` umesto direktno `powershell.exe`. Zaobilazi Application Control politike koje veruju Microsoft binary-jima.

### Data Sources

- Windows Security EC4688 (Process Created)
- Sysmon EC1 (Process Create)
- Sysmon EC11 (File Create)

### Primarni SPL Upiti

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

**SPL 3.3 — Sumnjivi DLL fajlovi u C:\Temp**

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| rex field=Message "TargetFilename:\s*(?<filename>[^\r\n]+)"
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| search filename="C:\\Temp*.dll" OR filename="C:\\Temp*.exe"
| table _time, host, process, filename
```

### Analiza

| Pokazatelj | Normalno | Sumnjivo |
|---|---|---|
| InstallUtil parent | msiexec, svchost | cmd.exe, powershell.exe |
| InstallUtil child | nikakav | cmd.exe, whoami.exe |
| DLL path | Program Files | C:\Temp, C:\Users\*\Downloads |
| Flag `/U` (uninstall) | Retko | Često (LOLBin signature) |

### False Positives

| Scenario | Objašnjenje |
|---|---|
| Visual Studio razvoj | Build procesi koriste InstallUtil legitimno |
| .NET aplikacije setup | Software instalacija |

### Tuning

- Whitelist InstallUtil parent procesi (msiexec, setup.exe)
- Alert samo na DLL/EXE iz user-writable path-ova
- Korelacija sa Defender SmartScreen evento

### Incident Response

1. Identifikovati DLL/EXE koji je pokrenut
2. Hash & VirusTotal lookup
3. Isolate host
4. Memory dump pre nego što proces pokušaš da zaustaviš
5. Identifikovati delivery vector

---

## DETECTION CARD #4 — KERBEROASTING

**MITRE Tactic:** Credential Access  
**MITRE Technique:** T1558.003 (Kerberoasting)

### Opis napada

Napadač traži TGS tickete za naloge sa SPN-om (servisni nalozi). RC4 enkripcija u TGS response-u je krekibilna offline. Cilj — dobiti hash service naloga koji često ima privilegovane permisije.

### Data Sources

- Windows Security EC4769 (Kerberos service ticket requested)

### Primarni SPL Upiti

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

**SPL 4.2 — Više TGS zahteva u kratkom periodu (mass kerberoasting)**

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

### Analiza

| Pokazatelj | Normalno | Sumnjivo |
|---|---|---|
| Encryption type | 0x12 (AES256), 0x11 (AES128) | **0x17 (RC4-HMAC)** |
| Service requests po useru | 1-3 (legitimne aplikacije) | > 5 (mass roasting) |
| Service target | krbtgt, machine accounts | User accounts sa SPN |
| Source | DC, application server | User workstation |

### False Positives

| Scenario | Objašnjenje |
|---|---|
| Legacy aplikacija sa RC4 | Stari SQL Server, custom aplikacija |
| MS Office sa SPN | Retko, ali moguće |

### Tuning

- Whitelist legacy aplikacije
- Posebna pažnja na naloge sa "admincount=1" property-jem
- Migracija na AES enkripciju (msDS-SupportedEncryptionTypes)

### Incident Response

1. Identifikovati service nalog čiji TGS je traženo
2. **Hitno:** rotirati lozinku service naloga
3. Postaviti AES enkripciju za nalog
4. Pregledati permisije naloga (Domain Admin? lokalni Admin?)
5. Razmotriti gMSA (Group Managed Service Account) migraciju

---

## DETECTION CARD #5 — LATERAL MOVEMENT (C2 Implant)

**MITRE Tactic:** Command and Control  
**MITRE Technique:** T1071.001 (Web Protocols), T1572 (Protocol Tunneling)

### Opis napada

Napadač pokreće C2 implant (Sliver, Cobalt Strike, Metasploit) koji uspostavlja mTLS/HTTPS konekciju prema napadačkom serveru. Sve dalje komande idu kroz taj kanal.

### Data Sources

- Sysmon EC1 (Process Create)
- Sysmon EC3 (Network Connection)
- Sysmon EC11 (File Create)
- Sysmon EC22 (DNS Query)

### Primarni SPL Upiti

**SPL 5.1 — Procesi iz C:\Temp koji prave mrežne konekcije**

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| rex field=Message "DestinationIp:\s*(?<dst_ip>[^\r\n]+)"
| rex field=Message "DestinationPort:\s*(?<dst_port>[^\r\n]+)"
| search process="C:\\Temp\\*" OR process="C:\\Users\\*\\AppData\\*" OR process="C:\\ProgramData\\*"
| stats count by host, process, dst_ip, dst_port
| sort - count
```

**SPL 5.2 — Beaconing pattern (regularni intervali)**

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

**SPL 5.3 — Interne IP destinacije (nije internet)**

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

### Analiza

| Pokazatelj | Normalno | Sumnjivo |
|---|---|---|
| Process path | Program Files, System32 | C:\Temp, AppData, ProgramData |
| Destination IP | Public Microsoft/Google | Interni IP koji nije DC ili poznati server |
| Connection interval | Random | Regular (60s + jitter) |
| Connection duration | Kratke ili long-lived legit | Periodic short bursts |

### False Positives

| Scenario | Objašnjenje |
|---|---|
| OneDrive sync | OneDrive ide na Microsoft IP-ove (52.x.x.x, 150.171.x.x) |
| Windows Update | svchost.exe, port 443 prema windowsupdate.com |
| Browser auto-update | Chrome/Firefox update mehanizmi |

### Tuning preporuke

**KLJUČNO:** Dodaj na Sysmon NetworkConnect watchlist:

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

1. **Hitno:** isolate kompromitovani host (network)
2. Memory dump
3. Analiziraj process tree
4. Identifikovati C2 server
5. Blokirati C2 IP na perimeter firewall
6. Pregled da li je C2 širio se na druge hostove

---

## DETECTION CARD #6 — CREDENTIAL DUMPING

**MITRE Tactic:** Credential Access  
**MITRE Technique:** T1003.002 (SAM), T1003.005 (Cached Credentials), T1003.006 (DCSync)

### Opis napada

Napadač izvlači lokalne i cached domain kredencijale kroz `reg save` SAM/SYSTEM/SECURITY hive-ova, ili pokušava DCSync prema DC-u.

### Data Sources

- Windows Security EC4688 (Process Created)
- Sysmon EC1 (Process Create)
- Sysmon EC11 (File Create — hive fajlovi)
- Windows Defender Operational log

### Primarni SPL Upiti

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

**SPL 6.3 — Mimikatz / SharpKatz detection (Defender blokade)**

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

GUIDs su:
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

### Analiza

| Pokazatelj | Normalno | Sumnjivo |
|---|---|---|
| reg.exe save | Backup tools | Kombinacija SAM+SYSTEM+SECURITY |
| Hive file location | C:\Windows\System32\config | C:\Temp, C:\Users\Public |
| LSASS access | csrss.exe, wininit.exe | Procesi iz user space |
| DCSync source | DC machine account | User account |

### False Positives

| Scenario | Objašnjenje |
|---|---|
| Backup software | Veeam, BackupExec rade reg save legitimno |
| System administrator | Manuelni backup pre upgrade-a |
| Forensics tools | Verzionirana evidencija |

### Tuning

- Whitelist backup software service accounts
- Alert samo na kombinaciju SAM + SYSTEM + SECURITY u kratkom periodu
- DCSync alert je high-fidelity — uvek istraži

### Incident Response

1. **Kritičan alert** — DCSync ili Mimikatz signature = potencijalni Domain Admin kompromis
2. Hitno isolation host-a
3. Force krbtgt password reset (DVAPUT, ne jednom)
4. Reset svih privilegovanih naloga
5. Forensic memory analiza
6. Threat hunt — drugi hostovi sa istim IOC-ima

---

## DETECTION CARD #7 — PERSISTENCE (Scheduled Task)

**MITRE Tactic:** Persistence  
**MITRE Technique:** T1053.005 (Scheduled Task/Job)

### Opis napada

Napadač kreira scheduled task koji pokreće malware pri logon-u ili po rasporedu, kao SYSTEM. Implant ostaje aktivan posle reboot-a.

### Data Sources

- Windows Security EC4698 (Scheduled Task Created)
- Windows Security EC4702 (Scheduled Task Updated)
- Windows TaskScheduler EC106 (Task registered)
- Sysmon EC11 (File Create u C:\Windows\System32\Tasks)

### Primarni SPL Upiti

**SPL 7.1 — Scheduled task creation (master upit)**

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

**SPL 7.4 — Sysmon FileCreate u Tasks folderu**

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| rex field=Message "TargetFilename:\s*(?<filename>[^\r\n]+)"
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| search filename="C:\\Windows\\System32\\Tasks\\*"
| search NOT process="*svchost*" NOT process="*MsMpEng*"
| table _time, host, process, filename
```

### Analiza

| Pokazatelj | Normalno | Sumnjivo |
|---|---|---|
| Task creator | SYSTEM, Administrator | User account |
| Task command path | Program Files, System32 | C:\Temp, AppData |
| Run As | User koji ga je napravio | SYSTEM (escalation) |
| Trigger | Scheduled time | LogonTrigger, BootTrigger |
| Task name | Descriptive | Mimicry of legitimate (WindowsUpdate*, Adobe*) |

### False Positives

| Scenario | Objašnjenje |
|---|---|
| Software instalacija | Mnogi installer kreiraju tasks |
| Group Policy preference | Domain policy task deployment |
| Backup software | Schedule jobs |

### Tuning

- Whitelist poznate enterprise software task names
- Alert na kombinaciju user creator + SYSTEM runas + suspicious path
- Korelacija sa file create eventima (Sysmon EC11)

### Incident Response

1. Identifikovati task command i runas
2. Disable task (ne delete — preserve evidence)
3. Hash check command binary
4. Identifikovati creator account
5. Pregled drugih taskova kreiranih od istog accounta
6. Sweep za isti task name na drugim hostovima

---

## DETECTION CARD #8 — C2 + EXFILTRATION

**MITRE Tactic:** Command and Control / Exfiltration  
**MITRE Technique:** T1071.001 (Web Protocols), T1041 (Exfiltration Over C2 Channel)

### Opis napada

Persistent C2 kanal kroz HTTPS/mTLS (Sliver, Cobalt Strike). Sve komande, file uploads, i exfiltration idu kroz isti enkriptovani kanal.

### Data Sources

- Sysmon EC3 (Network Connection)
- Sysmon EC22 (DNS Query)
- Firewall logs (perimeter)

### Primarni SPL Upiti

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

### Analiza

| Pokazatelj | Normalno | Sumnjivo |
|---|---|---|
| Connection interval | Random | Regular (heartbeat) |
| Destination | CDN, public services | Single IP held over time |
| Process | Browser, system services | User-writable path binary |
| TLS SNI | Matches destination | Doesn't match or empty |

### False Positives

| Scenario | Objašnjenje |
|---|---|
| OneDrive sync (Microsoft IPs) | 52.x.x.x, 150.171.x.x |
| Windows Update | windowsupdate.microsoft.com |
| Antivirus updates | Defender update kanali |
| Telemetry (Microsoft, Adobe, browser) | Regular small requests |

### Tuning

- Maintain allowlist legitimnih cloud servisa (Microsoft, Google, Adobe IP ranges)
- Threshold based on baseline traffic patterns
- Investigate na osnovu **kombinacije** indikatora, ne pojedinačnog

### Incident Response

1. **Hitno isolate** kompromitovani host
2. Capture network traffic (PCAP)
3. Identifikovati C2 destinaciju
4. Block na perimeter firewall i DNS
5. Threat intel lookup za destinaciju
6. Sweep mreže za isti IOC

---

## SPLUNK DASHBOARD STRUKTURA

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

### Dashboard 2 — "Phase 2 — Password Spray Detection"

**Panel 2.1 — Single Value: Spray Count**

```spl
index=main source="WinEventLog:Security" EventCode=4771 earliest=-24h
| stats count
```

**Panel 2.2 — Timeline**

```spl
index=main source="WinEventLog:Security" EventCode=4771 earliest=-24h
| rex field=Message "Client Address:\s*::ffff:(?<src_ip>[^\r\n]+)"
| timechart span=5m count by src_ip
```

**Panel 2.3 — Target Users (Bar Chart)**

```spl
index=main source="WinEventLog:Security" EventCode=4771
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| stats count by username
| sort - count
```

**Panel 2.4 — Source IP Table**

```spl
index=main source="WinEventLog:Security" (EventCode=4771 OR EventCode=4768)
| rex field=Message "Client Address:\s*::ffff:(?<src_ip>[^\r\n]+)"
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| stats count by src_ip, username, EventCode
| sort - count
```

### Dashboard 3 — "Phase 4 — Kerberoasting Detection"

```spl
index=main source="WinEventLog:Security" EventCode=4769
| rex field=Message "Service Name:\s*(?<service>[^\r\n]+)"
| rex field=Message "Ticket Encryption Type:\s*(?<enc_type>[^\r\n]+)"
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| where enc_type="0x17"
| search NOT service="krbtgt"
| timechart span=10m count by service
```

### Dashboard 4 — "Phase 6 — Credential Dumping"

```spl
index=main source="WinEventLog:Security" EventCode=4688
| rex field=Message "Process Command Line:\s*(?<cmdline>[^\r\n]+)"
| search (cmdline="*reg*save*SAM*" OR cmdline="*reg*save*SYSTEM*" OR cmdline="*reg*save*SECURITY*")
| table _time, host, cmdline
| sort - _time
```

### Dashboard 5 — "Phase 7 — Persistence Detection"

```spl
index=main source="WinEventLog:Security" EventCode=4698
| rex field=Message "Task Name:\s*(?<taskname>[^\r\n]+)"
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| rex field=Message "<Command>(?<command>[^<]+)</Command>"
| table _time, host, username, taskname, command
| sort - _time
```

### Dashboard 6 — "MITRE ATT&CK Mapping"

Heat map koji prikazuje aktivnost po MITRE tehnikama:

```spl
index=main source="WinEventLog:Security" earliest=-24h
| eval mitre=case(
    EventCode=4771, "T1110.003",
    EventCode=4769, "T1558.003",
    EventCode=4698, "T1053.005",
    match('Process Command Line', "InstallUtil"), "T1218.004",
    match('Process Command Line', "reg.*save"), "T1003.002",
    true(), "Other"
)
| where mitre != "Other"
| stats count by mitre
```

---

## UNIVERZALNI SPL UPITI (CHEAT SHEET)

### Top Failed Logons

```spl
index=main source="WinEventLog:Security" EventCode=4625
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| stats count by username, host
| sort - count
```

### LOLBins na sve mašine

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

### PowerShell Script Block

```spl
index=main source="WinEventLog:PowerShell" EventCode=4104
| rex field=Message "ScriptBlockText=(?<script>[^\r\n]+)"
| search (script="*Invoke-Mimikatz*" OR script="*AMSI*" OR script="*DownloadString*" OR script="*IEX*" OR script="*EncodedCommand*")
| table _time, host, script
```

### WMI Activity

```spl
index=main source="WinEventLog:WMI" EventCode=5861
| rex field=Message "Operation:\s*(?<operation>[^\r\n]+)"
| table _time, host, operation
```

---

## INCIDENT RESPONSE RUNBOOK

### Priority levels

| Level | Definicija | Response time |
|---|---|---|
| **P1 — Critical** | Domain compromise potential, active C2, credential theft | < 15 min |
| **P2 — High** | Privilege escalation, lateral movement, persistence | < 1 sat |
| **P3 — Medium** | Suspicious activity, recon, failed exploitation | < 4 sata |
| **P4 — Low** | Anomalije bez clear malicious intent | < 24 sata |

### Generic IR proces

**1. Detect & Triage (0-15 min)**
- Alert assessment
- Initial classification (P1-P4)
- Notify on-call team
- Document timeline start

**2. Investigate (15 min - 4 sata)**
- Correlate alerts
- Pull related logs (Splunk searches)
- Identifikuj scope (kojeg hostova, kojeg naloga)
- Memory dump if possible

**3. Contain (paralelno sa investigate)**
- Network isolation kompromitovanog hosta
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

### Per-phase IR actions

| Phase | First action | Containment | Eradication |
|---|---|---|---|
| 1 — Recon | Identify source IP | Block firewall | N/A (no compromise yet) |
| 2 — Spray | Reset spray-target accounts | Block source IP | Force MFA where possible |
| 3 — Execution | Isolate host | Kill process | Remove dropper, scan disk |
| 4 — Kerberoast | Rotate service account password | Enable AES encryption | Migrate to gMSA |
| 5 — Lateral | Isolate all hosts in path | Block C2 | Remove implant from all hosts |
| 6 — Cred Dump | Reset ALL affected credentials | Force password rotation | Reset krbtgt 2x if domain compromise |
| 7 — Persistence | Disable scheduled task/run key | Remove persistence | Sweep all hosts for same IOC |
| 8 — C2 | Block C2 destination | Network isolation | Memory analysis, sandbox malware |

---

## DETECTION COVERAGE MATRICA

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

## THREAT HUNTING HYPOTHESES

Tipični SOC L2 threat hunting "stories":

### Hypothesis 1: "Suspicious LOLBin abuse"

**Hypothesis:** Napadač koristi InstallUtil/MSBuild za code execution bez powershell.exe

**Hunt query:**
```spl
index=main source="WinEventLog:Security" EventCode=4688
| rex field=Message "New Process Name:\s*(?<process>[^\r\n]+)"
| rex field=Message "Process Command Line:\s*(?<cmdline>[^\r\n]+)"
| rex field=Message "Creator Process Name:\s*(?<parent>[^\r\n]+)"
| search (process="*InstallUtil*" OR process="*msbuild*" OR process="*regasm*" OR process="*regsvcs*")
| stats count values(parent) as parents values(cmdline) as cmds by host, process
| where count > 0
```

### Hypothesis 2: "C2 beaconing from unusual binaries"

**Hypothesis:** Implant beaconing iz user-writable path-a

**Hunt query:**
```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| rex field=Message "DestinationIp:\s*(?<dst_ip>[^\r\n]+)"
| search process="C:\\Users\\*" OR process="C:\\Temp\\*"
| stats dc(dst_ip) as unique_dests count by host, process
| where count > 20
```

### Hypothesis 3: "Service account abuse"

**Hypothesis:** Service nalog (sa SPN) loguje se interaktivno (Type 2 / 10) — netipično za servisne naloge

**Hunt query:**
```spl
index=main source="WinEventLog:Security" EventCode=4624
| rex field=Message "Logon Type:\s*(?<logon_type>[^\r\n]+)"
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| where logon_type=2 OR logon_type=10
| search username="*Service*" OR username="*svc*"
| stats count by username, host, logon_type
```

### Hypothesis 4: "Off-hours activity from privileged accounts"

```spl
index=main source="WinEventLog:Security" EventCode=4624
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| eval hour=strftime(_time, "%H")
| where (hour < "07" OR hour > "19")
| search username="Administrator" OR username="*Admin*"
| stats count by username, host, hour
```

---

## ZA CV / PORTFOLIO

### Linkovi za GitHub repo struktura

```
purple-team-lab/
├── README.md                              # Overview & screenshots
├── 01_LAB_SETUP.md                        # Lab arhitektura
├── 02_ATTACK_PLAYBOOK.md                  # 8 faza napada
├── 03_DETECTION_PLAYBOOK.md               # SPL upiti
├── detection-cards/
│   ├── 01_reconnaissance.md
│   ├── 02_password_spray.md
│   ├── 03_execution_lolbins.md
│   ├── 04_kerberoasting.md
│   ├── 05_lateral_movement.md
│   ├── 06_credential_dumping.md
│   ├── 07_persistence.md
│   └── 08_c2_exfiltration.md
├── splunk/
│   ├── dashboards/
│   │   ├── overview.xml
│   │   ├── password_spray.xml
│   │   └── ...
│   ├── savedsearches/
│   │   └── all_detections.conf
│   └── props.conf
├── sysmon/
│   └── sysmonconfig.xml
├── scripts/
│   ├── lab_validation.ps1
│   └── audit_policy.cmd
└── screenshots/
    ├── splunk_dashboard.png
    ├── bloodhound_graph.png
    └── attack_chain.png
```

### CV bullet points

```
Purple Team Home Lab — SOC Analyst L2 Portfolio | 2026

• Designed and implemented Active Directory lab (Win Server 2022 DC, 2x Win10 endpoints, Kali, Splunk SIEM)
• Simulated 8 MITRE ATT&CK techniques: T1046, T1110.003, T1558.003, T1218.004, T1071.001, T1003.002/006, T1053.005, T1041
• Deployed modern C2 framework (Sliver) with mTLS evasion and validated detection gaps
• Engineered 30+ Splunk SPL detection queries with false positive tuning
• Authored vendor-agnostic detections as code (Sigma) compiled to Splunk; CIM-normalized, version-controlled (Detection-as-Code)
• Built MITRE-mapped detection dashboard with 6 panels for real-time monitoring
• Documented incident response runbook per attack phase
• Identified and documented AD CS misconfigurations (ESC1, ESC2, ESC3, ESC15)
• Demonstrated blue team success: Defender + AMSI successfully blocked DCSync attempts
```

---

## PRODUCTION HARDENING PLAYBOOK (Segment 10)

**Cilj:** "Before/After Detection Engineering" — za svaki napad iz Faza 1-8 definisati hardening fix + re-run SPL upit koji potvrđuje da napad sad fail-uje ili je detektovan na novom sloju.

**Centralna poenta:** Hardening ≠ Detection. Prevention smanjuje napadački surface, ali surface nikad nije nula. Detection ostaje *safety net* za sve što prođe kroz prevention layer.

---

### Hardening Fix #1 — Faza 2 Password Spray

**Prevention controls:**
- Fine-Grained Password Policy (min 14 chars, complexity enabled)
- Account Lockout Threshold = 5
- Lockout Duration = 30 minutes
- Lockout Observation Window = 30 minutes

**Re-run SPL — verifikacija lockout-a:**

```spl
index=main source="WinEventLog:Security" EventCode=4740
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| rex field=Message "Caller Computer Name:\s*(?<src_host>[^\r\n]+)"
| table _time, username, src_host
| sort - _time
```

**SPL za low-and-slow detection (bypass attempt):**

```spl
index=main source="WinEventLog:Security" EventCode=4771 earliest=-7d
| rex field=Message "Client Address:\s*::ffff:(?<src_ip>[^\r\n]+)"
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| bucket _time span=1h
| stats dc(username) as unique_users count by _time, src_ip
| where unique_users > 5
| sort - _time
```

> Napadač koji čeka 35 min između pokušaja po useru prolazi lockout, ali pravi distinct multi-user pattern preko dužeg vremena.

---

### Hardening Fix #2 — Faza 4 Kerberoasting

**Prevention controls:**
- `msDS-SupportedEncryptionTypes` = 24 (AES128 + AES256) za sve service account-e
- Service account password ≥ 20 chars random
- Description, info, comment polja očišćena od password leak-a
- gMSA migracija (preporuka za long-term)

**Re-run SPL — RC4 sad anomalija:**

```spl
index=main source="WinEventLog:Security" EventCode=4769
| rex field=Message "Ticket Encryption Type:\s*(?<enc_type>[^\r\n]+)"
| rex field=Message "Service Name:\s*(?<service>[^\r\n]+)"
| where enc_type="0x17"
| stats count by service, enc_type
```

> Posle AES enforcement, svaki 0x17 (RC4) event je anomalija. Threshold za alert se okreće — RC4 sad mora da alertuje upravo zato što ne bi trebalo da postoji.

**SPL za password leak audit:**

```spl
| inputlookup ad_users.csv
| eval has_leak=if(match(description, "(?i)pass|pwd|cred"), 1, 0)
| where has_leak=1
| table samAccountName, description
```

---

### Hardening Fix #3 — Faza 5 Sliver Execution

**Prevention controls:**
- AppLocker Deny rules za C:\Temp, C:\Users\*\AppData\Local\Temp, C:\Users\Public
- AppLocker service (AppIDSvc) na Automatic + Started
- GPO deployment kroz centralnu polisu
- WDAC kao sledeći korak za visok security tier

**Re-run SPL — AppLocker Block events:**

```spl
index=main source="WinEventLog:Microsoft-Windows-AppLocker/EXE and DLL" EventCode=8004
| rex field=Message "(?<blocked_path>C:\\\\[^\s]+\.exe)"
| rex field=Message "User:\s*(?<user>[^\r\n]+)"
| table _time, user, blocked_path
| sort - _time
```

**SPL za bypass attempts (signed LOLBin abuse):**

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| rex field=Message "ParentImage:\s*(?<parent>[^\r\n]+)"
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| rex field=Message "CommandLine:\s*(?<cmdline>[^\r\n]+)"
| search process="*InstallUtil*" OR process="*MSBuild*" OR process="*regsvr32*"
| search cmdline="*\\Temp\\*" OR cmdline="*\\AppData\\*"
| table _time, parent, process, cmdline
```

> AppLocker blokira direktnu execution iz user path-ova, ali signed LOLBin može da load-uje payload iz tih path-ova. Detection layer hvata kombinaciju.

---

### Hardening Fix #4 — Faza 8 mTLS C2 Beacon

**Prevention controls:**
- Sysmon NetworkConnect include rule za C:\Temp, C:\Users, C:\ProgramData
- Sysmon include rule za LOLBin binary-je
- Sysmon config deploy kroz GPO startup script (NETLOGON share)
- Version control u Git-u sa tagovima (v2.1-purple)

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

**SPL za beacon interval anomaly (jitter analysis):**

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

> Pravilni intervali sa malim jitter-om = beaconing signature. Sliver default je 60s ± 30%.

---

### Hardening Coverage Matrica

| Faza | Napad | Prevention Layer | Detection Layer | Status |
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

**L1 thinking:** "Imamo Splunk i Defender, pokriveni smo."

**L2 thinking:** "Prevention + Detection layer + Detection-as-Code + MITRE ATT&CK coverage + false positive tuning."

**L3 thinking:** "Threat model → attack paths → koji su realistic napadi → prevention investment vs detection investment optimization."

**Glavna poenta za hiring manager-a:** Defense in Depth znači da napadač mora da zaobiđe više slojeva. Ali nijedan sloj nije bulletproof. Detection ostaje *safety net* za sve što prevention propušta. To je razlika između SOC analitičara koji misli alate i onog koji misli metodologiju.

---

**Kraj Dokumenta 3**

---

## ZAVRŠNE NAPOMENE

### Šta dalje raditi (next steps)

1. **Recompletraj Sysmon config** — uključi NetworkConnect za user-writable putanje (`\Temp\`, `\AppData\`, `\ProgramData\`), NE za ime fajla (pokriveno u Seg 10)
2. **Snimi video u 10 segmenata** (8 napadačkih + Splunk Dashboard Tour + Production Hardening bonus). Za CV minimum verziju snimi Seg 4, 6, 8, 9, 10.
3. **Postavi GitHub repo** sa strukturom iznad (README + `detections/sigma/` + `detections/splunk/savedsearches.conf` su već tu)
4. **Dodaj screenshote** sa Splunk dashboard-a
5. **Napiši blog post** koji prati video — SEO i sharing

### Za fresh Claude projekat

Kad pokreneš novi Claude projekat:
- Upload ova 3 dokumenta odmah
- U system prompt-u dodaj: "Ovo je nastavak Purple Team Lab projekta. Svi setup, attack i detection detalji su u priloženim dokumentima."
- Claude će imati kompletan kontekst bez recap-a

---

**Sa ovim dokumentima + repo-om (README, Sigma, Splunk pack) lab je solidan SOC L2 portfolio. Sledeći skok ka L3: NDR/EDR sloj (Lab v2) i merenje detection coverage-a kroz emulaciju (Atomic Red Team).**
