# Benign baseline — false-positive queries

Generated from `detections/splunk/purple_lab/default/savedsearches.conf` at `3138c41`.

**Before running anything:** set the Splunk time picker to *Date & Time Range → Between* `11/02/2026 18:40:00.000` and `11/03/2026 18:40:00.000`, and leave it there for every query below. The searches carry no time bounds of their own.

**Count unit:** distinct result rows (the rows the search returns), never firings. Record the row count and, if non-zero, a screenshot or the rows.

## 1. Purple - LOLBin Execution (CIM tstats)  (scheduled)

```
| tstats summariesonly=false allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("installutil.exe","msbuild.exe","regsvr32.exe","mshta.exe","regasm.exe","regsvcs.exe")
        AND (Processes.process="*\\Temp\\*" OR Processes.process="*\\AppData\\*" OR Processes.process="*\\ProgramData\\*")
    by Processes.dest Processes.parent_process_name Processes.process_name Processes.process Processes.user
  | rename "Processes.*" AS *
  | eval firstTime=strftime(firstTime,"%F %T"), lastTime=strftime(lastTime,"%F %T")
```

## 2. Purple - C2 Beacon from User-Writable Path (CIM tstats)  (UNSCHEDULED)

```
| tstats summariesonly=false allow_old_summaries=true count values(All_Traffic.dest_port) as dest_ports
    from datamodel=Network_Traffic.All_Traffic
    where (All_Traffic.app="*\\Temp\\*" OR All_Traffic.app="*\\AppData\\*" OR All_Traffic.app="*\\ProgramData\\*" OR All_Traffic.app="*\\Users\\Public\\*")
    by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app _time span=1m
  | rename "All_Traffic.*" AS *
  | stats count dc(_time) as beacons earliest(_time) as firstTime latest(_time) as lastTime by src dest dest_port app
  | where beacons > 5
```

## 3. Purple - Kerberoasting RC4 Service Ticket  (scheduled)

```
index=main source="WinEventLog:Security" EventCode=4769 Ticket_Encryption_Type="0x17"
    Service_Name!="krbtgt*" Service_Name!="*$"
  | stats count min(_time) as firstTime max(_time) as lastTime values(Service_Name) as services
        by Client_Address Account_Name Ticket_Encryption_Type
  | eval firstTime=strftime(firstTime,"%F %T"), lastTime=strftime(lastTime,"%F %T")
```

## 4. Purple - Kerberoasting User-SPN Ticket (etype-agnostic)  (UNSCHEDULED)

```
index=main source="WinEventLog:Security" EventCode=4769
    Service_Name!="krbtgt*" Service_Name!="*$" Account_Name!="*$" Account_Name!="*$@*"
  | stats count min(_time) as firstTime max(_time) as lastTime values(Ticket_Encryption_Type) as etypes
        by Client_Address Account_Name Service_Name
  | eval firstTime=strftime(firstTime,"%F %T"), lastTime=strftime(lastTime,"%F %T")
```

## 5. Purple - Password Spray (multi-user from one source)  (scheduled)

```
index=main source="WinEventLog:Security" EventCode=4771 (Failure_Code="0x18" OR Failure_Code="0xE")
  | bucket _time span=5m
  | stats dc(Account_Name) as unique_users count values(Account_Name) as targets by _time Client_Address
  | where unique_users >= 5
```

## 6. Purple - Spray Success (4771 then 4768 same source)  (scheduled)

```
index=main source="WinEventLog:Security" (EventCode=4771 OR (EventCode=4768 Result_Code="0x0"))
  | eval src=replace(Client_Address,"^::ffff:","")
  | transaction src maxspan=10m
  | search eventcount>5 EventCode=4768 EventCode=4771
  | table _time src Account_Name eventcount
```

## 7. Purple - SAM Hive Dump via reg save  (scheduled)

```
index=main source="WinEventLog:Security" EventCode=4688 New_Process_Name="*\\reg.exe"
    Process_Command_Line="*save*"
    (Process_Command_Line="*SAM*" OR Process_Command_Line="*SYSTEM*" OR Process_Command_Line="*SECURITY*")
  | table _time host Creator_Process_Name Process_Command_Line
```

## 8. Purple - DCSync from non-DC  (scheduled)

```
index=main source="WinEventLog:Security" EventCode=4662
    (Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*89e95b76-444d-4c62-991a-0facbeda640c*")
    Account_Name!="*$" Account_Name!="MSOL_*"
  | table _time host Account_Name Properties
```

## 9. Purple - Scheduled Task Persistence (SYSTEM + user path)  (scheduled)

```
index=main source="WinEventLog:Security" EventCode=4698 Account_Name!="*$"
  | rex "<Command>(?<task_command>[^<]+)</Command>"
  | rex "<Arguments>(?<task_args>[^<]+)</Arguments>"
  | rex "<UserId>(?<task_runas>[^<]+)</UserId>"
  | eval runas_system=if(task_runas=="S-1-5-18" OR upper(task_runas)=="SYSTEM" OR upper(task_runas)=="NT AUTHORITY\\SYSTEM",1,0)
  | where like(task_command,"%\\Temp\\%") OR like(task_command,"%\\AppData\\%") OR runas_system=1
        OR match(task_args,"(?i)IEX|Invoke-Expression|DownloadString|DownloadFile|Net\.WebClient|FromBase64String|(^|\s)[-/](e|ec|en|enc[a-z]*)\s")
  | table _time host Account_Name Task_Name task_command task_args task_runas
```

## 10. Purple - LSASS Access (credential theft mask)  (scheduled)

```
index=main (source="WinEventLog:Microsoft-Windows-Sysmon/Operational" OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational") EventCode=10
    TargetImage="*\\lsass.exe"
    GrantedAccess IN ("0x1438","0x143a","0x1f0fff","0x1f1fff","0x1f2fff","0x1f3fff","0x1fffff")
    SourceImage!="C:\\Windows\\System32\\svchost.exe"
    SourceImage!="C:\\Windows\\System32\\wininit.exe"
    SourceImage!="C:\\Windows\\System32\\csrss.exe"
    SourceImage!="C:\\Windows\\System32\\taskmgr.exe"
    SourceImage!="C:\\Windows\\System32\\MRT.exe"
    SourceImage!="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"
    SourceImage!="C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MsMpEng.exe"
    SourceImage!="C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe"
    SourceImage!="C:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe"
  | table _time host SourceImage TargetImage GrantedAccess
```

## 11. Purple - Kerbrute User Enumeration (4768 error 0x6)  (scheduled)

```
index=main source="WinEventLog:Security" EventCode=4768 Result_Code="0x6"
  | bucket _time span=1m
  | stats count dc(Account_Name) as unique_users by _time Client_Address
  | where count > 50 AND unique_users > 20
```

## 12. Purple - Verify Account Lockout (post FGPP)  (UNSCHEDULED)

```
index=main source="WinEventLog:Security" EventCode=4740
  | table _time Target_User_Name Caller_Computer_Name
```

## 13. Purple - RC4 Anomaly (post AES enforcement)  (UNSCHEDULED)

```
index=main source="WinEventLog:Security" EventCode=4769 Ticket_Encryption_Type="0x17"
  | stats count by Service_Name Ticket_Encryption_Type
```

## 14. Purple - Sliver C2 Beacon by JA4 Fingerprint  (scheduled)

```
index=main source="*ssl.log*" NOT _raw="#*" "t13i131000_f57a46bbacb6_e5728521abd4"
  | rex field=_raw "^(?P<ts>\S+)\t\S+\t(?P<orig_h>\S+)\t\S+\t(?P<resp_h>\S+)"
  | sort 0 _time
  | streamstats current=f last(_time) as prev by orig_h resp_h
  | eval gap=_time-prev
  | stats count avg(gap) as avg_interval stdev(gap) as jitter
        min(_time) as firstTime max(_time) as lastTime by orig_h resp_h
  | where count > 5
  | eval firstTime=strftime(firstTime,"%F %T"), lastTime=strftime(lastTime,"%F %T"),
        avg_interval=round(avg_interval,1), jitter=round(jitter,1)
```

## 15. Purple - Large Outbound Transfer (possible exfiltration)  (UNSCHEDULED)

```
index=main source="*conn.log*" NOT _raw="#*"
  | rex field=_raw "^(?P<ts>\S+)\t\S+\t(?P<orig_h>\S+)\t(?P<orig_p>\S+)\t(?P<resp_h>\S+)\t(?P<resp_p>\S+)\t(?P<proto>\S+)\t(?P<service>\S+)\t(?P<duration>\S+)\t(?P<orig_bytes>\S+)\t(?P<resp_bytes>\S+)"
  | where orig_h!="-" AND match(orig_h,"^192\.168\.182\.") AND NOT match(resp_h,"^192\.168\.182\.13[57]$")
  | eval orig_bytes=if(orig_bytes="-",0,tonumber(orig_bytes))
  | bucket _time span=10m
  | stats sum(orig_bytes) as bytes_out dc(resp_h) as dests values(resp_p) as ports by _time orig_h
  | where bytes_out > 10000000
  | eval mb_out=round(bytes_out/1024/1024,1)
  | table _time orig_h mb_out dests ports
```

_Pipeline-health searches (Telemetry Gap, Sensor Feed Stale, Wazuh Sensor Health) are excluded: they watch the collection pipeline, not attacker behaviour, and the window's continuity is checked separately._

---

## Positive controls — a zero only counts if the rule could have seen something

Run these with the same time picker. Each one proves the rule's false-positive source was
actually exercised in the window; without it, a zero is "unmeasured", not "clean".

**C2 Beacon (#2)** — the same search with its final `| where beacons > 5` removed must return the
OneDrive rows (`OneDrive.exe`, `OneDrive.Sync.Service.exe` under `AppData`).

**Kerberoasting etype-agnostic (#4)** — must return the `tstark` requests (21:22, 10:48, 10:53)
and nothing from `pparker` or `fcastle`.

**Large Outbound Transfer (#15)** — expected zero, because the 100 MB copy went over IPv6. The
control is that the transfer exists in Zeek at all:

```
index=main source="*conn.log*" "fd15:4ba5:5a2b:1008" "445"
```

**Spray / Kerbrute / Lockout (#5, #6, #11, #12)** — Kerberos is being logged in the window:

```
index=main source="WinEventLog:Security" (EventCode=4768 OR EventCode=4769 OR EventCode=4771)
| stats count by EventCode
```

**LSASS (#10)** — Sysmon process-access events exist in the window:

```
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 | stats count by host
```
