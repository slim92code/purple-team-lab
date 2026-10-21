# Detections — Detection-as-Code

Vendor-agnostic detections (Sigma) + a deployable Splunk pack, version-controlled.
This is the artifact that backs the "Detection-as-Code" claim in the playbooks.

```
detections/
├── sigma/
│   └── sigma_rules.yml              # 9 rules, vendor-agnostic source of truth
└── splunk/
    ├── purple_lab/                  # deployable Splunk app -> copy to etc/apps/
    │   ├── default/
    │   │   ├── app.conf
    │   │   ├── savedsearches.conf   # 12 detections (CIM/TA-normalized, macro-free)
    │   │   └── props.conf           # Sysmon timestamp fix (lab_issues.md #10)
    │   └── metadata/default.meta
    └── cim-acceleration/            # apply to Splunk_SA_CIM (see Install below)
        ├── datamodels.conf          # accelerate Endpoint + Network_Traffic
        └── macros.conf              # point CIM index allowlists at index=main
```

## Install (works out-of-the-box)

```bash
# 1. Prereq apps (Splunkbase): Splunk_TA_windows, Splunk_TA_microsoft_sysmon, Splunk_SA_CIM
# 2. Deploy the detections app
cp -r detections/splunk/purple_lab "$SPLUNK_HOME/etc/apps/"
# 3. Accelerate the two CIM data models used by the tstats headliners
cp detections/splunk/cim-acceleration/datamodels.conf "$SPLUNK_HOME/etc/apps/Splunk_SA_CIM/local/"
cp detections/splunk/cim-acceleration/macros.conf     "$SPLUNK_HOME/etc/apps/Splunk_SA_CIM/local/"
# 4. Restart
"$SPLUNK_HOME/bin/splunk" restart
```

The detections use `summariesonly=false`, so they return results immediately (raw scan)
even before acceleration finishes building summaries, then speed up automatically once it does.

## Why this is built on TAs + CIM (and not raw `rex field=Message`)

The teaching playbook (`03_detection_playbook.md`) shows hand-parsed `rex field=Message`
queries so the raw event structure is visible. **Production detections do not parse the
raw Message** — they rely on the Splunk Technology Add-ons, which already extract every
field at index/search time:

| Source | Add-on | Gives you (no rex) |
|---|---|---|
| Windows Security | Splunk Add-on for Microsoft Windows | `Account_Name`, `Service_Name`, `Ticket_Encryption_Type`, `Client_Address`, `Logon_Type`, `Process_Command_Line`, `New_Process_Name`, `Creator_Process_Name`, … |
| Sysmon | Splunk Add-on for Sysmon | `Image`, `ParentImage`, `CommandLine`, `TargetFilename`, `DestinationIp`, `DestinationPort`, `GrantedAccess`, `SourceImage`, `TargetImage`, `Initiated`, … |

The headliner detections run via `tstats` against the **accelerated Endpoint and
Network_Traffic CIM data models** — millisecond search over millions of events, the
difference between "I parsed some logs" and "I do detection engineering."

> The only rex that remains is in the scheduled-task rule, which parses the **task XML
> embedded inside the 4698 event body** — that XML is data inside the event, not the
> event wrapper, so a targeted extraction there is correct.

## Compile Sigma → Splunk

```bash
pip install sigma-cli pysigma-backend-splunk
sigma convert -t splunk -p sysmon -p windows-audit detections/sigma/sigma_rules.yml
```

The `-p sysmon` / `-p windows-audit` pipelines map the Sigma taxonomy to the same
TA-extracted field names used in `savedsearches.conf`. Same logic, two formats: Sigma is
the portable source of truth, the `.conf` is the deployed instance.

## Coverage

| # | Rule | MITRE | Layer |
|---|---|---|---|
| 1 | InstallUtil LOLBin from user path | T1218.004 | Detection |
| 2 | Kerberoasting RC4 ticket | T1558.003 | Detection |
| 3 | Password spray (multi-user/source) | T1110.003 | Detection |
| 4 | reg save SAM/SYSTEM/SECURITY | T1003.002 | Detection |
| 5 | DCSync from non-machine account | T1003.006 | Detection |
| 6 | Scheduled-task persistence | T1053.005 | Detection |
| 7 | C2 beacon from user path (behavioral) | T1071.001 / T1572 | Detection |
| 8 | LSASS access mask | T1003.001 | Detection |
| 9 | Kerbrute userenum (4768 0x6) | T1087.002 | Detection |

Rule 7 is deliberately **behavioral, not IOC-based** — it keys on process location +
egress, never on a specific implant filename, so a renamed binary still trips it.
