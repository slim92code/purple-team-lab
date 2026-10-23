# Detections — Detection-as-Code

Vendor-agnostic detections (Sigma) + a deployable Splunk pack, version-controlled.
This is the artifact that backs the "Detection-as-Code" claim in the playbooks. It is
the shared library for the whole lab and grows per iteration: v2 added the host rules,
v3 added network (Zeek) rules and a Wazuh custom rule.

```
detections/
├── sigma/
│   ├── sigma_rules.yml              # v2 — 9 host rules (Windows/Sysmon), source of truth
│   └── v3_ndr.yml                   # v3 — 3 network rules (Zeek: krb5, conn, ssl/JA4)
├── wazuh/
│   └── local_rules.xml             # v3 — custom rules fixing the 60228 scheduled-task gap
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

## Compile the v3 network rules (Zeek)

```bash
pip install sigma-cli pysigma-backend-splunk pysigma-pipeline-zeek
sigma convert -t splunk -p zeek detections/sigma/v3_ndr.yml
```

The Wazuh rules are deployed directly:

```bash
cp detections/wazuh/local_rules.xml /var/ossec/etc/rules/
/var/ossec/bin/wazuh-control restart
# the \Updater task now re-scores to level 12; a benign OneDrive task stays level 4
```

## Coverage

**v2 — host (Windows/Sysmon), `sigma/sigma_rules.yml`**

| # | Rule | MITRE | Source |
|---|---|---|---|
| 1 | InstallUtil LOLBin from user path | T1218.004 | Sysmon EID 1 |
| 2 | Kerberoasting RC4 ticket | T1558.003 | 4769 |
| 3 | Password spray (multi-user/source) | T1110.003 | 4771 |
| 4 | reg save SAM/SYSTEM/SECURITY | T1003.002 | Sysmon EID 1 |
| 5 | DCSync from non-machine account | T1003.006 | 4662 |
| 6 | Scheduled-task persistence | T1053.005 | 4698 |
| 7 | C2 beacon from user path (behavioral) | T1071.001 / T1572 | Sysmon EID 3 |
| 8 | LSASS access mask | T1003.001 | Sysmon EID 10 |
| 9 | Kerbrute userenum (4768 0x6) | T1087.002 | 4768 |

**v3 — network (Zeek), `sigma/v3_ndr.yml`**

| # | Rule | MITRE | Source |
|---|---|---|---|
| 10 | Kerberoasting by user-SPN, etype-agnostic | T1558.003 | Zeek `kerberos.log` |
| 11 | WinRM lateral movement east-west (5985) | T1021.006 | Zeek `conn.log` |
| 12 | Sliver C2 via JA4 TLS fingerprint | T1071.001 | Zeek `ssl.log` |

**v3 — EDR tuning (Wazuh), `wazuh/local_rules.xml`**

| id | Rule | MITRE |
|---|---|---|
| 100210 | Scheduled task with a PowerShell download cradle → level 12 | T1053.005 / T1059.001 |
| 100211 | Scheduled task with obfuscated/hidden-window launcher → level 10 | T1053.005 / T1027 |

Two rules are deliberately **behavioral/pattern-based, not IOC-based**: rule 7 keys on
process location + egress (a renamed binary still trips it), and rule 10 keys on the SPN
pattern rather than the ticket encryption type (AES Kerberoasting trips it, where an
RC4-only rule would miss it). The Wazuh rules score the task's *command*, which is what
the built-in rule 60228 ignores.
