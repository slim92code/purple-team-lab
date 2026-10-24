# Detections — Detection-as-Code

Vendor-agnostic detections (Sigma) + a deployable Splunk pack, version-controlled.
Shared across the whole lab and grown per iteration: v2 added the host rules, v3 added
network (Zeek) rules and Wazuh custom rules.

```
detections/
├── sigma/
│   ├── sigma_rules.yml              # 10 host rules (Windows/Sysmon), source of truth
│   └── v3_ndr.yml                   # v3 — 3 network rules (Zeek: krb5, conn, ssl/JA4)
├── wazuh/
│   └── local_rules.xml             # v3 — 5 rules: LSASS access + 92900 tuning + 60228 gap
└── splunk/
    ├── purple_lab/                  # deployable Splunk app -> copy to etc/apps/
    │   ├── default/
    │   │   ├── app.conf
    │   │   ├── savedsearches.conf   # 13 detections, macro-free (2 via CIM, 11 raw)
    │   │   └── props.conf           # Sysmon timestamp fix (lab_issues.md #10), keyed on source::
    │   └── metadata/default.meta
    └── cim-acceleration/            # apply to Splunk_SA_CIM (see Install below)
        ├── datamodels.conf          # accelerate Endpoint + Network_Traffic
        └── macros.conf              # point CIM index allowlists at index=main
```

## Install (works out-of-the-box)

Scheduled searches and alerting are Enterprise features. On Splunk Free the app installs and
every search runs on demand, but `enableSched = 1` has no effect and nothing fires on its
own. That is the difference between the two lab versions: v2 ran on Free and is documented
as queries, v3 runs on Enterprise and its alerts fire on schedule. Check which you have
with `| rest /services/licenser/groups | table title, is_active`.

This app ships 13 searches, 9 of them scheduled. The v3 lab's own Splunk runs six alerts,
which is a different list — two of those six (JA4 C2, large outbound transfer) were written
ad hoc in the lab and have no Splunk search here. Screenshot 11 in
[`v3/README.md`](../v3/README.md) maps the six against what ships.

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
queries so the raw event structure is visible. The deployed detections do not parse the raw
Message. They use the Splunk Technology Add-ons, which extract the fields at index and
search time:

| Source | Add-on | Gives you (no rex) |
|---|---|---|
| Windows Security | Splunk Add-on for Microsoft Windows | `Account_Name`, `Service_Name`, `Ticket_Encryption_Type`, `Client_Address`, `Logon_Type`, `Process_Command_Line`, `New_Process_Name`, `Creator_Process_Name`, … |
| Sysmon | Splunk Add-on for Sysmon | `Image`, `ParentImage`, `CommandLine`, `TargetFilename`, `DestinationIp`, `DestinationPort`, `GrantedAccess`, `SourceImage`, `TargetImage`, `Initiated`, … |

Two detections run via `tstats` against CIM data models rather than raw events. How well
that works in this lab was measured rather than assumed, and the answer is mixed.

| | State in this lab |
| --- | --- |
| `Endpoint.Processes` | populated; the LOLBin detection works against it |
| `Network_Traffic.All_Traffic` | **empty**; the C2 beacon detection cannot return anything |
| Acceleration | **off** on both models, so `tstats` here is a raw scan |

The cause is the forwarder's sourcetype. Every Windows channel arrives as a bare
`WinEventLog`, with the channel name only in `source`:

```
sourcetype = WinEventLog
source     = WinEventLog:Microsoft-Windows-Sysmon/Operational
```

The Splunk Add-on for Sysmon keys its CIM field aliases and eventtypes on the per-channel
sourcetype (`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`). Under a bare
`WinEventLog` none of that applies, so Sysmon EID 3 events carry no `app`, `src`, `dest` or
`dest_port`, nothing tags them into `Network_Traffic`, and the model stays at zero. The
events themselves are there: 444 EID 3 events across the three hosts in seven days.

The other eleven detections filter on `source=` rather than `sourcetype=`, which is why they
work on this configuration. That was not a deliberate choice at the time; it is the reason
the pack mostly survives a forwarder setup the add-ons were not expecting.

Fixing it is a forwarder change, not a rule change: set per-channel sourcetypes with
`renderXml = 1` in `inputs.conf`, then enable acceleration with the shipped
`cim-acceleration/datamodels.conf`. Scoped into [v4](../v4/README.md).

The one remaining `rex` is in the scheduled-task rule, which parses the task XML embedded in
the `4698` event body. That XML is data inside the event rather than the event wrapper, so a
targeted extraction there is correct.

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
/var/ossec/bin/wazuh-analysisd -t        # MUST print no WARNING and no ERROR
/var/ossec/bin/wazuh-control restart

# Never skip the -t step. The bug these rules document was a rule that loaded,
# counted as coverage, and was silently ignored, and -t had been saying so.
```

## Coverage

**Host rules (Windows/Sysmon), `sigma/sigma_rules.yml`**

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
| 10 | Kerberoasting by user-SPN, etype-agnostic | T1558.003 | 4769 |

Rule 10 was added after the v3 run. Rule 2 keys on RC4, which is the canonical
Kerberoasting signal, and here it has never had an event to match: 30 days of `4769` traffic
is 1,649 tickets, every one of them `0x12` (AES-256), zero RC4. Rule 10 keys on the SPN
owner instead of the encryption type, which is what survives a domain on AES. It is noisier
and ships unscheduled in the Splunk pack until a per-environment SPN allowlist exists.

Rule 2 is kept rather than deleted, and not only as a reference for older domains. RC4 is
not blocked on `MARVEL.LOCAL` — the service account still holds an RC4 key, and the
Pass-the-Ticket step of the v3 run obtained a `4768` TGT for it at `0x17`. The roast came
back AES because `GetUserSPNs` requested no specific etype and the KDC issued the strongest
one both sides shared. Rule 2 therefore still covers the explicit downgrade, which this
domain would honour; what it cannot see is the default-etype roast, which is what a current
toolchain produces. The two rules cover different halves of the same technique, so it is
worth knowing which half your environment exposes before trusting either alone.

**Network rules (Zeek), `sigma/v3_ndr.yml`**

| # | Rule | MITRE | Source |
|---|---|---|---|
| 11 | Kerberoasting by user-SPN, etype-agnostic | T1558.003 | Zeek `kerberos.log` |
| 12 | WinRM lateral movement east-west (5985) | T1021.006 | Zeek `conn.log` |
| 13 | Sliver C2 via JA4 TLS fingerprint | T1071.001 | Zeek `ssl.log` |

Rule 12 carries an approved-source list that has to be filled in per environment. Zeek
`conn.log` cannot tell a jump host from a workstation, so without that list the rule matches
every WinRM session rather than only east-west ones.

Rule 13 needs the **FoxIO JA4 package** (`zkg install zeek/foxio/ja4`). `ja4` is not a base
Zeek field, so without the package `ssl.log` has no such column and the rule cannot fire.
The Zeek deployment here is otherwise stock, which is why no sensor config ships in this
repo; Suricata is stock too, and the Suricata evidence cited in v3 is its built-in protocol
logging and anomaly events rather than signatures written for this lab.

Rule 11 had the same defect as the Wazuh rule documented in [v3](../v3/README.md): a filter
that could not match. Its machine-account exclusion was written `client|endswith: '$'`, but
Zeek writes the client as `principal/REALM`, so a machine account reads
`THEPUNISHER$/MARVEL.LOCAL` and does not end in `$`. The exclusion did nothing and the rule
alerted on every machine account's service ticket. Caught by reading the lab's own
`kerberos.log` screenshot, where the clients are `Administrator/MARVEL.LOCAL`,
`pparker/MARVEL.LOCAL` and so on. It uses `contains` now. The host-side `4769` rule can use a
suffix test because Windows supplies the bare account name; the same expression is wrong on
the wire.

**v3 — EDR tuning (Wazuh), `wazuh/local_rules.xml`**

| id | Level | Rule | MITRE |
|---|---|---|---|
| 100200 | 12 | Dump-capable `GrantedAccess` mask on `lsass.exe` | T1003.001 |
| 100201 | 0 | Suppress measured platform LSASS readers (child of 100200) | — |
| 100205 | 0 | Suppress the same readers under built-in `92900` directly | — |
| 100210 | 12 | Scheduled task with a PowerShell download cradle | T1053.005 / T1059.001 |
| 100211 | 10 | Scheduled task with obfuscated/hidden-window launcher | T1053.005 / T1027 |

#### Why `100200` exists

It replaces an earlier attempt bound to
`<if_group>sysmon_event10</if_group>`. The real group is `sysmon_event_10`, one underscore
away, so the rule was loaded, counted as coverage, and silently ignored. `wazuh-analysisd -t`
had been printing `WARNING: (7610): Group 'sysmon_event10' was not found ... Rule '100200'
will be ignored.` the whole time.

A second draft bound to `<if_sid>92900</if_sid>` and could not fire either: `92900` filters
on `grantedAccess` being `0x1010` or `0x40`, so a child requiring a full-access mask is
mutually exclusive with its own parent. Caught by running it, not by reading it. The shipped
rule binds to `<if_group>sysmon_event_10</if_group>`, the group the eventchannel decoder
assigns to every EID 10 event.

#### Why the mask list is short

Measured against 935 real `ProcessAccess` reads of
`lsass.exe` from THEPUNISHER's Sysmon log, a draft that also matched `0x1010`/`0x1410` would
have alerted 90 times with 89 benign (79 from `WmiPrvSE.exe`; `wazuh-agent.exe` itself reads
LSASS at `0x1fffff`). The shipped version alerts once on the same sample.

#### Why the exclusions anchor the full path

The nine excluded readers are listed as full paths, not as `\svchost.exe`. A filename-suffix
exclusion also suppresses `C:\Temp\svchost.exe`, which is how a masquerading implant would
hide from the rule that is supposed to catch it. The Sigma rule and the Splunk search both
matched on suffix until this was checked, and the Sigma list also carried `wininit.exe` and
`csrss.exe` that the other two did not. All three now use the same nine anchored paths, and
the Wazuh pattern is tested against both the real paths and a fake `svchost.exe` in a
user-writable directory, which still alerts.

What none of the three catch: code injected into the genuinely signed `svchost.exe` or
`MsMpEng.exe` inherits a legitimate `SourceImage` and is suppressed. Separating that needs
`CallTrace`, and this lab has no sample to test such a pattern against.

#### Why `100205` is separate

Built-in `92900` fires at level 12 for any read-permission
LSASS access. In this lab it fired 32 times and all 32 were benign. `100205` hangs off
`92900` itself so that existing false positive is suppressed whether or not `100200` matches.

#### Verification, 24 Oct 2026

Every rule was deployed and fired by a targeted trigger.
Times UTC.

| Rule | Trigger | Result |
|---|---|---|
| — | `wazuh-analysisd -t` | clean (previous version raised `7610`) |
| `100200` | PowerShell `OpenProcess(lsass, 0x1FFFFF)` | level 12, 11:42:39 |
| `100201` | 20 platform reads forced through the chain | 0 alerts |
| `100205` | `MsMpEng.exe` on LSASS at `0x1010` | 0 alerts (was level 12, 32/32) |
| `100210` | task with `IEX` + `DownloadString` | level 12, 11:48:57 |
| `100211` | task with `-nop -w hidden -enc` | level 10, 11:49:04 |
| negative | task running `defrag.exe` | stays `60228` level 4 |
| negative | task running `powershell.exe -ExecutionPolicy Bypass -File …` | stays `60228` level 4 |

Not covered: an LSASS read from code injected into an already-excluded signed process.
That needs `CallTrace`, and this lab has no sample to test a pattern against.

**Coverage limit:** Wazuh receives Sysmon from 1 of the lab's 3 Windows agents, so `100200`
can only fire on THEPUNISHER. The `4698` task rules are unaffected, since the Security
channel is configured on all three. Full write-up in
[`v3/README.md`](../v3/README.md#known-gaps-carried-into-v4).

Two rules key on behaviour rather than an indicator. Rule 7 keys on
process location + egress (a renamed binary still trips it), and rules 10 and 11 key on the SPN
pattern rather than the ticket encryption type (AES Kerberoasting trips it, where an
RC4-only rule would miss it). The Wazuh task rules score the task's *command*, which is what
the built-in rule 60228 ignores, and `100201` builds its exclusion list from the sources
actually observed in this lab rather than from a generic allowlist.
