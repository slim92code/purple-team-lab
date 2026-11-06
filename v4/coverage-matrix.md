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
| 2 | C2 Beacon from User-Writable Path | 5b | *not yet measured* | |
| 3 | Kerberoasting RC4 Service Ticket | 4a | **✗ silent — by design, the roast was AES** | M |
| 4 | Kerberoasting User-SPN (etype-agnostic) | 4a | **✓ fires** | M |
| 5 | Password Spray (multi-user from one source) | 2 | **✗ silent — one account below threshold** | M |
| 6 | Spray Success (4771 then 4768 same source) | 2 | **✓ fires — and one false positive** | M |
| 7 | SAM Hive Dump via reg save | 9b | N/E | — |
| 8 | DCSync from non-DC | 9c | N/E | — |
| 9 | Scheduled Task Persistence | 10 | *not yet measured* | |
| 10 | LSASS Access (credential theft mask) | 8 | **✓ fires** | M |
| 11 | Kerbrute User Enumeration (4768 error 0x6) | 1 | **✗ silent — structural** | M |
| 12 | Verify Account Lockout (post FGPP) | 2 | **✓ fires, output unusable** | M |
| 13 | RC4 Anomaly (post AES enforcement) | 4a | **✗ silent — nothing to anomaly on yet** | M |
| 14 | Sliver C2 Beacon by JA4 Fingerprint | 5a | **✓ fires on one of two hosts** | M |
| 15 | Large Outbound Transfer | 11, 12 | *not yet measured* | |

Nine measured, three N/E, three outstanding. Of the nine, four fire and five are silent — but the
split that matters is not fires-versus-silent. It is that **two of the four that fire are
defective in ways a tick in this column would hide**: `#12` fires and cannot say which account
was locked, and `#6` fires on the attack and also on benign clock skew. And of the five silent,
three are silent for reasons that are correct or by design, one is silent by a single account,
and none are silent because the rule is simply wrong.

Three cells are N/E by decision rather than by accident. A phase runs in the before-run only if
a shipped rule measures it **and** the after-run will run it too; dropping a phase from one
column alone would make the comparison asymmetric, so it is dropped from both. Phases 3 and 9b
were not executed. Phase 9c was attempted in an earlier run and failed at RPC 1825, and
repairing it mid-measurement would change the estate between columns.

---

## Cell detail

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

## Not yet measured

Three cells: `#2 C2 Beacon from User-Writable Path`, `#9 Scheduled Task Persistence`, and
`#15 Large Outbound Transfer`.

The chain that produces them ran on 6 November and the evidence is still in the index, so these
are re-runnable now and will not be re-runnable indefinitely — Splunk's `main` index has already
rolled older buckets off once in this lab's history, which is how the 20 October raw data was
lost.

Two notes on method, so these three are filled the same way the nine were:

- `#15` ships with `enableSched = 0`, like `#12`. It must be measured by re-running its search.
  An absent alert says nothing about it.
- `#2` runs over the `Network_Traffic` CIM data model rather than a raw sourcetype, so a silent
  result has one more possible cause than usual: the rule can be right, the attack can have
  happened, and the model can still be missing the event. The cell is not complete without
  checking whether Sysmon `EventCode=3` exists for the beaconing process **and** whether
  `All_Traffic.app` holds the path in the form the rule's `*\\Temp\\*` pattern matches. This lab
  has already shipped one rule that queried a model which never received the events it needed.

## Still owed to this matrix

Two things this column does not yet have, recorded so they are not discovered later as gaps.

**The other four detection layers.** Every cell above is Splunk. The v3 matrix carried five
sources per phase — Splunk, Zeek, Suricata, Wazuh, and the Windows log itself — and two cells here
already depend on Zeek to mean anything (`#11`, where Zeek holds the only record of the enum, and
`#5`, where it supplies the undercount). Wazuh and Suricata are unexamined for this run. An empty
Wazuh column is a finding; an unmentioned one is an error.

**The fixes this column has earned, all held until step 8.** Four rules want changes that are
deliberately not being made, because changing a rule between the before and after columns
destroys the comparison those columns exist to make:

| Rule | Change owed | Why it waits |
| ---- | ----------- | ------------ |
| `#10` LSASS Access | exclude `C:\Windows\Sysmon64.exe` | fires benignly after a DC Sysmon restart, which the bundles will cause |
| `#12` Verify Account Lockout | `Account_Locked_Out_Name`; drop `Caller_Computer_Name` | fires correctly, reports nothing usable |
| `#6` Spray Success | exclude `0x25` from the failure side | benign clock skew satisfies the rule's shape |
| `#15` Large Outbound Transfer | calibrate the placeholder threshold | needs the second benign window's real egress |

`#13` is owed a positive test rather than a fix: after AES enforcement, a deliberate RC4 request
should produce a row, and without that test its two silences prove nothing.
