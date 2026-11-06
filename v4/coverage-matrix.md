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
| 3 | Kerberoasting RC4 Service Ticket | 4a | *not yet measured* | |
| 4 | Kerberoasting User-SPN (etype-agnostic) | 4a | *not yet measured* | |
| 5 | Password Spray (multi-user from one source) | 2 | *not yet measured* | |
| 6 | Spray Success (4771 then 4768 same source) | 2 | *not yet measured* | |
| 7 | SAM Hive Dump via reg save | 9b | N/E | — |
| 8 | DCSync from non-DC | 9c | N/E | — |
| 9 | Scheduled Task Persistence | 10 | *not yet measured* | |
| 10 | LSASS Access (credential theft mask) | 8 | **✓ fires** | M |
| 11 | Kerbrute User Enumeration (4768 error 0x6) | 1 | **✗ silent — structural** | M |
| 12 | Verify Account Lockout (post FGPP) | 2 | *not yet measured* | |
| 13 | RC4 Anomaly (post AES enforcement) | 4a | *not yet measured* | |
| 14 | Sliver C2 Beacon by JA4 Fingerprint | 5a | **✓ fires on one of two hosts** | M |
| 15 | Large Outbound Transfer | 11, 12 | *not yet measured* | |

Three cells are N/E by decision rather than by accident. A phase runs in the before-run only if
a shipped rule measures it **and** the after-run will run it too; dropping a phase from one
column alone would make the comparison asymmetric, so it is dropped from both. Phases 3 and 9b
were not executed. Phase 9c was attempted in an earlier run and failed at RPC 1825, and
repairing it mid-measurement would change the estate between columns.

---

## Cell detail

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

Nine cells. The chain that produces them ran on 6 November and the evidence is still in the
index, so these are re-runnable now and will not be re-runnable indefinitely — Splunk's `main`
index has already rolled older buckets off once in this lab's history, which is how the 20 October
raw data was lost.

Two of the nine need their method stated before they are filled, because an absent alert means
nothing for either: `#12 Verify Account Lockout` and `#15 Large Outbound Transfer` both ship with
`enableSched = 0`, so each must be measured by re-running its search rather than by looking for a
triggered alert.
