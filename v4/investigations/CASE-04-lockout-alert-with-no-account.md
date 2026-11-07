# CASE-04 — The lockout alert fires correctly and cannot say which account

| | |
| --- | --- |
| Alert | `Purple - Verify Account Lockout` returns two rows. Both output columns are empty. |
| Fired | 6 Nov 2026, 11:32:05.998 and 11:32:05.999 CET |
| Severity | Medium. The control worked; the alert cannot describe what it did. |
| MITRE | [T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/) (the lockout is the defence, not the attack) |
| Verdict | True positive, unusable output. Two causes, one of them not the rule's fault. |
| Cell | [`#12` in the coverage matrix](../coverage-matrix.md) |

## 1. What the alert showed

```
index=main source="WinEventLog:Security" EventCode=4740 earliest=-1d latest=now
| table _time Target_User_Name Caller_Computer_Name
```

| `_time` | Target_User_Name | Caller_Computer_Name |
| ------- | ---------------- | -------------------- |
| 6 Nov 11:32:05.999 | *(empty)* | *(empty)* |
| 6 Nov 11:32:05.998 | *(empty)* | *(empty)* |

An analyst receiving this learns that something was locked out, twice, at a precise moment, and
nothing else. Not which account. Not where the attempts came from. The two fields the rule chose
to display are the two an analyst would ask for first.

This rule ships with `enableSched = 0`, so it has no triggered-alert history and an absent alert
would carry no information. It was measured by running the search.

**What actually happened:** `kerbrute bruteuser` against `tstark` with six wrong passwords at
11:32:05–06, four and a half seconds after the spray in
[CASE-01](CASE-01-password-spray-undercount.md). The account locked. The defence worked.

## 2. Questions

1. Is the data missing, or is the rule asking for it by the wrong name?
2. Both columns are empty — is it one fault or two?
3. If `4740` cannot name the source, what can?
4. Does any other layer have what this one is missing?

## 3. Queries

Everything the event carries, rather than the two fields the rule selects:

```spl
index=main source="WinEventLog:Security" EventCode=4740 earliest=-1d latest=now
| head 2
| table *
```

And the same event as the EDR received it:

```spl
index=main sourcetype=wazuh rule.id=60115 earliest=-1d latest=now
| table _time rule.level data.win.eventdata.targetUserName data.win.system.eventID data.win.eventdata.subjectUserName
```

## 4. Findings

### 4.1 The account name is there, under three other names

| Field | Value |
| ----- | ----- |
| `Account_Locked_Out_Name` | `tstark` |
| `Account_Locked_Out_Security_ID` | `S-1-5-21-…-1110` |
| `user`, `src_user` | `tstark` |
| `Account_Name` | multivalue: `HYDRA-DC$`, `tstark` |

The Splunk Add-on for Windows extracts the locked-out principal as `Account_Locked_Out_Name`.
**`Target_User_Name` is not a field this source produces at all**, so the rule tables an empty
column where the entire point of the alert belongs.

This is the third instance in this repository of a rule keyed on a field name that was guessed
rather than read off the data — the [Zeek Kerberoasting
filter](../../detections/sigma/v3_ndr.yml) and the `props.conf` sourcetype were the first two.
Like both of those, it was not found by reading the rule. It was found by running it and looking
at the output.

### 4.2 The second empty column is not the rule's fault, and no field name fixes it

The raw event ends like this:

```
Additional Information:
	Caller Computer Name:
```

The label is present and the value is not. **Windows wrote this `4740` without populating
`Caller Computer Name`**, so there is nothing for any field name to extract. The rule is tabling
a column that cannot hold a value on this estate.

That has a consequence worth stating plainly, because it is a property of the event type and not
of this lab's configuration:

**`4740` alone cannot attribute a lockout to a source.** The attempts came from
`192.168.182.133` and this event does not say so. An alert built only on `4740` can tell an
analyst that an account locked and cannot begin to tell them whether it was an attack, a stale
service credential or a user with a bad cached password.

### 4.3 What can attribute it is already running

Attribution requires the failures, not the lockout — `4771` carries `Client_Address` and `4740`
does not. `Purple - Spray Success` correlates exactly that, and it fired on this chain with the
attacker host named:

| `_time` | src | Accounts | eventcount |
| ------- | --- | -------- | ---------- |
| 6 Nov 11:32:00.913 | `192.168.182.133` | Administrator, SQLService, fcastle, pparker, tstark | 19 |

So the pair is complementary in a way neither rule's description mentions: `#12` establishes that
a lockout happened and when, `#6` establishes where from. Neither is sufficient and they were
written as if independent.

### 4.4 The EDR has the field the SIEM is missing

Wazuh `60115` — *user account locked out (multiple login errors)* — fired at level 9 on the same
two events:

| `_time` | rule.level | targetUserName | eventID | subjectUserName |
| ------- | ---------- | -------------- | ------- | --------------- |
| 11:32:06.953 | 9 | `tstark` | 4740 | `HYDRA-DC$` |
| 11:32:06.941 | 9 | `tstark` | 4740 | `HYDRA-DC$` |

`data.win.eventdata.targetUserName` holds `tstark` outright.

**This changes the shape of the fix.** The estate already has the locked-out account on an
alerting path; what it lacks is routing. So the owed work is not "repair the Splunk extraction"
but "take the lockout alert from the layer that already names the account" — which touches no
Splunk rule, and therefore does not disturb the before/after comparison at all.

It is the clearest operational return in this column from reading more than one layer, and it
only appeared because the two were compared. Neither cell states it alone: the Splunk cell says
the field is empty, the Wazuh cell says a lockout fired. The useful sentence is in the gap.

### 4.5 One lockout, two alert rows

`RecordNumber` 2319917 and 2319918, one millisecond apart, same account, same subject. The DC
wrote the event twice and the rule tables both, so an analyst sees two rows for one lockout.

Minor on its own. Worth recording because duplicate rows are how a feed loses an analyst's trust,
and because any count built on this rule — "how many lockouts today" — is wrong by a factor of
two.

### 4.6 The rule's name describes a hardening change that predates v4

Not a new finding, and
[already corrected in the v4 plan](../README.md): the rule ships as *Verify Account Lockout (post
FGPP)* with the description *"confirms FGPP lockout now fires on spray attempts (absent
pre-hardening)"*. The fine-grained password policy has been in force on `Domain Users` since
4 June 2026 — lockout after five failures in thirty minutes — so the lockout is the current
state, not a v4 change.

It is restated here because it bears directly on how this cell reads: `#12` fires in the before
column and will fire in the after column, and **that pair of identical cells is not evidence of
anything hardening did.** The plan's fix is to keep the over-threshold burst in both runs as a
measured boundary rather than as a hardening effect.

## 5. Verdict

**True positive. The control worked, the rule found it, and the output is unusable as written.**

Four separate statements, which is why this cell needed a case file rather than a line:

- The account name was never missing; the rule asked for it by a name this source does not use.
- The source column cannot be fixed at all, because Windows did not write the value.
- Another rule already supplies the attribution, and neither description says they pair.
- Another layer already supplies the account name, which makes the fix routing rather than repair.

## 6. What this changes

**Held until after the hardening run.**

| Owed | Detail |
| ---- | ------ |
| Route the lockout alert from Wazuh `60115` | It already carries `targetUserName`. Preferred fix: no Splunk rule changes, so the before/after comparison is untouched |
| `Account_Locked_Out_Name` in place of `Target_User_Name` | The fallback if the alert has to stay in Splunk |
| Drop `Caller_Computer_Name` | It cannot hold a value; replace it with the `#6` correlation or with nothing |
| De-duplicate, or state the factor | Two rows per lockout, consistently |

## 7. What a reader should take from this

**Run the rule and read its output, not its logic.** Every defect in this case is invisible when
reading the search text: `Target_User_Name` looks like a reasonable field name, `Caller_Computer_
Name` looks like a reasonable thing to display, and the duplicate rows are a property of the
source. All four appear the moment the rule is executed against a real event.

And the second habit, which is the one that produced the cheap fix: **when a rule's output is
missing a field, check whether another layer already has it before deciding to repair the rule.**
The repair was a two-line change. The routing is none.
