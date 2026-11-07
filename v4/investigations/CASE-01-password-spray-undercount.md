# CASE-01 — A password spray that fired two alerts, neither from the spray rule

| | |
| --- | --- |
| Alert | **None from `Purple - Password Spray`.** Two others fired: `Purple - Spray Success`, and Wazuh `60205`. |
| Ran | 6 Nov 2026, 11:32:00–11:32:01 CET |
| Severity | High |
| MITRE | [T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/) |
| Verdict | True positive. The rule written for it did not fire, and the reason is in the telemetry rather than the threshold. |
| Cell | [`#5` in the coverage matrix](../coverage-matrix.md) |

## 1. Where this case starts

Not with an alert. With a silent cell.

The before-run matrix records `Purple - Password Spray (multi-user from one source)` as
`✗ silent` for phase 2a. The attack definitely ran — `kerbrute passwordspray` against seven
accounts with the password `Password1`, one success — so the question is not whether anything
happened. It is why the rule that exists for this exact technique returned nothing, and whether
the estate saw the spray at all.

The rule needs five distinct accounts failing pre-authentication from one source inside five
minutes:

```
EventCode=4771 (Failure_Code="0x18" OR Failure_Code="0xE")
| bucket _time span=5m
| stats dc(Account_Name) as unique_users … by _time Client_Address
| where unique_users >= 5
```

Run over the window it returns no rows. That number — how many distinct accounts the Windows log
can actually show for this attack — is what the rest of this case is about.

## 2. Questions

1. How many accounts did the Windows log record failing, and is that the same as how many the
   spray tried?
2. The rule's own description says this estate yields four countable accounts against a threshold
   of five. Is four right?
3. Did anything else detect the spray?
4. If something did, can it be relied on?
5. Is the threshold wrong, or is the input wrong?

## 3. Queries

The rule, verbatim, over a window containing the attack:

```spl
index=main source="WinEventLog:Security" EventCode=4771 (Failure_Code="0x18" OR Failure_Code="0xE")
  earliest=-1d latest=now
| bucket _time span=5m
| stats dc(Account_Name) as unique_users count values(Account_Name) as targets by _time Client_Address
| where unique_users >= 5
```

Every `4771` from the attacker host, by failure code — the control, so that "no rows" is a
statement about the estate and not about the query:

```spl
index=main source="WinEventLog:Security" EventCode=4771 earliest=-1d latest=now
| stats count dc(Account_Name) as accounts values(Account_Name) as targets by Failure_Code Client_Address
```

The same failures with timestamps, which is what separates the spray from what ran next to it:

```spl
index=main source="WinEventLog:Security" EventCode=4771 Failure_Code="0x18" earliest=-1d latest=now
| eval src=replace(Client_Address,"^::ffff:","")
| search src="192.168.182.133"
| table _time Account_Name
| sort _time
```

What the network saw, which is not the same set:

```spl
index=main sourcetype=zeek "KDC_ERR_C_PRINCIPAL_UNKNOWN" earliest=-1d latest=now
| rex field=source "/current/(?<log_file>[^/]+)"
| where log_file="kerberos.log"
| bucket _time span=1m
| stats count by _time
```

## 4. Findings

### 4.1 Three accounts, not four

The timestamped failures split cleanly in two:

| Window | Accounts | What produced them |
| ------ | -------- | ------------------ |
| 11:32:00.913 – 11:32:01.425 | `Administrator` ×2, `SQLService` ×2, `pparker` ×2 | the spray |
| 11:32:05.983 – 11:32:05.996 | `tstark` ×8 | `kerbrute bruteuser`, a separate action |

The spray produced **three** distinct countable accounts. The fourth — `tstark` — is a different
attack that happened 4.5 seconds later and landed in the same five-minute bucket.

So the rule's own description, which has said "four countable accounts against a threshold of
five" since v3, was describing a figure inflated by an adjacent action. Measured on its own the
spray gets three. The rule is two short, not one.

Also confirmed from the control: **there is no `0xE` at all.** The `0xE` branch exists because
`Guest` supplied the fifth account that way in the 20 October run; `Guest` has been disabled
since and produces nothing.

### 4.2 Two accounts the Windows log cannot contain

Zeek holds 59 `KDC_ERR_C_PRINCIPAL_UNKNOWN` errors in the window, and the minute breakdown places
two of them inside the spray:

| Minute | Count | Phase |
| ------ | ----- | ----- |
| 11:03 | 57 | the earlier `kerbrute userenum` |
| **11:32** | **2** | **the spray** |

The two are `frankcastle` and `peterparker` — the long forms of two accounts whose short forms,
`fcastle` and `pparker`, do exist. The wordlist carried both spellings.

An authentication attempt against a principal that does not exist produces **no `4771` of any
failure code.** Windows has nothing to write: there is no account to fail. So those two attempts
are invisible to the rule by construction, not by threshold.

### 4.3 The attack was larger than the threshold and the log reported it smaller

Putting 4.1 and 4.2 together, with the success from `4768`:

| What the spray did | Count | Visible to `#5`? |
| ------------------ | ----- | ---------------- |
| Failed against existing accounts | 3 | yes |
| Failed against non-existent principals | 2 | **no — no event exists** |
| Succeeded (`fcastle`, TGT at 11:32:01.111, `0x12`) | 1 | no — success is not a `4771` |
| Unaccounted | 1 | — |
| **Total attempted** | **7** | **3 countable** |

The spray touched at least six accounts. The rule needs five. It can count three.

That is the finding, and it is sharper than "the threshold is too high for this lab": the attack
**exceeded** the threshold and the telemetry **under-reported** it, by more than the margin. And
the size of the undercount is not a property of the estate — it grows with however many
non-existent names the attacker's wordlist happens to contain, which is a number the defender
does not control and cannot see from the Windows log at all.

**A threshold tuned on what the Windows log can count is tuned on an undercount.**

**One attempt was unaccounted, and has since been identified.** `kerbrute` reported seven logins
and only six could be allocated from the Windows log; all fourteen `0x18` and all four `0x12`
events from the attacker host are distributed between the spray and `bruteuser`, so the seventh
produced no `4771` of any code.

It is **`Guest`**, found by
[HUNT-01](../hunts/HUNT-01-spray-without-the-4771-count.md) in Zeek's record of the wire, which
lists all eight principals the minute touched. `Guest` is disabled, so it writes nothing.

That completes the roster, and the completion is the finding: **every account this rule cannot see
is invisible for a different reason** — `fcastle` because it succeeded, `frankcastle` and
`peterparker` because they do not exist, `Guest` because it is disabled. No single adjustment to
the rule recovers them, which is why the answer in HUNT-01 is a different rule on a different
source rather than a tweak to this one.

### 4.4 Two other things detected it

The spray was not missed by the estate. It was missed by one rule.

**`Purple - Spray Success` fired**, on the same source, in the same second:

| `_time` | src | Accounts | eventcount |
| ------- | --- | -------- | ---------- |
| 6 Nov 11:32:00.913 | `192.168.182.133` | Administrator, SQLService, fcastle, pparker, tstark | 19 |

It correlates failures and a success from one source rather than counting distinct accounts, so
the undercount that silences `#5` does not silence it. Note what its account list contains:
five names, including `fcastle` — because a *success* is a `4768`, and this rule reads both.
The information `#5` needed was in the index; `#5` is just not looking at the half of it that
survived.

**Wazuh `60205` fired at level 10**, twice, in the same minute — *multiple Windows audit failure
events*, a built-in frequency rule.

### 4.5 And `60205` is better than its name, but priced on seven hours

The obvious objection to 4.4 is that `60205` is generic and fires on anything. Measured, it does
not. Over 6 November, with Wazuh verified alive and continuous:

| EventID | Count | Distribution | `60205` fired? |
| ------- | ----- | ------------ | -------------- |
| `4674` | 744 | exactly 48 on every full hour, flat | **no, not once** |
| `4771` | 20 | 4 at 09:00, 16 at 11:32 | yes, twice, in the 11:00 hour |

So it separates **burst from rate**: one failed privileged-object operation every seventy-five
seconds, all day, does not trigger it; sixteen pre-authentication failures in six seconds does.
That is a frequency rule working correctly.

What cannot be claimed is a false-positive rate. The benign baseline measured the Splunk searches
and nothing in Wazuh, and it could not have done otherwise — the wazuh-vm disk filled and
`alerts.json` sat at zero bytes from that window's start until 11:00 the next morning
([documented in the baseline](../benign-baseline.md)). The next candidate window, 4–5 November,
has no data at all: the estate was powered off, and Wazuh, the heartbeat and the Windows Security
log all read zero for both days.

So the support for "Wazuh covers this phase" is **zero false positives across roughly fifteen
hours of verified-alive Wazuh carrying 744 benign audit failures.** Stronger than it first looked,
and still not a working day.

## 5. Verdict

**True positive. Detected twice, by neither of the rules whose name says password spray.**

Three statements, all true, which is the point of the case:

- `Purple - Password Spray` did not fire, and lowering its threshold is the wrong fix.
- The estate detected the spray anyway, through a correlation rule and a generic EDR frequency
  rule.
- A coverage matrix built from one tool would have recorded this phase as a miss.

The threshold stays at 5. Detections are not tuned down to a lab's account count, and tuning one
to a number produced by an undercount is worse than leaving it — the undercount moves with the
attacker's wordlist, so any threshold derived from it is calibrated against the adversary's
choices rather than the estate's.

## 6. What this changes

**Nothing yet, deliberately.** Every fix below is held until after the hardening run. Changing a
rule between the before and after columns destroys the comparison those columns exist to make,
and this cell is one of the two the comparison most depends on.

| Owed | Why |
| ---- | --- |
| A Zeek rule on `KDC_ERR_C_PRINCIPAL_UNKNOWN` | The only layer that records attempts against non-existent principals has no rule that acts on them — the same gap [CASE-02](CASE-02-kerberos-enumeration.md) is entirely about |
| `60205`'s false-positive rate over a clean day | The rule currently carrying this phase is priced on fifteen hours; the number needs a fresh idle run, which is an action rather than a query |
| Re-word `#5`'s description | It says four countable accounts. Three is the measured figure; the fourth was a neighbouring attack |

## 7. What a reader should take from this

A silent rule is not a coverage gap and a firing rule is not coverage. This phase has one of each
and the honest answer is in neither cell alone.

The transferable part is narrower than "use more than one data source", which is advice nobody
needs. It is this: **before tuning a threshold, measure what the telemetry is capable of
counting.** `#5` was not badly calibrated. It was calibrated against a log that structurally
cannot see two of the six accounts the attack touched, and no amount of threshold work fixes a
rule whose input is missing the evidence.
