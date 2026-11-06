# CASE-02 — Account enumeration: four detection layers, one holds the evidence, none alerts

| | |
| --- | --- |
| Alert | **None, from any layer.** |
| Ran | 6 Nov 2026, 11:03:15 CET |
| Severity | Low on its own. It supplied the target list for [CASE-01](CASE-01-password-spray-undercount.md). |
| MITRE | [T1087.002 — Domain Account Discovery](https://attack.mitre.org/techniques/T1087/002/) |
| Verdict | True positive, undetected. Structural, not a threshold. |
| Cell | [`#11` in the coverage matrix](../coverage-matrix.md) |

## 1. Where this case starts

`kerbrute userenum` against 58 names, from the attacker host, finishing in 32 milliseconds:

```
2026/11/06 11:03:15 >  [+] VALID USERNAME:  administrator@MARVEL.LOCAL
2026/11/06 11:03:15 >  Done! Tested 58 usernames (1 valid) in 0.032 seconds
```

The lab ships a rule for exactly this — `Purple - Kerbrute User Enumeration (4768 error 0x6)` —
and it returned nothing. So did everything else.

This case is short, because the answer is not a tuning problem and there is nowhere for the
investigation to go once it is established. The value is in establishing it rather than assuming
it, and in what it says about the other three layers.

## 2. Questions

1. Did the rule stay silent because of its threshold, or because its input does not exist?
2. If the input does not exist, is that audit policy — something fixable — or is it Windows?
3. Did the attack reach the KDC at all?
4. Which of the four layers has evidence, and does any rule act on it?

## 3. Queries

The rule, verbatim:

```spl
index=main source="WinEventLog:Security" EventCode=4768 Result_Code="0x6" earliest=-1d latest=now
| bucket _time span=1m
| stats count dc(Account_Name) as unique_users by _time Client_Address
| where count > 50 AND unique_users > 20
```

The control that turns "no rows" into a measurement:

```spl
index=main source="WinEventLog:Security" EventCode=4768 earliest=-1d latest=now
| stats count by Result_Code
```

On the domain controller, because the next hypothesis is audit policy:

```
auditpol /get /subcategory:"Kerberos Authentication Service"
```

And the network, which is where the evidence turns out to be:

```spl
index=main sourcetype=zeek "KDC_ERR_C_PRINCIPAL_UNKNOWN" earliest=-1d latest=now
| rex field=source "/current/(?<log_file>[^/]+)"
| where log_file="kerberos.log"
| bucket _time span=1m
| stats count by _time
```

## 4. Findings

### 4.1 The event the rule counts is never written

| Result_Code | count |
| ----------- | ----- |
| `0x0` | 55 |

Fifty-five ticket requests in the window, every one a success. **Not one `0x6`.** The rule's
predicate cannot be satisfied: `count > 50 AND unique_users > 20` is being applied to an empty
set, and lowering either number changes nothing.

### 4.2 It is not audit policy

```
Kerberos Authentication Service   Success and Failure
```

Failure auditing is on. The hypothesis that this is a misconfiguration — the cheap, hopeful
explanation — is wrong. **This domain controller does not write a `4768` for a principal that
does not exist**, which makes sense once stated: there is no account for the event to be about.

That is the whole finding, and it means the shipped rule is correct against a KDC that behaves
differently and inert against this one. It is kept rather than deleted for that reason, and this
cell is the evidence of which kind of KDC this is.

### 4.3 The attack arrived, and Zeek has all of it

| Minute | Count | Phase |
| ------ | ----- | ----- |
| **11:03** | **57** | this enumeration |
| 11:32 | 2 | the spray in [CASE-01](CASE-01-password-spray-undercount.md) |

Fifty-nine `KDC_ERR_C_PRINCIPAL_UNKNOWN` on the wire, all from `192.168.182.133`, each carrying
the principal that was tried.

The 57 match the attack exactly: 58 names tested, one valid, 57 unknown. So the KDC received
every attempt and answered every one with an error — and wrote none of it down. The detection
problem is not visibility. The evidence is complete, on a sensor that is deployed, indexed and
queryable.

### 4.4 Nothing acts on it, and that is the gap

All four layers, measured:

| Layer | What it has | Rule that fires |
| ----- | ----------- | --------------- |
| Windows / Splunk | nothing — no `0x6` is written | `#11` exists and is inert |
| Wazuh | nothing — its built-in authentication-failure rules key on `4771`, which enumeration never produces | none |
| Suricata | the `krb5` traffic, 83 events, no signature on it | none |
| **Zeek** | **all 59 errors, with principals** | **none** |

The shipped Zeek content is three rules in [`v3_ndr.yml`](../../detections/sigma/v3_ndr.yml):
Kerberoasting on `zeek/kerberos`, WinRM lateral movement on `zeek/conn`, and the JA4 beacon on
`zeek/ssl`. None keys on `KDC_ERR_C_PRINCIPAL_UNKNOWN`.

So the one layer that can see this attack has no rule that reads it, and the only rule that
exists watches a log that will never contain it. **Of four detection layers, exactly one holds
the evidence and none alerts.**

### 4.5 A note for anyone re-running the Zeek query

It also returns one hit in `http.log` from `192.168.182.1`, which is not evidence of anything.
That is the browser running the Splunk search: the string `KDC_ERR_C_PRINCIPAL_UNKNOWN` crossed
the monitored segment inside the HTTP request to Splunk Web on port 8000, and Zeek recorded the
act of looking. Worth knowing before it is mistaken for a second source.

## 5. Verdict

**True positive, undetected, and the reason is structural.**

This is the v3 finding that [Zeek recorded a spray attempt the Windows log never
did](../../v3/README.md#findings), reproduced in v4 against a different phase and measured across
all four layers rather than two. In v3 it was an observation about one event type. Here it is a
coverage statement with a number on it.

The rule is not wrong and the threshold is not wrong. The input is absent, and no amount of work
on the rule reaches that.

## 6. What this changes

**One rule, held until after the hardening run.** A Zeek rule on
`KDC_ERR_C_PRINCIPAL_UNKNOWN` — one source, many distinct principals, short window. The logsource
`zeek/kerberos` is already in use by the Kerberoasting rule, so this needs no new telemetry, no
new parser and no new feed: it is a rule against a field Zeek already extracts into a log already
indexed.

It is the cheapest coverage gain available anywhere in the before-run column, and it is
deliberately not written yet. New detection content between the before and after columns changes
what the after column is measuring, which is the one thing this build sequence refuses to do.

## 7. What a reader should take from this

Three checks separate "the rule is silent" from "the rule cannot work", and in this case they are
the whole investigation:

1. **Count the event the rule counts** — not the rule's output. An empty rule and an empty source
   look identical and mean opposite things.
2. **Check the audit policy before concluding anything about the platform.** The hopeful
   explanation is usually configuration, and ruling it out is one command.
3. **Ask whether another layer has the evidence, and then whether anything reads it.** Those are
   two separate questions, and stopping after the first turns a coverage gap into a reassurance.

The third is the one this case nearly got wrong. "Zeek sees it" was written down first as
corroboration — proof the attack arrived — and only later as the gap it actually is. Having the
evidence and alerting on it are not the same property, and a matrix that records the first can
read as though it recorded the second.
