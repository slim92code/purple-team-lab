# HUNT-01 — Is the spray detectable by any signal that does not depend on the account count?

| | |
| --- | --- |
| Hypothesis-driven | Not alert-driven. Starts from a claim, ends with a rule or a disproof. |
| Hunted | 7 Nov 2026, against the before-run window of 6 Nov |
| Outcome | **Hypothesis proven.** Two viable signals found, one of them closing two gaps with one rule. |
| Opens from | [CASE-01](../investigations/CASE-01-password-spray-undercount.md), [CASE-02](../investigations/CASE-02-kerberos-enumeration.md) |

## 1. Why this hunt, and what is not being hunted

`Purple - Password Spray` cannot fire on this estate. That is settled: the spray yields three
countable accounts against a threshold of five, two of the accounts it tried do not exist and
produce no `4771` at all, and the fourth account the rule sees belongs to a different attack.
[CASE-01](../investigations/CASE-01-password-spray-undercount.md) measured all of it.

**So "why did the rule not fire" is a closed question and is not this hunt.** Re-asking it would
be triage in reverse.

The open question is different and worth something: **is this spray detectable at all, by a
signal that does not depend on counting accounts in the Windows failure log?** If one exists it is
a rule. If none does, the negative result is what makes the `#5` cell honest rather than
apologetic.

Three hypotheses, each testable against the same window.

| | Hypothesis | Why that source |
| --- | ---------- | --------------- |
| **H1** | Correlating *all* Kerberos AS activity from one source — successes included — reaches a usable count where failures alone do not | The success is in `4768` and the rule reads `4771`; `fcastle` is invisible to it for that reason alone |
| **H2** | The spray is visible as an NTLM failure pattern (`4625`) | This is the default spray signal in most SIEM content, so its absence or presence is worth establishing rather than assuming |
| **H3** | The network layer counts attempts rather than accounts, so it sees every principal tried regardless of whether it exists | Zeek records the wire; a non-existent principal produces a KDC error on the wire and no Windows event at all |

## 2. H1 — all AS activity from one source: **proven, 5 accounts**

```spl
index=main source="WinEventLog:Security" (EventCode=4771 OR EventCode=4768) earliest=-1d latest=now
| eval src=replace(Client_Address,"^::ffff:","")
| bucket _time span=5m
| stats dc(Account_Name) as accounts values(Account_Name) as targets count by _time src
| where accounts > 2
| sort _time
```

| `_time` | src | accounts | targets | events |
| ------- | --- | -------- | ------- | ------ |
| 6 Nov 11:30 | `192.168.182.133` | **5** | Administrator, SQLService, fcastle, pparker, tstark | 19 |

Five distinct accounts — enough for the shipped threshold, from the same window where the shipped
rule counts three. The whole difference is `fcastle`, whose attempt **succeeded** and therefore
appears as a `4768` rather than a `4771`.

**So the rule is one account short partly because it only looks at failures.** A spray that
succeeds hides its own best evidence from a failure-counting rule: the account that matters most
is the one that stops producing failure events.

This signal is real and it is also **largely already implemented** — `Purple - Spray Success`
correlates `4771` and `4768` from one source and fired on this chain at 11:40. The difference is
that it requires both event types present in a transaction with more than five events, while this
counts distinct accounts across both. Overlapping, not identical.

## 3. H2 — NTLM failures: **disproven, and the negative result is the point**

```spl
index=main source="WinEventLog:Security" EventCode=4625 earliest=-1d latest=now
| stats count dc(Account_Name) as accounts values(Account_Name) as targets by Workstation_Name IpAddress
```

**No results. Not one `4625` in the window.**

`kerbrute` sprays over Kerberos, so there is no NTLM authentication to fail. That is unremarkable
about the tool and worth recording about the detection landscape: **a SIEM whose spray detection
keys on `4625` — which is the common default, and what most published content uses — would have
seen nothing whatsoever from this attack.** Not a low count. Zero.

This is the same shape as [CASE-02](../investigations/CASE-02-kerberos-enumeration.md): a rule
correct in general, inert against this estate, because the event it counts is never written. The
difference is that here the rule is hypothetical and the finding is about what *not* to build.

## 4. H3 — the network counts attempts, not accounts: **proven, 8 principals**

```spl
index=main sourcetype=zeek earliest=-1d latest=now
| rex field=source "/current/(?<log_file>[^/]+)"
| where log_file="kerberos.log"
| rex field=_raw "^(?P<ts>\S+)\t\S+\t(?P<orig_h>\S+)\t\S+\t(?P<resp_h>\S+)\t\S+\t(?P<req_type>\S+)\t(?P<client>[^\t]+)\t(?P<service>[^\t]+)\t(?P<success>\S+)\t(?P<error_msg>\S+)"
| where req_type="AS"
| bucket _time span=5m
| stats dc(client) as distinct_clients values(client) as clients count by _time orig_h
| sort _time
```

| `_time` | src | distinct principals | what it is |
| ------- | --- | ------------------- | ---------- |
| 11:00 | `.133` | **58** | the enumeration — every name in the wordlist |
| 11:30 | `.133` | **8** | the spray, plus `bruteuser` |
| 09:10–09:35, 11:20, 19:20 | `.137`, `.138` | **1–3** | ordinary machine and user authentication |

Eight principals on the wire where the shipped rule's input shows three. Named:

```
Administrator  Guest  SQLService  fcastle  frankcastle  peterparker  pparker  tstark
```

### 4.1 This closes an open item in CASE-01

`CASE-01` recorded that `kerbrute` reported seven logins and only six could be accounted for,
and left the seventh unexplained rather than guessing. It is **`Guest`**.

The full roster, with why each is or is not countable:

| Account | Windows `4771` | On the wire | Why |
| ------- | -------------- | ----------- | --- |
| Administrator | `0x18` ×2 | yes | ordinary failure |
| SQLService | `0x18` ×2 | yes | ordinary failure |
| pparker | `0x18` ×2 | yes | ordinary failure |
| fcastle | **none** | yes | succeeded — it is a `4768` |
| frankcastle | **none** | yes | principal does not exist |
| peterparker | **none** | yes | principal does not exist |
| **Guest** | **none** | yes | **disabled** |
| tstark | `0x18` ×8 | yes | from `bruteuser`, 4.5 s later |

Seven sprayed, one brute-forced, eight on the wire, three countable by the shipped rule. Every
account the rule cannot see is invisible for a *different* reason — success, non-existence,
and disablement — which is why no single adjustment to the rule recovers them.

`Guest` is also the account whose `0xE` failure supplied the fifth name in the 20 October run,
before it was disabled. So the rule's `0xE` branch exists because of this account, and this
account is now one of the reasons the rule cannot reach five.

### 4.2 The separation is large, and one threshold covers both phases

| Activity | Distinct principals per 5 min per source |
| -------- | ---------------------------------------- |
| Enumeration | 58 |
| Spray | 8 |
| **Benign maximum observed** | **3** |

A threshold of five distinct principals from one source in five minutes fires on both attacks and
clears benign traffic by a comfortable margin — on **one field, in one log, with one rule.**

That is the part worth the hunt: [CASE-02](../investigations/CASE-02-kerberos-enumeration.md)
recorded that nothing acts on what Zeek sees for the enumeration, and `CASE-01` recorded that the
spray is two accounts short. **Both gaps close with the same rule**, because both attacks are the
same shape on the wire — one source, many principals — and differ only in how many.

### 4.3 A case-sensitivity trap in the benign numbers

The benign counts of 3 are inflated. From the output:

```
THEPUNISHER$/MARVEL.LOCAL
administrator/MARVEL.LOCAL
thepunisher$/MARVEL.LOCAL
```

`THEPUNISHER$` and `thepunisher$` are the same account and count as two distinct clients.
Normalised, the real benign maximum is **2**, not 3 — which widens the margin, but only for a
rule that normalises.

A rule written without `lower()` on the principal would inflate its own benign baseline and could
be tuned to a threshold that an attacker can sit under. This is the same class of defect as the
[v3 Zeek Kerberoasting filter](../../detections/sigma/v3_ndr.yml), which excluded machine accounts
with `endswith: '$'` against data that writes `THEPUNISHER$/MARVEL.LOCAL` — a field-format
assumption, visible in the data, invisible in the rule.

## 5. Findings

**Hypothesis proven, twice, and disproven once in a way that matters.**

| | Result | Value |
| --- | ------ | ----- |
| H1 — all AS activity, Windows | **5 accounts** | Real, largely covered by `#6` already |
| H2 — NTLM `4625` | **zero events** | The default spray signal is blind here. Do not build on it |
| H3 — distinct principals, Zeek | **8 vs 3** | A rule, and it closes a second gap at the same time |

And one incidental result: the account `CASE-01` could not place is `Guest`, which means every
account the shipped rule misses is missed for a different reason.

## 6. Recommendation

**One Zeek rule, written after the hardening run, covering phases 1 and 2a.**

```
Source:     Zeek kerberos.log, AS requests only
Group by:   lower(client) per id.orig_h, 5-minute window
Fire when:  distinct principals >= 5
Measured:   enum 58, spray 8, benign maximum 2 after normalisation
```

Three things it must carry, all of them measured above rather than assumed:

1. **`lower()` on the principal.** Without it the benign baseline reads 3 instead of 2 and the
   margin is misstated.
2. **No dependence on the KDC's error code.** The spray's eight principals fail three different
   ways and one succeeds; counting attempts rather than outcomes is what makes the rule work.
3. **A documented benign maximum of 2.** The margin between 2 and 5 is the rule's whole safety
   factor and it comes from one day of one lab — it needs re-measuring on any real estate.

**Not written now.** New detection content between the before and after columns changes what the
after column measures, which is the one thing this build sequence refuses to do. It is the same
rule [CASE-02](../investigations/CASE-02-kerberos-enumeration.md) already owes, and this hunt is
what establishes its threshold and its second use.

**And one thing not to do:** do not lower `#5`'s threshold. This hunt found a signal that works;
it did not find a reason to weaken one that does not. `#5` stays at five accounts, correct against
an estate that produces five countable failures, and the Zeek rule covers what it cannot see.
