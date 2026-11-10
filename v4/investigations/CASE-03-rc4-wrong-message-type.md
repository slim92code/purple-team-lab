# CASE-03 — The RC4 rule reads the wrong Kerberos message, and its own description says so

| | |
| --- | --- |
| Alert | **None.** Two rules exist for RC4 and both returned nothing. |
| Ran | 6 Nov 2026 — RC4 tickets issued at 11:48:12.502 and 12:21:45.874 CET |
| Severity | High. RC4 was issued to an attacker twice and no rule read it. |
| MITRE | [T1558.003 — Kerberoasting](https://attack.mitre.org/techniques/T1558/003/), [T1550.003 — Pass-the-Ticket](https://attack.mitre.org/techniques/T1550/003/) |
| Verdict | Both rules correct as written, pointed at the wrong message type. |
| Cells | [`#3` and `#13` in the coverage matrix](../coverage-matrix.md) |

## 1. Where this case starts

With a result that looked like confirmation.

`Purple - RC4 Anomaly (post AES enforcement)` returned nothing, and pre-hardening that is the
expected reading: AES enforcement has not been applied, so the rule has nothing to invert yet.
`Purple - Kerberoasting RC4 Service Ticket` returned nothing too, and that is also expected —
the roast came back AES-256, which is why the etype-agnostic companion `#4` exists and fired.

Both cells were written as `✗ silent — by design`. Both were wrong, and neither was wrong about
the query.

The error surfaced from somewhere else entirely: measuring Pass-the-Ticket, which has no rule and
therefore no cell in the matrix at all.

## 2. Questions

1. Is there RC4 in this estate's Kerberos traffic at all?
2. The controls said no. What did they actually cover?
3. If RC4 exists, which rule should have seen it, and why did it not?
4. Was this knowable before the measurement?

## 3. Queries

The control both cells rested on — service tickets by encryption type:

```spl
index=main source="WinEventLog:Security" EventCode=4769 earliest=-1d latest=now
| stats count values(Service_Name) as services by Ticket_Encryption_Type
```

The same question asked of the other Kerberos message type, which is the query that was never
run:

```spl
index=main source="WinEventLog:Security" EventCode=4768 earliest=-1d latest=now
| stats count values(Ticket_Encryption_Type) as etypes values(Client_Address) as src by Account_Name
```

And timestamped, per principal:

```spl
index=main source="WinEventLog:Security" EventCode=4768 Account_Name="fcastle" earliest=-1d latest=now
| table _time Ticket_Encryption_Type Client_Address Result_Code
| sort _time
```

## 4. Findings

### 4.1 The control was right and the conclusion was too wide

| Ticket_Encryption_Type | count | services |
| ---------------------- | ----- | -------- |
| `0x12` | 125 | `HYDRA-DC$`, `SPIDERMAN$`, `SQLService`, `THEPUNISHER$`, `krbtgt` |

One hundred and twenty-five service tickets, every one AES-256, no `0x17`. That measurement is
correct and it is still true.

What was written next to it — "no RC4 anywhere" — does not follow from it. The control covers
`4769`, the ticket-granting **service** exchange. Kerberos has another one.

### 4.2 RC4 is in this estate, in ticket-granting tickets

| `_time` | Account | etype | Client_Address | What it is |
| ------- | ------- | ----- | -------------- | ---------- |
| 11:32:01.111 | `fcastle` | `0x12` | `.133` | TGT from the spray success |
| **11:48:12.502** | `fcastle` | **`0x17`** | `.133` | **the TGT `GetUserSPNs` requested** |
| **12:21:45.874** | `SQLService` | **`0x17`** | `.138` | the Pass-the-Ticket |

Two RC4 tickets, both successful, both on the attack path, to two different principals from two
different tools.

**The roast's own TGT was RC4, eleven milliseconds before the AES service ticket that `#4`
caught.** `impacket` requests RC4 for its own ticket-granting ticket as a matter of course and
this KDC issued it; the service ticket then came back AES only because `GetUserSPNs` specified no
etype for it and the KDC chose the strongest shared option. The louder cryptographic signal and
the alert that fired were eleven milliseconds and one message type apart.

### 4.3 Neither RC4 rule can reach it

Both read `4769`:

| Rule | Search keys on | Can it see a `0x17` TGT? |
| ---- | -------------- | ------------------------ |
| `#3` Kerberoasting RC4 Service Ticket | `EventCode=4769 Ticket_Encryption_Type="0x17"` | no |
| `#13` RC4 Anomaly (post AES enforcement) | `EventCode=4769 Ticket_Encryption_Type="0x17"` | no |

For `#3` this is defensible — it is a Kerberoasting rule and a roast is a TGS request, so reading
`4769` is the right scope. Its silence here really is by design.

For `#13` it is not. Its description reads *"after AES enforcement every `0x17` is an anomaly —
threshold inverts."* That is a statement about **all** RC4 on the domain, and the rule implements
it over one of the two message types that carry an encryption type. The clearest `0x17` anomaly
this chain produced — a service account obtaining a ticket-granting ticket at RC4, from a
workstation, 33 minutes after its SPN was roasted — is outside what the rule reads. It was
invisible before enforcement and it will be invisible after.

### 4.4 This was knowable from the repo, in the rule next door

The sharpest part of this case is that nothing new had to be discovered.

`#3`'s own description, shipped in `savedsearches.conf`, says:

> *RC4 is not blocked here. The service account still holds an RC4 key and the KDC issues one on
> request — the Pass-the-Ticket step of the v3 run got a `4768` TGT for that same account at
> `0x17`.*

So the repository already recorded, in prose, that RC4 lives in `4768` in this estate, with the
exact account and the exact message type. And `#13` — written to catch every surviving `0x17` —
reads `4769` only.

The knowledge and the rule were in the same file and did not meet. That is a different failure
from the ones v3 catalogued: those rules were wrong about a field format or bound to a group that
did not exist, and reading them would not have revealed it. This one is a rule contradicted by
the paragraph beside it.

### 4.5 Why the before column could not have found this alone

Pre-hardening, `#13` is **supposed** to be silent. A silent result is what the cell expects, so it
reads as confirmation rather than as a question. The control that would have caught the error —
asking `4768` the same question — had no reason to be run, because nothing in the cell suggested
the answer might be elsewhere.

What forced it was measuring phase 6, Pass-the-Ticket, which has **no shipped rule and therefore
no cell.** The RC4 ticket turned up as a property of an attack nobody was scoring.

**A matrix built from the rules that exist cannot find the gaps between them.** The phases with no
rule are not empty rows to be filled in later; they are where this kind of error is visible.

## 5. Verdict

**Two RC4 tickets issued to an attacker, neither detected, and the rule named for the job cannot
be fixed by tuning.**

`#3` is correct and correctly silent. `#13` is a scope defect: its description describes the
domain and its search covers half of it.

It also settles a question v3 left as an inference. The v3 write-up concluded this domain
*prefers* AES rather than *enforcing* it, on the evidence of a single RC4 TGT. Two tickets, two
principals, two tools is no longer an inference.

## 6. What this changes

**Resolved, 10 Nov 2026 — the one item not held for step 8.** This case's first owed item is
closed, because it is bundle 4's prerequisite and could not wait: with `#13` reading the wrong
message type, AES enforcement would have measured silence both sides of the hardening and the
silence would have meant *"the rule looks at the wrong event"*, not *"enforcement worked"*.

The fixed rule, run over the preceding seven days, returns the two tickets this case was written
about:

| `Account_Name` | `Service_Name` | Message type | Count | Source |
| -------------- | -------------- | ------------ | ----- | ------ |
| `SQLService` | `krbtgt` | TGT (AS-REP) | 1 | `192.168.182.138` |
| `fcastle` | `krbtgt` | TGT (AS-REP) | 1 | `192.168.182.133` |

**Both are `4768`; neither is `4769`.** Section 3 inferred that from a control count of zero
`0x17` in `4769`; the rule now states it directly. It settles the question of degree this case
left slightly open: the old rule was not under-scoped on these tickets, it could not have returned
either at any threshold. And `fcastle`'s TGT came from `192.168.182.133`, the attacker's host —
RC4 issued to the attack path itself, by the rule named for RC4, unseen.

**A second finding came out of the deploy rather than the rule.** For an interval the file on disk
was correct, `btool savedsearches list --debug` confirmed it parsed and from which file, and the
running rule still read only `4769`: `btool` reads the file, `| rest` reads `splunkd`'s memory, and
a `savedsearch/_reload` was needed between them. Verifying the fix by diff or by `btool` would
have reported success over an unchanged rule. **Three steps, and only the third is evidence: the
file parses, `| rest` shows the loaded search changed, the rule returns the events it was blind
to.** The remaining four fixes in this column inherit that standard.

One divergence recorded rather than left to be found later: the instance kept the short original
`description`, the repository carries the longer two-message-type text. Behaviourally irrelevant,
but it is the same species of drift as [CASE-07](CASE-07-the-loudest-rule-is-not-in-the-repo.md).

**The rest is still held until after the hardening run, like everything else in this column.**

| Owed | Detail |
| ---- | ------ |
| ~~`#13` reads `4768` as well as `4769`~~ | **Done** — deployed and verified above, 10 Nov 2026 |
| `#13`'s positive test uses a TGT | After enforcement, a deliberate RC4 request should produce a row. Testing with a TGS would pass against a rule that still cannot see the real case |
| `#3`'s cell wording | "No RC4 anywhere" corrected to the scope the control actually covered |

**And it gives the after column a real prediction rather than a hope.** AES enforcement should
make the Pass-the-Ticket step fail: `Rubeus asktgt` presenting an RC4 key against a KDC that
enforces AES has nothing to negotiate. So the after-run has two things to measure on this cell
rather than one — whether the fixed `#13` fires on an attempted RC4 request, and whether the
request succeeds at all. A silent `#13` after enforcement means something only if the second
question is answered too.

## 7. What a reader should take from this

**An expected silence is the hardest kind to audit.** Every other cell in this column was checked
because something looked wrong. This one looked right, and the cell that exposed it was not a
cell.

Two habits would have caught it earlier, and neither is clever:

1. **When a rule's description makes a claim about a protocol, check that the search covers the
   protocol.** "Every `0x17`" and `EventCode=4769` are not the same statement, and the gap between
   them is a sentence long.
2. **Read the rules next to the one being measured.** The evidence here was four lines away, in a
   description written by the same hand that wrote the rule that missed it.
