# CASE-08 — The alerts give the ends of the chain and not the links

| | |
| --- | --- |
| Alert | **None, for either phase.** The steps on both sides of them alerted. |
| Ran | 6 Nov 2026 — Pass-the-Ticket 12:21:45, WinRM pivot 12:23:39, collection 16:24:38 CET |
| Severity | High. These are the steps that connect the ones that did alert. |
| MITRE | [T1550.003 — Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/), [T1021.006 — WinRM](https://attack.mitre.org/techniques/T1021/006/), [T1074.001 — Local Data Staging](https://attack.mitre.org/techniques/T1074/001/) |
| Verdict | Three true positives, no alerts. One has no detection content; two have content that is not deployed or not applicable. |
| Cells | Phases 6 and 7 in [the coverage matrix](../coverage-matrix.md) — neither has a numbered Splunk cell |

## 1. Where this case starts

With a gap in the middle of a timeline.

Five steps of this chain are measured. Three produced alerts and two did not, and the two that
did not are adjacent, consecutive, and sit between the three that did:

| Time | Step | Alert |
| ---- | ---- | ----- |
| 11:48:12 | Kerberoast `SQLService` via `fcastle` | **`#4` fired at 11:50** |
| 12:21:45 | Pass-the-Ticket — `SQLService` TGT from SPIDERMAN | — |
| 12:23:39 | WinRM pivot — SPIDERMAN → THEPUNISHER | — |
| 16:24:38 | 6.59 MB pulled back over WinRM | — |
| 17:27:09 | Exfiltration to the C2 | **`#15` returns the row** |

An analyst reading only the alerts sees a Kerberoast on one host and an exfiltration from
another, four and a half hours apart, with nothing in between. **The alerts establish that the
attack happened and not how it moved.**

Both unalerted steps have something in common that is worth naming before the detail: they are
the attacker *using* what the alerted steps obtained. The roast produced a credential; the PtT
spends it. The pivot produced access; the collection spends it.

## 2. Questions

1. Did the Pass-the-Ticket succeed, and is there any detection content for it anywhere?
2. There is a shipped Zeek rule for WinRM lateral movement. Did it alert?
3. What is the 6.59 MB at 16:24, and why does the exfiltration rule not see it?
4. Why did the alerting steps alert and these not?

## 3. Queries

Pass-the-Ticket, from the ticket-granting-ticket log:

```spl
index=main source="WinEventLog:Security" EventCode=4768 Account_Name="SQLService" earliest=-1d latest=now
| table _time Account_Name Ticket_Encryption_Type Client_Address Result_Code
```

The WinRM rule's logic, translated from
[`v3_ndr.yml`](../../detections/sigma/v3_ndr.yml) — `id.resp_p: 5985`, `conn_state` in
`SF`/`S1`/`OTH`, excluding `192.168.182.1`:

```spl
index=main source="*conn.log*" NOT _raw="#*" earliest=-1d latest=now
| rex field=_raw "^(?P<ts>\S+)\t\S+\t(?P<orig_h>\S+)\t(?P<orig_p>\S+)\t(?P<resp_h>\S+)\t(?P<resp_p>\S+)\t(?P<proto>\S+)\t(?P<service>\S+)\t(?P<duration>\S+)\t(?P<orig_bytes>\S+)\t(?P<resp_bytes>\S+)\t(?P<conn_state>\S+)"
| where resp_p="5985" AND orig_h!="192.168.182.1"
| table _time orig_h resp_h conn_state duration orig_bytes resp_bytes
| sort _time
```

And whether anything alerted, for either phase:

```spl
index=_audit action=alert_fired earliest=-7d latest=now
| stats count by ss_name
```

## 4. Findings

### 4.1 The Pass-the-Ticket succeeded, and nothing anywhere detects it

| `_time` | Account | etype | Client_Address | Result_Code |
| ------- | ------- | ----- | -------------- | ----------- |
| 6 Nov 12:21:45.874 | `SQLService` | `0x17` | `::ffff:192.168.182.138` | `0x0` |

A service account obtaining a ticket-granting ticket from a workstation, successfully, 33 minutes
after its SPN was roasted. `SQLService` has no business authenticating from SPIDERMAN; the host
that runs the service is the only place it should appear from.

**No shipped rule covers this, in any layer.** That was verified rather than assumed, because v3
had recorded a rule named `V3 - Pass-the-Ticket EC4768` as *scheduled and running* in a private
namespace where no inventory could see it. A namespace-wildcard search for it returns nothing —
it has been deleted since v3. [CASE-07](CASE-07-the-loudest-rule-is-not-in-the-repo.md) is the
case that check turned into.

The [ATT&CK layer](../../detections/attack_navigator_layer.json) already scores `T1550.003` at 75
rather than 100, with the note that it was *"exercised and recorded during the run, but no rule
for it exists in `detections/`"*. That was the honest call when it was written and this cell is a
second data point for it, not a correction.

**The detection is not hard to state**, which is what makes the gap worth recording: a `4768` for
an account that holds an SPN, sourced from anything other than the host that runs the service.
The RC4 encryption type is a second signal on the same event — and the rule that should have read
it is pointed at the wrong message type, which is [CASE-03](CASE-03-rc4-wrong-message-type.md).

### 4.2 The WinRM rule's logic matches, and the rule is not deployed anywhere

Seven connections, SPIDERMAN to THEPUNISHER on 5985:

| `_time` | conn_state | duration | bytes out | bytes **in** |
| ------- | ---------- | -------- | --------- | ------------ |
| 12:23:39.312 | `SF` | 2.4 s | 24,670 | 11,336 |
| 12:23:39.961 | **`RSTO`** | 1.7 s | 11,528 | 6,100 |
| 12:23:40.770 | `SF` | 0.9 s | 17,306 | 5,515 |
| 12:23:41.625 | `SF` | 0.04 s | 2,556 | 341 |
| 16:24:38.964 | `SF` | 18.2 s | 123,226 | **6,594,812** |
| 16:24:39.202 | `SF` | 18.0 s | 11,841 | 7,015 |
| 16:24:39.560 | `SF` | 17.6 s | 17,758 | 5,515 |

Workstation to workstation, which is precisely the pattern the rule's description names from the
v3 chain. Six of the seven match its `conn_state` list; the `RSTO` one does not, so the rule
undercounts by one — a connection the originator reset is still a connection that happened.

**But "the rule fires" is the wrong way to say this, and an earlier version of the matrix cell
said it.** The rule lives in `v3_ndr.yml` as **Sigma** — portable, vendor-agnostic rule content.
There is no corresponding saved search in the Splunk app, and the alert history for the whole week
contains no WinRM entry. So what was measured is the rule's **logic matching the data**, by
translating it into SPL by hand.

Nothing on this estate would have alerted on the pivot. The distinction matters because the two
statements look identical in a coverage table:

| | Phase 6 | Phase 7 |
| --- | ------- | ------- |
| Detection content exists | no | **yes** |
| Content matches the data | — | **yes, 6 of 7** |
| Anything would have alerted | no | **no** |

Same outcome, different cause, and only the first row distinguishes them. This is
[CASE-07](CASE-07-the-loudest-rule-is-not-in-the-repo.md)'s theme arriving from the other
direction: there, rules that existed and did not run; here, rule content that exists and was
never deployed.

**One more thing the rule's own file admits.** Its `filter_approved_source` list contains a single
address, `192.168.182.1`, and its false-positive note says plainly that *"an empty or unmaintained
list turns this into an alert on all WinRM."* In an estate with no jump host that is harmless and
it is why the pivot stands out. In any estate with administrative WinRM it is the whole rule.

### 4.3 The second burst is collection, and the exfiltration rule cannot see it

At 16:24, four hours after the pivot, one session pulls **6.59 MB back** to SPIDERMAN against
123 KB sent. Same channel, opposite direction.

`Purple - Large Outbound Transfer` does not see it, and not because of its threshold — 6.59 MB
would clear 10 MB only in aggregate, but the rule never considers it at all:

```
| where orig_h!="-" AND (match(orig_h,"^192\.168\.182\.") OR match(orig_h,"^fd15:"))
        AND NOT match(resp_h,"^192\.168\.182\.13[57]$")
```

It measures **bytes leaving an internal host toward something that is not an internal host** —
and it explicitly excludes `.137` as a destination. This transfer is internal-to-internal, from
`.137` to `.138`, which is exactly the shape the rule is built to ignore so that east-west
file copies do not drown it.

So the staging step is invisible by design, one hour before the exfiltration that the same rule
does catch. **An internal 6.59 MB transfer and a 15 MB upload to a C2 are the same operation in
two legs, and the rule sees the second.**

Nothing here is a defect to fix cheaply. A rule that alerted on internal multi-megabyte transfers
would fire on every legitimate file copy in the estate, and the lab has no baseline for what that
volume looks like — the benign window could not measure east-west traffic any more than it could
measure egress. It is recorded as a gap with a reason rather than as an owed fix.

### 4.4 Why the ends alerted and the middle did not

The three alerting steps share a property: each produced a **new** artefact that a rule keys on —
a service ticket for a user-held SPN, a handle to LSASS, a scheduled task, a large outbound
transfer. The two silent steps produced no new artefact. A TGT request and a WinRM session are
both ordinary Kerberos and ordinary remote management; what makes them malicious is the account,
the source and the sequence.

That is why both gaps need **context rather than signatures**: `SQLService` authenticating from a
workstation is only anomalous if something knows where `SQLService` belongs, and
SPIDERMAN reaching THEPUNISHER on 5985 is only anomalous if something knows there is no jump host.

Which is exactly what the undocumented rule in
[CASE-07](CASE-07-the-loudest-rule-is-not-in-the-repo.md) was reaching for with its
account-to-expected-host lookup — the right idea, attached to a rule that notified nobody.

## 5. Verdict

**Three true positives, no alerts, and the chain's two connecting steps are the unalerted ones.**

- Pass-the-Ticket: successful, no detection content anywhere, confirmed by namespace-wildcard
  search rather than assumed.
- WinRM pivot: detection content exists as Sigma, its logic matches 6 of 7 connections, and it is
  deployed nowhere that alerts.
- Collection: 6.59 MB internal, invisible by design, one leg before an exfiltration that alerts.

The column's other cells are about rules that fire imprecisely. This one is about the shape of
the coverage: **the estate detects acquisition and detects egress, and does not detect movement.**

## 6. What this changes

| Owed | Detail |
| ---- | ------ |
| A Pass-the-Ticket rule | `4768` for an SPN-holding account from anything but its service host. Needs the same account-to-host mapping the CASE-07 rule has |
| Deploy the WinRM Sigma rule, or record that it is not deployed | The matrix should not read "fires" for content nothing runs |
| Add `RSTO` to its `conn_state` list | A reset connection happened |
| Maintain `filter_approved_source`, or state that it is empty on purpose | The rule's own file says what an unmaintained list does to it |
| Nothing for the collection step | Recorded as a gap with a reason. An east-west volume rule needs a baseline this lab has never measured |

Held until after the hardening run, with one exception: **correcting the matrix's phase-7 wording
is not a rule change** and has been done.

**And the after-run gains a prediction.** AES enforcement should make the Pass-the-Ticket fail
outright — `Rubeus asktgt` with an RC4 key against a KDC that enforces AES has nothing to
negotiate. So this phase has two things to measure next time rather than one: whether a rule
catches the attempt, and whether the attempt still works.

## 7. What a reader should take from this

**A coverage matrix reads as a list and an attack is a path.** Every cell in this column can be
correct while the column still fails to say that the attacker crossed from one host to another
and nothing noticed. The ends of this chain are well covered; the middle, where it actually
moved, is not covered at all.

The transferable habit is to lay the alerts on a timeline next to the attack and look at the
gaps rather than the entries. Here the gaps were adjacent, consecutive, and both of the same kind
— the attacker spending what the previous step earned. That is not a coincidence of this lab.
Acquisition makes new artefacts and is easy to key on; use makes ordinary traffic, and needs to
be judged against what normal looks like for that account on that host.
