# HUNT-02 — Can the beacon be separated from legitimate software by behaviour instead of a path allowlist?

| | |
| --- | --- |
| Hypothesis-driven | Starts from a claim, ends with a rule or a disproof. |
| Hunted | 7 Nov 2026, against the before-run window of 6 Nov |
| Outcome | **One signal proven, one disproven — and the disproven one is inverted.** |
| Opens from | [CASE-05](../investigations/CASE-05-c2-two-rules-one-host-each.md) |

## 1. Why this hunt, and a correction to the question

The [v4 plan](../README.md) framed this hunt as *"`Purple - C2 Beacon` ships unscheduled because
legitimate software beacons from `AppData` too"*. That was true on 24 October and is not true
now: the rule was given an allowlist in `485811a` on 3 November, scheduled, and
[it fired at 12:10](../coverage-matrix.md) on the before-run chain. The framing is stale and the
hunt is better for it.

What makes the question live is that **the allowlist has already failed once.**
[CASE-05](../investigations/CASE-05-c2-two-rules-one-host-each.md) found
`OneDrive\Update\OneDriveSetup.exe` firing the rule — a fourth OneDrive binary in a fourth
directory shape, not covered by the three allowlist entries, and absent from the benign window
because it is an installer that only runs when OneDrive updates itself.

So the hypothesis is not "can this rule be scheduled". It is: **is a beacon separable from
legitimate software by behaviour, rather than by a path allowlist that grows every time a vendor
adds a directory?**

Two candidate signals, both standard, both measurable on the same source.

| | Signal | Why it should work |
| --- | ------ | ------------------ |
| **S1** | **Interval regularity** — coefficient of variation of the gap between connections | The classic beacon metric. Implants call home on a timer; user-driven software does not |
| **S2** | **Destination cardinality** — connections per distinct destination | An implant talks to its controller. Cloud software talks to a CDN and a fleet of service endpoints |

Both are measured from Sysmon `EventCode=3`, because it is the only source that carries the
**process path** alongside the destination. Zeek has the flows and not the process; the CIM model
has the process and [drops the destination](../investigations/CASE-05-c2-two-rules-one-host-each.md).

## 2. S1 — interval regularity: **disproven, and inverted**

```spl
index=main sourcetype=XmlWinEventLog EventCode=3 earliest=-1d latest=now
| sort 0 _time
| streamstats current=f last(_time) as prev by Image
| eval gap=_time-prev
| where gap > 0 AND gap < 3600
| stats count avg(gap) as mean_gap stdev(gap) as jitter by Image
| eval cv=round(jitter/mean_gap,2)
| sort cv
```

| Image | n | mean gap | jitter | **CV** |
| ----- | - | -------- | ------ | ------ |
| `OneDrive\OneDrive.exe` | 39 | 1484.8 s | 668.6 | **0.45** |
| **`C:\Temp\GlobalProtect_Update.exe`** | 10 | **30.0 s** | 23.9 | **0.79** |
| `OneDrive\…\OneDrive.Sync.Service.exe` | 56 | 1018.9 s | 880.5 | 0.86 |
| `OneDrive\…\OneDrive.Sync.Service.exe` | 58 | 977.4 s | 858.7 | 0.88 |
| `OneDriveStandaloneUpdater.exe` | 2 | 146.7 s | 206.6 | 1.41 |
| `nslookup.exe` | 13 | 8.5 s | 12.5 | 1.46 |
| `powershell.exe` | 14 | 398.4 s | 683.2 | 1.72 |

**The implant is not the most regular process on the estate. `OneDrive.exe` is.**

A rule keyed on "lowest coefficient of variation" would rank OneDrive above the beacon. This is
not a weak signal — it is **pointing the wrong way**, and a threshold set anywhere that catches
the beacon at 0.79 also catches OneDrive at 0.45.

**Why, and whether it generalises.** Sliver's jitter is doing exactly what it is for: a 30-second
callback with 23.9 seconds of standard deviation is 79% variation, which is deliberately
indistinguishable from irregular. Meanwhile OneDrive polls on a timer with modest variation
because it is a sync client, not because anyone is hiding. **Jitter is a configuration option for
the attacker and a side effect for the vendor**, so this ordering is not an accident of this lab —
it is what happens whenever the implant is configured by someone who has read the same detection
literature.

**One derived signal does separate them, and it is weaker than it looks.** The mean gap is 30
seconds against 977–1485 for the OneDrive processes — a factor of thirty. So **period**
discriminates here where **regularity** does not. But period is equally attacker-controlled: an
implant set to call home hourly would sit inside the OneDrive range and nothing about this
measurement would catch it. Recorded as a usable signal on this estate and a fragile one in
general.

## 3. S2 — destination cardinality: **proven, conditional on the path filter**

```spl
index=main sourcetype=XmlWinEventLog EventCode=3 earliest=-1d latest=now
| stats count dc(DestinationIp) as dests values(DestinationPort) as ports by Image
| eval conns_per_dest=round(count/dests,1)
| sort -conns_per_dest
```

| Image | conns | dests | ports | **conns/dest** |
| ----- | ----- | ----- | ----- | -------------- |
| `C:\Windows\system32\nslookup.exe` | 14 | 1 | 53 | **14.0** |
| **`C:\Temp\GlobalProtect_Update.exe`** | 12 | **1** | 443 | **12.0** |
| `powershell.exe` | 22 | 6 | 53, 80, 443, 5985, 8080, 8081 | 3.7 |
| `OneDrive\…\OneDrive.Sync.Service.exe` | 57 | 24 | 80, 443 | 2.4 |
| `OneDrive\…\OneDrive.Sync.Service.exe` | 59 | 27 | 80, 443 | 2.2 |
| `OneDriveStandaloneUpdater.exe` | 2 | 1 | 443 | 2.0 |
| `OneDrive\OneDrive.exe` | 40 | 25 | 80, 443 | 1.6 |
| `OneDriveStandaloneUpdater.exe` | 5 | 5 | 443 | 1.0 |

**The beacon talks to exactly one address, twelve times. Every OneDrive process talks to
twenty-four to twenty-seven.** That is the separation: 12.0 against 1.6–2.4, a factor of five
with nothing in between.

It also explains itself. An implant has one controller. Cloud sync software resolves to a CDN and
a fleet of regional service endpoints, and gets a different address almost every time — which is
why `dc(DestinationIp)` tracks its connection count closely and the ratio stays near 1.

**The honest caveat: the beacon is second, not first.** `nslookup.exe` ranks above it, legitimately
— a DNS client talking to one resolver fourteen times is exactly the same shape.

**And that caveat is already handled, by the rule this hunt is about.** `#2` restricts to
user-writable paths — `\Temp\`, `\AppData\`, `\ProgramData\`, `\Users\Public\` — which removes
`nslookup.exe` from `System32` and every other system binary with a single service destination.
**Within the population the rule already looks at, the discriminator is clean.** The signal works
not instead of the path filter but because of it.

## 4. Findings

| | Result | Value |
| --- | ------ | ----- |
| S1 — interval regularity | **disproven, inverted** | OneDrive is more regular than the implant. Do not build on CV |
| S1b — mean period | separates here, 30 s vs ~1000 s | Usable on this estate, attacker-controlled in general |
| S2 — connections per destination | **proven**, 12.0 vs 1.6–2.4 | A rule, and it replaces a growing allowlist with a measured property |

**The most useful result is the disproof.** Interval regularity is the signal most beacon-detection
content reaches for first, and on this estate it would rank a Microsoft sync client above a live
C2 implant. A team that built it would get a false positive on OneDrive and a false sense of
coverage on the beacon — the worst available combination, and it would survive review because the
method is textbook.

**And S2 would have caught the allowlist leak for free.** `OneDriveSetup.exe` — the binary that
fired the rule in `CASE-05` because no allowlist entry covered it — is an installer that makes a
handful of connections to a CDN. Its `conns_per_dest` is low by construction. A behavioural
condition would have excluded it without anyone noticing it existed, which is the whole argument
against maintaining a list of vendor directories by hand.

This is a prediction rather than a measurement: `OneDriveSetup.exe` ran on 2 November and is
outside this window, so its ratio was not measured here. It is named as the test the
recommendation has to pass.

## 5. Recommendation

**Add a behavioural condition to `#2`, after the hardening run, and stop extending the allowlist.**

```
Keep:     the user-writable path filter — it is what makes the ratio meaningful
Add:      dc(dest) and count per Image per window, with count/dc(dest) >= 5
Measured: beacon 12.0 | OneDrive family 1.6–2.4 | threshold 5 sits in the gap
Drop:     nothing yet — run the allowlist and the ratio together for one cycle
```

Three conditions on that, each from the measurements above:

1. **Do not key on interval regularity.** It is inverted on this estate and the reason it is
   inverted — jitter is a setting for the attacker and an accident for the vendor — is not
   specific to this lab.
2. **Keep the path filter.** The ratio only discriminates inside a population that excludes system
   binaries talking to one service. Without it, `nslookup` outranks the implant.
3. **Validate against `OneDriveSetup.exe` specifically**, since it is the known allowlist leak and
   the claim is that behaviour excludes it where a path list did not.

**Not implemented now.** New detection logic between the before and after columns changes what the
after column measures. The allowlist entry `CASE-05` owes is the stopgap; this is the replacement
for it, and both wait for step 8.

**One measurement this hunt could not make.** Bytes-out to bytes-in ratio was the third candidate
signal and was dropped: Sysmon `EventCode=3` carries no byte counts, and the source that does —
Zeek `conn.log` — carries no process path. Correlating them per connection is possible and was
not attempted, so the signal is untested rather than disproven. Recorded so it is not mistaken
for a dead end.
