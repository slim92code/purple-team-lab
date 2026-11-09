# CASE-09 — A catch-up alert for a three-day-old attack suppressed a live one

| | |
| --- | --- |
| Alert | Two fired at 14:50:46 on 9 November, for attacks that happened on **6 November**. |
| Consequence | The real attack two hours later matched the same rule and was **suppressed, three runs in a row.** |
| Severity | High. A detection was disabled for 24 hours by its own stale replay. |
| Verdict | Not a rule defect. A scheduler behaviour colliding with a throttle. |
| Found | 9 Nov 2026, during the bundle 1 control re-run |

## 1. Where this case starts

With a rule that matched and did not alert.

The [bundle 1 control re-run](../coverage-matrix.md) repeated the password spray at 16:34:48.
`Purple - Spray Success` returns a row for it when run by hand. The scheduled search then ran at
16:40, 16:50 and 17:00, succeeded every time, returned one result every time — and no alert was
recorded for any of them.

`scheduler.log` said why in one line, and the first reading of it was wrong:

```
result_count=1, alert_actions="", suppressed=1, fired=0, skipped=1
```

Throttled. The rule's suppression period is 24 hours, and its last recorded firing was
**6 November at 11:40** — three days earlier, long expired. So the throttle should not have been
armed, and working out what armed it is this case.

## 2. Questions

1. The throttle is active. What fired recently enough to arm it?
2. If something fired today, why is it not in the before-run's picture of this rule?
3. Is the suppression key working, or is it the empty-field defect suspected earlier?
4. Does this affect other rules?

## 3. Queries

Per-run detail for the rule, rather than the aggregate:

```spl
index=_internal sourcetype=scheduler savedsearch_name="Purple - Spray Success*" earliest=-24h latest=now
| table _time status result_count fired suppressed
| sort _time
```

The audit log, which records deliveries rather than matches:

```spl
index=_audit action=alert_fired earliest=-24h latest=now
| table _time ss_name
| sort _time
```

And the search ID of the run that fired, because it carries its own scheduled time:

```spl
index=_internal sourcetype=scheduler savedsearch_name="Purple - Spray Success*" earliest="11/09/2026:14:45:00" latest="11/09/2026:14:55:00"
| table _time sid result_count fired suppressed
```

## 4. Findings

### 4.1 Something did fire today, at 14:50:46

| `_time` | result_count | fired | suppressed |
| ------- | ------------ | ----- | ---------- |
| **14:50:46.965** | **2** | **2** | 0 |
| 14:50:49.302 | 0 | 0 | 0 |
| 15:00 – 16:30, every 10 min | 0 | 0 | 0 |
| **16:40, 16:50, 17:00** | 1 | **0** | **1** |

The audit log confirms the delivery:

```
14:50:46.967   Purple - Spray Success (4771 then 4768 same source)
14:50:46.992   Purple - LSASS Access (credential theft mask)
14:51:18.691   Purple - Wazuh Sensor Health (single-feed host)
```

So two attack rules fired within 25 milliseconds of each other at 14:50 — and the estate had
been reverted to a clean snapshot an hour earlier. **There was no attack at 14:50.** The spray
had not happened yet; it came at 16:34.

### 4.2 The search that fired cannot be reproduced, and the search ID says why

Running the rule verbatim over every plausible window returns nothing — not the twenty minutes
around 14:50, not the rule's own `-24h@h`, not with `index=main` and not without it. The raw
`4768` and `4771` events of that period do not satisfy it either: the busiest source, `.137`,
produces four events where the rule needs more than five.

The two search IDs resolve it:

| Executed | `sid` fragment | Scheduled for |
| -------- | -------------- | ------------- |
| 14:50:46 | `…_at_**1794013200**_7618` | **7 Nov 2026, 02:00** |
| 14:50:49 | `…_at_1794232200_7620` | 9 Nov 2026, 14:50 |

The first was **not a current run.** The `at_` component carries the slot the execution belongs
to, not the moment it ran, and that slot is two days in the past.

**The job's own results settle what it searched.** Because the alert fired, the dispatch
artifact is retained, and it can be read back directly rather than reconstructed:

```spl
| loadjob "scheduler__nobody_cHVycGxlX2xhYg__RMD56f21d888b74d0278_at_1794013200_7618"
| table _time src Account_Name eventcount
```

| `_time` | src | Accounts | eventcount |
| ------- | --- | -------- | ---------- |
| **2026-11-06 09:29:43** | `192.168.182.138` | Administrator, `SPIDERMAN$` | 10 |
| **2026-11-06 11:32:00** | `192.168.182.133` | Administrator, SQLService, fcastle, pparker, tstark | 19 |

Both rows are from **6 November**. For a 7 November 02:00 slot with
`dispatch.earliest_time = -24h@h`, the window is 6 Nov 02:00 to 7 Nov 02:00, and these are the
two transactions inside it — the before-run's spray at 11:32, and the clock-skew false positive
at 09:29 that [CASE-01](CASE-01-password-spray-undercount.md) records.

So the two alerts delivered at 14:50 today were **a replay of a true positive and a replay of a
false positive, both three days old.** `Purple - LSASS Access` fired in the same millisecond, its
own stale window containing the 6 November LSASS read.

### 4.2b The mechanism is not explained, and the setting that should prevent it is enabled

The obvious reading is a catch-up execution of a slot missed while the lab was powered off. The
configuration contradicts it:

```
/opt/splunk/etc/system/default/savedsearches.conf    realtime_schedule = 1
/opt/splunk/etc/system/default/savedsearches.conf    schedule_window = 0
```

`realtime_schedule = 1` is the effective value — nothing in the app overrides it — and under it
the scheduler is supposed to compute the next run from the current time and **skip** missed
slots rather than backfill them.

So what is established is the behaviour, not its cause:

| Established by measurement | Not established |
| -------------------------- | --------------- |
| A run executed at 14:50:46 on 9 Nov | Why a two-day-old slot executed at all |
| Its slot was 7 Nov 02:00 | Whether this is restart-specific, version-specific, or something else |
| It searched that slot's window and returned two 6 November rows | — |
| It delivered two alerts and armed the throttle | — |

That is worth stating plainly rather than papering over, because **it makes the finding worse,
not better.** "Backfill was enabled and replayed old alerts" is a configuration mistake with an
obvious fix. "Old alerts replayed while the setting that prevents backfill was enabled" is a
behaviour nobody would predict from reading the configuration, which is exactly the kind of thing
this lab exists to find. The cause is owed; the consequence below is not contingent on it.

### 4.3 The stale alert armed the throttle, and the live attack paid for it

`alert.suppress = 1`, `alert.suppress.period = 24h`.

| Time | Event |
| ---- | ----- |
| 14:50:46 | Catch-up fires on the **6 November** spray. Suppression armed until 9 Nov 14:50 **tomorrow** |
| 16:34:48 | The **real** spray runs |
| 16:40, 16:50, 17:00 | Rule matches, `suppressed=1`, `fired=0` |

**The detection was consumed by a replay of an attack it had already reported three days
earlier.** An analyst watching this estate received an alert at 14:50 for something historical,
with nothing in it to say so, and then received nothing at all for the live attack.

### 4.4 A correction: the empty throttle key is not the cause here

An earlier reading of this blamed `alert.suppress.fields = Client_Address` against a search whose
final line is `| table _time src Account_Name eventcount` — the field is renamed to `src` by an
`eval`, so the suppression key is empty and one global entry throttles every source instead of
one per attacker address.

**That defect is real and it is not what caused this.** The 6 November spray came from
`192.168.182.133`; today's spray came from `192.168.182.133`. With a correctly populated key the
suppression entry would have been keyed on that address, matched today's attack, and suppressed
it identically. The outcome is the same either way.

So the key remains an owed fix — a global throttle will hide a second attacker while a first is
suppressed — but the cause of this case is the collision between catch-up execution and
throttling, and attributing it to the key would have been a tidy wrong answer.

### 4.5 How widespread this is

Three rules delivered alerts at 14:50–14:51. Two of them are stale replays of the 6 November
chain. The third, `Purple - Wazuh Sensor Health`, fired at 14:51:18 and is legitimate — the
estate was coming up and the heartbeat was briefly absent, which is the condition that rule
exists to report.

Every scheduled `Purple` rule also shows exactly one `skipped` execution in the same 24 hours,
consistent with a single moment of scheduler saturation during the Splunk restart. One skip each
is not a problem. The catch-up behaviour is, because it is silent, it looks like a detection, and
it has a side effect that lasts a day.

## 5. Verdict

**Two false alerts and one missed real one, from a scheduler behaviour rather than a rule
defect.**

Every rule involved worked correctly. The searches matched what they were written to match. The
throttle did what throttles do. The failure is in the interaction:

- A lab that is powered off accumulates missed schedule slots.
- At least one was executed on restart against its **own historical window**, despite
  `realtime_schedule = 1`, which is supposed to prevent exactly that.
- The attacks inside that window re-alerted, with no marker distinguishing them from live events
  — one true positive and one false positive, both three days old.
- And the throttle they armed then blinded the rule for 24 hours.

For this lab the consequence is a measurement problem: a control re-run designed to confirm the
before column instead found that the column's `#6` verdict is not reproducible on the alerting
path. For a real estate the consequence is worse — **an outage is followed by a burst of stale
alerts, and the rules that fire them go deaf for a day, exactly when an attacker would most
expect monitoring to be degraded.**

## 6. What this changes

| Owed | Detail |
| ---- | ------ |
| **Find the cause** | `realtime_schedule = 1` should have prevented this. Until it is explained, no configuration change can be claimed to fix it — reproduce it on the next restart and watch `scheduler.log` while it happens |
| Mark or suppress historical results | Whatever the cause, a scheduled alert needs something that distinguishes "matched now" from "matched in a replayed window". The event timestamps are in the results; nothing reads them |
| `#6`'s throttle key | `Client_Address` is renamed to `src` before the `table`. Not the cause here, still wrong |
| Re-read `#6`'s before-run verdict | It is recorded as firing, and the search does fire. The alert path is not reproducible |

Held with everything else until after the hardening run, with one exception worth raising now:
**this will recur on every bundle.** The plan calls for a snapshot and a possible rollback per
bundle, and each restart produces another round of catch-up executions against windows that
contain the before-run. Every hardening column is at risk of both a stale alert burst and a
throttled real detection.

## 7. What a reader should take from this

**An alert's timestamp is when it was delivered, not when the thing happened.** Everything in
this case follows from that gap. The 14:50 alert was true — a spray really did occur from
`192.168.182.133` with those five accounts — and it was three days old, and nothing in the alert
said so.

Two habits fall out, and the second is the one that actually found this:

1. **After any monitoring outage, treat the first wave of alerts as suspect.** Check the event
   timestamps inside them, not the delivery time.
2. **When a rule matches and no alert arrives, read `scheduler.log` rather than inferring.** The
   `sid` carries the scheduled time, and in this case the difference between the scheduled time
   and the execution time *was* the whole answer. Four reconstruction attempts failed before
   anyone looked at the search ID.
