# CASE-07 — The loudest rule on the instance is in nobody's inventory, and notifies nobody

| | |
| --- | --- |
| Alert | 28 firings in seven days, from a rule that is in no file in this repository. |
| Found | 7 Nov 2026, while measuring a different phase |
| Severity | High as a process finding. The rule itself detects nothing an analyst receives. |
| MITRE | n/a — this is a detection-engineering case, not an attack |
| Verdict | Coverage that reports to nobody, invisible to every inventory, depending on data outside version control. |
| Related | [the alert-history section of the matrix](../coverage-matrix.md) |

## 1. Where this case starts

With a question about something else.

[CASE-03](CASE-03-rc4-wrong-message-type.md) established that Pass-the-Ticket has no shipped
detection. Before writing that down as a gap, one check remained: v3 recorded a rule called
`V3 - Pass-the-Ticket EC4768` as *"scheduled, running, and absent from every listing made from
the admin account"* — a saved search in a private namespace, invisible to inventory. If it still
existed, "no coverage" would be false.

The query to settle it uses a namespace wildcard, which is the whole lesson of that v3 finding:

```spl
| rest /servicesNS/-/-/saved/searches splunk_server=local
| search title="*Pass-the-Ticket*" OR title="*4768*" OR search="*4768*"
| table title eai:acl.owner eai:acl.app eai:acl.sharing disabled cron_schedule
```

The PtT rule is gone — deleted sometime after v3, present nowhere. **CASE-03's gap is confirmed.**

What the wider version of that query returned instead is this case.

## 2. Questions

1. How much detection content exists on this instance outside the shipped app?
2. How much of it actually runs?
3. Could any of it have fired on the chain, and would that change a cell in the matrix?
4. Has anything been firing that nobody has seen?

## 3. Queries

Everything outside `purple_lab` that is not a Splunk built-in:

```spl
| rest /servicesNS/-/-/saved/searches splunk_server=local
| search eai:acl.app="search" NOT eai:acl.owner="nobody"
| table title eai:acl.owner eai:acl.sharing disabled is_scheduled cron_schedule actions
| sort -is_scheduled title
```

The alert history, which no measurement in this project had read:

```spl
index=_audit action=alert_fired earliest=-7d latest=now
| stats count min(_time) as first max(_time) as last by ss_name
| sort -count
```

And the triggered-alert list, twice — once the way that fails:

```spl
| rest /services/alerts/fired_alerts splunk_server=local
| rest /servicesNS/-/-/alerts/fired_alerts splunk_server=local
```

## 4. Findings

### 4.1 Twenty-three searches outside the app, twenty-two of them inert

They are named like detections: `LSASS Access — notepad.exe injection`,
`C2 Injection — Sliver notepad.exe`, `Sliver C2 — JA4 Fingerprint Detection`,
`Kerberoasting - Network Layer Detection`, `Privilege Escalation: Domain Admins Group
Modification`, `V3 - Kerberoasting SQLService`, and seventeen more.

| State | Count | Effect |
| ----- | ----- | ------ |
| enabled **and** scheduled | **1** | runs |
| scheduled but `disabled=1` | 6 | never runs |
| enabled but `is_scheduled=0` | 16 | saved queries, not detections |

**An inventory that counted titles would report 38 detections where 16 run.** The names are the
names of real techniques, several duplicate shipped rules, and reading the list says nothing
about whether anything fires. Counting rules is not measuring coverage — which is the same
mistake, in a different form, that the v3 Wazuh rule made when it loaded into a group that did
not exist and reported as coverage anyway.

### 4.2 This resolves a worry rather than creating one

`LSASS Access — notepad.exe injection` and `C2 Injection — Sliver notepad.exe` describe exactly
what `#10` measured on 6 November: `notepad.exe` opening LSASS with `0x1f3fff`. Had either been
scheduled, a cell recorded as "fires via `#10`" might have been firing from content that is not
in this repository, and the matrix would have been crediting the wrong rule.

Neither is scheduled. **The cells stand**, and they stand because this was checked rather than
assumed.

### 4.3 One rule runs, and it is the noisiest thing on the estate

```
index=* EventCode=4769
| eval src=replace(Client_Address, "::ffff:", "")
| where NOT match(Service_Name, "\$$") AND Service_Name!="krbtgt" AND src!="::1"
| lookup userhost Account_Name OUTPUT expected_ip
| lookup enc_types enc_code AS Ticket_Encryption_Type OUTPUT enc_name, risk
| eval anomaly=if(isnull(expected_ip), "NOT IN LOOKUP", if(src!=expected_ip, "HIGH", "OK"))
| where anomaly!="OK"
```

`Kerberoasting Detection - TGS Source Anomaly`. Owner `admin`, sharing `user`, hourly,
`alert_threshold = 0` with `greater than`, `alert.track` on, **`actions` empty**.

| `ss_name` | fired, 7 days |
| --------- | ------------- |
| **`Kerberoasting Detection - TGS Source Anomaly`** | **28** |
| every rule in `purple_lab` combined | 8 |

Twenty-eight against eight. The loudest rule on this instance is the one that appears in no
inventory, no repository and no coverage matrix.

### 4.4 Its design is better than the shipped rule's, in one real way

`Purple - Kerberoasting User-SPN Ticket` (`#4`) carries its allowlist inside the search text — a
hard-coded principal, SPN and two source addresses:

```
| where NOT (Account_Name="tstark@MARVEL.LOCAL" AND Service_Name="SQLService"
      AND (Client_Address="::ffff:192.168.182.137" OR Client_Address="::ffff:192.168.182.138"))
```

The undocumented rule uses a lookup mapping accounts to expected source hosts. That generalises
past three users, needs no search edit to add one, and keeps the policy out of the detection
logic. **It is arguably the design `#4` should have had**, and recording that is the point of
reading other people's rules rather than only counting them.

### 4.5 And three properties together make it worse than no rule

**The `NOT IN LOOKUP` branch fires on every account the table does not cover.** So its alert
volume is a function of a lookup's completeness rather than of anything an attacker did. An
incomplete `userhost` table turns legitimate authentication into alerts, continuously.

**The threshold is zero**, so a single row triggers. There is no burst requirement, no distinct
count, nothing separating one unexpected source from a pattern.

**`actions` is empty.** It runs hourly, tracks its firings, and sends nothing — no email, no
webhook, no notification of any kind. Twenty-eight alerts went into a list and reached nobody.

That is the v3 Wazuh pattern precisely — *it loaded, reported as coverage, and was discarded* —
with the difference that this one leaves a measurable trail. The trail says it has been firing
every few hours for a week.

**And it cannot be adopted as it stands.** It depends on two lookups, `userhost` and `enc_types`,
which exist on the instance and in no file here. Transcribed into the app it would return nothing
at all, and nothing in this repository records that those tables are part of the estate's
detection logic.

### 4.6 The alert history confirms the whole before-run column

Worth separating from the rest, because it is the one piece of good news.

| Attack | Time | Rule | Alert fired |
| ------ | ---- | ---- | ----------- |
| Roast | 11:48:12 | `#4` | 11:50 |
| C2 beacon | 12:04–12:09 | `#14` and `#2` | 12:10, both |
| LSASS read | 17:06:07 | `#10` | 17:10 |
| Scheduled task | 17:19:10 | `#9` | 17:20 |

Every cell recorded as `✓ fires` by re-running a search has a corresponding triggered alert in
the next scheduling cycle. **Two independent methods, no disagreement.** That was not guaranteed
— the whole column was measured one way, and this is the first time the other way was asked.

### 4.7 `Purple - Spray Success` fired twice, which settles a hedge in CASE-01

11:40 is the attack. **09:40 is the clock-skew false positive.**

[CASE-01](CASE-01-password-spray-undercount.md) describes that row as a shape the rule *cannot
distinguish* from a spray followed by a success. The history upgrades it: the alert was
**delivered**. This estate sent a password-spray alert for ordinary authentication that failed on
time drift, ninety minutes before the real one, and the only reason it is known is that nobody
was reading either.

### 4.8 The same trap caught this investigation

`| rest /services/alerts/fired_alerts` returned **zero rows**. `| rest
/servicesNS/-/-/alerts/fired_alerts` returned **nine**. Same endpoint, same instance; `/services/`
resolves in the caller's namespace and the rule lives in another user's.

The `/servicesNS/-/-/` form was used correctly for `saved/searches` **one query earlier in this
same investigation**, and then not used here. Third reproduction of the v3 `| rest` finding,
during the investigation of that finding, by someone who had just written it down.

**One more row nearly became a bad reading.** The namespace-wildcard version returns an entry
with `title` of `-`, no owner, no app, and `triggered_alert_count = 17` — the largest number in
the table and visually identical to the rule rows. It is the aggregate: `9 + 2 + (6 × 1) = 17`.
The arithmetic is what established that.

The two counters then reconcile, and the gap is retention rather than disagreement:

| Source | Kerberoasting | `purple_lab` | Total |
| ------ | ------------- | ------------ | ----- |
| `_audit`, 7 days | 28 | 8 | 36 |
| `fired_alerts` | 9 | 8 | 17 |

Nineteen of the undocumented rule's firings have aged out of the triggered-alert list, which is
its own measure of how long it has been running unread.

## 5. Verdict

**The estate runs sixteen scheduled detections. This repository documents fifteen, and the
sixteenth is the one that fires most.**

- It is invisible to every inventory taken the ordinary way.
- It notifies nobody, so twenty-eight firings produced no response.
- It depends on lookup tables that are not in version control.
- Its core design idea is better than the shipped rule it duplicates.
- And none of the matrix's cells are wrong, because the twenty-two inert searches were checked
  rather than assumed.

## 6. What this changes

| Owed | Detail |
| ---- | ------ |
| Correct the matrix's scope sentence | "Fifteen attack-facing searches" is true of `purple_lab` and false of the estate. Already done |
| Decide on `Kerberoasting Detection - TGS Source Anomaly` | Adopt the lookup design into `#4`, or disable it. Running unread is the one option that should not continue |
| Commit `userhost` and `enc_types`, or drop the dependency | A rule whose logic lives in an uncommitted lookup is not reviewable and not portable |
| Set `actions`, or accept that nothing is an alert | Across `purple_lab` too: the pack ships trigger and throttle settings and [tells the reader to add their own notification action](../../detections/README.md). This case is what that costs |
| An inventory query that does not lie | `/servicesNS/-/-/`, filtered on `disabled=0 AND is_scheduled=1`, which is the only combination that means anything |

As with every other owed item in this column, the rule changes wait for step 8 — but **the
scope correction and the inventory query do not**, because neither alters what any detection does.

## 7. What a reader should take from this

**Three different ways of counting coverage all gave the wrong answer here**, and each failed
differently:

| Method | Reported | Actual |
| ------ | -------- | ------ |
| Reading `savedsearches.conf` | 15 attack-facing searches | 16 scheduled on the estate |
| Counting saved-search titles | 38 detections | 16 run |
| `\| rest /services/…` | 0 firings | 28 |

The only count that held was `disabled=0 AND is_scheduled=1` over a namespace wildcard, plus the
audit log. Everything else is a plausible number produced by a reasonable method.

And the transferable one, which is really this project's recurring theme in a new place: **a rule
that fires and notifies nobody is indistinguishable from a rule that does not exist, except in
the audit log.** The only reason this was found is that somebody finally read it — and the
immediate cause of reading it was a question about something else entirely.
