# CASE-06 — Scheduled task persistence, scored the same as OneDrive

| | |
| --- | --- |
| Alert | Windows `4698`, Wazuh rule `60228` at **level 4** |
| Fired | 20 Oct 2026 |
| Severity | Reported as low. Actually critical. |
| MITRE | [T1053.005 — Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) |
| Verdict | True positive that arrived looking like routine noise. |
| Handed from | [CASE-05](CASE-05-lsass-access.md) |

## 1. What the alert showed

A scheduled task named `\Updater` created on THEPUNISHER, running

```
powershell.exe -WindowStyle Hidden -c IEX(... update.ps1)
```

![Persistence 4698](../screenshots/08_persistence_updater_4698.png)

Wazuh scored it **level 4**, which is the same score it gave a benign
`\OneDrive Standalone Update Task` on the same host, from the same rule.

![The rule gap](../screenshots/13_wazuh_rule_gap_60228.png)

## 2. Questions

1. What does the task actually run, and is that in the event?
2. Who created it and under which principal does it run?
3. Why is a download cradle scored the same as a OneDrive updater?
4. Are there other tasks on this host or the others with the same shape?

## 3. Queries

```spl
index=main source="WinEventLog:Security" EventCode=4698
| rex "<Command>(?<task_command>[^<]+)</Command>"
| rex "<UserId>(?<task_runas>[^<]+)</UserId>"
| table _time, host, Account_Name, Task_Name, task_command, task_runas
```

What Wazuh did with the same event:

```bash
sudo zcat /var/ossec/logs/alerts/*/*/*.json.gz | grep '"id":"60228"' \
| python3 -c "
import sys, json
for line in sys.stdin:
    try: d = json.loads(line)
    except Exception: continue
    e = d.get('data', {}).get('win', {}).get('eventdata', {})
    print(d['rule']['level'], e.get('taskName'))
"
```

Sweep for the same pattern elsewhere:

```spl
index=main source="WinEventLog:Security" EventCode=4698
| rex "<Command>(?<task_command>[^<]+)</Command>"
| search task_command="*IEX*" OR task_command="*DownloadString*" OR task_command="*hidden*"
| stats values(Task_Name) by host
```

## 4. Findings

| | |
| --- | --- |
| Task name | `\Updater` |
| Command | `powershell.exe -WindowStyle Hidden -c IEX(...)` |
| Runs as | SYSTEM |
| Trigger | at logon |
| Wazuh rule | `60228`, level 4 |
| Same rule and level fired for | `\OneDrive Standalone Update Task` |

**The content is in the event and nothing reads it.** `60228` alerts on the fact that a task
was created. The task definition, including the full command line, arrives in the
`taskContent` field. Nothing scores it. A hidden-window PowerShell download cradle and a
Microsoft updater are indistinguishable to the rule, so they are indistinguishable in the
alert queue.

**Level 4 is below where anyone looks.** This is the practical failure. The event was
received, parsed and alerted. An analyst working a queue sorted by severity would never
reach it, and if they did they would see a routine task-creation notice.

**`taskContent` arrives HTML-escaped**, so the angle brackets of the task XML are encoded
while the command text inside is not. Patterns have to key on command tokens rather than on
XML structure.

## 5. Verdict

True positive. SYSTEM-level persistence with a download cradle, delivered into the queue at
the same severity as a OneDrive update.

This is a different failure from CASE-05. There the telemetry never arrived or the rule
could not load. Here everything worked and the output was still useless, because scoring
creation without scoring content throws away the only part that distinguishes the two.

## 6. The fix, and what it took to prove it

Rules `100210` and `100211` in
[`detections/wazuh/local_rules.xml`](../../detections/wazuh/local_rules.xml) read the task
definition and re-score it.

| Rule | Matches | Level |
| ---- | ------- | ----- |
| `100210` | `IEX`, `Invoke-Expression`, `DownloadString`, `DownloadFile`, `Net.WebClient`, `FromBase64String` | 12 |
| `100211` | `-enc`, `-EncodedCommand`, `-w hidden`, `-WindowStyle Hidden`, `-nop`, `-NoProfile` | 10 |

Verified by targeted trigger on 24 Oct 2026, times UTC:

| Trigger | Result |
| ------- | ------ |
| Task with `IEX` + `DownloadString` | `100210`, **level 12**, 11:48:57 |
| Task with `-nop -w hidden -enc` | `100211`, **level 10**, 11:49:04 |
| Task running `defrag.exe C: /O` | stays `60228`, level 4 |
| Task running `powershell.exe -ExecutionPolicy Bypass -File ...` | stays `60228`, level 4 |

The second negative test is the one that matters. A scheduled task that legitimately runs
PowerShell with `-ExecutionPolicy Bypass` is the realistic false positive for these rules,
and neither fired on it. Writing a rule that alerts is easy. Writing one that stays quiet
when it should is the part worth testing.

Unlike the LSASS rules, these work on all three hosts, because `4698` arrives over the
Security channel and every agent reads it.

## 7. Recommendations

Containment:

1. Remove `\Updater` from THEPUNISHER after preserving the task XML as evidence.
2. Enumerate scheduled tasks on all three hosts and compare against a known-good list.
3. The task runs as SYSTEM at logon, so assume it executed at least once.

Detection tuning:

4. Deploy `100210` and `100211`. Run `wazuh-analysisd -t` first and confirm it prints no
   warning.
5. Keep `60228` as the parent rather than replacing it, so routine task creation is still
   recorded at level 4 for hunting.
6. Add the same content scoring to the Splunk side, where the shipped rule already parses
   the task XML out of the `4698` body.

Hardening:

7. Restrict who can create scheduled tasks that run as SYSTEM.
8. PowerShell script-block logging gives a second, independent view of what the cradle
   downloads, which the task definition alone does not show.
9. Application allowlisting would stop the cradle regardless of how the task is scored.
