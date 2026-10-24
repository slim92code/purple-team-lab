# CASE-05 — LSASS access, and four layers of coverage that were not there

| | |
| --- | --- |
| Alert | Sysmon EID 10 in Splunk. **Wazuh produced no alert.** |
| Fired | 20 Oct 2026, after the 12:42 pivot |
| Severity | Critical |
| MITRE | [T1003.001 — LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) |
| Verdict | True positive on one host. Undetectable on another. |
| Handed from | [CASE-04](CASE-04-lateral-movement-winrm.md) |

## 1. What the alert showed

Sysmon EID 10 on THEPUNISHER: `notepad.exe` opening a handle to `lsass.exe` with
`GrantedAccess 0x1F3FFF`.

![LSASS EID 10](../screenshots/07_lsass_sysmon_ec10.png)

`notepad.exe` has no reason to read LSASS memory. The access mask is near-full, which is
what a memory dump needs rather than what a status query needs. The process name is a
disguise; SharpKatz was executed in memory through Sliver, inside a host process.

## 2. Questions

1. Which process really did this, and how did it come to be `notepad.exe`?
2. Is the access mask consistent with a dump or with normal inspection?
3. The EDR is deployed on this host. Why is there no EDR alert?
4. Would the same attack have been visible on the other endpoint?
5. What was recovered?

## 3. Queries

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
  TargetImage="*\\lsass.exe" SourceImage!="*\\MsMpEng.exe"
| table _time, host, SourceImage, GrantedAccess, CallTrace
```

Is the host capable of producing this event at all:

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=1 OR EventCode=10)
| stats count by host, EventCode
```

On the Wazuh manager, every LSASS alert it has ever recorded:

```bash
sudo zcat /var/ossec/logs/alerts/*/*/*.json.gz | grep 'sysmon_eid10_detections' \
| python3 -c "
import sys, json, collections
c = collections.Counter()
for line in sys.stdin:
    try: d = json.loads(line)
    except Exception: continue
    e = d.get('data', {}).get('win', {}).get('eventdata', {})
    c[(e.get('sourceImage'), e.get('grantedAccess'))] += 1
for (s, g), n in c.most_common(): print(n, g, s)
"
```

## 4. Findings

The attack was caught on one host by one source. Everything else that should have covered
it did not, for four different reasons.

### 4.1 The other endpoint cannot produce the event

| Host | Sysmon EID 1 | Sysmon EID 10 |
| ---- | ------------ | ------------- |
| THEPUNISHER | logging | 629 |
| SPIDERMAN | 1,191 | **0** |

SPIDERMAN's Sysmon is alive and forwarding. Its `ProcessAccess` section is
`onmatch: include` with no rule lines under it, so the include list matches nothing. Reading
`sysmon64 -c` on the host confirms it, and grouping 5,000 recent events by ID returns eleven
distinct IDs with no EID 10 among them.

The same dump on SPIDERMAN would have left no trace. Not a missed alert, no event.

![The blind spot](../screenshots/12_spiderman_lsass_blindspot.png)

Checked later, and it is worse than one host being misconfigured: the empty include is what
[`config/sysmonconfig.xml`](../../config/sysmonconfig.xml) shipped. SPIDERMAN was running the
repo's own baseline exactly as published. THEPUNISHER only had the event because someone had
added the `lsass` line on the host and never put it back in the file. Every rule in this case
file was written and tuned against a config that could not produce its input, and the one
host that worked was the accident.

### 4.2 The EDR never received the event

Wazuh is deployed on all three Windows hosts and reports healthy. Across every archived
alert file:

| Agent | Alerts | From Sysmon | EID 10 |
| ----- | ------ | ----------- | ------ |
| HYDRA-DC | 51,725 | 0 | 0 |
| SPIDERMAN | 22,782 | 0 | 0 |
| THEPUNISHER | 18,591 | 376 | 32 |

Only THEPUNISHER carries a `Microsoft-Windows-Sysmon/Operational` block in its `ossec.conf`.
The DC case is the sharpest: Sysmon is installed and running there and its own log holds
43,683 events that the agent never reads.

### 4.3 The EDR's own LSASS rule is a 100% false positive

Wazuh's built-in rule `92900` fires at **level 12** for LSASS access with read permissions.
All 32 EID 10 alerts it has ever produced here are benign:

| Source | Count | Masks |
| ------ | ----- | ----- |
| `MsMpEng.exe` (Defender) | 29 | `0x101000`, `0x1010` |
| `svchost.exe` | 2 | `0x101000` |
| `MRT.exe` | 1 | `0x101000` |

The reason is in the rule. `92900` filters `grantedAccess` to `0x1010` or `0x40`, which is
what Defender uses. `0x1F3FFF`, the mask used here, is not matched. The severity is
inverted: wrong every time on the benign mask, silent on the aggressive one. Confirmed by
trigger, a PowerShell `OpenProcess(lsass, PROCESS_ALL_ACCESS)` produced a Sysmon event and
no Wazuh alert.

### 4.4 The custom rule written to fix it could not load

A custom LSASS rule had been deployed against `<if_group>sysmon_event10</if_group>`. The
real group is `sysmon_event_10`, one underscore away. It alerted zero times, ever, and the
silence read as "no attack has been run since", which was also true. Wazuh had been
reporting the fault on every start:

```
wazuh-analysisd: WARNING: (7610): Group 'sysmon_event10' was not found.
Invalid 'if_group'. Rule '100200' will be ignored.
```

## 5. Verdict

True positive, and the most useful finding in the lab is not the detection but what sat
around it. A deployed EDR, a built-in rule at level 12, and a custom rule written
specifically for this technique, and none of the three would have told an analyst that
credentials were being read out of memory.

The dump recovered NTLM and SHA1 material, a cleartext `MARVEL\administrator` credential
and the `THEPUNISHER$` machine account.

![Credentials recovered](../attack/11_lsass_credentials_recovered.png)

## 6. What happened next

The attacker established persistence through a scheduled task. Handed off as
[CASE-06](CASE-06-persistence-scheduled-task.md).

## 7. Recommendations

Containment:

1. Treat `MARVEL\administrator` as compromised. Reset it and the `krbtgt` account twice,
   with the required interval between resets.
2. Reset the `THEPUNISHER$` machine account.
3. Rebuild both endpoints rather than cleaning them.

Detection tuning:

4. Replace `92900` as the LSASS signal. The rules in
   [`detections/wazuh/local_rules.xml`](../../detections/wazuh/local_rules.xml) key on
   dump-capable masks and suppress the platform processes measured on this baseline. `100205`
   hangs off `92900` directly so the 32-for-32 false positive stops as well.
5. Measure before shipping. A draft of the replacement that also matched `0x1010` and
   `0x1410` would have fired 90 times against 935 real reads sampled from this host, 89 of
   them benign, 79 from `WmiPrvSE.exe` alone.
6. Run `wazuh-analysisd -t` as part of deployment. A rule that cannot load reports as
   coverage.
7. `CallTrace` is the field that separates injected code in a signed process from the
   signed process itself. Not used here because the lab has no sample to test a pattern
   against, which is the honest reason rather than an oversight.

Hardening:

8. Enable LSA Protection (`RunAsPPL`) on both endpoints.
9. Add the `ProcessAccess` rule to SPIDERMAN's Sysmon config so the host stops being blind.
10. Add a Sysmon `localfile` block to the Wazuh agent on SPIDERMAN and HYDRA-DC. Three
    agents reporting is not three hosts covered.
