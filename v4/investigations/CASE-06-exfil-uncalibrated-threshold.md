# CASE-06 — Exfiltration detected twice, and a Windows download that looks the same

| | |
| --- | --- |
| Alert | `Purple - Large Outbound Transfer` returns three rows. **Two are the attack, one is Windows Update.** |
| Fired | 6 Nov 2026 — 16:40, 17:20 and 17:30 buckets CET |
| Severity | High |
| MITRE | [T1041 — Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/) |
| Verdict | True positive on both transfers. One false positive from a threshold that was never calibrated, and cannot be yet. |
| Cell | [`#15` in the coverage matrix](../coverage-matrix.md) |

## 1. What the alert showed

```
| bucket _time span=10m
| stats sum(orig_bytes) as bytes_out dc(resp_h) as dests values(resp_p) as ports by _time orig_h
| where bytes_out > 10000000
```

| `_time` | orig_h | MB out | ports |
| ------- | ------ | ------ | ----- |
| 16:40 | `192.168.182.137` | 12.5 | 80, 137, 138, 443 |
| 17:20 | `192.168.182.137` | 14.3 | 80, 138, 443, **8080** |
| 17:30 | `fd15:…:336d:c973` | 66.8 | 136, 443, **8080**, 8081 |

Three rows, one host, two address families, inside fifty minutes. Two of them carry port 8080 and
one does not, which is the only thing visibly separating them — and `values(resp_p)` lists which
ports appeared without saying how the bytes divide, so that separation is a hint rather than a
finding.

This rule ships with `enableSched = 0`, so it was measured by running the search. An absent alert
would have meant nothing.

## 2. Questions

1. Which of these three are the exfiltration?
2. The 16:40 row has no 8080 and four ports including NetBIOS. What is it?
3. The rule excludes the lab's own telemetry. Did the exclusions work?
4. The IPv6 branch has never run against real traffic. Did it work?
5. Can the threshold be calibrated?

## 3. Queries

The rule, verbatim, over the window — the full text is in
[the matrix cell](../coverage-matrix.md).

The attribution query, which is what turns a row into a verdict:

```spl
index=main source="*conn.log*" NOT _raw="#*" earliest=-1d latest=now
| rex field=_raw "^(?P<ts>\S+)\t\S+\t(?P<orig_h>\S+)\t(?P<orig_p>\S+)\t(?P<resp_h>\S+)\t(?P<resp_p>\S+)\t(?P<proto>\S+)\t(?P<service>\S+)\t(?P<duration>\S+)\t(?P<orig_bytes>\S+)\t(?P<resp_bytes>\S+)"
| where orig_h="192.168.182.137" AND _time>=…16:40 AND _time<…16:50
| eval orig_bytes=if(orig_bytes="-",0,tonumber(orig_bytes))
| stats sum(orig_bytes) as bytes by resp_h resp_p service
| sort -bytes
```

## 4. Findings

### 4.1 Both exfiltrations fire, including the first real test of the IPv6 branch

The flows behind the two attack rows:

| `_time` | orig_h → resp_h | port | bytes |
| ------- | --------------- | ---- | ----- |
| 17:27:09 | `.137` → `192.168.182.133` | 8080 | 15,000,222 |
| 17:37:22 | `fd15:…:336d:c973` → `fd15:…:ba4a:4fe8` | 8081 | 15,000,229 |
| 17:37:37 | same | 8081 | 55,000,229 |

Three HTTP PUTs to the C2: 15 MB over IPv4, then 15 MB and 55 MB over IPv6. The 10-minute
bucketing sums the two IPv6 transfers into the 66.8 MB row.

**The IPv6 branch worked, and this is the first time it has been exercised against a real
transfer.** It was added in `485811a` on 3 November against no traffic at all, because the lab's
IPv6 path had never carried anything larger than a probe. A rule branch that has never matched
real data is an assumption; this one is now a measurement.

Two details worth keeping from the attacker side. The first IPv6 attempt went to port **8080** and
failed — *"Unable to connect"*, the listener being IPv4-only — before succeeding on 8081. And the
server's own response headers pin the clock: `Date: 16:27:16 GMT` against a Splunk `_time` of
`17:27:09`, exactly +1 hour, which is the independent confirmation that `_time` in this index is
CET and equals the time the attack happened.

### 4.2 The third row is Windows, and one destination accounts for all of it

| resp_h | port | service | bytes |
| ------ | ---- | ------- | ----- |
| `20.209.97.107` | 443 | ssl | **13,091,342** |
| `192.168.182.131` | 9997 | — | 2,573,830 |
| `4.208.165.242` | 443 | ssl | 24,278 |
| `192.168.182.255` | 137 | dns | 150 |

A single Microsoft address took 12.5 MB over two TLS flows, 8,409,958 and 4,205,343 bytes at
16:48:14 and 16:48:17. That is the whole row.

**False positive**, and precisely the one the rule's own description predicts: *"10 MB per 10
minutes was never calibrated against this estate's normal egress, so expect false positives from
Windows Update, OneDrive and browser traffic."* The rule is not malfunctioning. It is reporting
that a Windows service downloaded something, which is what a volume threshold set at 10 MB does.

**A hypothesis of mine that was wrong, recorded because the way it was wrong is instructive.** The
port list on that row includes NetBIOS 137 and 138, and I proposed that broadcast traffic was
inflating the total — a plausible mechanism, since broadcast inflates `dc(resp_h)` as well. The
attribution says port 137 contributed **150 bytes** against 13 MB. Wrong by four orders of
magnitude, and it would have stayed plausible indefinitely without the breakdown, because the
rule's own output shows ports and not their weights.

### 4.3 The telemetry exclusions work

2.57 MB went to the Splunk forwarder on `192.168.182.131:9997` inside that same bucket, and the
rule's sum is 12.48 MB — the Microsoft traffic alone. So
`NOT (resp_h="192.168.182.131" AND resp_p="9997")` did its job.

This is worth confirming rather than assuming, because the benign baseline's only firing rule was
this one and all four of its rows were the lab watching itself. The exclusions added afterwards
hold.

### 4.4 The threshold cannot be calibrated yet, and the reason is the same fault it is waiting on

The calibration belongs to step 8 of the build sequence — a second benign window measured **with
internet**, against real Windows Update, OneDrive and browser egress. That window does not exist,
because the guests cannot browse: a VMware NAT advertising an IPv6 ULA prefix with no route out,
plus lossy UDP/53 from the Windows hosts, [measured and
root-caused](../README.md) on 6 November and deliberately left unrepaired so the estate does not
change between the before and after columns.

So this cell is in an unusual position: **the rule and its fix are waiting on the same event.**
The threshold needs real egress to be calibrated against, and real egress is what step 8 restores.
Until then 10 MB per 10 minutes stands as a documented placeholder, and this false positive is
the evidence of what it costs rather than a defect to be fixed now.

The same measurement also explains why the benign baseline could not have priced it: during that
window the guests had no working egress at all, so `#15` was measured against telemetry traffic
only and returned four rows, every one of them the monitoring stack. Third rule in this column
with that property.

### 4.5 Suricata captured the file and said nothing about it

Measured independently, for the IPv4 transfer:

| event_type | dest | port |
| ---------- | ---- | ---- |
| `fileinfo` | `192.168.182.133` | 8080 |
| `flow` | `192.168.182.133` | 8080 |
| `http` | `192.168.182.133` | 8080 |

`fileinfo` means Suricata extracted metadata for the transferred object itself — stronger evidence
than a byte count, since it identifies *what* left rather than how much. And there is no
signature on it: this is stock Suricata with no custom rules, so the exfiltration is fully
recorded and entirely unalerted.

Visibility without a rule, in the layer best placed to say what was taken. Same shape as
[CASE-02](CASE-02-kerberos-enumeration.md), different phase.

## 5. Verdict

**Two true positives and one false positive, from a rule behaving exactly as documented.**

- Both exfiltrations fire, over both address families, and the IPv6 branch is now measured rather
  than assumed.
- The third row is a Windows service download, correctly identified, on a placeholder threshold.
- The exclusions work.
- Nothing here is a rule defect. The open item is a number that cannot be derived until the
  estate can reach the internet.

## 6. What this changes

| Owed | Detail |
| ---- | ------ |
| Calibrate the threshold | Step 8, against the second benign window. Blocked on the same internet fault that step 8 begins by fixing |
| Weight the port list, or drop it | `values(resp_p)` invites exactly the wrong inference — it is what made the broadcast hypothesis in 4.2 look reasonable |
| A Suricata signature, or a documented decision not to | `fileinfo` already identifies the object; nothing reads it |

**One risk recorded now rather than discovered later.** The firewall GPO's cell in the hardening
run rests on this rule going silent when the IPv6 SMB path is blocked. If step 8 raises this
threshold past the transfer the GPO is meant to stop, that cell stops meaning anything. The
coupling is [already noted in the plan](../README.md) and this case is where it becomes concrete:
the threshold and a hardening verdict are tied to the same number.

## 7. What a reader should take from this

**A volume rule's output cannot be triaged from its own output.** Three rows, one host, fifty
minutes — and deciding which are the attack took a per-destination breakdown that the rule does
not produce. `values(resp_p)` listed four ports on the false positive and the bytes were 99.99% on
one of them.

The transferable habit: **when a threshold rule fires, attribute the volume before judging the
row.** Not because the rule is untrustworthy, but because "12.5 MB from this host with these
ports" and "12.5 MB to one Microsoft address" are the same row and different incidents.
