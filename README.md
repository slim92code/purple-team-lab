# Purple Team Home Lab — Active Directory Detection Engineering

A self-built Active Directory lab (`MARVEL.LOCAL`) where each attacker technique is run,
detected, and then stress-tested for what the default tooling misses. Gaps get closed and
re-proven.

Detection-as-code lives at the repo root. Each lab iteration has its own folder.

Status: [v2](v2/) complete, [v3](v3/) complete, [v4](v4/) is a
[design document](v4/README.md) and not yet built.

**On the commit history.** The work came first and the repository second. The v2 detections
are dated January 2026 and the v3 kill chain was run on 20 October 2026. This repository was
created in June 2026 but the files were only uploaded that October, so the history begins at
that import rather than at the lab, and the first bulk commit is it. Everything after it is
ordinary work, including the corrections, which are kept rather than squashed because several
of them are the point.

A [ten-part video walkthrough](https://www.youtube.com/playlist?list=PLL1zKaMLDyG24fX3g8Ck42y_e6nPrRU4-)
covers the v2 chain end to end.

## Detection-as-Code

| Asset | What it is |
| ----- | ---------- |
| [`detections/sigma/`](detections/sigma) | 13 vendor-agnostic Sigma rules: 10 host, 3 network/Zeek |
| [`detections/wazuh/local_rules.xml`](detections/wazuh/local_rules.xml) | 5 Wazuh rules: LSASS detection, built-in false-positive tuning, scheduled-task gap |
| [`detections/splunk/purple_lab/`](detections/splunk/purple_lab) | Deployable Splunk app, 16 saved searches, 11 scheduled; 13 run on raw sourcetypes (11 Windows, 2 Zeek), 2 on CIM data models, 1 watches the collection pipeline itself ([one of which this lab's forwarder cannot populate](detections/README.md)) |
| [`detections/attack_navigator_layer.json`](detections/attack_navigator_layer.json) | MITRE ATT&CK Navigator coverage layer, 15 techniques across v2 and v3 |
| [`config/`](config/) | Sysmon config including the `NetworkConnect` gap fix, and what the hosts actually run |

## Lab iterations

| Version | Detection stack | Status |
| ------- | --------------- | ------ |
| [v2](v2/) | Sysmon + Splunk SIEM | Complete. [Playbooks and screenshots](v2/README.md) |
| [v3](v3/) | + Zeek/Suricata NDR, Wazuh EDR | Complete. [Summary](v3/README.md), [technical report, 32 pp. (EN)](v3/Purple_Team_Report_v3_EN.pdf) |
| [v4](v4/) | v3 stack on a hardened, CIS-aligned baseline | Planned. [Design document](v4/README.md), not yet built |

### v2 — baseline

Domain controller plus two domain-joined Windows 10 endpoints. Sysmon and a Splunk Universal
Forwarder on each host, audit policy enforced via GPO. Eight-phase kill chain with Defender
enabled throughout.

Main finding: default Sysmon did not log `NetworkConnect` for a bare `C:\Temp`, so a C2
beacon from that path went unrecorded. Closed with a behavioral detection keyed on process
location rather than filename.

### v3 — network and host detection layers

Zeek + Suricata for network detection and Wazuh for host EDR, added on top of the v2 stack.
The kill chain was re-run and each phase checked against all five sources.

Findings:

- Zeek recorded a spray attempt the Windows log never did, because an unknown-principal
  attempt produces no `4771`.
- One JA4 TLS fingerprint linked Sliver C2 beacons across both endpoints.
- Three separate Wazuh problems: scheduled-task creation scored the same for a malicious and
  a benign task; a Sysmon ingestion gap left the EDR blind on two of three hosts (since
  closed), one of them
  a DC whose own Sysmon log holds 43,683 events the agent never reads; and the built-in
  credential-access rule fired 32 times at level 12 with all 32 benign.

The custom rule written to close the second one bound to a Wazuh group that does not exist,
so it loaded, reported as coverage, and was discarded. `wazuh-analysisd -t` had been printing
the warning the whole time. The replacement rules are tuned against 935 real LSASS reads
sampled from the host, which took a draft that would have alerted 90 times (89 benign) down
to one. Each rule is verified by a targeted trigger, with two negative tests.

Auditing the repo afterwards turned up three more of the same shape, this time in the
shipped content rather than in the lab:

- The [Sysmon config](config/) here shipped `ProcessAccess` as an empty `include`, which logs
  nothing. The host that produced the LSASS evidence was the one that had been hand-edited;
  the host documented as a blind spot was running this baseline correctly.
- The [Zeek Kerberoasting rule](detections/sigma/v3_ndr.yml) excluded machine accounts with
  `endswith: '$'`, but Zeek writes `THEPUNISHER$/MARVEL.LOCAL`, so the filter never matched.
  The field format was visible in a screenshot already in the write-up.
- The Splunk app's `props.conf` was keyed on a sourcetype this lab's forwarder never emits,
  so the timestamp fix it documents was never applied.

All three are fixed and described where they happened. None were found by reading the rule.

Seven [alert-triage case files](v3/investigations/) cover the chain phase by phase: the
alert, the questions asked, the queries run, the verdict, and the tuning that follows. Three
of them are about detections that did not work.

### v4 — planned, not yet built

[`v4/README.md`](v4/README.md) is a design document. It scopes a rebuild of the v3 stack on a
hardened baseline (advanced audit policy, credential protection, network-protocol hardening,
account and Kerberos policy, execution controls), after which the same kill chain is re-run
to produce a before/after detection-coverage matrix. The deliverable is a set of alert-triage
case files rather than an attack narrative.

The plan is committed before the work. The deliverable is a before/after comparison, so the
predictions and the residual-gap list have to be on record first.

---

Stevan Mrkšić, self-taught, Belgrade. [LinkedIn](https://www.linkedin.com/in/stevan92mrksic/)

**Training, all TCM Security.** Completed: SOC 101, SOC 201, Detection Engineering for
Beginners, Practical Windows Forensics, Practical Ethical Hacking. In progress: Practical
Malware Analysis and Triage.
