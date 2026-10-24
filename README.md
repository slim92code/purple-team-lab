# Purple Team Home Lab — Active Directory Detection Engineering

A self-built Active Directory lab (`MARVEL.LOCAL`) where each attacker technique is run,
detected, and then stress-tested for what the default tooling misses. Gaps get closed and
re-proven.

Detection-as-code lives at the repo root. Each lab iteration has its own folder.

Status: [v2](v2/) complete, [v3](v3/) complete, [v4](v4/) is a
[design document](v4/README.md) and not yet built.

## Detection-as-Code

| Asset | What it is |
| ----- | ---------- |
| [`detections/sigma/`](detections/sigma) | 12 vendor-agnostic Sigma rules: 9 host (v2), 3 network/Zeek (v3) |
| [`detections/wazuh/local_rules.xml`](detections/wazuh/local_rules.xml) | 5 Wazuh rules: LSASS detection, built-in false-positive tuning, scheduled-task gap |
| [`detections/splunk/purple_lab/`](detections/splunk/purple_lab) | Deployable Splunk app, 12 saved searches, CIM/TA-normalized |
| [`detections/attack_navigator_layer.json`](detections/attack_navigator_layer.json) | MITRE ATT&CK Navigator coverage layer |
| [`config/sysmonconfig.xml`](config/sysmonconfig.xml) | Sysmon config including the `NetworkConnect` gap fix |

## Lab iterations

| Version | Detection stack | Status |
| ------- | --------------- | ------ |
| [v2](v2/) | Sysmon + Splunk SIEM | Complete. [Playbooks and screenshots](v2/README.md) |
| [v3](v3/) | + Zeek/Suricata NDR, Wazuh EDR | Complete. [Summary](v3/README.md), [technical report (SR)](v3/Purple_Team_izvestaj_v3_SR.pdf) |
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
  a benign task; a Sysmon ingestion gap left the EDR blind on two of three hosts, one of them
  a DC whose own Sysmon log holds 43,683 events the agent never reads; and the built-in
  credential-access rule fired 32 times at level 12 with all 32 benign.

The custom rule written to close the second one bound to a Wazuh group that does not exist,
so it loaded, reported as coverage, and was discarded. `wazuh-analysisd -t` had been printing
the warning the whole time. The replacement rules are tuned against 935 real LSASS reads
sampled from the host, which took a draft that would have alerted 90 times (89 benign) down
to one. Each rule is verified by a targeted trigger, with two negative tests.

### v4 — planned, not yet built

[`v4/README.md`](v4/README.md) is a design document. It scopes a rebuild of the v3 stack on a
hardened baseline (advanced audit policy, credential protection, network-protocol hardening,
account and Kerberos policy, execution controls), after which the same kill chain is re-run
to produce a before/after detection-coverage matrix. The deliverable is a set of alert-triage
case files rather than an attack narrative.

The plan is committed before the work. The deliverable is a before/after comparison, so the
predictions and the residual-gap list have to be on record first.

---

Self-taught. Certs: TCM Security SOC 201, Detection Engineering for Beginners,
Practical Windows Forensics.
