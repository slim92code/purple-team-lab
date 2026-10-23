# Purple Team Home Lab — Active Directory Detection Engineering

> A self-built Active Directory lab (`MARVEL.LOCAL`) where every attacker technique is
> executed, detected, stress-tested for what default tooling misses — and the gap is closed
> and re-proven. The loop a production detection-engineering team runs: attack, detect,
> find the gap, fix, re-prove.

**Detection-as-code lives at the repo root. Each lab iteration has its own folder.**

---

## Detection-as-Code

| Asset | What it is |
| ----- | ---------- |
| [`detections/sigma/`](detections/sigma) | 12 vendor-agnostic Sigma rules — 9 host (v2) + 3 network/Zeek (v3) |
| [`detections/wazuh/local_rules.xml`](detections/wazuh/local_rules.xml) | Wazuh custom rules fixing the v3 scheduled-task rule gap |
| [`detections/splunk/purple_lab/`](detections/splunk/purple_lab) | Deployable Splunk app — 12 saved searches, CIM/TA-normalized |
| [`detections/attack_navigator_layer.json`](detections/attack_navigator_layer.json) | MITRE ATT&CK Navigator coverage layer |
| [`config/sysmonconfig.xml`](config/sysmonconfig.xml) | Sysmon config including the `NetworkConnect` gap fix |

## Lab iterations

| Version | Detection stack | Status |
| ------- | --------------- | ------ |
| [**v2**](v2/) | Sysmon + Splunk SIEM | Documented — [playbooks and screenshots](v2/README.md) |
| [**v3**](v3/) | + Zeek/Suricata NDR, Wazuh EDR — 5 layers | [Technical report (SR)](v3/Purple_Team_izvestaj_v3_SR.pdf) |
| **v4** | v3 stack on a hardened, CIS-aligned baseline | In progress |

### v2 — baseline
Domain controller plus two domain-joined Windows 10 endpoints, Sysmon and a Splunk
Universal Forwarder on each host, audit policy enforced via GPO. Eight-phase kill chain
with Defender left enabled throughout. Headline finding: default Sysmon did not log
`NetworkConnect` for a bare `C:\Temp`, so a C2 beacon from that path went unrecorded —
closed with a behavioral detection keyed on process location rather than filename.

### v3 — network and host detection layers
Added Zeek + Suricata for network detection and Wazuh for host EDR on top of the v2
Splunk/Sysmon stack, taking the lab to five detection layers. The full kill chain was
re-run and each phase evaluated against all five. Findings include JA4 TLS fingerprinting
of C2 beacons across two endpoints, and two Wazuh coverage gaps — alerts not reaching
Splunk, and scheduled-task creation firing at the same severity for malicious and benign
tasks alike.

### v4 — in progress
Rebuild of the v3 stack on a hardened baseline: advanced audit policy, credential
protection, network-protocol hardening, account and Kerberos policy, and execution
controls. The same kill chain is then re-run to produce a before/after detection-coverage
matrix, with residual gaps recorded as a deliberate, documented risk register rather than
left implicit. The deliverable is a set of alert-triage case files — what the alert showed,
what was queried, the verdict, and the tuning recommendation — rather than an attack
narrative.

---

*Self-taught. Certs: TCM Security SOC 201, Detection Engineering for Beginners,
Practical Windows Forensics.*
