# Purple Team Home Lab — Active Directory Detection Engineering

> A self-built Active Directory lab (`MARVEL.LOCAL`) where every attacker technique is
> executed, detected, stress-tested for what default tooling misses — and the gap is closed
> and re-proven. The loop a production detection-engineering team runs: attack, detect,
> find the gap, fix, re-prove.

**Detection-as-code lives at the repo root. Each lab iteration has its own folder.**

**Lab status —** [**v2**](v2/) ✅ complete · [**v3**](v3/) ✅ complete · [**v4**](v4/) 🚧 planned,
[design document](v4/README.md) only, not yet built.

---

## Detection-as-Code

| Asset | What it is |
| ----- | ---------- |
| [`detections/sigma/`](detections/sigma) | 12 vendor-agnostic Sigma rules — 9 host (v2) + 3 network/Zeek (v3) |
| [`detections/wazuh/local_rules.xml`](detections/wazuh/local_rules.xml) | 5 Wazuh rules — LSASS detection, built-in false-positive tuning, scheduled-task gap |
| [`detections/splunk/purple_lab/`](detections/splunk/purple_lab) | Deployable Splunk app — 12 saved searches, CIM/TA-normalized |
| [`detections/attack_navigator_layer.json`](detections/attack_navigator_layer.json) | MITRE ATT&CK Navigator coverage layer |
| [`config/sysmonconfig.xml`](config/sysmonconfig.xml) | Sysmon config including the `NetworkConnect` gap fix |

## Lab iterations

| Version | Detection stack | Status |
| ------- | --------------- | ------ |
| [**v2**](v2/) | Sysmon + Splunk SIEM | ✅ **Complete** — [playbooks and screenshots](v2/README.md) |
| [**v3**](v3/) | + Zeek/Suricata NDR, Wazuh EDR — 5 layers | ✅ **Complete** — [summary](v3/README.md), [technical report (SR)](v3/Purple_Team_izvestaj_v3_SR.pdf) |
| [**v4**](v4/) | v3 stack on a hardened, CIS-aligned baseline | 🚧 **Planned** — [design document](v4/README.md), not yet built |

### v2 — baseline
Domain controller plus two domain-joined Windows 10 endpoints, Sysmon and a Splunk
Universal Forwarder on each host, audit policy enforced via GPO. Eight-phase kill chain
with Defender left enabled throughout. Headline finding: default Sysmon did not log
`NetworkConnect` for a bare `C:\Temp`, so a C2 beacon from that path went unrecorded —
closed with a behavioral detection keyed on process location rather than filename.

### v3 — network and host detection layers
Added Zeek + Suricata for network detection and Wazuh for host EDR on top of the v2
Splunk/Sysmon stack, taking the lab to five detection layers. The full kill chain was
re-run and each phase evaluated against all five. Findings include a spray attempt the
network layer caught that the endpoint log never recorded, JA4 TLS fingerprinting linking
C2 beacons across two endpoints, and three distinct Wazuh problems: scheduled-task creation
firing at the same severity for a malicious task and a benign one alike; a Sysmon ingestion
gap leaving the EDR blind on two of three hosts, including a DC whose own Sysmon log holds
43,683 events the agent never reads; and a built-in credential-access rule that fired 32
times at level 12 with all 32 benign. The custom rule written to close the second one bound
to a Wazuh rule group that does not exist, so it loaded, reported as coverage, and was
silently ignored — the engine had been warning about it the whole time. Replacement rules
are tuned against 935 real LSASS reads from the host, taking a draft that would have
alerted 90 times (89 benign) down to one, and each is verified by a targeted trigger with
two negative tests — including a scheduled task that legitimately runs PowerShell with
`-ExecutionPolicy Bypass`, which correctly does not fire.

### v4 — planned, not yet built
**[`v4/README.md`](v4/README.md) is a design document.** It scopes a rebuild of the v3 stack
on a hardened baseline — advanced audit policy, credential protection, network-protocol
hardening, account and Kerberos policy, execution controls — after which the same kill chain
is re-run to produce a before/after detection-coverage matrix. The deliverable is a set of
alert-triage case files rather than an attack narrative.

The plan is committed **before** the work because the deliverable is a before/after
comparison, and the residual gaps are named in advance so they read as a risk register
rather than as excuses written around whatever got through. v2 and v3 are the completed
labs; v4 is the next build.

---

*Self-taught. Certs: TCM Security SOC 201, Detection Engineering for Beginners,
Practical Windows Forensics.*
