# Scenario 03 — Nmap Reconnaissance

| | |
|---|---|
| **MITRE ATT&CK** | T1046 (Network Service Discovery) / T1595 (Active Scanning) |
| **Attacker** | Kali — 192.168.56.10 |
| **Target** | Ubuntu — 192.168.56.20 |
| **Detection source** | Suricata (NIDS) on `enp0s3`, Emerging Threats ruleset |
| **Status** | ✅ Validated |

---

## 1. Attack

Reconnaissance is the first stage of most intrusions — mapping which hosts are
up and which services are exposed. From Kali, Nmap was run against the Ubuntu
target:

```bash
nmap -sS -T4 192.168.56.20      # SYN scan
nmap -A 192.168.56.20           # aggressive: version + OS + scripts
```

The aggressive scan (`-A`) sends real service probes, OS-fingerprinting packets,
and script traffic — far noisier than a bare SYN scan and far more likely to trip
network signatures.

> _Evidence: `evidence/scenario-03-nmap/attack-output.txt`_

---

## 2. Detection

This is the scenario that demonstrates **why a NIDS exists**. A port scan
generates almost **no host-side log** — the target OS does not record "someone
scanned me" — so Wazuh (host-based) is effectively blind to it. Suricata, reading
packets on the wire, is not:

- Suricata flagged the scan's **ICMP probes** (`SURICATA ICMPv4 unknown code`)
  and, where services responded, service-banner signatures from the Emerging
  Threats ruleset.
- Events are written to `/var/log/suricata/eve.json` and forwarded to the Wazuh
  manager by the agent, where Wazuh's built-in Suricata decoders surface them
  (base rule 86601 for Suricata alerts).

> _Evidence: `evidence/scenario-03-nmap/suricata-fast-log.txt`,
> `evidence/scenario-03-nmap/wazuh-suricata-alert.json`_

---

## 3. Triage

- **Source IP** — `192.168.56.10` probing a single target across many
  ports/services → classic reconnaissance.
- **Pattern** — ICMP sweeps plus TCP service probing in a short window is scanning
  behavior, not normal traffic.
- **Severity** — recon is pre-attack. On its own it is *informational-to-low*: it
  tells you someone is looking, not that they got in.

**Verdict:** Reconnaissance detected. Low immediate severity, but a meaningful
early-warning signal — especially valuable if the same source later escalates to
an exploit or brute force (the kind of correlation a SOC watches for).

---

## 4. Response

**Alert only — do not auto-block.** This is the deliberate counter-example to the
brute-force response:

- Scans are extremely common background noise; auto-blocking every scanner
  creates false positives and operational churn.
- A SYN/ICMP scan can carry a **spoofed source IP**. Auto-blocking on it can be
  weaponized — an attacker spoofs a scan "from" your own gateway or DNS to trick
  you into blocking critical infrastructure.

The correct response is to log, alert, and watch whether the same source
escalates. See [triage-methodology.md](../triage-methodology.md) and the response
table in the [README](../../README.md).

---

## 5. Lessons Learned

- **HIDS and NIDS see different things.** This scenario is invisible to Wazuh's
  host agents but obvious to Suricata — the clearest justification in the lab for
  running both (defense-in-depth).
- **Sensor placement determines visibility.** Suricata only sees traffic on the
  interface it monitors (`enp0s3`). Traffic on another path (e.g. the NAT adapter)
  is invisible to it. See [challenges-and-resolutions.md](../challenges-and-resolutions.md), item 1.
- **Spoofability drives response policy.** The fact that scan source IPs can be
  forged is *the* reason recon is alert-only while brute force is block-eligible.
