<!--
  README for the SOC home lab portfolio.
  Placeholders are marked with <<...>> — fill these in with your real values.
  Before publishing: redact cloud IPs, remove any credentials, add screenshots.
-->

# SOC Home Lab — Detection, Enrichment & Automated Response

> At 22:01 UTC, a brute-force run from the lab's Kali host locked out the Windows
> target's `Client` account after a burst of failed RDP logons — then one
> attempt succeeded. Wazuh fired rule **60115** (account lockout) and **92657**
> (successful remote logon, flagged as possible pass-the-hash). I confirmed the
> source as `192.168.56.10` across every 4625 event, correlated the lockout with
> the subsequent 4624, and traced the full sequence from first failure to
> compromise. That workflow — detect, correlate, decide — is what this lab is
> built to practice, automate, and document.

A self-built Security Operations Center lab demonstrating **end-to-end threat
detection across host and network layers, threat-intel-driven detection, and
SOAR automation** — from attack, to detection, to enrichment, to a case landing
in front of an analyst.

---

## What This Lab Demonstrates

- **End-to-end SOC workflow** — attack → detection → enrichment → case creation,
  not just tool deployment.
- **Defense in depth (HIDS + NIDS)** — host-based detection (Wazuh agents) *and*
  network-based detection (Suricata), covering attacks that one layer alone
  would miss.
- **Threat-intel-driven detection** — phishing email analyzed, IOCs extracted and
  operationalized into a Wazuh watchlist that fires on any connection to known
  infrastructure.
- **SOAR automation** — Wazuh → Shuffle → VirusTotal enrichment → TheHive case,
  fully automated.
- **Detection engineering judgment** — custom rules, alert tuning to cut noise,
  and reasoning about when a rule *should not* fire (false positives).
- **Real troubleshooting** — a documented log of the engineering problems solved
  to make the pipeline work (see [Challenges & Resolutions](docs/challenges-and-resolutions.md)).

---

## Skills at a Glance

| Domain | Tools / Techniques |
|---|---|
| SIEM / HIDS | Wazuh (agents, custom rules, CDB lists, correlation) |
| NIDS | Suricata (Emerging Threats ruleset, eve.json) |
| Endpoint telemetry | Sysmon (Windows), journald (Linux) |
| SOAR / automation | Shuffle (SOAR workflows, webhook integration, API) |
| Threat intelligence | VirusTotal enrichment, abuse.ch feeds, IOC watchlists |
| Case management | TheHive (alerts, cases, observables) |
| Adversary simulation | Hydra, ncrack, xfreerdp, Nmap, phishing analysis (emlAnalyzer) |
| Frameworks | MITRE ATT&CK mapping |

---

## Architecture

![SOC lab architecture](docs/architecture.png)

<details>
<summary>Text version of the diagram</summary>

```
                         INTERNAL NETWORK (192.168.56.0/24)
   ┌──────────────┐          attack traffic          ┌──────────────────┐
   │   Kali       │ ───────────────────────────────▶ │  Ubuntu target   │
   │  Attacker    │   SSH/RDP brute force, nmap,      │  Wazuh agent +   │
   │ 192.168.56.10│   IOC connection                 │  Suricata (NIDS) │
   └──────────────┘ ───────────────────────────────▶ │ 192.168.56.20    │
          │                                           └────────┬─────────┘
          │                                           ┌────────┴─────────┐
          └─────────────────────────────────────────▶│  Windows target  │
                                                      │  Wazuh agent +   │
                                                      │  Sysmon          │
                                                      └────────┬─────────┘
                                                               │ NAT adapter
                                                               ▼  (internet)
                                          ┌────────────────────────────────┐
                                          │       Wazuh Manager (cloud)     │
                                          │  rules · CDB threat list ·      │
                                          │  correlation · alerting         │
                                          └────────────────┬────────────────┘
                                                           │ forwards curated alerts
                                                           ▼
                                          ┌────────────────────────────────┐
                                          │        Shuffle (SOAR)           │
                                          │  webhook → VirusTotal enrich    │
                                          └────────────────┬────────────────┘
                                                           ▼
                                          ┌────────────────────────────────┐
                                          │           TheHive               │
                                          │   alert / case for analyst      │
                                          └────────────────────────────────┘
```

</details>

Each VM uses two adapters: an **internal** adapter (isolated attack traffic) and
a **NAT** adapter (lets agents reach the cloud backend). See
[docs/architecture.md](docs/architecture.md) for the full design and rationale.

---

## Detection Scenarios

| # | Scenario | MITRE | Detection | Source | Status |
|---|---|---|---|---|---|
| 01 | [SSH Brute Force](docs/scenarios/01-ssh-brute-force.md) | T1110 | Wazuh 5710 / 5712 | Ubuntu agent (journald) | ✅ Validated |
| 02 | [RDP Brute Force → Lockout → Compromise](docs/scenarios/02-rdp-brute-force.md) | T1110 | Wazuh 60122 / 60115 / 92657 | Windows agent (Security log) | ✅ Validated |
| 03 | [Nmap Recon](docs/scenarios/03-nmap-recon.md) | T1046 / T1595 | Suricata (ET ruleset) | Ubuntu Suricata | ✅ Validated |
| 04 | [Phishing IOC → SOAR Enrichment](docs/scenarios/04-phishing-ioc.md) | T1566 | Wazuh 100100 (custom, CDB match) | Suricata → Wazuh → Shuffle → TheHive | ✅ Validated |

> **Detection latency note:** <<fill in — e.g. agent-based host alerts fired in
> ~X s; Suricata flow-based detection took ~60–90 s due to flow-record flush
> timing. Document the gap and why it exists.>>

See [docs/triage-methodology.md](docs/triage-methodology.md) for how each alert
is triaged — what I check next, malicious vs. benign reasoning, and when to
escalate.

---

## The SOAR Pipeline (Scenario 04 highlight)

The most complete automation path, end to end:

1. A phishing email is analyzed; its IOC (attacker IP) is extracted and added to
   a Wazuh **CDB watchlist**.
2. A connection to that IOC is detected on the wire by Suricata.
3. Wazuh **custom rule 100100** matches the destination against the watchlist →
   level-12 alert, MITRE T1566.
4. The manager forwards the alert to a **Shuffle** workflow.
5. Shuffle enriches the IOC via **VirusTotal** (detection count, hosting, country).
6. Shuffle creates an enriched **alert in TheHive** for analyst triage.

Full walkthrough: [docs/scenarios/04-phishing-ioc.md](docs/scenarios/04-phishing-ioc.md).

---

## Repository Structure

```
README.md                          ← you are here
docs/
  architecture.md                  ← full architecture + networking design
  scenarios/                       ← per-attack IR reports (detect→triage→respond)
    01-ssh-brute-force.md
    02-rdp-brute-force.md
    03-nmap-recon.md
    04-phishing-ioc.md
  triage-methodology.md            ← analyst triage logic
  challenges-and-resolutions.md    ← engineering problems solved (standout section)
  mitre-coverage.md                ← ATT&CK mapping
config/                            ← reproducible configs (sanitized)
  local_rules.xml                  ← custom Wazuh rules
  phishing-iocs                    ← CDB threat-intel list
  ossec-integration.xml            ← Shuffle integration block
  shuffle-workflow.json            ← exported SOAR workflow
evidence/                          ← screenshots + raw alert JSON per scenario
```

---

## Honesty & Scope Notes

- The lab is isolated; the phishing IOC uses a **reserved documentation IP**
  (203.0.113.17, RFC 5737). "Known-bad" means known-bad *within this lab's threat
  list* — exactly how real watchlists work. VirusTotal enrichment is demonstrated
  separately against a **genuinely malicious IP** sourced from abuse.ch, with the
  lab IOC documented as synthetic.
- All attack traffic targets the author's own lab VMs only.
- Cloud backend IPs and credentials are redacted in this public repo.

---

## Future Work

- Automated response (auto-block brute-force source IPs via `firewall-drop`).
- Human-in-the-loop response (Shuffle → analyst approval → action).
- False-positive tuning scenario (benign stale-credential retries).
- Additional detections (web attack, credential dumping).
