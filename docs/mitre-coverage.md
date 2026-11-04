# MITRE ATT&CK Coverage

How the lab's detections map to the ATT&CK framework. Each technique is tied to the
scenario that exercises it and the detection source that catches it.

_Mapped to **MITRE ATT&CK v20 (Enterprise)**. ATT&CK **v19** (Apr 2026) split the
former *Defense Evasion* tactic: **TA0005 was renamed → _Stealth_** and a new
**TA0112 _Defense Impairment_** was added — this table uses the current naming._

| Tactic | Technique | ID | Detection | Scenario |
|---|---|---|---|---|
| Reconnaissance | Active Scanning | T1595 | Suricata — Nmap OS-detection probes (SID 2200025, ET 2018489) | [01](scenarios/01-nmap-recon.md) ✅ |
| Discovery | Network Service Discovery | T1046 | Suricata — ET SCAN port rules (database/VNC/SSH ports); generic port scans not detected | [01](scenarios/01-nmap-recon.md) ✅ |
| Credential Access | Brute Force: Password Guessing | T1110.001 | Wazuh 5710 / 5712 (SSH — 5710 tags .001; 5712's own tag is the parent T1110) | [03](scenarios/03-ssh-brute-force.md) ✅ |
| Credential Access | Brute Force: Password Guessing | T1110.001 | Wazuh 60122 / 60204 / 60115 (RDP failures, correlation, lockout) | [04](scenarios/04-rdp-brute-force.md) ✅ |
| Lateral Movement | Remote Services: RDP | T1021.001 | Wazuh 92657 / 92653 (successful RDP logon) | [04](scenarios/04-rdp-brute-force.md) ✅ |
| Initial Access | Valid Accounts: Local Accounts | T1078.003 | Wazuh 92657 / 92653 — local admin `Client` logon (built-in rule mis-tags T1078.002; §2) | [04](scenarios/04-rdp-brute-force.md) ✅ |
| Initial Access | Phishing: Spearphishing Link | T1566.002 | Email analysis (emlAnalyzer) of the crafted sample | [02](scenarios/02-phishing-ioc.md) · analyzed sample |
| Execution | User Execution: Malicious Link | T1204.001 | Wazuh 100100 — Suricata **http** event to the phishing server (curl = simulated click) | [02](scenarios/02-phishing-ioc.md) · simulated ✅ |
| Discovery | Account Discovery | T1087 | Sysmon (net.exe) | — (seen, not captured) |
| Discovery | Remote System Discovery | T1018 | Sysmon | — (seen, not captured) |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | Wazuh 92900 (LSASS access, behavioral) — fired live | [05](scenarios/05-credential-dumping.md) ✅ |
| Credential Access | OS Credential Dumping | T1003 | Custom 100002 (Mimikatz PE OriginalFileName — name-based, so mapped to the parent; behavioral 92900 carries T1003.001) — fired live | [05](scenarios/05-credential-dumping.md) ✅ |
| Command & Control | Ingress Tool Transfer | T1105 | Wazuh 92075 (certutil `-urlcache` download) — fired live | [05](scenarios/05-credential-dumping.md) ✅ |

> **✅ = detection validated** — a rule fired and its alert is captured in `evidence/`. Rows without ✅ are observed-only: telemetry **visibility** with no captured detection (T1087 / T1018), or an **analyzed sample** with no detection rule (T1566.002). (The visibility-vs-detection distinction, per DeTT&CT.)

---

## Coverage notes

- **Brute Force (T1110)** is detected on **two platforms through two different log
  sources** — Linux journald (sshd) and the Windows Security channel. Same
  technique, different telemetry: the clearest argument for cross-platform host
  coverage.
- **Scanning (T1046 / T1595)** is visible only to the **network** sensor (Suricata),
  not the host agents — the clearest argument for NIDS alongside HIDS. Coverage is
  partial: OS fingerprinting and scans touching watched ports are detected; a plain
  SYN scan of ports 1–1000 is not (tested — Scenario 01 §6). Kali is modeled as an
  external attacker (`HOME_NET` scoped to the victims), which is why T1595
  (Reconnaissance) is mapped alongside T1046.
- **SOAR / alert creation is not phishing-only.** Forwarding to Shuffle is filtered
  to the actionable alerts — by rule group (`phishing`) and by rule ID (`5712` SSH
  correlation, `60115` RDP lockout, `92900` LSASS access, `92657` RDP logon).
  Phishing (02), SSH (03), RDP (04), and credential dumping (05) are all forwarded
  and raised as alerts in TheHive — RDP raises two (the lockout and the successful
  logon), and the cred-dump (rule 92900) is forwarded by its specific rule ID,
  not the `sysmon_eid10_detections` group (which also carries other Event-ID-10
  process-access events, e.g. benign OneDrive activity). The Nmap/Suricata recon alerts (01) and the
  per-attempt brute-force
  rules (`5710`, `60122`) are deliberately held back to keep noise off the SOAR
  layer. Phishing is the scenario where **VirusTotal enrichment** is showcased —
  its lab IOC is a private IP (so VT returns a non-informative result, 0/56, on the live run), and the
  enrichment *capability* is shown with a clearly labeled synthetic test event
  carrying a real known-bad IP (Scenario 02 §5b). Phishing maps to **two** techniques,
  each to its own evidence: **T1566.002** (the analyzed email) and **T1204.001**
  (the simulated-click connection that rule 100100 observes) — the single network
  event is not mapped to T1566 on its own.
- The Sysmon-visible techniques (T1087, T1018) were **seen in telemetry but
  not captured** as alerts — they surfaced incidentally during Windows testing and
  show the depth of process-level data available for future detection work, not
  detections the lab currently fires.

---

## Built-in rule tag audit

Wazuh's built-in rules ship generic ATT&CK tags that aren't always right for the event
they fire on. Reading them critically is the skill; the mismatches this lab relies on
(each checked against the technique's own ATT&CK page):

| Rule | Built-in tag(s) | Accurate here | Why the built-in is off |
|---|---|---|---|
| 60122 (4625 fail) | **T1531** only | T1110.001 | [T1531](https://attack.mitre.org/techniques/T1531/) is *Impact* — an adversary deleting/locking others' accounts to deny access; a failed logon is the brute-force attempt, not access removal. |
| 60115 (4740 lockout) | T1110 + **T1531** | T1110.001 | T1110 fits; **T1531 is wrong** — the lockout is the *defensive control* firing, not the adversary removing access. |
| 92657 (Type-3 NLA) | **T1550.002** + **T1078.002** + T1021.001 | T1021.001 + T1078.003 | Pass-the-Hash needs a stolen **hash** (a real password was used); T1078.002 is **AD-domain** — `Client` is a local WORKGROUP account (→ T1078.003). |
| 92653 (Type-10 RDP) | T1021.001 + **T1078.002** | T1021.001 + T1078.003 | T1021.001 correct; T1078.002 (domain) → **.003 (Local)**. |
| 5710 (SSH invalid user) | T1110.001 + **T1021.004** | T1110.001 | T1021.004 (SSH *lateral movement*) needs a successful valid-account login; 5710 fires on an invalid-user **failure** — no session. |
| 5712 / 60204 (correlation) | T1110 (parent) | T1110.001 | Parent is acceptable for a multi-event correlation; the exercised behavior is password guessing (.001). |
| 100002 (custom) | T1003 (parent) | T1003 | Deliberate — a name match can't prove the LSASS sub-technique; behavioral 92900 carries T1003.001. |

Accurate as tagged: 92075 (T1105), 92900 (T1003.001).

**Tactic naming.** Wazuh emits the pre-v19 tactic name **Defense Evasion** on
92657/92653 (ATT&CK v19 renamed **TA0005 → _[Stealth](https://attack.mitre.org/tactics/TA0005/)_**).
T1078.003 is valid under several tactics (Stealth, Persistence, Privilege Escalation,
Initial Access); this lab maps the local-account logon to **Initial Access** — the
foothold reading that fits the intrusion story.
