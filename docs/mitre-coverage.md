# MITRE ATT&CK Coverage

How the lab's detections map to the ATT&CK framework. Each technique is tied to the
scenario that exercises it and the detection source that catches it.

| Tactic | Technique | ID | Detection | Scenario |
|---|---|---|---|---|
| Reconnaissance | Active Scanning | T1595 | Suricata (ICMP/service probes) | [01](scenarios/01-nmap-recon.md) |
| Discovery | Network Service Discovery | T1046 | Suricata (ET ruleset) | [01](scenarios/01-nmap-recon.md) |
| Credential Access | Brute Force | T1110 | Wazuh 5710 / 5712 (SSH) | [03](scenarios/03-ssh-brute-force.md) |
| Credential Access | Brute Force | T1110 | Wazuh 60122 / 60115 / 92657 (RDP) | [04](scenarios/04-rdp-brute-force.md) |
| Initial Access | Phishing | T1566 | Wazuh 100100 (custom, CDB IOC match) | [02](scenarios/02-phishing-ioc.md) |
| Reconnaissance | Phishing for Information | T1598 | Email analysis (emlAnalyzer) | [02](scenarios/02-phishing-ioc.md) |
| Execution | User Execution: Malicious Link | T1204.001 | IOC detonation → Suricata/Wazuh | [02](scenarios/02-phishing-ioc.md) |
| Discovery | Account Discovery | T1087 | Sysmon (net.exe) | — (observed on Windows) |
| Discovery | Remote System Discovery | T1018 | Sysmon | — (observed on Windows) |
| Execution | Scheduled Task/Job | T1053 | Sysmon (taskschd.dll load) | — (observed on Windows) |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | Wazuh 92900 (LSASS access) + custom 100002 (Mimikatz name) | [05](scenarios/05-credential-dumping.md) ✅ |

---

## Coverage notes

- **Brute Force (T1110)** is detected on **two platforms through two different log
  sources** — Linux journald (sshd) and the Windows Security channel. Same
  technique, different telemetry: the clearest argument for cross-platform host
  coverage.
- **Scanning (T1046 / T1595)** is caught only by the **network** sensor (Suricata),
  not the host agents — the clearest argument for NIDS alongside HIDS.
- **SOAR / case creation is not phishing-only.** Forwarding to Shuffle is filtered
  to the actionable alerts — by rule group (`phishing`, `sysmon_eid10_detections`)
  and by rule ID (`5712` SSH correlation, `60115` RDP lockout, `92657` RDP
  compromise). Phishing (02), SSH (03), RDP (04), and credential dumping (05) are
  all forwarded and raised as cases in TheHive — RDP raises two (the lockout and
  the compromise), and the cred-dump (rule 92900) forwards via the
  `sysmon_eid10_detections` group. The Nmap/Suricata recon alerts (01) and the
  per-attempt brute-force
  rules (`5710`, `60122`) are deliberately held back to keep noise off the SOAR
  layer. Phishing is simply the scenario where **VirusTotal enrichment** is
  showcased, because its IOC is a real external IP — the brute-force sources are
  private RFC 1918 addresses VirusTotal can't resolve (see the selective-enrichment
  note in [architecture.md](architecture.md) §6). Phishing also chains three
  techniques: T1598 → T1566 → T1204.001.
- The Sysmon-observed techniques (T1087, T1018, T1053) surfaced incidentally during
  Windows testing and show the depth of process-level telemetry available for
  future detection work.
