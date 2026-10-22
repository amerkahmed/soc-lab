# MITRE ATT&CK Coverage

How the lab's detections map to the ATT&CK framework. Each technique is tied to the
scenario that exercises it and the detection source that catches it.

| Tactic | Technique | ID | Detection | Scenario |
|---|---|---|---|---|
| Reconnaissance | Active Scanning | T1595 | Suricata (ICMP/service probes) | [03](scenarios/03-nmap-recon.md) |
| Discovery | Network Service Discovery | T1046 | Suricata (ET ruleset) | [03](scenarios/03-nmap-recon.md) |
| Credential Access | Brute Force | T1110 | Wazuh 5710 / 5712 (SSH) | [01](scenarios/01-ssh-brute-force.md) |
| Credential Access | Brute Force | T1110 | Wazuh 60122 / 60115 / 92657 (RDP) | [02](scenarios/02-rdp-brute-force.md) |
| Initial Access | Phishing | T1566 | Wazuh 100100 (custom, CDB IOC match) | [04](scenarios/04-phishing-ioc.md) |
| Reconnaissance | Phishing for Information | T1598 | Email analysis (emlAnalyzer) | [04](scenarios/04-phishing-ioc.md) |
| Execution | User Execution: Malicious Link | T1204.001 | IOC detonation → Suricata/Wazuh | [04](scenarios/04-phishing-ioc.md) |
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
- **Phishing (T1566)** is the only technique in the lab that runs the full chain
  from analysis through automated case creation, and it chains T1598 → T1566 →
  T1204.001.
- The Sysmon-observed techniques (T1087, T1018, T1053) surfaced incidentally during
  Windows testing and show the depth of process-level telemetry available for
  future detection work.
