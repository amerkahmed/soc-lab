# MITRE ATT&CK Coverage

How the lab's detections map to the ATT&CK framework. Each technique is tied to the
scenario that exercises it and the detection source that catches it.

| Tactic | Technique | ID | Detection | Scenario |
|---|---|---|---|---|
| Reconnaissance | Active Scanning | T1595 | Suricata — Nmap OS-detection probes (SID 2200025, ET 2018489) | [01](scenarios/01-nmap-recon.md) |
| Discovery | Network Service Discovery | T1046 | Suricata — ET SCAN port rules (database/VNC/SSH ports); generic port scans not detected | [01](scenarios/01-nmap-recon.md) |
| Credential Access | Brute Force | T1110 | Wazuh 5710 / 5712 (SSH) | [03](scenarios/03-ssh-brute-force.md) |
| Credential Access | Brute Force | T1110 | Wazuh 60122 / 60115 / 92657 (RDP) | [04](scenarios/04-rdp-brute-force.md) |
| Initial Access | Phishing | T1566 | Wazuh 100100 (custom, CDB IOC match) | [02](scenarios/02-phishing-ioc.md) |
| Execution | User Execution: Malicious Link | T1204.001 | IOC detonation (curl — simulated click) → Suricata/Wazuh | [02](scenarios/02-phishing-ioc.md) · simulated |
| Discovery | Account Discovery | T1087 | Sysmon (net.exe) | — (observed on Windows) |
| Discovery | Remote System Discovery | T1018 | Sysmon | — (observed on Windows) |
| Execution | Scheduled Task/Job | T1053 | Sysmon (taskschd.dll load) | — (observed on Windows) |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | Wazuh 92900 (LSASS access) + custom 100002 (Mimikatz name) | [05](scenarios/05-credential-dumping.md) ✅ |
| Command & Control | Ingress Tool Transfer | T1105 | Sysmon EID 1 (certutil command line, observed) | [05](scenarios/05-credential-dumping.md) |

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
  note in [architecture.md](architecture.md) §6). Phishing's validated technique is
  T1566 (the detected IOC callback); the user-click stage (T1204.001) is simulated
  via the curl detonation, not an observed user action.
- The Sysmon-observed techniques (T1087, T1018, T1053) surfaced incidentally during
  Windows testing and show the depth of process-level telemetry available for
  future detection work.
