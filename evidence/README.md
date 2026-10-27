# Evidence

Captured proof that each scenario fired end to end — raw alert JSON and
screenshots, one folder per scenario. Within a scenario, the artifacts share a
single Wazuh **event ID**, so the detection, the SOAR run, and the TheHive case
tie together. Cross-host clocks are reconciled by event ID + UTC (see the
[README](../README.md#honesty--scope-notes)); the exact capture commands are in
[CAPTURE-COMMANDS.md](CAPTURE-COMMANDS.md).

## What's here

**`scenario-01-nmap/`** — Nmap recon caught by Suricata (rule 86601, an alert event).
- Original run (2026-10-22): `attack-output.txt` · `suricata-fast-log.txt` (last 20 lines only) · `wazuh-suricata-alert.json` · `wazuh-suricata.png`
- `retest-2026-10-27/` — per-scan-type re-test (`-sS`, `-sV`, `-A`, `-sS -p 1-1000`):
  `before/` the `HOME_NET` fix (`nmap-*.txt`, `fast-*.txt` extracts, `sig-*.txt` per-signature counts) and `after/` it (`nmap2-*.txt`, `fast2-*.txt`, `sig2-*.txt`, incl. the `-p1000` run) · `homenet-change.diff` · `wazuh-2018489-alert.json`

**`scenario-02-phishing/`** — phishing IOC match (rule 100100) → Shuffle → VirusTotal → TheHive.
- `emlanalyzer-output.txt` · `eml-analysis.png`
- `wazuh-100100-alert.json` (the TCP flow match) · `wazuh-100100-FALSE-POSITIVE-icmp.json` (the pre-tuning ICMP false positive)
- `shuffle-workflow.png` · `shuffle-run-201.png` · `virustotal-enrichment.png` · `thehive-alert.png`

**`scenario-03-ssh/`** — SSH brute force, event `1792785099.20359`.
- `attack-output.txt` (Hydra) · `alert-5712.json` (correlation) · `alert-5710.json` (per-attempt)
- `wazuh-5712-alerts.png` · `wazuh-5712-detail.png` · `shuffle-aggregated.png` · `thehive-alert.png`

**`scenario-04-rdp/`** — RDP brute force → lockout → compromise (lockout `…895940`, compromise `…933151`).
- `attack-output.txt` (xfreerdp3 — winning password redacted)
- `alert-60122.json` (failed logon) · `alert-60115.json` (lockout) · `alert-92657.json` (compromise)
- `wazuh-rdp-sequence.png` · `wazuh-92657-detail-1.png` · `wazuh-92657-detail-2.png`
- `shuffle-rdp-lockout.png` · `shuffle-rdp-compromise.png` · `thehive-lockout.png` · `thehive-compromise.png`

**`scenario-05-creddump/`** — Mimikatz LSASS access (rule 92900), event `1792790035.929684`.
- `attack-output.txt` (certutil + Mimikatz — dumped credentials redacted)
- `wazuh-92900-alert.json` · `wazuh-92900-alerts.png` · `wazuh-92900-detail.png`
- `shuffle-creddump.png` · `thehive-creddump.png`

## Provenance & integrity

- Raw alert JSON is captured verbatim from the manager (`/var/ossec/logs/alerts/…`);
  screenshots are from the Wazuh dashboard, Shuffle, and TheHive.
- Cloud backend IPs are redacted (`<MANAGER_IP>` / `<THEHIVE_IP>`); internal
  RFC 1918 lab addresses are kept (non-routable, and they illustrate the design).
- Sensitive attacker output is redacted: the dumped credentials in Scenario 05 and
  the winning RDP password in Scenario 04.
