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

**`scenario-02-phishing/`** — reframed as an L1 phishing investigation (redesigned 2026-10-27, **recapture pending**): email analysis (T1566.002) → IOC → http-event match on the lab phishing server `192.168.56.99` (rule 100100, T1204.001) → Shuffle → TheHive alert with IOC observable.
- `emlanalyzer-output.txt` · `eml-analysis.png` (recapture — new sample, auth passes)
- `wazuh-100100-alert.json` (http-event match, `dest_ip 192.168.56.99`) · `wazuh-100100-FALSE-POSITIVE-icmp.json` (naive rule over-matching a per-packet alert event — reproducible tuning exercise, see Scenario 02 §3a / challenges #14)
- `shuffle-run-201.png` (webhook run, rule_id 100100) · `thehive-alert.png` (VT-enriched description: `VT malicious: 20`) · `thehive-observable.png` (the IOC attached as an observable) · `virustotal-enrichment.png` (manual lookup of `1.92.135.168` — 20/92, Cobalt Strike C2, §5b) · `shuffle-workflow.png`

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
