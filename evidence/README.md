# Evidence

Captured proof that each scenario fired end to end — raw alert JSON and
screenshots, one folder per scenario. Within a scenario, the artifacts share a
single Wazuh **event ID**, so each detection, its SOAR run, and its TheHive alert
tie together. (Scenarios 04 and 05 are a single multi-stage incident captured in one
~98-second window — each forwarded detection still chains by its own event ID, and
the stages share one source/host/account. Scenario 02 additionally carries a
*separate, clearly labeled* synthetic enrichment event — see its entry below.) Cross-host clocks are reconciled
by event ID + UTC (see the
[README](../README.md#honesty--scope-notes)); the exact capture commands are in
[CAPTURE-COMMANDS.md](CAPTURE-COMMANDS.md).

## What's here

**`scenario-01-nmap/`** — Nmap recon caught by Suricata (rule 86601, an alert event).
- Original run (2026-10-22): `attack-output.txt` · `suricata-fast-log.txt` (last 20 lines only) · `wazuh-suricata-alert.json` · `wazuh-suricata.png`
- `retest-2026-10-27/` — per-scan-type re-test (`-sS`, `-sV`, `-A`, `-sS -p 1-1000`):
  `before/` the `HOME_NET` fix (`nmap-*.txt`, `fast-*.txt` extracts, `sig-*.txt` per-signature counts) and `after/` it (`nmap2-*.txt`, `fast2-*.txt`, `sig2-*.txt`, incl. the `-p1000` run) · `homenet-change.diff` · `wazuh-2018489-alert.json`

**`scenario-02-phishing/`** — reframed as an L1 phishing investigation (redesigned + re-validated 2026-10-28): email analysis (T1566.002) → IOC → http-event match on the lab phishing server `192.168.56.99` (rule 100100, T1204.001) → Shuffle → TheHive alert with IOC observable.
- `emlanalyzer-output.txt` · `eml-analysis.png` (recapture — new sample, auth passes)
- **Real detection chain — one event `1793225059.80603`, HTTP 200:** `wazuh-100100-alert.json` (http-event match, `dest_ip 192.168.56.99`, `status 200`) · `wazuh-100100-discover.png` (the same alert in the Wazuh dashboard) · `shuffle-run-real.png` (webhook run) · `thehive-alert-real.png` (`VT malicious: 0` — VT has no intel on the private IP) · `thehive-observable-real.png` (IOC `192.168.56.99` attached). The detection JSON `id`, the Shuffle `$exec.id`, and the TheHive `Reference` all read `1793225059.80603`.
- **Tuning exercise:** `wazuh-100100-FALSE-POSITIVE-icmp.json` (naive rule over-matching a per-packet alert event — reproducible, see Scenario 02 §3a / challenges #14).
- **Synthetic enrichment demo — a separate event `1793219216.47653`, IOC `1.92.135.168` (§5b):** `shuffle-run-synthetic.png` · `thehive-alert-synthetic.png` (`VT malicious: 20`) · `thehive-observable-synthetic.png` · `virustotal-enrichment.png` (manual VT lookup — 20/92 — corroborating the fields). No traffic is ever sent to the known-bad IP.
- `shuffle-workflow.png` (the Shuffle workflow itself).

**`scenario-03-ssh/`** — SSH brute force → auto-block, event `1793228621.106252` (one event ties the whole chain).
- `attack-output.txt` (Hydra, 25 guesses) · `alert-5712.json` (correlation, `frequency 8` threshold) · `alert-5710.json` (per-attempt, `firedtimes 13`)
- **Auto-block:** `alert-651-block.json` (firewall-drop `add` 192.168.56.10) · `alert-652-unblock.json` (`delete` after the 300 s timeout) · `active-response-block.txt` (the `active-responses.log` add/delete + the `iptables` DROP)
- `wazuh-5712-alerts.png` · `wazuh-5712-detail.png` · `shuffle-aggregated.png` · `thehive-alert.png` (description shows `Correlation threshold: 8 failed logins / 120s`) · `thehive-observable.png` (attacker IP)

**`scenario-04-rdp/`** — RDP brute force → lockout → interactive session, one live pass **2026-10-29 02:33–02:34 UTC** (lockout `1793241183.1942214`, NLA logon `1793241240.1979272`, Type-10 session `1793241240.2020471`).
- `attack-output.txt` (xfreerdp3 brute-force method — winning password redacted; Kali's local clock, authoritative timeline is the JSONs)
- `alert-60122-failure.json` (failed logon, Type 3) · `alert-60115-lockout.json` (account lockout, 4740) · `alert-92657-type3-nla.json` (NLA pre-auth, Type 3 — the forwarded headline) · `alert-92653-type10-session.json` (genuine interactive RDP session, Type 10)
- `wazuh-rdp-sequence.png` (the full arc in one Discover view)
- `shuffle-rdp-lockout.png` · `shuffle-rdp-compromise.png` · `thehive-lockout.png` · `thehive-compromise.png`

**`scenario-05-creddump/`** — certutil ingress → Mimikatz LSASS dump, one live pass **2026-10-29 02:34 UTC**; all three rules fired (certutil `1793241263.2077496`, Mimikatz name `1793241281.2087863`, LSASS access `1793241281.2094013`).
- `attack-output.txt` (certutil + Mimikatz — dumped credentials redacted)
- `alert-92075-certutil.json` (ingress transfer, T1105) · `alert-92900-lsass.json` (LSASS access, forwarded, T1003.001) · `alert-100002-mimikatz.json` (PE OriginalFileName, T1003)
- `wazuh-92900-alerts.png` · `wazuh-92900-detail.png`
- `shuffle-creddump.png` · `thehive-creddump.png`

## Provenance & integrity

- Raw alert JSON is captured verbatim from the manager (`/var/ossec/logs/alerts/…`);
  screenshots are from the Wazuh dashboard, Shuffle, and TheHive.
- Cloud backend IPs are redacted (`<MANAGER_IP>` / `<THEHIVE_IP>`); internal
  RFC 1918 lab addresses are kept (non-routable, and they illustrate the design).
- Sensitive attacker output is redacted: the dumped credentials in Scenario 05 and
  the winning RDP password in Scenario 04.
