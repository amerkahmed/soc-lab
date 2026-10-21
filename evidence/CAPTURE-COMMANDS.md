# Evidence Capture Commands

Copy-paste commands to grab the proof for each scenario. Run the attack, wait for
the alert, then run the capture command. Screenshots are noted where a command
can't produce the artifact.

> **Before you start:** make sure the Wazuh agent is **Active**
> (`sudo /var/ossec/bin/agent_control -l` on the manager) and, for JSON capture,
> that JSON alert logging is on. If `/var/ossec/logs/alerts/alerts.json` doesn't
> exist, enable it in `ossec.conf` under `<alerts>`:
> `<jsonout_output>yes</jsonout_output>`, then `systemctl restart wazuh-manager`.
>
> `jq` makes the JSON readable: `sudo apt install jq` (manager).

---

## Scenario 01 — SSH brute force

**Attack (Kali):**
```bash
hydra -l fakeuser -P ~/passwords.txt ssh://192.168.56.20 -t 4 | tee evidence/scenario-01-ssh/attack-output.txt
```

**Capture the correlation alert (manager):**
```bash
mkdir -p evidence/scenario-01-ssh
# newest SSH brute-force (5712) alert, pretty-printed
sudo grep '"id":"5712"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-01-ssh/alert-5712.json
# supporting failed-login (5710) alert
sudo grep '"id":"5710"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-01-ssh/alert-5710.json
```

**Screenshot:** the manager `alerts.log` tail or the dashboard showing 5710/5712 →
`evidence/scenario-01-ssh/wazuh-alerts.png`

---

## Scenario 02 — RDP brute force → lockout → compromise

**Attack (Kali):**
```bash
mkdir -p evidence/scenario-02-rdp
for pass in $(cat ~/winpass.txt); do
  echo "=== Trying: $pass ==="
  xfreerdp3 /u:Client /p:"$pass" /v:192.168.56.30 /cert:ignore +auth-only
done 2>&1 | tee evidence/scenario-02-rdp/attack-output.txt
```

**Capture the alerts (manager):**
```bash
# account lockout (60115)
sudo grep '"id":"60115"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-02-rdp/alert-60115.json
# the escalation — successful remote logon (92657)
sudo grep '"id":"92657"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-02-rdp/alert-92657.json
# a representative failed logon (60122)
sudo grep '"id":"60122"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-02-rdp/alert-60122.json
```

**Screenshot:** the three rules firing in sequence →
`evidence/scenario-02-rdp/wazuh-alerts.png`

> Tip: if `Client` is locked from a previous run, reset it on Windows:
> `net user Client <<new-password>> /active:yes`

---

## Scenario 03 — Nmap recon (Suricata)

**Attack (Kali):**
```bash
mkdir -p evidence/scenario-03-nmap
sudo nmap -A 192.168.56.20 | tee evidence/scenario-03-nmap/attack-output.txt
```

**Capture Suricata's own log (target):**
```bash
# fast.log excerpt showing the scan alerts
sudo grep "192.168.56.10" /var/log/suricata/fast.log | tail -20 \
  > evidence/scenario-03-nmap/suricata-fast-log.txt
```

**Capture the Suricata alert as seen by Wazuh (manager):**
```bash
# Suricata alerts surface under base rule 86601
sudo grep '"id":"86601"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-03-nmap/wazuh-suricata-alert.json
```

**Screenshot:** optional — the dashboard filtered to `rule.groups: ids` →
`evidence/scenario-03-nmap/wazuh-suricata.png`

---

## Scenario 04 — Phishing IOC → SOAR

**Analysis (Kali):**
```bash
mkdir -p evidence/scenario-04-phishing
emlAnalyzer -i ~/paypal_phish.eml --header --html --url --text \
  | tee evidence/scenario-04-phishing/emlanalyzer-output.txt
```

**Detonate the IOC (target) + keep the Python server up on Kali:**
```bash
# Kali:  python3 -m http.server 80
curl -m 5 http://192.168.56.10/        # (lab test traffic across the monitored iface)
```

**Capture the IOC-match alert (manager) — wait ~60-90s for the flow to flush:**
```bash
sudo grep '"id":"100100"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-04-phishing/wazuh-100100-alert.json
```

**Screenshots (the SOAR half can't be captured by CLI):**
- Shuffle workflow run with the HTTP node returning 201 →
  `evidence/scenario-04-phishing/shuffle-run-201.png`
- The enriched alert in TheHive (VirusTotal fields visible) →
  `evidence/scenario-04-phishing/thehive-alert.png`

---

## Redaction reminder

Before committing, scrub any public cloud IPs or credentials from the captured
files:

```bash
# dry-run: see what would match
grep -rInE "159\.203\.|142\.93\.|password|api[_-]?key|token" evidence/
```

Replace real cloud IPs with `<MANAGER_IP>` / `<THEHIVE_IP>` in any captured JSON
before publishing.
