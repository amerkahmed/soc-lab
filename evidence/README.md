# Evidence

Captured proof that each scenario actually fired — screenshots and raw alert JSON.
This is the single most important section for credibility: it shows the lab is real,
not just described. Reviewers trust evidence with timestamps, rule IDs, and source
IPs far more than a generic dashboard screenshot.

## What to capture (per scenario)

Create one folder per scenario and drop in the artifacts below.

```
evidence/
  scenario-01-ssh/
    attack-output.txt        # Hydra output from Kali
    wazuh-alerts.png         # rules 5710 / 5712 firing (manager or dashboard)
    alert-5712.json          # raw JSON of the brute-force correlation alert
  scenario-02-rdp/
    attack-output.txt        # xfreerdp3 loop output (LOGON_FAILURE → LOCKED_OUT)
    wazuh-alerts.png         # rules 60122 / 60115 / 92657
    alert-60115.json         # raw lockout alert JSON
    alert-92657.json         # raw successful-logon alert JSON (the escalation)
  scenario-03-nmap/
    attack-output.txt        # nmap -A output
    suricata-fast-log.txt    # /var/log/suricata/fast.log excerpt
    wazuh-suricata-alert.json
  scenario-04-phishing/
    emlanalyzer-output.txt   # emlAnalyzer analysis of the sample
    wazuh-100100-alert.json  # the IOC-match alert (level 12, T1566)
    shuffle-run-201.png      # Shuffle workflow run, HTTP node 201
    thehive-alert.png        # the enriched alert in TheHive
```

## Tips for good evidence
- Keep **timestamps, rule IDs, and source IPs visible** — they prove the event is
  real and tie the screenshot to the narrative.
- Raw alert JSON is stronger than a screenshot; capture both where you can.
- Redact any credentials or public cloud IPs before committing.

## Already-captured reference alerts (from the build)
The phishing IOC detection was validated live — rule 100100 fired 4 times at
level 12 with `mitre.id: ["T1566"]` on a flow to the IOC. The RDP attack produced
the full `ERRCONNECT_LOGON_FAILURE → ERRCONNECT_ACCOUNT_LOCKED_OUT` sequence and
the corresponding 60122 / 60115 / 92657 alerts. Re-run each scenario to capture
fresh screenshots for publication.
