# Config — reproducible artifacts

Sanitized configuration from the lab, so the detection and automation pieces are
reproducible. Secrets and public cloud IPs are redacted.

| File | What it is | Deploy to |
|---|---|---|
| `local_rules.xml` | Custom Wazuh rules (Mimikatz 100002, phishing IOC 100100) | `/var/ossec/etc/rules/local_rules.xml` (manager) |
| `phishing-iocs` | CDB threat-intel watchlist (IOC IPs) | `/var/ossec/etc/lists/phishing-iocs` (manager) |
| `ossec-ruleset-list.xml` | Snippet to register the CDB list | inside `<ruleset>` in `ossec.conf` (manager) |
| `ossec-integration.xml` | Wazuh → Shuffle integration block (group-filtered) | inside `<ossec_config>` in `ossec.conf` (manager) |
| `local_internal_options.conf` | JSON decoder field-limit fix | append to `/var/ossec/etc/local_internal_options.conf` (manager) |
| `thehive-http-body.json` | TheHive alert body for the **enriched (phishing) path** — severity, tags, VT fields, IOC observable (the `Hive_Enriched` node). The SSH and RDP/cred-dump paths post their own bodies; see `shuffle-workflow.json` | Shuffle workflow |
| `paypal_phish.eml` | The crafted phishing sample for analysis | analyze on Kali with `emlAnalyzer` |
| `shuffle-workflow.json` | Exported Shuffle SOAR workflow (webhook, cloud IPs, and API keys scrubbed) | import into Shuffle |
| `active-response.xml` | SSH brute-force auto-block — `firewall-drop` on rule 5712, 300 s timeout (Scenario 03) | inside `<ossec_config>` in `ossec.conf` (manager) |
| `sysmon-config.md` | Sysmon version + the ProcessCreate/ProcessAccess rules that drive 92075 / 92900 / 100002 (Scenario 05) | reference (Windows endpoint `sysmonconfig.xml`) |
| `lockout-policy.txt` | Windows account-lockout policy (`net accounts` 10 / 10 / 10) behind 60115 and the ~10-min auto-expiring lockout (Scenario 04); 60204 is a separate Wazuh correlation, not driven by this policy | reference (Windows endpoint) |

## Redactions
- Shuffle webhook URL → `webhook_REDACTED`
- Cloud IPs and API keys are not included.

## Not included here
- The Windows agent `<localfile>` Security eventchannel block (add on the Windows
  endpoint's `ossec.conf`):
  ```xml
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
  </localfile>
  ```
