# Config — reproducible artifacts

Sanitized configuration from the lab, so the detection and automation pieces are
reproducible. Secrets and public cloud IPs are redacted.

| File | What it is | Deploy to |
|---|---|---|
| `local_rules.xml` | Custom Wazuh rules (SSH example, Mimikatz, phishing IOC 100100) | `/var/ossec/etc/rules/local_rules.xml` (manager) |
| `phishing-iocs` | CDB threat-intel watchlist (IOC IPs) | `/var/ossec/etc/lists/phishing-iocs` (manager) |
| `ossec-ruleset-list.xml` | Snippet to register the CDB list | inside `<ruleset>` in `ossec.conf` (manager) |
| `ossec-integration.xml` | Wazuh → Shuffle integration block (group-filtered) | inside `<ossec_config>` in `ossec.conf` (manager) |
| `local_internal_options.conf` | JSON decoder field-limit fix | append to `/var/ossec/etc/local_internal_options.conf` (manager) |
| `thehive-http-body.json` | Reference body for the Shuffle HTTP → TheHive node | Shuffle workflow |
| `paypal_phish.eml` | The crafted phishing sample for analysis | analyze on Kali with `emlAnalyzer` |

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
- The exported Shuffle workflow JSON (add `shuffle-workflow.json` after exporting
  it from Shuffle, with the webhook/API key scrubbed).
