# Challenges & Resolutions

Real engineering problems solved while building this lab. Each is an actual issue
that broke the pipeline, with the diagnosis and fix. This is the section that
shows hands-on depth a clean happy-path writeup can't — most of SOC engineering is
exactly this kind of troubleshooting.

---

### 1. Suricata sensor placement (NIDS visibility gap)
Traffic to an external IP egressed via the **NAT** adapter, which Suricata wasn't
watching (it monitors `enp0s3`, the internal interface). The packets were
invisible to the sensor, so detections silently failed.
**Fix / lesson:** a NIDS only sees the segment it's attached to; sensor placement
determines visibility. Test traffic had to traverse the monitored interface.

### 2. Suricata interface misconfiguration
Suricata's `af-packet` config defaulted to `eth0`, which doesn't exist on the
target (the interface is `enp0s3`). The service failed to start / saw zero packets
until the interface name was corrected.

### 3. Suricata missing ruleset on startup
The service wouldn't start until `suricata-update` pulled down the Emerging
Threats ruleset — the referenced `suricata.rules` file didn't exist yet.

### 4. Wazuh JSON decoder field limit
Suricata's verbose `eve.json` events (especially `stats` records) exceeded Wazuh's
default JSON decoder field limit, throwing `Too many fields for JSON decoder` and
**silently dropping events**.
**Fix:** `analysisd.decoder_order_size=1024` in `local_internal_options.conf`.

### 5. Windows Security event channel not collected
The Windows agent collected Sysmon but not the **Security** log, so failed logons
(4625) never reached the manager.
**Fix:** add a `<localfile>` block for the `Security` event channel.
**Lesson:** Sysmon and the Security log are different sensors covering different
telemetry — deep process data does not include authentication events.

### 6. Custom rule field-name mismatch
Suricata's `eve.json` puts the IP at top level (`dest_ip`), decoded by Wazuh as
`dest_ip`, **not** `data.dest_ip`. The custom IOC rule matched nothing until the
field name was corrected.
**Tool:** `wazuh-logtest` was decisive for confirming the real decoded field names
without needing live traffic.

### 7. XML rule syntax (unclosed group)
A hand-edited `local_rules.xml` left the first `<group>` unclosed before a second
opened — `End of file and some elements were not closed (line 38)` — which
**prevented the entire manager from starting**.
**Lesson:** a single malformed custom rule takes down *all* detection; validate XML
and watch the manager startup log after every rule change.

### 8. SOAR body broke on a field that changes type between sources
The Shuffle→TheHive JSON body referenced `$exec.text`. On host-based alerts this
is a string; on Suricata alerts it's a JSON **object**. Inserting the object
shattered the JSON body (`invalid decimal literal`).
**Fix:** build the body only from consistently-typed fields (`title`, `rule_id`,
`id`) and never the variable-shaped `text` blob.
**Lesson:** SOAR templates must be resilient to differing alert schemas across
sources.

### 9. Agent silently lost its manager connection
Repeated manager restarts (during rule development) dropped the agent's
connection; it "set lock" and didn't auto-recover. Detection *appeared* broken —
but `wazuh-logtest` still fired the rule, because logtest runs locally on the
manager and doesn't need the agent.
**Lesson:** **`logtest` success ≠ live detection**; live detection also requires
the agent→manager link. Confirm with `agent_control -l` showing the agent
**Active**.

### 10. Alert-volume flood exhausting the SOAR webhook
Once Suricata was flowing, a low forwarding threshold (`<level>7</level>`) pushed a
flood of low-value alerts to Shuffle (~1+/sec), likely exhausting the SaaS
execution quota so no workflow runs appeared.
**Fix:** forward only curated rule **groups** instead of a broad level.
**Lesson:** forward signal, not noise — tune what reaches the SOAR layer.

### 11. Suricata stats noise
Suricata emitted large `event_type: stats` records every few seconds, flooding
logs and adding decoder load. Disabled via `stats: enabled: no`.

### 12. TheHive API key auth not enabled
A valid API key still returned 401 because the `key` auth provider wasn't enabled
on TheHive. The `WWW-Authenticate: Basic` response header was the tell.
**Fix:** add `{name: key}` to `auth.providers` in `application.conf`. (Basic auth
worked as an interim fallback.)

### 13. HTTP node timeout bound to a variable
The Shuffle HTTP node's connection-timeout field was accidentally set to a
VirusTotal variable that resolved to `0` (`timeout cannot be ≤ 0`).
**Fix:** set it to a plain `30`.

---

## What this log demonstrates

Taken together these span the whole stack: network sensor placement, SIEM decoder
internals, Windows vs. Linux log sources, rule syntax, SOAR schema handling, agent
connectivity, alert tuning, and API authentication. The recurring theme — and the
most useful takeaway — is that **a working demo and a working pipeline are
different things**: `logtest` passing, a rule validating, or a node returning 200
each prove only one link, and end-to-end detection requires every link at once.
