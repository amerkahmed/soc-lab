# Challenges & Resolutions

Real engineering problems solved while building this lab — each an actual issue
that broke the pipeline, with the diagnosis and fix. This kind of troubleshooting
is most of SOC engineering.

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

### 14. Phishing rule over-matched (false positive → reproducible tuning fix)
Base rule 86600 matches **every** Suricata event type — per-packet signature
**alerts**, protocol events, and connection **flows**. Custom rule 100100 first
checked only `dest_ip` (`match_key`) with no event-type scope, so it fired on *any*
event whose destination was the IOC, not just the callback connection. The original
misfire: an early build used the Kali attacker IP as the IOC stand-in, so the
target's **ICMP echo replies** to a scan (SID 2200025) were addressed to that IP
and tripped the phishing rule (level 12) on scan traffic.
**Band-aid (first fix):** `<field name="proto">TCP</field>` on a packet-level match
stopped the ICMP hit but filtered by a packet field rather than fixing the scope.
**Fix (now):** scope to `event_type: http` (match the HTTP transaction that *is* the
callback, not a per-packet alert), use `address_match_key` for the IP field, and
give the phishing server its own IP (`192.168.56.99`). `http` also fires in
near-real-time (~1–2 s) vs ~60 s for a flow record; the non-HTTP coverage gap is a
documented blind spot (Scenario 02 §10).
**Reproducibility:** the shared-IP trigger no longer recurs naturally once the IOC
has its own IP, so the fix is validated deterministically by feeding two labeled
test events (one `alert`, one `http`) for the IOC and confirming the naive rule
matches both while the scoped rule matches only the http event (Scenario 02 §3a).
**Lesson:** a rule can fire on the right indicator and still be scoped wrong — scope
to the event type that represents what you mean, and validate with a deterministic
test. Evidence: `evidence/scenario-02-phishing/wazuh-100100-FALSE-POSITIVE-icmp.json`
vs `wazuh-100100-alert.json` (recapture).

### 15. Enabled ET SCAN rules could never fire on the attacker (`HOME_NET` scope)
A re-test of Scenario 01 found plain SYN (`-sS`) and version (`-sV`) scans produced
**zero** Suricata alerts; only Nmap's OS-detection ICMP probe tripped Suricata's
built-in decoder rule (SID 2200025). The cause: Suricata's default `HOME_NET`
(`[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]`) included Kali, and `EXTERNAL_NET`
is `!$HOME_NET`. Of 274 enabled ET SCAN rules, 237 match only traffic from
`$EXTERNAL_NET` — e.g. `ET SCAN NMAP OS Detection Probe` is
`alert udp $EXTERNAL_NET 10000: -> $HOME_NET 10000:` — so they were loaded but
could never match the attacker.
**Fix:** scope `HOME_NET` to the victim hosts (`[192.168.56.20,192.168.56.30]`),
modeling Kali as external. After the fix: `-sS` 5 alerts, `-sV` 4, `-A` 45 across
8 signatures (including SID 2018489).
**Lesson:** a loaded rule is not a working rule — variable scoping can silently
disable most of a ruleset. Validate with real traffic and count alerts per
signature. A SYN scan of ports 1–1000 is still undetected (documented as a blind
spot in Scenario 01 §6).
**Also hit during the re-test:** Nmap 7.991 aborted in its reverse-DNS resolver
(`massdns.cc … Assertion 'new_reqs.empty()' failed`); `-n` (no reverse DNS) avoids
it without changing the traffic sent to the target.

---

## What this log demonstrates

Taken together these span the whole stack: network sensor placement, SIEM decoder
internals, Windows vs. Linux log sources, rule syntax, SOAR schema handling, agent
connectivity, alert tuning, and API authentication. The recurring theme — and the
most useful takeaway — is that **a working demo and a working pipeline are
different things**: `logtest` passing, a rule validating, or a node returning 200
each prove only one link, and end-to-end detection requires every link at once.
