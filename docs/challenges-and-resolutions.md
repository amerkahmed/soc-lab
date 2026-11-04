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
The Shuffle→TheHive JSON body referenced `$exec.text`, which maps from Wazuh's
**`full_log`** — and `full_log` is not consistently typed. It is **absent/empty**
for some rules (e.g. the 4740 lockout `60115` and the LSASS-access `92900` carry
none), a **plain string** only for journald/syslog alerts (sshd — `5712`), and a **JSON
object** for JSON-sourced events: Suricata `eve.json` (`100100`) **and** the Windows
eventchannel `4624` (`92657`/`92653`), which the SOAR parses to a nested
`win.system`/`win.eventdata` object (`shuffle-rdp-compromise.png`). Inserting the object form shattered the hand-built JSON body
(`invalid decimal literal`).
**Fix:** build the body only from consistently-typed scalar fields (`title`,
`rule_id`, `id`) and never the variable-shaped `full_log`/`text` blob.
**Lesson:** SOAR templates must be resilient to differing alert schemas — the same
field can be missing, a string, or a nested object depending on the rule and the log
source. (It's the same mechanism behind the Shuffle `text` reading `NULL` for
`60115`/`92900` while other alerts carry it.)

**One remaining `text` use (by design).** The phishing body still reads
`$exec.text.dest_ip` for the IOC observable. It resolves there because rule 100100's
`full_log` is the Suricata **http** event (a JSON object), so `dest_ip` is present in
`text` — evidenced by the live VT lookup on `192.168.56.99` (`thehive-alert-real.png`).
The SSH and other bodies already use `$exec.all_fields.*`; migrating the phishing body
to `$exec.all_fields.data.dest_ip` is the robust follow-up, since `text` is empty when
the node is run outside a real `100100` execution.

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
On this instance (**TheHive 5.8.0**), a valid API key still returned 401 because the
`key` auth provider wasn't active in `auth.providers`. The `WWW-Authenticate: Basic`
response header was the tell.
**Fix:** add `{name: key}` to `auth.providers` in `application.conf` (alongside
`local`/`session`); Basic auth worked as an interim fallback.
**Note:** whether `key` ships in the default `auth.providers` varies by version and
install, so this is recorded as observed on our instance, not as a universal default.

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
test events (one `alert`, one `http`) for the IOC: the naive rule fires `100100` on
the alert event (the false positive) and the scoped rule fires only on the http
callback. (The naive rule also *misses* the http callback — built-in 86602 pre-empts
it, see item 16 — so it is both noisy and blind; Scenario 02 §3a.)
**Lesson:** a rule can fire on the right indicator and still be scoped wrong — scope
to the event type that represents what you mean, and validate with a deterministic
test. Evidence: `evidence/scenario-02-phishing/wazuh-100100-FP-synthetic.json`
vs `wazuh-100100-alert.json` (recapture).

### 15. Enabled ET SCAN rules could never fire on the attacker (`HOME_NET` scope)
A re-test of Scenario 01 found plain SYN (`-sS`) and version (`-sV`) scans produced
**zero** Suricata alerts; only Nmap's OS-detection ICMP probe tripped Suricata's
built-in decoder rule (SID 2200025). The cause: Suricata's default `HOME_NET`
(`[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]`) included Kali, and `EXTERNAL_NET`
is `!$HOME_NET`. Of 274 enabled ET SCAN rules (ET Open, as of Oct 2026), 232 match
only traffic from `$EXTERNAL_NET` — e.g. `ET SCAN NMAP OS Detection Probe` is
`alert udp $EXTERNAL_NET 10000: -> $HOME_NET 10000:` (SID 2018489 rev 4) — so they
were loaded but could never match the attacker.
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

### 16. Custom http rule never fired — a built-in sibling pre-empted it
After switching rule 100100 to match HTTP events, it was written as
`if_sid 86600` + `<field name="event_type">^http$</field>`. `wazuh-logtest` on a
synthetic http event showed it matching **86602** ("Suricata: HTTP", level 0) — the
custom rule never fired. Cause: Wazuh's Suricata ruleset has a specific built-in
child of base rule 86600 for each event type (86601 alert, 86602 http, 86603 dns,
86604 tls). Because 86602 is **level 0**, OSSEC evaluates it before higher-level rules
(a level-0 match ends evaluation), so for an http event a custom rule hung off the same
parent 86600 is never reached. (The earlier flow-based
version worked only because there is **no** built-in flow rule, so the custom rule
was the sole matching child.)
**Fix:** chain the custom rule off the specific event-type rule —
`<if_sid>86602</if_sid>` — so 100100 is a child of the http rule and is evaluated
whenever 86602 matches. The redundant `event_type` field is dropped (86602 already
enforces it).
**Lesson:** when extending Wazuh's built-in decoders, build on the **most specific**
rule that already matches your event, not the generic base — and confirm with
`wazuh-logtest` which rule actually fires, since a silent pre-emption looks exactly
like "my rule is broken." Non-HTTP IOC callbacks would chain off 86604 (tls) / 86603
(dns) the same way.

### 17. Custom Sysmon rule passed logtest but never fired live (parentless rule kept the default SYSLOG category)
Custom rule 100002 (Mimikatz by PE `OriginalFileName`) passed `wazuh-logtest` but
produced **no live alert** on real Sysmon Event ID 1 traffic. It was written
**parentless** — matching `providerName` + `eventID` + `originalFileName` fields
with no `<if_group>`/`<if_sid>`. analysisd routes events to rules by **category**: it
only evaluates a top-level rule when the rule's category matches the event's decoder
type (*"categories must match"*, `analysisd.c`). A parentless custom rule keeps the
default category **SYSLOG**, while agent-forwarded Sysmon events decode as **windows**
(`DECODER_WINDOWS`), so the rule was never reached on them — even though the fields
decoded correctly. `wazuh-logtest` applies the **same** category gate (`logtest.c`), so
a logtest pass reflects how the event decoded in that run, not a rule being exempt from
the live routing.
**Misdiagnosis corrected:** an earlier write-up blamed a *missing* `sysmon_event1`
group. That was wrong — built-in rule **61603** decodes Sysmon EID 1 and **does**
assign the `sysmon_event1` group.
**Fix:** anchor the rule with `<if_group>sysmon_event1</if_group>` so it becomes a
child of the Sysmon process-creation tree and is evaluated on every EID-1 event.
After the fix, 100002 fired live (event `1793500464.18771518`, level 15, T1003)
alongside the behavioral LSASS rule 92900 — see Scenario 05 §2b.
**Lesson:** `logtest` success ≠ live detection (again) — a parentless rule keeps
category SYSLOG and is skipped by the top-level category gate on Windows events.
Anchor custom Sysmon rules to the Sysmon tree (child of 61603 → `sysmon_event1`),
or they silently never fire.

### 18. SOAR → TheHive runs over plaintext HTTP (lab limitation, flagged for hardening)
The Shuffle HTTP node posts alerts to TheHive at `http://<THEHIVE_IP>:9000/api/v1/alert`
with an `Authorization: Bearer` header. On the isolated lab backend this is
functional, but the API key travels **in cleartext** — if the pipeline were exposed
beyond the host-only segment, the token could be sniffed.
**Status:** accepted as a known lab risk. The SOAR runs on **Shuffle Cloud** (SaaS),
so the alert POST travels from Shuffle's cloud to the TheHive host across the public
internet — the bearer token is exposed on that hop, not confined to a host-only
segment. The key is held in Shuffle's cache (`$shuffle_cache.hive-key.value`), not
hardcoded in the exported workflow, so it is not in this repo. **Production hardening** would terminate
TLS in front of TheHive (a reverse proxy on `:443`) and switch the node to `https://`,
keeping the token off the wire.
**Lesson:** a working automation and a *secure* automation are different — transport
security is part of the pipeline design, not an afterthought.

---

## What this log demonstrates

Taken together these span the whole stack: network sensor placement, SIEM decoder
internals, Windows vs. Linux log sources, rule syntax, SOAR schema handling, agent
connectivity, alert tuning, and API authentication. The recurring theme — and the
most useful takeaway — is that **a working demo and a working pipeline are
different things**: `logtest` passing, a rule validating, or a node returning 200
each prove only one link, and end-to-end detection requires every link at once.
