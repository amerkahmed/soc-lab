# Scenario 02 — [High] Phishing Investigation → IOC Detection → SOAR Enrichment

A Tier-1 phishing investigation, end to end: a reported email is analyzed, its
IOCs are extracted and operationalized into a watchlist, and when a host connects
to the phishing server the detection fires, enriches, and lands an analyst-ready
alert in TheHive. The workflow mirrors how an L1 analyst actually handles a
user-reported phish — **analyze → extract → "did anyone click?" → contain** — and
each step is mapped only to the technique its own evidence supports.

> **Status: redesigned 2026-10-27 — evidence recapture pending.** This scenario was
> restructured around a **lab-owned phishing server** (`192.168.56.99`) so the IOC
> is real and reachable within the lab, replacing the earlier
> documentation-IP-plus-attacker-IP stand-in. The pipeline (Wazuh → Shuffle →
> VirusTotal → TheHive) is unchanged in shape; screenshots and alert JSON are being
> recaptured against the new design. Evidence files referenced below marked _(recapture)_
> are regenerated on the re-run.

| | |
|---|---|
| **MITRE ATT&CK** | T1566.002 (Spearphishing Link) — represented by the analyzed sample · T1204.001 (User Execution: Malicious Link) — **simulated** via a `curl` "click" · the detection itself observes the resulting outbound connection |
| **Phishing server (lab IOC)** | `192.168.56.99` — a lab-owned host serving a fake login page (its own IP, separate from the Kali attacker `192.168.56.10`) |
| **Detection source** | Suricata http event → Wazuh custom rule 100100 (CDB watchlist match) |
| **Automation** | Wazuh → Shuffle → VirusTotal → TheHive (IOC attached as an observable) |
| **Status** | ⏳ Rebuilt; detection → SOAR → TheHive alert re-run pending |

---

## 1. Report intake

The investigation starts the way most real ones do: a user forwards a suspicious
email (`config/paypal_phish.eml`) to the SOC. The analyst's first job is not to
decide guilt but to **analyze the artifact** and extract anything that can be
turned into detection.

---

## 2. Email analysis (analyst, manual)

Analyzed on Kali with `emlAnalyzer` plus manual header inspection:

```bash
emlAnalyzer -i paypal_phish.eml --header --html --url --text
```

The sample carries the classic deception markers an L1 analyst is trained to spot:

- **Typosquatted sender** — `service@paypa1-secure.com` (the "1" is a digit, not
  the letter "l").
- **Mismatched Reply-To** — `collect@mail.ru`, unrelated to the apparent sender.
- **Urgency / social engineering** — "verify within 24 hours or permanently
  suspended".
- **Credential-harvesting URL on a raw IP over HTTP** —
  `http://192.168.56.99/paypal/login/verify.php`.

**Why authentication results are not the deciding factor.** The sample is crafted
so SPF/DKIM/DMARC **pass** — because the attacker *owns* the lookalike domain and
can publish valid records for it. This is the point an L1 analyst has to internalize:
a DMARC pass authenticates the *sending domain*, not the message's intent, and
[DMARC does not stop lookalike / "cousin" domains](https://www.m3aawg.org/TechnologySummaries/DMARC).
The verdict rests on the **typosquat, the Reply-To mismatch, and the raw-IP harvest
URL**, not on an SPF result.

**Extracted IOCs (defanged):**
- Sender domain: `paypa1-secure[.]com`
- Reply-To: `collect@mail[.]ru`
- URL: `hxxp://192[.]168[.]56[.]99/paypal/login/verify[.]php`
- IP: `192[.]168[.]56[.]99`

**Verdict (analysis stage):** Confirmed phishing sample — this is the
**T1566.002 (Spearphishing Link)** artifact. The technique is evidenced by the
email itself, not by an observed delivery through a mail system (the lab has no
mail server; the email is a crafted training sample).

> _Evidence (recapture): `evidence/scenario-02-phishing/emlanalyzer-output.txt`,
> `eml-analysis.png`_

---

## 3. Operationalize the IOC (analyst → engineer)

The extracted IP is turned into a live detection — the analyst-to-engineer step
that makes threat intel useful.

**CDB list** (`config/phishing-iocs`, deployed to `/var/ossec/etc/lists/`):
```
192.168.56.99:phishing_infrastructure
```
Registered in `ossec.conf` under `<ruleset>` as
`<list>etc/lists/phishing-iocs</list>`. CDB lists are built when the analysis
engine starts, so the manager is restarted after any change
([Wazuh docs](https://documentation.wazuh.com/current/user-manual/ruleset/cdb-list.html)).

Because the phishing server has its **own** IP (not the attacker's), the watchlist
needs a single, real entry — no documentation-IP placeholder and no attacker-IP
stand-in.

**Custom rule 100100** (`config/local_rules.xml`):
```xml
<group name="phishing,ioc,">
  <rule id="100100" level="12">
    <if_sid>86602</if_sid>
    <list field="dest_ip" lookup="address_match_key">etc/lists/phishing-iocs</list>
    <description>Connection to known phishing infrastructure (IOC match)</description>
    <mitre>
      <id>T1204.001</id>
    </mitre>
  </rule>
</group>
```

Plain-English, line by line:
- `if_sid 86602` — builds on Wazuh's **built-in Suricata HTTP rule** (86602, a child
  of the base 86600), which already matches only `event_type: http` events — logged
  by Suricata **per HTTP request**, so the rule fires in **near-real-time (~1–2 s)**
  rather than waiting ~60 s for a flow record. Chaining off 86602 (not 86600) is
  deliberate: Wazuh has a specific built-in child of 86600 per event type
  (86601 alert / 86602 http / 86603 dns / 86604 tls), and the specific one pre-empts
  a custom sibling hung off 86600 — so an `if_sid 86600 + event_type=http` rule never
  fires on http events (it loses to 86602). This was found with `wazuh-logtest` and
  is written up in [challenges-and-resolutions.md](../challenges-and-resolutions.md),
  item 16. A per-packet alert produces no http event, so it can't trip the rule
  (see §3a); §10 covers the specificity-vs-coverage choice.
- `list field="dest_ip" lookup="address_match_key"` — checks the http event's
  destination IP against the CDB watchlist. `address_match_key` is the lookup
  Wazuh's docs require **for IP-address fields** (the old rule used the plain
  `match_key`, which is for exact string keys).
- `level 12` — high importance; it reaches Shuffle because the rule is in the
  `phishing` group, which the integration forwards **by group**
  (`config/ossec-integration.xml`), not by level.
- **MITRE `T1204.001`** — the rule observes the *outbound connection* that follows
  a click, i.e. User Execution: Malicious Link. It does **not** by itself prove
  T1566 (that the message was phishing); that evidence comes from the email
  analysis in §2. Mapping the connection to T1566 alone would be
  [leaping to conclusions](https://www.cisa.gov/sites/default/files/2023-01/Best%20Practices%20for%20MITRE%20ATTCK%20Mapping.pdf) —
  inferring a technique the single artifact does not establish.

### 3a. Tuning exercise — an over-broad rule, and a reproducible fix

Detection engineering is mostly tuning, so the rule is built in two iterations and
the false-positive step is made **reproducible on demand** rather than just
asserted.

**Why the rule can over-match.** Base rule 86600 matches **every** Suricata event
type — per-packet signature **alerts**, protocol events (`http`/`dns`/`tls`), and
connection **flows** alike (verified against Wazuh's ruleset source). A naive rule
that only checks `dest_ip` with `match_key`, and no event-type scope, therefore
fires on *any* event whose destination is the IOC — including a per-packet decoder
alert, not just the connection that represents an actual callback.

**Where this first showed up (history).** In an earlier build the IOC stand-in was
the Kali attacker's own IP. When the attacker scanned the victim, the target's
**ICMP echo replies** (SID 2200025 — the same alert as Scenario 01) were addressed
*to* that IP, so their top-level `dest_ip` matched the watchlist and fired the
phishing rule (level 12) on scan traffic — a false positive captured in
`wazuh-100100-FALSE-POSITIVE-icmp.json`. That specific trigger depended on the
attacker IP doubling as the IOC; with the phishing server on its own IP
(`192.168.56.99`) it no longer recurs naturally, which is exactly why the fix is
validated deterministically below rather than by waiting for it to happen again.

**Reproduce the over-match on demand (deterministic).** Feed the manager two
labeled test events for the IOC — one a per-packet `alert`, one an `http`
transaction (the callback) — and compare what each rule version matches:

```bash
# Both events target the IOC. SYNTHETIC — no traffic is sent anywhere.
TS=$(date -u +%Y-%m-%dT%H:%M:%S.000000+0000)
# (1) a per-packet ALERT event to the IOC (what a stray signature/probe looks like)
echo "{\"timestamp\":\"$TS\",\"in_iface\":\"enp0s3\",\"event_type\":\"alert\",\"src_ip\":\"192.168.56.20\",\"dest_ip\":\"192.168.56.99\",\"proto\":\"ICMP\",\"alert\":{\"signature\":\"SYNTHETIC test alert\",\"signature_id\":9999999},\"lab_note\":\"SYNTHETIC\"}" | sudo tee -a /var/log/suricata/eve.json
# (2) an HTTP transaction event to the IOC (the real callback)
echo "{\"timestamp\":\"$TS\",\"in_iface\":\"enp0s3\",\"event_type\":\"http\",\"src_ip\":\"192.168.56.20\",\"dest_ip\":\"192.168.56.99\",\"dest_port\":80,\"proto\":\"TCP\",\"http\":{\"hostname\":\"192.168.56.99\",\"url\":\"/paypal/login/verify.php\"},\"lab_note\":\"SYNTHETIC\"}" | sudo tee -a /var/log/suricata/eve.json
```

Result — confirmed with `wazuh-logtest`, then captured live:

- **Naive rule** (`if_sid 86600`, `match_key`, no event-type scope) is **doubly
  wrong**: on the per-packet **alert** event it fires `100100` (level 12) — a false
  positive on scan/ICMP traffic — and on the real **http** callback it does **not**
  fire at all, because Wazuh's built-in `86602` (http) pre-empts it (first matching
  child wins; see item 16). So it alerts on the wrong thing *and* misses the right
  thing.
- **Scoped rule** (`if_sid 86602`, child of Suricata's http rule, + `address_match_key`,
  as deployed) is correct on both: the alert event matches `86601` and never reaches
  `100100` (no false positive), while the real http callback fires `100100`.

**Why not just `proto=TCP`?** An earlier band-aid added `<field name="proto">TCP</field>`
to a packet-level match to stop the ICMP hit. Scoping to the **event type** — the
HTTP transaction that *is* the callback — fixes the confusion at its root instead of
filtering by a packet field. (Choosing `http` over the broader `flow` is a
deliberate specificity-vs-coverage call; see §10.)

**Lesson:** a rule can fire on the right indicator and still be scoped wrong — here
it matched a per-packet *alert* when it meant the *HTTP transaction*. Scope to the
event type that represents what you actually mean, and validate the fix with a
deterministic test rather than hoping the false positive recurs. See
[challenges-and-resolutions.md](../challenges-and-resolutions.md), item 14.

> _Evidence (recapture): `wazuh-100100-FALSE-POSITIVE-icmp.json` (over-match on an
> alert event) vs `wazuh-100100-alert.json` (http-scoped match) — regenerated with
> the two-event test above._

---

## 4. "Did anyone click?" — the detection (T1204.001, simulated)

With the watchlist live, the question an analyst asks next is **did any host
actually reach the phishing server?** In the lab, the click is simulated from the
victim with a `curl` to the lab-owned server (standing in for a user following the
link):

```bash
curl -m 5 http://192.168.56.99/paypal/login/verify.php
```

That request produces a Suricata **http** transaction event, which Wazuh matches
against the watchlist in near-real-time (~1–2 s). Expected alert (to be captured on
the re-run):

```
** Alert <event-id>:
Rule: 100100 (level 12) -> 'Connection to known phishing infrastructure (IOC match)'
  mitre.id: ["T1204.001"]
  event_type: http   src_ip: 192.168.56.20   dest_ip: 192.168.56.99   dest_port: 80
  proto: TCP   http.url: /paypal/login/verify.php
```

A watchlist hit on the HTTP callback is deterministic, high-signal evidence: an
internal host reached infrastructure the team had already flagged. It answers "did
someone click" with a yes — it does **not** yet prove credentials were submitted
(see §6).

> _Evidence (recapture): `wazuh-100100-alert.json`_

---

## 5. SOAR automation (Wazuh → Shuffle → VirusTotal → TheHive)

The level-12 alert is forwarded by the manager's Shuffle integration (by rule
group) to the workflow:

1. **Webhook** receives the alert.
2. **VirusTotal node** looks up the alert's `dest_ip`.
3. **HTTP request node** POSTs a hand-built JSON body to TheHive's
   `/api/v1/alert`, and **attaches the IOC as an observable** on the alert, so the
   analyst gets an actionable, pivot-ready indicator rather than just a description.
   Returns **HTTP 201 Created**.

> _Evidence (recapture): `shuffle-run-201.png`, `thehive-alert.png`,
> `shuffle-workflow.png`_

### 5a. Enrichment on the live run

The real IOC here is a **private lab IP** (`192.168.56.99`), so VirusTotal has
nothing to report on it — a correct, expected result, not a pipeline failure. On
the live run, the value the pipeline adds is the **attached observable and the
analyst-ready alert**, not external reputation.

### 5b. Enrichment capability — labeled synthetic test

To show what VirusTotal enrichment *produces* for genuinely malicious
infrastructure — without ever sending traffic to a real C2 — a **clearly labeled
synthetic http event** carrying a real known-bad IP is injected into the pipeline
and run through the same Wazuh → Shuffle → VirusTotal → TheHive path:

```bash
# SYNTHETIC — no traffic is sent to the IP; this is a pipeline validation test only
TS=$(date -u +%Y-%m-%dT%H:%M:%S.000000+0000)
echo "{\"timestamp\":\"$TS\",\"in_iface\":\"enp0s3\",\"event_type\":\"http\",\"src_ip\":\"192.168.56.20\",\"dest_ip\":\"<known-bad-ip>\",\"dest_port\":80,\"proto\":\"TCP\",\"http\":{\"hostname\":\"<known-bad-ip>\",\"url\":\"/\"},\"lab_note\":\"SYNTHETIC TEST EVENT\"}" | sudo tee -a /var/log/suricata/eve.json
```

This follows the detection-engineering convention of validating an alert with a
representative, labeled test input (cf.
[Palantir's ADS framework](https://github.com/palantir/alerting-detection-strategy-framework),
which requires a true-positive validation step). The VirusTotal screenshot is a
**manual web lookup** shown only to illustrate the enrichment fields — it is not
output of the live pipeline.

> _Evidence (recapture): `shuffle-run-201.png` (synthetic run), `virustotal-enrichment.png`
> (manual lookup, clearly labeled)_

---

## 6. Triage & verdict

The analyst-ready alert lands in TheHive with the IOC attached:

- **IOC match** — rule 100100 fired because a host's HTTP request matched the
  `phishing_infrastructure` watchlist entry. Deterministic, high-signal: an
  internal host reached flagged infrastructure.
- **Direction & context** — *outbound*, from an internal victim to the phishing
  server over HTTP. In the phishing chain this is the post-click callback
  (T1204.001), simulated here by the `curl`.
- **What it does and doesn't prove** — the match proves the **connection
  happened**; it does not prove credentials were submitted. That is the first thing
  to establish on the host.

**Verdict:** True positive — confirmed contact with known-bad infrastructure.
Confidence that the connection occurred: **High** (an exact CDB match). Confidence
that it was malicious depends on the indicator's source and age — an IP is the
[easiest indicator for an attacker to change](https://flashpoint.io/blog/the-pyramid-of-pain-and-cyber-threat-intelligence/),
so a stale or shared IP could match benign traffic; here the IOC is freshly
extracted from the analyzed sample, which is why confidence is high.

> _Evidence (recapture): `thehive-alert.png` (alert with observable attached)_

---

## 7. Response

- **Automatable — block egress to the IOC.** Blocking the *destination* (the
  phishing server) is low-risk: it stops further callbacks, and unlike a spoofable
  scan source (Scenario 01), the block target is the known-bad infrastructure
  itself.
- **Human-in-the-loop — investigate the host and user.** Determine whether the link
  was clicked and whether credentials were entered on the harvest page. Pull the
  list of other recipients (in a real environment, from the mail gateway) and check
  whether any other host connected to the IOC. If submission is suspected,
  force-reset the user's credentials and treat the account as compromised.
- **Close the loop.** Any related indicators are added back to the CDB watchlist —
  turning the investigation's output into new automated detection.

See the tiered response model in
[architecture.md §7](../architecture.md#7-response-strategy-tiered-model).

---

## 8. MITRE ATT&CK mapping (evidence-based)

| Stage | Technique | Evidence it rests on |
|---|---|---|
| The reported email | **T1566.002** Spearphishing Link | The analyzed sample (§2) — typosquat, Reply-To mismatch, raw-IP harvest URL |
| The simulated click → outbound connection | **T1204.001** Malicious Link (simulated) | The Suricata http event to the phishing server, matched by rule 100100 (§4) |

Each row is mapped only to the technique its own artifact establishes — the email
to the phishing technique, the connection to the user-execution technique — rather
than inferring the whole phishing chain from a single network event
([CISA ATT&CK mapping best practices](https://www.cisa.gov/sites/default/files/2023-01/Best%20Practices%20for%20MITRE%20ATTCK%20Mapping.pdf)).

---

## 9. The complete workflow

```
User reports email  →  analyst analyzes it (T1566.002)  →  IOCs extracted
   →  IP added to Wazuh CDB watchlist
   →  simulated click: host makes an HTTP request to the phishing server
   →  Suricata http event → Wazuh rule 100100 matches the watchlist (T1204.001)
   →  alert forwarded to Shuffle → VirusTotal lookup → TheHive alert (IOC attached)
   →  analyst triages, contains, and feeds new indicators back to the watchlist
```

---

## 10. Lessons Learned

- **Own your lab infrastructure.** Giving the phishing server a real, reachable IP
  of its own removed the documentation-IP placeholder and the attacker-IP stand-in,
  so the one false positive left is a *deliberate, reproducible* tuning exercise
  (§3a) rather than an artifact of a shared IP.
- **Map to evidence, not to the story.** The email proves T1566.002; the connection
  proves T1204.001. A single network event does not prove "phishing" on its own.
- **Match the event type that *is* the behavior.** Scoping rule 100100 to the
  Suricata **http** transaction (not any event with a matching `dest_ip`) fixed the
  over-match *and* made the detection near-real-time. Use `address_match_key` for IP
  fields. Tuning false positives is core SOC work, so the before/after is kept
  reproducible on demand.
- **Specificity vs coverage — a deliberate call.** `http` matches the credential-
  harvest callback precisely and fires in ~1–2 s, where a `flow` record would add
  ~60 s of flow-timeout latency. The trade-off is coverage: a **non-HTTP callback
  (TLS/DNS/other) is a blind spot** — a `flow`-scoped rule would be the protocol-
  agnostic backstop, at the cost of latency and more noise. For this HTTP scenario,
  specificity wins; the gap is documented rather than papered over. (A later refinement
  could confirm the server's HTTP `200` response to detect a *successful* callback.)
- **Authentication results don't decide phishing.** SPF/DKIM/DMARC can all pass for
  a lookalike domain the attacker owns; the content indicators are what matter.
- **Enrich honestly.** A private IOC yields nothing from VirusTotal — say so. Show
  the enrichment *capability* with a clearly labeled synthetic test, never by
  touching real malicious infrastructure.
