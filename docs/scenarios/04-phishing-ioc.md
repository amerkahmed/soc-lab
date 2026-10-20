# Scenario 04 — Phishing Analysis → IOC Detection → SOAR Enrichment

The flagship scenario: it ties email analysis, threat-intel-driven detection, and
full SOAR automation into one end-to-end story.

| | |
|---|---|
| **MITRE ATT&CK** | T1566 (Phishing) — with T1598 (info gathering), T1204.001 (user clicks link) |
| **Attacker infra (lab IOC)** | 203.0.113.17 (reserved documentation IP, RFC 5737) |
| **Detection source** | Suricata flow → Wazuh custom rule 100100 (CDB match) |
| **Automation** | Wazuh → Shuffle → VirusTotal → TheHive |
| **Status** | ✅ Validated (detection + SOAR pipeline); enrichment display finalizing |

---

## 1. The phishing sample

A realistic phishing email (`config/paypal_phish.eml`) was crafted to practice
analysis. It deliberately contains the classic deception techniques:

- **Typosquatted sender** — `service@paypa1-secure.com` (the "1" is a digit, not
  the letter "l").
- **Mismatched Reply-To** — `collect@mail.ru`, unrelated to the apparent sender.
- **Urgency / social engineering** — "verify within 24 hours or permanently
  suspended".
- **Credential-harvesting URL on a raw IP over HTTP** —
  `http://203.0.113.17/paypal/login/verify.php`.
- **Failed authentication headers** — `spf=fail`, `dkim=none`,
  `dmarc=fail (p=reject)`.

---

## 2. Analysis & IOC extraction

Analyzed on Kali with `emlAnalyzer` plus manual header inspection:

```bash
emlAnalyzer -i paypal_phish.eml --header --html --url --text
```

The analysis surfaced every planted indicator — the typosquat, the Reply-To
mismatch, the SPF/DKIM/DMARC failures, the `Received`-chain origin IP, and the
raw-IP HTTP harvesting URL.

**Extracted IOCs (defanged):**
- Sender domain: `paypa1-secure[.]com`
- Reply-To: `collect@mail[.]ru`
- URL: `hxxp://203[.]0[.]113[.]17/paypal/login/verify[.]php`
- IP: `203[.]0[.]113[.]17`

> _Evidence: `evidence/scenario-04-phishing/emlanalyzer-output.txt`_

---

## 3. Operationalizing the IOC in Wazuh (threat intel → detection)

The extracted IP was turned into a live detection — the analyst-to-engineer step.

**CDB list** (`config/phishing-iocs`, deployed to `/var/ossec/etc/lists/`):
```
203.0.113.17:phishing_infrastructure
```
Registered in `ossec.conf` under `<ruleset>` as
`<list>etc/lists/phishing-iocs</list>`.

**Custom rule 100100** (`config/local_rules.xml`):
```xml
<group name="phishing,ioc,">
  <rule id="100100" level="12">
    <if_sid>86600</if_sid>
    <list field="dest_ip" lookup="match_key">etc/lists/phishing-iocs</list>
    <description>Connection to known phishing infrastructure (IOC match)</description>
    <mitre>
      <id>T1566</id>
    </mitre>
  </rule>
</group>
```

The rule fires when any Suricata event's **`dest_ip`** matches an entry on the CDB
list — i.e. any connection to known phishing infrastructure.

---

## 4. Detonation & detection (validated)

Connecting to the IOC from the victim produced a Suricata flow record, which
Wazuh matched against the list. Confirmed live on the manager:

```
** Alert 1791847443.16785448:
Rule: 100100 (level 12) -> 'Connection to known phishing infrastructure (IOC match)'
  mitre.id: ["T1566"]  mitre.tactic: ["Initial Access"]  mitre.technique: ["Phishing"]
  event_type: flow   src_ip: 192.168.56.20   dest_ip: 192.168.56.10   dest_port: 80
  firedtimes: 4   mail: true
```

> _Evidence: `evidence/scenario-04-phishing/wazuh-100100-alert.json`_

---

## 5. SOAR automation (Wazuh → Shuffle → VirusTotal → TheHive)

The level-12 alert is forwarded by the manager's Shuffle integration to a Shuffle
workflow:

1. **Webhook** receives the alert.
2. **VirusTotal node** looks up the IP and returns detection stats (HTTP 200).
3. **HTTP request node** POSTs a hand-built JSON body to TheHive's
   `/api/v1/alert`, embedding selected VT fields (malicious count, country,
   owner) in the description. Returns **HTTP 201 Created**.

> _Evidence: `evidence/scenario-04-phishing/shuffle-run-201.png`,
> `evidence/scenario-04-phishing/thehive-alert.png`_

**Honesty note (keep this in the writeup):** the lab IOC `203.0.113.17` is a
reserved documentation address, so VirusTotal legitimately returns "clean" for
it. To demonstrate real enrichment output, the VT lookup is shown against a
genuinely malicious IP sourced from a public threat feed (abuse.ch), verified on
VirusTotal, and the lab IOC is documented as synthetic. "Known-bad" in the CDB
list means known-bad *within this lab's own threat intel* — which is exactly how
real watchlists work.

---

## 6. The complete kill-chain narrative

```
Phishing email analyzed  →  IOCs extracted  →  IP added to Wazuh CDB watchlist
   →  connection to IOC detected on the wire (Suricata)
   →  Wazuh rule 100100 matches the watchlist (level 12, T1566)
   →  alert forwarded to Shuffle
   →  Shuffle enriches the IOC via VirusTotal
   →  enriched alert created in TheHive for the analyst
```

This is the full detect → enrich → escalate loop, and it demonstrates the thing
most home labs never reach: turning the output of an investigation (IOCs) back
into automated detection content.

---

## 7. Lessons Learned

- **Threat intel is only useful once operationalized.** Extracting IOCs is step
  one; the value is loading them into a watchlist that fires automatically.
- **Field names are decoded, not raw.** Wazuh decodes Suricata's `dest_ip` as
  top-level `dest_ip`, not `data.dest_ip`; `wazuh-logtest` was the tool that
  confirmed the real field name. See
  [challenges-and-resolutions.md](../challenges-and-resolutions.md), item 6.
- **SOAR templates must tolerate differing alert schemas.** The TheHive body
  broke when it referenced a field (`$exec.text`) that is a string on host alerts
  but an object on Suricata alerts. Building the body only from consistently-typed
  fields fixed it. See item 8.
- **Forward signal, not noise.** An over-broad forwarding threshold flooded the
  SOAR webhook; filtering by rule *group* fixed it. See item 10.
