# Scenario 03 — [Medium] SSH Brute Force

| | |
|---|---|
| **MITRE ATT&CK** | T1110 (Brute Force) |
| **Attacker** | Kali — 192.168.56.10 |
| **Target** | Ubuntu — 192.168.56.20 |
| **Detection source** | Wazuh agent → journald (sshd) |
| **Rules fired** | 5710 (invalid user), 5712 (brute-force correlation) |
| **Reaches** | Detection → SOAR → TheHive case |
| **Status** | ✅ Validated |

---

## 1. Attack

SSH is the standard remote-access service on Linux and a constant target of
automated credential-guessing on the public internet. With OpenSSH running on
the Ubuntu target, a password list was run from Kali against a non-existent
username, so every attempt fails and no real account is ever at risk:

```bash
hydra -l fakeuser -P ~/passwords.txt ssh://192.168.56.20 -t 4
```

`-t 4` limits parallel connections so the burst looks like realistic tooling
rather than a flood. Hydra reports `0 valid password found` — the attack
completes without a successful login, which fixes the expected verdict up front:
*attempted access, no compromise*.

> _Evidence: `evidence/scenario-03-ssh/attack-output.txt`_

---

## 2. Detection

Each failed attempt is written by sshd to journald, collected by the Wazuh
agent, and matched on the manager. Two rules do the work:

- **Rule 5710** — "sshd: Attempt to login using a non-existent user." Fires once
  per attempt (level 5). On its own, a single 5710 is noise — a fat-fingered
  username looks identical.
- **Rule 5712** — "sshd: brute force trying to get access to the system. Non
  existent user." (level 10). This is the correlation rule: it fires once
  **eight** failures from one source stack up inside the time window. That shift
  from per-attempt noise to a single pattern alert is the whole point of
  brute-force detection.

Each run of the attack tripped 5712 exactly once, so three separate runs show up
as three correlation hits:

![Wazuh Discover filtered on rule.id:5712 — three brute-force runs, each collapsed into one correlation alert](../../evidence/scenario-03-ssh/wazuh-5712-alerts.png)
*Three attack runs, three 5712 hits. Each hit represents a full burst of failed
logins collapsed into one alert — the per-attempt 5710 events never reach the
analyst as individual noise.*

Expanding one 5712 alert shows the fields triage actually uses — `data.srcip`,
`data.srcuser`, `rule.frequency`, and the MITRE mapping:

![Expanded 5712 alert showing srcip 192.168.56.10, srcuser fakeuser, frequency 8, MITRE T1110 Credential Access / Brute Force](../../evidence/scenario-03-ssh/wazuh-5712-detail.png)
*One 5712 alert expanded: `frequency: 8`, `data.srcip: 192.168.56.10`,
`data.srcuser: fakeuser`, mapped to T1110 (Credential Access → Brute Force).*

> _Evidence: `evidence/scenario-03-ssh/alert-5712.json` (level 10 correlation),
> `evidence/scenario-03-ssh/alert-5710.json` (per-attempt). Authoritative event
> times are the UTC timestamps inside the JSON; dashboard wall-clock rendering
> depends on the viewer's timezone._

---

## 3. Triage

- **Source IP** — a single source (`192.168.56.10`) across every attempt →
  targeted, not distributed noise. The IP is trustworthy because SSH requires a
  completed TCP handshake, which can't be spoofed.
- **Username** — `fakeuser`, which does not exist. A high volume of failures
  against a non-existent account is characteristic of automated scanning, not a
  legitimate user mistyping.
- **Rate** — eight failures inside the correlation window, far above human speed
  → tooling.
- **Correlation** — rule 5712 confirms the volume/time threshold was crossed.

**Verdict:** Confirmed brute-force attempt. No successful login in this run
(`0 valid password found`), so the outcome is *attempted access, no
compromise* — but the source is a clear candidate for blocking.

---

## 4. Response — SOAR aggregation and case creation

The 5712 alert is forwarded to Shuffle by webhook. The key behavior here is
**aggregation**: Wazuh's correlation has already collapsed the burst, so Shuffle
receives **one** event for the whole run rather than one per failed login.

![Shuffle workflow run — a single webhook carrying rule_id 5712, severity 3, for the whole brute-force burst](../../evidence/scenario-03-ssh/shuffle-aggregated.png)
*One Shuffle run per correlation alert. The `$exec` payload carries `rule_id:
5712`, the sshd title, and the source log line — a single actionable event, not
eight.*

Shuffle then opens a case in TheHive. This is the same path phishing (Scenario
02) takes — **SSH brute force reaches case creation too**; phishing is simply the
scenario where VirusTotal enrichment is showcased.

![TheHive alert for the SSH brute force — SEVERITY:MEDIUM, tags brute-force/ssh/wazuh, description with source, target user, attempt count, MITRE and rule](../../evidence/scenario-03-ssh/thehive-alert.png)
*TheHive case: `SEVERITY:MEDIUM`, tagged brute-force / ssh / wazuh, description
`SSH brute force | Source: 192.168.56.10 | Target user: fakeuser | Correlated
failed attempts: 8 | MITRE T1110 | Rule 5712`. The `Reference` ties the case
back to the exact Wazuh event that created it.*

A brute force in progress is a strong auto-block candidate: high confidence,
time-sensitive (every minute is more guesses), reversible, and backed by a
non-spoofable source IP. In the tiered response model this is the case that
justifies an automated `firewall-drop` rather than waiting for an analyst.

---

## 5. Lessons Learned

- Attacking a **non-existent user** keeps the exercise safe while still producing
  the exact detection signature.
- The split between the per-attempt rule (5710) and the correlation rule (5712)
  is the core of brute-force detection — a single failure is noise; the
  *pattern* is the alert, and only the pattern should reach the analyst.
- Correlation also does the SOAR a favor: because 5712 collapses the burst, the
  case queue sees one case per campaign, not one per guess.
- Contrast with Scenario 04 (Windows RDP): the same technique (T1110) surfaces
  through a completely different log source (journald vs. the Windows Security
  channel), which is why host coverage must span both platforms.
