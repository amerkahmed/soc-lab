# Triage Methodology

How each alert in this lab is triaged — what to check, how to separate malicious
from benign, and when to escalate. This is the analyst-reasoning layer that sits
on top of the detections.

---

## The questions asked on every alert

1. **Who is the source?** Internal/known host, or unexpected/external? One source
   or many?
2. **What is the target?** A real account/host, or a non-existent one (attacks on
   non-existent users look different from a real user's mistake)?
3. **What is the volume and rate?** Human-speed, or automated-tooling-speed?
4. **Did it correlate?** Did a correlation rule (e.g. brute-force) fire, or is this
   a single isolated event?
5. **What happened next?** Was a failure followed by a *success*? Was recon
   followed by an *exploit*? The follow-on event usually decides severity.
6. **Is it spoofable?** Can the source IP be trusted for a blocking decision?

---

## Per-scenario triage logic

### Nmap recon (Scenario 01)
- **Malicious indicators:** one source probing many ports/services on a host;
  OS-fingerprinting probes (malformed ICMP, Nmap's UDP probe).
- **Severity:** low on its own — recon is pre-attack, not intrusion.
- **Do not auto-block:** scan source IPs are spoofable; blocking on them can be
  weaponized.
- **Escalate when:** the same source later escalates (brute force, exploit) — the
  correlation is the value.

### Phishing IOC (Scenario 02)
- **Malicious indicators:** an HTTP request whose destination matches the IOC
  watchlist (rule 100100). By definition the destination is known-bad.
- **Enrichment:** VirusTotal detection count / hosting / country adds context for
  the analyst before they promote to a case.
- **Escalate when:** the IOC match fires at all — it means an endpoint reached
  known-bad infrastructure.

### SSH brute force (Scenario 03)
- **Malicious indicators:** single source, non-existent username, a rapid burst of
  failures that crosses the 5712 correlation threshold (8 events / 120 s) far faster
  than a human mistyping.
- **Benign look-alike:** a real user mistyping a few times (low volume, real
  account, ends in success) — would *not* trip 5712 and would not come as a burst.
- **Escalate when:** correlation fires, or any success follows the failures.

### RDP brute force → compromise (Scenario 04)
- **Malicious indicators:** consistent source IP across all 4625s, a brute-force
  correlation (60204), and an account lockout (60115) — then, separately, a
  valid-credential logon (rule 92657) from that same attacking IP.
- **Benign look-alike:** a stale cached credential (a mapped drive or scheduled
  task with an old password) can generate repeated 4625s from a *known internal*
  host and end benignly. The source IP and whether it ends in a legitimate success
  are what separate them.
- **Two phases, not one crack.** The lockout (60115) shows the online guessing was
  *blocked*, not that it succeeded. The later 92657 logon used a valid credential
  obtained out-of-band (in this lab, the account's own password, ~12 min later once
  the lockout expired — Scenario 04 §1), so a lockout and a success in the same
  episode is expected, not contradictory.
- **Escalate immediately when:** rule 92657 fires — a valid-credential logon from
  the attacking source is a confirmed compromise (the interactive Type-10 session,
  92653, confirms a real foothold), regardless of whether the guessing itself got in.

### Credential dumping (Scenario 05)
- **Malicious indicators:** a process reading **LSASS** memory (`grantedAccess 0x1010`),
  especially from a user-writable path (`C:\Users\Public\`) — rule 92900 (Sysmon
  Event ID 10). On an endpoint this has essentially no benign explanation.
- **Correlation:** fires on the same host/account compromised in Scenario 04 —
  brute force → compromise → credential theft is one coherent progression.
- **Severity is impact-based:** the detecting rule is level 12, but the incident is
  Critical — every credential cached on the host must be treated as stolen.
- **Escalate immediately:** this is post-compromise, so isolate the host and rotate
  credentials rather than block a perimeter source (the attacker is already inside).

---

## Malicious vs. benign — the general principle

A detection rule matches a *pattern*; it cannot know *intent*. Triage is the step
that supplies intent by asking: is there a legitimate explanation that fits all the
evidence (source, target, volume, outcome)? If a benign explanation fits, it is a
candidate false positive to tune (as in the Scenario 02 ICMP-vs-TCP tuning example). If
not, escalate.

The goal of tuning is to **reduce false positives without creating false
negatives** — e.g. whitelisting a known management host is fine, but whitelisting
"all internal IPs" would blind the SOC to an attacker who already has a foothold.

---

## Severity assignment (what each alert is rated, and why)

Severity is **impact-based** — the effect if the alert is a true positive — not the
detecting rule's Wazuh level. This follows the standard analytics-rule convention
(e.g. Microsoft Sentinel: *Low* = minimal immediate effect, the attacker needs more
steps; *Medium* = some effect, limited in scope; *High* = wide-ranging access) and
the impact-based incident prioritization in NIST SP 800-61 Rev 3 (functional impact
and data impact are among its risk factors).

In TheHive (severity 1–4 = Low / Medium / High / Critical), the alerts that are
forwarded and raised as alerts map as follows:

| Rule | What it means | Stage / impact | Severity |
|---|---|---|---|
| 5712 — SSH brute-force correlation | repeated failures from one source | attempts only, no access | **Medium** |
| 60115 — RDP account lockout | sustained brute force crossed the lockout threshold | no access gained; the lockout is also a temporary DoS on the account | **Medium** |
| 92657 — RDP successful logon (built-in "pass-the-hash" tag is a false lead; see Scn 04) | admin logon from the attacking host | wide-ranging access to the host | **High** |
| 100100 — phishing IOC callback | internal host reached known-bad infrastructure | strong compromise indicator | **High** |
| 92900 — LSASS access (credential dump) | a process read LSASS memory | credential theft on a compromised admin host | **Critical** |

Recon (Nmap, rule 86601) and the per-attempt rules (5710, 60122) are **Low** and are
not forwarded to the SOAR layer (see the forwarding note in the README).

**Why 60204 (the Windows brute-force correlation) is detected but not forwarded.**
Wazuh's built-in rule **60204** ("Multiple Windows Logon Failures", level 10,
T1110) correlates **8 failed logons from one source IP within 240 s** — the Windows
analogue of SSH's 5712, and it rates **Medium** on the same basis: repeated
failures, no access gained (Elastic's equivalent *Multiple Logon Failure from the
same Source Address* rule is `risk_score 47` / Medium). It is **not** forwarded in
this lab. On a host with a lockout policy, the lockout (60115) already carries the
Windows brute-force headline, and forwarding both would raise two Medium alerts for
one episode — the duplicate-incident anti-pattern (one attack, one case, so related
signals update one incident rather than spawning parallel ones). 60204 still fires
and is captured as detection evidence; it simply doesn't get its own alert. On a
host with **no lockout policy**, 60115 never fires, so 60204 should be forwarded in
its place — it is also the only one of the two that catches an attacker pacing
*below* the lockout threshold, since its 8-in-240 s window is independent of the
account lockout counter.

**Two deliberate calls:**
- **92900 is rated Critical on an impact basis** — a confirmed dump means every
  credential cached on the host is stolen. Vendor *detection* rules rate the LSASS
  access itself only **Medium** — a noisy standalone signal (Elastic's *LSASS Memory
  Dump Handle Access* rule is `risk_score 47` / Medium); the step up to Critical
  reflects the confirmed-incident impact, not the detection in isolation.
- **100100 is High** as contact with known-bad infrastructure; a case could be made
  for Medium, since a watchlist hit proves the connection occurred but not that
  credentials were submitted (see Scenario 02 §6).

This mapping is set **dynamically** by the Shuffle integration: a `Severity` node
(`execute_python`) reads the alert's rule ID and sets the TheHive severity —
`{60115: Medium, 92657: High, 92900: Critical}` — so the cred-dump lands Critical and
the RDP logon High, matching impact rather than a fixed default. The phishing
(`100100`) and SSH (`5712`) branches post their own fixed severities (High and
Medium) on their own paths.
