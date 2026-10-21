# Scenario 02 — [High] RDP Brute Force → Lockout → Compromise

The richest scenario in the lab: it runs the full arc from first failed logon to
confirmed compromise of a local **administrator** account, and is written as an
analyst would hand it off — in ticket form. The successful-logon alert (rule
92657) is the escalation trigger: the moment an attempt becomes a compromise.

| | |
|---|---|
| **MITRE ATT&CK** | T1110.001 (Brute Force: Password Guessing) → T1021.001 (Remote Services: RDP) / T1078.002 (Valid Accounts: Domain/Local) — the successful-logon stage also flags T1550.002 (Pass the Hash) |
| **Attacker** | Kali — 192.168.56.10 |
| **Target** | Windows 10 — DESKTOP-T0LOHB5 (192.168.56.30) |
| **Target account** | `Client` — a **local administrator** account |
| **Detection source** | Wazuh agent → Windows Security event channel |
| **Rules fired** | 60122 (logon failure, 4625) · 60115 (account lockout, 4740) · 92657 (successful remote logon, 4624) |
| **Status** | ✅ Validated |

---

## 1. Attack

Remote Desktop (RDP) is the most commonly brute-forced Windows service on the
public internet. The attack targets `Client`, an existing **local administrator**
account on the host — a higher-value target than a purpose-made test account,
since compromising an admin grants broad control.

Hydra's RDP module proved unreliable (experimental, NLA handshake issues) and
`ncrack` gave no clear output; an `xfreerdp3` loop was the dependable method for
generating real authentication attempts:

```bash
for pass in $(cat ~/winpass.txt); do
  echo "=== Trying: $pass ==="
  xfreerdp3 /u:Client /p:"$pass" /v:192.168.56.30 /cert:ignore +auth-only
done
```

Each wrong password returned `ERRCONNECT_LOGON_FAILURE [0x00020014]`. After five
failures the account locked (`ERRCONNECT_ACCOUNT_LOCKED_OUT [0x00020018]`) — the
realistic consequence of a sustained brute force against a system with an
account-lockout policy. Because lockout interrupts the attack, the successful
compromise was performed as a separate logon after the account was unlocked —
exactly how a real intrusion plays out when lockout defenses are in place.

> _Evidence: `evidence/scenario-02-rdp/attack-output.txt` (password redacted)_

---

## 2. Detection

The attempts generated Windows Security events on the `Client` account, collected
by the Wazuh agent and matched on the manager:

- **Rule 60122** (level 5) — "Logon Failure - Unknown user or bad password," from
  **Event ID 4625** (Logon Type 3, NTLM), source `192.168.56.10`. One per failed
  attempt.
- **Rule 60115** (level 9) — "User account locked out (multiple login errors),"
  from **Event ID 4740**. The lockout message names the caller: `Caller Computer
  Name: kali`.
- **Rule 92657** (level 6) — "Successful Remote Logon Detected … possible
  pass-the-hash attack," from **Event ID 4624** when the correct password hit.
  The event records `Workstation Name: kali`, `Source Network Address:
  192.168.56.10`, `Logon Type: 3`, `Authentication Package: NTLM`.

> _Evidence: `evidence/scenario-02-rdp/alert-60122.json`,
> `alert-60115.json`, `alert-92657.json`_

**Configuration note:** these detections did not work until a `<localfile>` block
for the **Security** event channel was added to the Windows agent's `ossec.conf`.
By default the agent collected Sysmon but not the Security log — two different
sensors. See [challenges-and-resolutions.md](../challenges-and-resolutions.md), item 5.

---

## 3. Ticket

> The format a Tier 1 analyst hands off: summary → observations → enrichment →
> verdict → recommended action → escalation.

**Alert summary**
Successful RDP logon (rule 92657, possible pass-the-hash) to the local
administrator account `Client` on DESKTOP-T0LOHB5, preceded by a burst of failed
logons and an account lockout — all from a single source. Timeline: failures and
lockout at 22:17 UTC, successful logon at 22:19 UTC.

**Observations**
- **Source** — `192.168.56.10` (workstation name `kali`), consistent across every
  4625, the 4740 lockout, and the final 4624. A single source driving all three
  stages is the signature of a targeted brute force, not scattered user error.
- **Target** — `Client`, a **local administrator** account. High impact if
  compromised.
- **Volume & timing** — a tight burst of failures in seconds (far faster than
  human typing) → automated tooling.
- **Lockout** — rule 60115 confirms the failures crossed the lockout threshold,
  i.e. the activity was sustained, not incidental.
- **The pivot** — rule 92657 shows a *successful* 4624 from the same attacking IP.
  Logon Type 3 + NTLM (NTLM V2) from an unexpected host is exactly the pattern
  that warrants escalation. Wazuh flags it as *possible pass-the-hash*.

**Enrichment**
VirusTotal is not meaningful here — the source is an internal/private IP (RFC
1918) that VT cannot resolve. The relevant enrichment is host/identity context:
`Client` is a local admin, the source is the known attacker host, and the logon
used NTLM (not Kerberos), which is consistent with pass-the-hash or direct
credential use over RDP. (Contrast Scenario 04, where the IOC is a real external
IP and VT enrichment applies.)

**Verdict** — **True Positive — confirmed compromise.** Not a benign look-alike:
the single source, automated volume, lockout, and subsequent success from the
attacking IP all align. Confidence: **High.**

**Recommended action**
- Disable / force-reset the `Client` account; its credentials are compromised.
- Isolate or investigate DESKTOP-T0LOHB5 for post-exploitation activity (this host
  is the foothold for the credential-dumping chain in
  [Scenario 05](05-credential-dumping.md)).
- Block the source IP — safe here, because a completed RDP logon requires a real
  TCP handshake, so the source IP is genuine and not spoofable (see the tiered
  response model in [architecture.md](../architecture.md) §7).

**Escalate?** — **Yes.** A successful logon to a local admin account from a
brute-force source is a confirmed compromise. Escalate to Tier 2 / incident
response with the full timeline attached.

---

## 4. Triage reasoning — malicious vs. benign

A burst of failed Windows logons (4625) is not automatically malicious. The same
pattern can come from a **benign true positive** — e.g. a stale cached credential
(a mapped drive or scheduled task holding an old password) retrying from a known
internal host. What separates this case from that benign look-alike:

| Signal | This compromise | Benign (stale credential) |
|---|---|---|
| Source | Unexpected host (`kali`) | Known internal host |
| Passwords | Many different guesses | One specific old password |
| Rate | Automated burst | Machine-steady retries |
| Outcome | **Success from the attacking IP** | Never a success from a suspicious source |

The decisive factor is the final successful 4624 from the attacking IP. See
[triage-methodology.md](../triage-methodology.md) for the false-positive vs.
benign-true-positive distinction in full.

---

## 5. Lessons Learned

- **The successful logon is the alert that matters most.** Failed attempts are
  noise until one succeeds — rule 92657 is the escalation trigger, and tying it
  back to the preceding failures and lockout is the analytic core of this scenario.
- **Lockout interrupts brute force — and that's realistic.** The account locked
  before the correct password was reached, so the compromise came as a separate
  logon after unlock. A real intrusion against a lockout-protected system behaves
  the same way; the lockout alert (60115) is itself a valuable mid-attack signal.
- **Sysmon ≠ Security log.** Deep process telemetry (Sysmon) does not include
  authentication events. Collecting the Windows **Security** channel is required
  to see RDP brute force.
- **NTLM over RDP is a flag.** The 92657 detection keys on a successful NTLM
  (not Kerberos) remote logon — the "possible pass-the-hash" condition — which is
  why this stage is mapped to T1550.002 alongside the RDP and valid-accounts
  techniques.
