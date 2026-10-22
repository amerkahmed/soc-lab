# Scenario 03 — [Medium] SSH Brute Force

| | |
|---|---|
| **MITRE ATT&CK** | T1110 (Brute Force) |
| **Attacker** | Kali — 192.168.56.10 |
| **Target** | Ubuntu — 192.168.56.20 |
| **Detection source** | Wazuh agent → journald (sshd) |
| **Rules fired** | 5710 (invalid user), 5712 (brute-force correlation) |
| **Status** | ✅ Validated |

---

## 1. Attack

SSH is the standard remote-access service on Linux and a constant target of
automated credential-guessing on the public internet. With OpenSSH running on
the Ubuntu target, a password list was run from Kali against a non-existent
username (so every attempt fails and no account is actually at risk):

```bash
hydra -l fakeuser -P ~/passwords.txt ssh://192.168.56.20 -t 4
```

`-t 4` limits parallel connections so the burst is realistic rather than a flood.
Using a non-existent user means every attempt is a clean failure — exactly the
signal wanted for triggering detection.

> _Evidence: `evidence/scenario-03-ssh/attack-output.txt`_

---

## 2. Detection

Each failed attempt is logged by sshd to journald, collected by the Wazuh agent,
and matched on the manager:

- **Rule 5710** — "Attempt to login using a non-existent user", one per attempt.
- **Rule 5712** — "SSH brute force (multiple failed logins)" — the correlation
  rule that fires once enough failures stack up in a short window. This is the
  "this is an attack, not a typo" signal.

Both map to MITRE **T1110**.

> _Evidence: `evidence/scenario-03-ssh/wazuh-alerts.png`,
> `evidence/scenario-03-ssh/alert-5712.json`_

---

## 3. Triage

- **Source IP** — single source (`192.168.56.10`) across all attempts → targeted,
  not distributed noise.
- **Username** — `fakeuser`, which does not exist. Many failures against a
  non-existent account is characteristic of automated scanning/brute-forcing
  rather than a legitimate user mistyping.
- **Rate** — multiple attempts per second, far above human speed → tooling.
- **Correlation** — rule 5712 confirms the volume/time threshold was crossed.

**Verdict:** Confirmed brute-force attempt. No successful login observed in this
run, so the outcome is *attempted access, no compromise* — but the source is a
clear candidate for blocking.

---

## 4. Response

A brute force in progress is a strong auto-block candidate: high confidence,
time-sensitive (every minute is more guesses), reversible, and the source IP is
genuine because SSH requires a completed TCP handshake (not spoofable). In the
tiered response model this is the case that justifies an automated
`firewall-drop` rather than waiting for an analyst.

---

## 5. Lessons Learned

- Attacking a **non-existent user** keeps the exercise safe while still producing
  the exact detection signature.
- The distinction between the per-attempt rule (5710) and the correlation rule
  (5712) is the core of brute-force detection — a single failure is noise; the
  *pattern* is the alert.
- Contrast with Scenario 04 (Windows RDP): the same technique (T1110) surfaces
  through a completely different log source (journald vs. the Windows Security
  channel), which is why host coverage must include both platforms.
