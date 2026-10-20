# Scenario 02 — RDP Brute Force → Account Lockout → Compromise

| | |
|---|---|
| **MITRE ATT&CK** | T1110 (Brute Force) |
| **Attacker** | Kali — 192.168.56.10 |
| **Target** | Windows 10 — DESKTOP-T0LOHB5 (192.168.56.30) |
| **Detection source** | Wazuh agent → Windows Security event channel |
| **Rules fired** | 60122 (logon failure), 60115 (account lockout), 92657 (successful remote logon) |
| **Status** | ✅ Validated |

---

## 1. Attack

Remote Desktop (RDP) is the most commonly brute-forced Windows service on the
public internet, which makes it a realistic target. A dedicated test account
(`testuser`) was created on the Windows host, and RDP was enabled.

From Kali, a short password list was run against RDP. Hydra's RDP module proved
unreliable (experimental module, NLA handshake issues), and `ncrack` produced no
clear output; `xfreerdp3` in a loop was the dependable method for generating
authentication attempts:

```bash
for pass in $(cat ~/winpass.txt); do
  echo "=== Trying: $pass ==="
  xfreerdp3 /u:testuser /p:"$pass" /v:192.168.56.30 /cert:ignore +auth-only
done
```

Each wrong password returned `ERRCONNECT_LOGON_FAILURE [0x00020014]`. After
several failures the account locked
(`ERRCONNECT_ACCOUNT_LOCKED_OUT [0x00020018]`) — the realistic consequence of a
sustained brute force against a system with an account-lockout policy.

> _Evidence: `evidence/scenario-02-rdp/attack-output.txt`_

---

## 2. Detection

The attempts generated Windows Security **Event ID 4625** (failed logon,
Logon Type 3, NTLM) from source `192.168.56.10`. The Wazuh agent forwarded these
to the manager, which fired:

- **Rule 60122** (level 5) — "Logon Failure - Unknown user or bad password",
  one per failed attempt.
- **Rule 60115** (level 9) — "User account locked out (multiple login errors)",
  from Event ID 4740.
- **Rule 92657** (level 6) — "Successful Remote Logon Detected … possible
  pass-the-hash attack", from Event ID 4624 when a correct password hit. Wazuh
  explicitly flagged the source and questioned whether it should be connecting.

> _Evidence: `evidence/scenario-02-rdp/wazuh-alerts.png`,
> `evidence/scenario-02-rdp/alert-60115.json`_

**Configuration note:** these detections did not work until a `<localfile>` block
for the **Security** event channel was added to the Windows agent's `ossec.conf`.
By default the agent was collecting Sysmon but not the Security log — two
different sensors. See [challenges-and-resolutions.md](../challenges-and-resolutions.md), item 5.

---

## 3. Triage

Walking the alerts as an analyst would:

- **Source IP** — `192.168.56.10`, consistent across every 4625. A single source
  hammering one account is the signature of a targeted brute force, not scattered
  user error.
- **Target account** — `testuser`, a real local account (contrast with attacks on
  non-existent users, which look different).
- **Volume & timing** — a tight burst of failures in seconds, far faster than
  human typos → automated tooling.
- **Lockout** — rule 60115 confirms the failures crossed the account-lockout
  threshold, i.e. the activity was sustained.
- **The critical pivot** — rule **92657** shows a *successful* logon from the same
  attacking IP. This is the moment attempt becomes **compromise**. Logon Type 3 +
  NTLM from an unexpected host is exactly the pattern that warrants escalation.

**Verdict:** Confirmed compromise. Not a false positive — the source, volume,
timing, lockout, and subsequent success all align.

---

## 4. Response (what a real SOC would do)

Because the final logon succeeded, this sequence justifies immediate action:

- Disable / force-reset the `testuser` account.
- Isolate or investigate the Windows host for post-exploitation activity.
- Block the source IP (safe here — a completed RDP logon requires a real TCP
  handshake, so the source IP is genuine and not spoofable).

In this lab the successful-logon case is the candidate for a **human-in-the-loop**
response (analyst approves the disruptive action) rather than a blind auto-block,
because disabling an account and isolating a host are high-impact.

---

## 5. Lessons Learned

- **Sysmon ≠ Security log.** Deep process telemetry (Sysmon) does not include
  authentication events. Collecting the Windows **Security** channel is required
  to see brute force.
- **Tooling matters.** Hydra's RDP module is unreliable against modern Windows
  NLA; `xfreerdp3` (or ncrack) is the dependable choice for generating real 4625s.
- **The successful logon is the alert that matters most.** Failed attempts are
  noise until one succeeds — rule 92657 is the escalation trigger, and tying it
  back to the preceding failures is the analytic core of this scenario.
