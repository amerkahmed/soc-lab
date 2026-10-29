# Scenario 04 — [High] RDP Brute Force → Lockout → Interactive Session

Runs the full arc from the first failed logon to a confirmed **interactive RDP
session** on a local **administrator** account, written as an analyst would hand
it off — in ticket form. The successful-logon alerts (rules 92657 + 92653) are the
escalation trigger: the moment a wall of failures becomes a real foothold — the
same foothold the credential-dumping chain in
[Scenario 05](05-credential-dumping.md) runs inside.

| | |
|---|---|
| **MITRE ATT&CK** | T1110.001 (Brute Force: Password Guessing) → T1021.001 (Remote Services: RDP) with T1078.003 (Valid Accounts: Local Accounts). The built-in success rule 92657 also tags T1550.002 (Pass the Hash) / T1078.002 (Domain Accounts) — §2 explains why neither is accurate for a password-guessing attack on a local account. |
| **Attacker** | Kali — 192.168.56.10 (workstation `kali`) |
| **Target** | Windows 10 — DESKTOP-T0LOHB5 (192.168.56.30) |
| **Target account** | `Client` — a **local administrator** account |
| **Detection source** | Wazuh agent → Windows Security event channel |
| **Rules fired** | 60122 (logon failure, 4625 type 3) · 60115 (account lockout, 4740) · 92657 (successful NLA pre-auth, 4624 type 3) · 92653 (interactive RDP session, 4624 type 10) |
| **Reaches** | Detection → SOAR → **two** TheHive alerts (lockout `60115` + successful logon `92657`) |
| **Status** | ✅ Validated — single live pass, all four rules, `2026-10-29 02:33–02:34 UTC` |

---

## 1. Attack

Remote Desktop (RDP) is the most commonly brute-forced Windows service exposed to
the internet — Sophos' 2024 Active Adversary Report put RDP in **84%** of the
incident-response cases it reviewed. The attack targets `Client`, an existing
**local administrator** account on the host — a higher-value target than a
purpose-made test account, since compromising an admin grants broad control.

Hydra's RDP module proved unreliable (experimental, NLA handshake issues) and
`ncrack` gave no clear output; an `xfreerdp3` loop with `+auth-only` was the
dependable way to generate real authentication attempts. `+auth-only` performs the
**NLA credential check only** — a network (Type 3) logon — and never opens a
desktop, so every wrong password is a clean, fast 4625:

```bash
for pass in $(cat ~/winpass.txt); do
  echo "=== Trying: $pass ==="
  xfreerdp3 /u:Client /p:"$pass" /v:192.168.56.30 /cert:ignore +auth-only
done
```

Each wrong password returned `ERRCONNECT_LOGON_FAILURE [0x00020014]`. Once the
failures crossed the account's lockout threshold, **every** further attempt —
including the one with the correct password — returned
`ERRCONNECT_ACCOUNT_LOCKED_OUT [0x00020018]`. So the loop itself never produced a
successful logon: **the account locked first**, which is exactly the realistic
consequence of a sustained brute force against a lockout-protected system.

Because lockout interrupts the attack, the actual access was performed as a
**separate interactive RDP session after the account was cleared** — the pattern a
real intrusion follows when lockout defenses are in place. The host's policy is
`net accounts` **10 / 10 / 10** (threshold 10, lockout duration 10 min, reset
window 10 min), so in the wild the attacker waits out the 10-minute window. In the
lab the account was cleared immediately with ADSI to keep the run tight (~98 s end
to end):

```powershell
# Clear the lockout (lab shortcut for "wait out the 10-minute window")
$u = [ADSI]"WinNT://$env:COMPUTERNAME/Client,user"
$u.IsAccountLocked = $false
$u.SetInfo()
```

The post-clear access was a **real RDP session** (not `+auth-only`) — the attacker
logging in interactively with the now-known password. That genuine desktop session
is what makes the foothold usable for Scenario 05's hands-on credential dump.

> _Evidence: `evidence/scenario-04-rdp/attack-output.txt` — the brute-force console
> from this run (no password values are echoed). Its clock (`22:33:02–22:33:03`
> Kali local = **`02:33 UTC`**) lines up with the manager events below: ten
> `LOGON_FAILURE` results, then `ACCOUNT_LOCKED_OUT` once the lockout threshold is
> crossed._

---

## 2. Detection

The attempts generated Windows Security events on the `Client` account, collected
by the Wazuh agent and matched on the manager. The whole arc — the failure burst,
the lockout, the co-located failure, and **both** successful-logon events — appears
in one filtered view, every row a single source (`192.168.56.10`, workstation
`kali`) against a single account (`Client`):

![Wazuh Discover filtered on rule.id 60122/60115/92657/92653 and targetUserName Client — the failed-logon burst at 02:33:03, the 4740 lockout, then at 02:34:00 the Type-3 NLA success and the Type-10 RDP session, all from 192.168.56.10](../../evidence/scenario-04-rdp/wazuh-rdp-sequence.png)
*One intrusion, end to end: the failed-logon burst (`4625`, Type 3) at `02:33:03`,
the account lockout (`4740`) at `02:33:04`, then at `02:34:00` the successful NLA
pre-auth (Type 3) and the interactive RDP session (Type 10) — 13 hits, one source,
one account.*

Four rules carry the story. The first two are the brute force; the second two are
the single successful RDP login, which — with NLA — records **two** 4624s:

- **Rule 60122** (level 5) — "Logon Failure - Unknown user or bad password," from
  **Event ID 4625** (`logonType 3`, `NtLmSsp` / NTLM, `status 0xC000006D` — bad
  password), source `192.168.56.10`. One per failed attempt.
  _(event `1793241184.1944794`)_
- **Rule 60115** (level 9) — "User account locked out (multiple login errors),"
  from **Event ID 4740**; the lockout names the caller: `Caller Computer Name:
  kali`. _(event `1793241183.1942214`)_
- **Rule 92657** (level 6) — "Successful Remote Logon Detected … possible
  pass-the-hash attack," from **Event ID 4624**, `logonType 3`, `NTLM`. This is the
  **NLA network pre-authentication** of the successful login.
  _(event `1793241240.1979272`)_
- **Rule 92653** (level 3) — "User: WORKGROUP\Client logged using Remote Desktop
  Connection (RDP) from ip:192.168.56.10," from **Event ID 4624**, `logonType 10`
  (RemoteInteractive), `Negotiate`. This is the **genuine interactive desktop
  session** — the real foothold. _(event `1793241240.2020471`)_

**Why two success events for one login.** An RDP logon with NLA authenticates over
the network first (a Type 3 logon → `92657`) and then creates the interactive
session (a Type 10 logon → `92653`), ~0.2 s apart in the capture. The failed
attempts only ever reach the Type 3 stage, which is why every 4625 above is
`logonType 3`. The pair together is the signature of a **completed interactive RDP
login**, not merely a credential check.

![Expanded 92653 event 1793241240.2020471 — eventID 4624, logonType 10, Negotiate, rule 92653 level 3, description "User: WORKGROUP\Client logged using Remote Desktop Connection (RDP) from ip:192.168.56.10", logonProcessName User32 / svchost.exe, MITRE T1021.001](../../evidence/scenario-04-rdp/wazuh-92653-detail.png)
*The genuine interactive session expanded — the same event as
`alert-92653-type10-session.json` (`1793241240.2020471`): `logonType 10`,
`Negotiate`, `logonProcessName User32`, Wazuh's 92653 stating it plainly, "logged
using Remote Desktop Connection (RDP) from ip:192.168.56.10." (A local-admin RDP
logon under UAC records a **linked pair** of Type-10 logons — a filtered standard
token and a full elevated token, their logon IDs cross-referenced — so 92653 fires
more than once; this is the standard-token session.)*

**ATT&CK mapping note — the pass-the-hash tag is a false lead here.** Built-in rule
92657 is titled "possible pass-the-hash" and tags **T1550.002**, because it sees a
successful *NTLM* remote logon. But pass-the-hash means authenticating with a
stolen **hash** — and this attack brute-forced the actual **password**, so it is
**not** PtH. The NTLM package appears simply because the `Client` account is local
on a WORKGROUP host (no Kerberos/AD), so NTLM is the default. The accurate
techniques are **T1021.001 (RDP)** + **T1078.003 (Local Accounts)**; 92657 also
tags **T1078.002 (Domain Accounts)**, which is likewise wrong for a local account.
Built-in mappings are a useful starting point, not always exact for the environment
they fire in — and knowing *why* a tag is wrong is the analyst skill the mismatch
exercises.

**Configuration note:** these detections did not work until a `<localfile>` block
for the **Security** event channel was added to the Windows agent's `ossec.conf`.
By default the agent collected Sysmon but not the Security log — two different
sensors. See [challenges-and-resolutions.md](../challenges-and-resolutions.md), item 5.

> _Evidence: `alert-60122-failure.json`, `alert-60115-lockout.json`,
> `alert-92657-type3-nla.json`, `alert-92653-type10-session.json`. The lockout
> (`4740`, record 18641) and its co-located failure (`4625`, record 18642) share
> `systemTime 02:33:02.774Z` — consecutive event records, correct causal order.
> Match artifacts by event ID; on cross-host clocks see the
> [README](../../README.md#honesty--scope-notes) convention._

---

## 3. SOAR → case creation

The manager's Shuffle integration forwards the two **headline** RDP alerts — the
lockout (`60115`) and the successful NLA logon (`92657`) — by **rule ID**. The
per-attempt `60122` is deliberately *not* forwarded, so failed-logon noise never
reaches the SOAR layer; and the Type-10 session rule `92653` is rich **supporting
evidence** (it confirms a true interactive session) but is also not forwarded —
one headline alert per decision point, not four. Each forwarded alert produces its
own Shuffle run and its own TheHive alert:

![Shuffle run for the successful logon — $exec FINISHED, rule_id 92657, id 1793241240.1979272, the successful-remote-logon title](../../evidence/scenario-04-rdp/shuffle-rdp-compromise.png)
*Shuffle run for the successful logon: `FINISHED`, `rule_id 92657`,
`id 1793241240.1979272` — the webhook received the Wazuh alert and posted to TheHive.*

![TheHive alert for the successful logon — SEVERITY HIGH, tags 92657/wazuh, Reference 1793241240.1979272, description naming rule 92657, Client, possible pass-the-hash](../../evidence/scenario-04-rdp/thehive-compromise.png)
*TheHive alert: `SEVERITY:HIGH`, tagged `92657` / wazuh, description `Rule 92657 |
Agent: Project-Windows | Successful Remote Logon Detected - User: \Client …`.
`Reference 1793241240.1979272` ties the alert to the exact Wazuh event.*

The lockout raises a **parallel alert** a minute earlier (`shuffle-rdp-lockout.png`
+ `thehive-lockout.png`, `Reference 1793241183.1942214`, rule `60115`,
`SEVERITY:MEDIUM`) — a valuable mid-attack signal in its own right, not just a
precursor to the logon.

> _Evidence: `shuffle-rdp-compromise.png`, `shuffle-rdp-lockout.png`,
> `thehive-compromise.png`, `thehive-lockout.png`. No VirusTotal enrichment applies
> here — the source is a private RFC 1918 IP VT can't resolve; the relevant
> enrichment is host/identity context (see the Ticket below)._

---

## 4. Ticket

> The format a Tier 1 analyst hands off: summary → observations → enrichment →
> verdict → recommended action → escalation.

**Alert summary**
Successful RDP logon (rules 92657 + 92653) to the local administrator account
`Client` on DESKTOP-T0LOHB5, preceded by a burst of failed logons and an account
lockout — all from a single source. Timeline (UTC): failed logons `02:33:03`,
account lockout `02:33:04`, successful interactive session `02:34:00`.

**Observations**
- **Source** — `192.168.56.10` (workstation name `kali`), consistent across every
  4625, the 4740 lockout, and both final 4624s. A single source driving all stages
  is the signature of a targeted brute force, not scattered user error.
- **Target** — `Client`, a **local administrator** account. High impact if
  compromised.
- **Volume & timing** — a tight burst of failures inside one second (far faster
  than human typing) → automated tooling.
- **Lockout** — rule 60115 confirms the failures crossed the lockout threshold,
  i.e. the activity was sustained, not incidental.
- **The pivot** — rules 92657 (Type 3 NLA) **and** 92653 (Type 10 interactive)
  show a *successful* login from the same attacking IP, and the Type-10 event means
  a real desktop session was established — not just a credential check. That is the
  foothold.

**Enrichment**
VirusTotal is not meaningful here — the source is an internal/private IP (RFC 1918)
that VT cannot resolve. The relevant enrichment is host/identity context: `Client`
is a local admin, the source is the known attacker host, and the logon used NTLM
(local account, no Kerberos). (Contrast Scenario 02, where the IOC is a real
external IP and VT enrichment applies.)

**Verdict** — **True Positive — confirmed interactive compromise.** Not a benign
look-alike: the single source, automated volume, lockout, and the subsequent
Type-10 RDP session from the attacking IP all align. Confidence: **High.**

**Recommended action**
- Disable / force-reset the `Client` account; its credentials are compromised.
- Isolate or investigate DESKTOP-T0LOHB5 for post-exploitation activity — this host
  is the foothold for the credential-dumping chain in
  [Scenario 05](05-credential-dumping.md), where the LSASS dump runs **inside this
  same Type-10 session** as `Client`.
- Block the source IP — safe here, because a completed RDP logon requires a real
  TCP handshake, so the source IP is genuine and not spoofable (see the tiered
  response model in [architecture.md](../architecture.md) §7).

**Escalate?** — **Yes.** A successful interactive logon to a local admin account
from a brute-force source is a confirmed compromise. Escalate to Tier 2 / incident
response with the full timeline attached.

---

## 5. Triage reasoning — malicious vs. benign

A burst of failed Windows logons (4625) is not automatically malicious. The same
pattern can come from a **benign true positive** — e.g. a stale cached credential
(a mapped drive or scheduled task holding an old password) retrying from a known
internal host. What separates this case from that benign look-alike:

| Signal | This compromise | Benign (stale credential) |
|---|---|---|
| Source | Unexpected host (`kali`) | Known internal host |
| Passwords | Many different guesses | One specific old password |
| Rate | Automated burst | Machine-steady retries |
| Outcome | **Interactive Type-10 session from the attacking IP** | Never a success from a suspicious source |

The decisive factor is the final successful 4624s from the attacking IP — and
especially the **Type-10** one, which means a real session, not a background
credential retry. See [triage-methodology.md](../triage-methodology.md) for the
false-positive vs. benign-true-positive distinction in full.

---

## 6. Lessons Learned

- **The successful logon is the alert that matters most — and "successful" has two
  halves.** Failed attempts are noise until one succeeds. Here the success is a
  *pair*: the Type-3 NLA pre-auth (92657, the headline/forwarded alert) and the
  Type-10 interactive session (92653, the proof of a real foothold). Tying them
  back to the preceding failures and lockout is the analytic core.
- **Lockout interrupts brute force — and that's realistic.** The account locked
  before the correct password could be used, so the access came as a separate
  session after the lockout cleared. A real intrusion against a lockout-protected
  system behaves the same way; the lockout alert (60115) is itself a valuable
  mid-attack signal.
- **Read the technique tags critically.** 92657's "possible pass-the-hash"
  (T1550.002) is a *false lead* here — this was a brute-forced password, not a
  stolen hash, and the account is local (T1078.003), not domain (T1078.002). A good
  analyst knows why a built-in mapping is wrong for the environment it fired in.
- **Two alerts, one intrusion.** Forwarding by rule ID raises an alert for the
  lockout (60115) and another for the successful logon (92657), while the
  per-attempt failures (60122) and the supporting Type-10 event (92653) stay out of
  the queue — the analyst sees the two decision points, not the noise.
- **Sysmon ≠ Security log.** Deep process telemetry (Sysmon) does not include
  authentication events. Collecting the Windows **Security** channel is required to
  see RDP brute force.
