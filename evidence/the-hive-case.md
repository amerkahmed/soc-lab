# TheHive Case — RDP Brute Force → Valid-Credential Logon → LSASS Dump

The worked case for the combined Scenario 04 → 05 incident: one intrusion, raised as
one case. Alerts were forwarded Wazuh → Shuffle → TheHive and are captured in the
scenario evidence (`scenario-04-rdp/thehive-*.png`, `scenario-05-creddump/thehive-*.png`);
this report presents how they are triaged and managed as a single case — its
classification, observables, ATT&CK TTPs, and the NIST SP 800-61r3 Respond → Recover
task flow.

> **Note — substitute for a live TheHive case.** The lab's TheHive license expired,
> putting the instance in read-only mode, so a case could not be created in the UI.
> The forwarded **alerts** are captured in the screenshots above; this document is the
> written case report standing in for the live case — the triage, classification,
> tasks, observables, and TTPs as they would be managed in TheHive.

| | |
|---|---|
| **Title** | RDP brute force → valid-credential logon → LSASS dump — DESKTOP-T0LOHB5 (Client) |
| **Severity** | Critical |
| **TLP / PAP** | AMBER / GREEN |
| **Status** | Resolved (true positive) |
| **Assignee** | analyst (case owner) |
| **Tags** | `rdp` · `brute-force` · `credential-access` · `lsass` · `mimikatz` · `host:DESKTOP-T0LOHB5` · `src:192.168.56.10` |

---

## Description

### What happened

RDP brute force from 192.168.56.10 against local admin `Client` on DESKTOP-T0LOHB5
(192.168.56.30), then a successful logon and an LSASS credential dump.

### Timeline (UTC)

- **02:22:04** — 9 failed RDP logons (Type 3) from .10 → **60122**; correlation **60204**
  (8/240s) at :04.496; lockout **60115** at :04.594.
- **~02:32** — 10-minute lockout expired.
- **02:34:04** — Successful NLA logon (Type 3) from .10 → **92657**.
- **02:34:05** — Interactive Type-10 RDP session, logon `0x34af4d` → **92653**.
- **02:34:18–24** — Certutil → `C:\Users\Public\m.exe` (**92075**, T1105); Mimikatz
  (**100002**); LSASS read, grantedAccess 0x1010 (**92900**).

### What I checked

- Source IP across all 4625s: consistently 192.168.56.10.
- Lockout outcome: 60115 fired.
- Logon-ID linkage: dump processes (92075/100002) ran under `0x34af4d`, the Type-10
  session token (`0x34af4d` ↔ `0x34af73`). The dump executed inside the RDP foothold.
- Built-in tags on 92657: "possible pass-the-hash" (T1550.002) / domain (T1078.002).

### What I found

- Brute force → lockout = control worked and no access gained by guessing.
- Access used a valid credential after the lockout expired → obtained out-of-band,
  not cracked online.
- In-session LSASS dump by `m.exe` as local admin `Client`.
- The 92657 PtH tag is a false lead as a valid password was used, is local account
  (T1078.003), and not a replayed hash.
- All credentials cached on DESKTOP-T0LOHB5 must be treated as stolen.

### What I did

- Raised to Critical
- Opened the Scope → Contain → Eradicate → Recover → Review tasks.

### Verdict & next step

A true positive confirmed credential theft intrusion. The attacker has a foothold,
so contain the host and rotate every cached credential.

---

## Observables

| Type | Value | IOC | Note |
|---|---|---|---|
| ip | 192.168.56.10 | yes | attacker source (brute force + logon + dump) |
| url | http://192.168.56.10/mimikatz.exe | yes | ingress-tool-transfer source |
| filename | C:\Users\Public\m.exe | yes | renamed Mimikatz |
| ip / hostname | 192.168.56.30 (DESKTOP-T0LOHB5) | no | compromised host |

## TTPs (MITRE ATT&CK Enterprise)

| Technique | ID | Procedure |
|---|---|---|
| Brute Force: Password Guessing | T1110.001 | 9 RDP (NLA) guesses vs local admin `Client` from .10; correlated by 60204, stopped by 60115 |
| Valid Accounts: Local Accounts | T1078.003 | interactive RDP logon with a valid credential obtained out-of-band (92657/92653, session 0x34af4d) |
| Remote Services: RDP | T1021.001 | Type-10 interactive RDP session from .10 established the foothold |
| Ingress Tool Transfer | T1105 | certutil pulled Mimikatz (renamed m.exe) to C:\Users\Public (92075) |
| OS Credential Dumping: LSASS Memory | T1003.001 | m.exe read LSASS, grantedAccess 0x1010 (92900; name match 100002) |

## Tasks (NIST SP 800-61r3 Respond → Recover)

| Task | Action |
|---|---|
| Scope | confirm session/logon-ID linkage (done: dump under 0x34af4d = RDP Type-10 session); find what else `Client` touched |
| Contain | isolate DESKTOP-T0LOHB5; disable/reset `Client`; block 192.168.56.10 |
| Eradicate | remove `m.exe`; verify no persistence (accounts/services/tasks/run keys) |
| Recover | rebuild/restore; rotate every cached credential; restore under monitoring |
| Post-incident review | lockout gap (forward 60204 on no-lockout hosts); lessons learned |

## Closure

True positive. A valid-credential RDP logon from 192.168.56.10 followed a
lockout-blocked brute force; the actor dumped LSASS on DESKTOP-T0LOHB5 as local admin
`Client` (dump tied to RDP Type-10 session `0x34af4d`). Response: host isolated,
`Client` reset, `m.exe` removed, host-cached credentials rotated. Residual risk: any
credential cached on the host prior to rotation. Lesson: lockout throttles but does not
stop a valid-credential logon; ensure brute-force correlation (60204) coverage on hosts
without a lockout policy.

---

## Evidence

- Alerts (Wazuh → Shuffle → TheHive): `scenario-04-rdp/thehive-lockout.png`,
  `scenario-04-rdp/thehive-compromise.png`, `scenario-05-creddump/thehive-creddump.png`
- Underlying alert JSON: `scenario-04-rdp/alert-60122-failure.json`,
  `alert-60204-correlation.json`, `alert-60115-lockout.json`,
  `alert-92657-type3-nla.json`, `alert-92653-type10-session.json`;
  `scenario-05-creddump/alert-92075-certutil.json`, `alert-100002-mimikatz.json`,
  `alert-92900-lsass.json`
- Attack output: `scenario-04-rdp/attack-output.txt`, `scenario-05-creddump/attack-output.txt`
