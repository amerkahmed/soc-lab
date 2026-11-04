# Sysmon configuration (Windows endpoint)

Sysmon supplies the process-create (Event ID 1) and process-access (Event ID 10)
telemetry that Scenario 05 detects on. Captured from the live host with
`sysmon64 -c`, which dumps the **effective running config** (not just a file on disk).

- **Sysmon version:** 15.22 (Sysinternals)
- **Config schemaversion:** 4.90
- **Config file:** `.\sysmonconfig.xml`
- **Config hash:** `SHA256=4516404FA30EE87CEA558567820CDC78863CC4AB07889519E49EAC3CCA92E0D2`
- **Base config:** Olaf Hartong's **sysmon-modular**
  (`github.com/olafhartong/sysmon-modular`), identifiable by its
  `technique_id=…,technique_name=…` RuleNames carried in the evidence. The full ruleset
  is ~4,600 lines of `sysmon64 -c` output and is **not** reproduced here; the
  detection-relevant rules are excerpted verbatim below.

## ProcessCreate (Event ID 1) — feeds rules 92075 (certutil) and 100002 (Mimikatz)

`onmatch: include`. sysmon-modular captures both process-creates; the `ruleName`
each event carries (verbatim from the alerts) is its sysmon-modular technique tag:

```
certutil  OriginalFileName is 'certutil.exe'   → ruleName technique_id=T1202 (Indirect Command Execution)
m.exe     CommandLine contains 'ls'            → ruleName technique_id=T1083 (File and Directory Discovery)
```

- certutil's process-create matches the T1202 rule → Wazuh **92075** (T1105).
- Mimikatz (renamed `m.exe`, run from `C:\Users\Public\`) is captured too, but its
  recorded `ruleName` is **T1083 "File and Directory Discovery"** — a *coincidental*
  substring match: sysmon-modular's T1083 rule fires on a CommandLine containing `ls`,
  and the Mimikatz command `sekurlsa::logonpasswords` contains "ls". It is **not** the
  `C:\Users\Public\` path rule (sysmon-modular tags that **T1036 Masquerading**). The
  tag is noise — the real detection is the custom Wazuh rule **100002** matching the PE
  `OriginalFileName = mimikatz.exe` (T1003). Evidence: `alert-100002-mimikatz.json` —
  `image = C:\Users\Public\m.exe`, `originalFileName = mimikatz.exe`,
  `ruleName = technique_id=T1083,technique_name=File and Directory Discovery`,
  `commandLine = "…m.exe" privilege::debug sekurlsa::logonpasswords exit`.

## ProcessAccess (Event ID 10) — feeds rule 92900 (LSASS access)

`onmatch: include`. The LSASS-targeting rules (Compound Rules 0117–0120, verbatim):

```
TargetImage     filter: is   value: 'C:\Windows\system32\lsass.exe'
GrantedAccess   filter: is   value: '0x1FFFFF'   (0117)
GrantedAccess   filter: is   value: '0x1F1FFF'   (0118)
GrantedAccess   filter: is   value: '0x1010'     (0119)
GrantedAccess   filter: is   value: '0x143A'     (0120)
```

Mimikatz's `sekurlsa::logonpasswords` opened LSASS with **`0x1010`**, matching
Compound Rule 0119 → Event ID 10 → Wazuh **92900** (T1003.001). Evidence:
`alert-92900-lsass.json` — `targetImage = C:\Windows\system32\lsass.exe`,
`grantedAccess = 0x1010`, `sourceImage = C:\Users\Public\m.exe`.
