# Sysmon configuration (Windows endpoint)

Sysmon supplies the process-create (Event ID 1) and process-access (Event ID 10)
telemetry that Scenario 05 detects on. Captured from the live host with
`sysmon64 -c`, which dumps the **effective running config** (not just a file on disk).

- **Sysmon version:** 15.22 (Sysinternals)
- **Config schemaversion:** 4.90
- **Config file:** `.\sysmonconfig.xml`
- **Config hash:** `SHA256=4516404FA30EE87CEA558567820CDC78863CC4AB07889519E49EAC3CCA92E0D2`
- **Base config:** a SwiftOnSecurity-style `sysmon-config`. The full ruleset is
  ~4,600 lines of `sysmon64 -c` output and is **not** reproduced here; the
  detection-relevant rules are excerpted verbatim below.

## ProcessCreate (Event ID 1) — feeds rules 92075 (certutil) and 100002 (Mimikatz)

`onmatch: include`. Two include rules carry this scenario (verbatim from the dump):

```
OriginalFileName   filter: is          value: 'certutil.exe'      (Compound Rule "Indirect Command Execution")
Image              filter: begin with  value: 'C:\Users\Public\'
```

- certutil's process-create is logged by the first rule → Wazuh **92075** (T1105).
- Mimikatz was dropped by certutil to `C:\Users\Public\m.exe` and run from there, so
  its process-create is logged by the second rule. Its PE `OriginalFileName` is
  `mimikatz.exe`, which the custom Wazuh rule **100002** (T1003) matches.
  Evidence: `alert-100002-mimikatz.json` — `image = C:\Users\Public\m.exe`,
  `originalFileName = mimikatz.exe`.

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
