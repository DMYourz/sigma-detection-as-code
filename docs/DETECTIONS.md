# Detection Catalog

This rule set contains **8 Sigma rules** for Windows/Sysmon telemetry. Each rule is validated, unit-tested against labeled true-positive / false-positive events, and compiled to Splunk SPL by CI. The SPL below is the **actual generated output** from `python -m sigmatools convert`.

## Rules

| Rule | ATT&CK | Level | Log source |
|------|--------|-------|-----------|
| Certutil Download via URLCache | T1105 | high | process_creation |
| Mshta Executing Remote Payload | T1218.005 | high | process_creation |
| Encoded PowerShell Command Line | T1059.001, T1027 | high | process_creation |
| Rundll32 Executing JavaScript or VBScript | T1218.011 | high | process_creation |
| Scheduled Task Creation via schtasks | T1053.005 | medium | process_creation |
| WMIC Process Call Create | T1047 | high | process_creation |
| Suspicious LSASS Process Access | T1003.001 | high | process_access |
| Registry Run Key Persistence | T1547.001 | medium | registry_set |

## Rule detail + compiled SPL

### Certutil Download via URLCache

- **File:** `rules/windows/proc_creation_win_certutil_download.yml`
- **ATT&CK:** T1105
- **Level:** high
- **What it catches:** Detects the certutil LOLBin being used to download a file from a remote location, a common ingress tool transfer technique.

Compiled Splunk SPL:

```spl
Image="*\\certutil.exe" CommandLine IN ("*urlcache*", "*verifyctl*") CommandLine IN ("*http*", "*ftp*", "*\\*")
```

### Mshta Executing Remote Payload

- **File:** `rules/windows/proc_creation_win_mshta_remote_payload.yml`
- **ATT&CK:** T1218.005
- **Level:** high
- **What it catches:** Detects mshta.exe executing a remote URL or inline script, a signed-binary proxy execution technique used to retrieve and run HTA/script payloads.

Compiled Splunk SPL:

```spl
Image="*\\mshta.exe" CommandLine IN ("*http://*", "*https://*", "*vbscript:*", "*javascript:*")
```

### Encoded PowerShell Command Line

- **File:** `rules/windows/proc_creation_win_powershell_encoded.yml`
- **ATT&CK:** T1059.001, T1027
- **Level:** high
- **What it catches:** Detects PowerShell launched with an encoded (-EncodedCommand) payload, a common way to hide malicious script content from casual inspection.

Compiled Splunk SPL:

```spl
Image IN ("*\\powershell.exe", "*\\pwsh.exe") OR OriginalFileName="PowerShell.EXE" CommandLine IN ("* -enc *", "* -EncodedCommand *", "* -ec *")
```

### Rundll32 Executing JavaScript or VBScript

- **File:** `rules/windows/proc_creation_win_rundll32_javascript.yml`
- **ATT&CK:** T1218.011
- **Level:** high
- **What it catches:** Detects rundll32 used to execute inline JavaScript/VBScript, a signed-binary proxy execution technique used to run code outside script interpreters.

Compiled Splunk SPL:

```spl
Image="*\\rundll32.exe" CommandLine IN ("*javascript:*", "*vbscript:*", "*.RegisterXLL*")
```

### Scheduled Task Creation via schtasks

- **File:** `rules/windows/proc_creation_win_schtasks_persistence.yml`
- **ATT&CK:** T1053.005
- **Level:** medium
- **What it catches:** Detects creation of a scheduled task via schtasks.exe, frequently abused for persistence and privilege escalation.

Compiled Splunk SPL:

```spl
Image="*\\schtasks.exe" CommandLine="* /create *"
```

### WMIC Process Call Create

- **File:** `rules/windows/proc_creation_win_wmic_process_call_create.yml`
- **ATT&CK:** T1047
- **Level:** high
- **What it catches:** Detects use of WMIC to spawn a new process, a technique used for both local execution and lateral movement.

Compiled Splunk SPL:

```spl
Image="*\\WMIC.exe" CommandLine="*process*" CommandLine="*call*" CommandLine="*create*"
```

### Suspicious LSASS Process Access

- **File:** `rules/windows/process_access_win_lsass_dump.yml`
- **ATT&CK:** T1003.001
- **Level:** high
- **What it catches:** Detects a process opening a handle to LSASS with access rights commonly associated with credential dumping, excluding known-good system callers.

Compiled Splunk SPL:

```spl
TargetImage="*\\lsass.exe" GrantedAccess IN ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff") NOT (SourceImage IN ("*\\wininit.exe", "*\\MsMpEng.exe", "*\\svchost.exe"))
```

### Registry Run Key Persistence

- **File:** `rules/windows/registry_set_win_run_key_persistence.yml`
- **ATT&CK:** T1547.001
- **Level:** medium
- **What it catches:** Detects creation or modification of autostart Run/RunOnce registry keys by a non-standard process, a classic persistence mechanism.

Compiled Splunk SPL:

```spl
TargetObject IN ("*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*", "*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*", "*\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\*") NOT (Image IN ("*\\explorer.exe", "*\\msiexec.exe"))
```
