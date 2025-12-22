# MSHTA Executions

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1218.005| System Binary Proxy Execution: Mshta | https://attack.mitre.org/techniques/T1218/005/ |

#### Description
This query lists all mshta executions, or if mshta is used legitimately can be used to filter on suspicious mshta child processes.

#### Risk
Threat actors can use mshta to drop payloads on systems.

#### References
- https://redcanary.com/threat-detection-report/techniques/mshta/

## Defender XDR
```KQL
let SuspiciousChildProcesses = dynamic(['cmd.exe', 'powershell.exe', 'bash.exe', 'csscript.exe', 'mshta.exe', 'msiexec.exe', 'rundll32.exe']);
DeviceProcessEvents
| where InitiatingProcessFileName =~ 'mshta.exe' or ProcessVersionInfoOriginalFileName  =~ 'mshta.exe'
// Optionally only list suspicious child processes
//| where FileName in~ (SuspiciousChildProcesses)
| project-reorder  Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, AccountUpn, ProcessVersionInfoOriginalFileName
```

## Sentinel
```KQL
let SuspiciousChildProcesses = dynamic(['cmd.exe', 'powershell.exe', 'bash.exe', 'csscript.exe', 'mshta.exe', 'msiexec.exe', 'rundll32.exe']);
DeviceProcessEvents
| where InitiatingProcessFileName =~ 'mshta.exe' or ProcessVersionInfoOriginalFileName  =~ 'mshta.exe'
// Optionally only list suspicious child processes
//| where FileName in~ (SuspiciousChildProcesses)
| project-reorder  TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, AccountUpn, ProcessVersionInfoOriginalFileName
```