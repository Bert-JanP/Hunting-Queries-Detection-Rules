# Suspicious Explorer Child Process

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059 | Command and Scripting Interpreter | https://attack.mitre.org/techniques/T1059/ |

#### Description
This detection detects when explorer has suspicious child process and the commandline contains suspicious parameters, this child process can execute/install commands and is often used to install malware on systems.

Adjust the list of browsers to your environment.

#### Risk
A potentially malicious command has been executed and may have installed malicious software.

#### References
- https://mrd0x.com/filefix-clickfix-alternative/
- 

## Defender XDR
```KQL
let Parameters = dynamic(['http', 'https', 'Encoded', 'EncodedCommand', '-e', '-eC', '-enc', "-w", "://"]);
let SuspiciousChildProcesses = dynamic(['cmd.exe', 'powershell.exe', 'bash.exe', 'csscript.exe', 'mshta.exe', 'msiexec.exe', 'rundll32.exe']);
DeviceProcessEvents
| where InitiatingProcessFileName =~ "explorer.exe" or InitiatingProcessVersionInfoOriginalFileName =~ "explorer.exe"
| where FileName in~ (SuspiciousChildProcesses) or ProcessVersionInfoOriginalFileName in~ (SuspiciousChildProcesses)
| where ProcessCommandLine has_any (Parameters)
| project-reorder Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, AccountUpn, ProcessVersionInfoOriginalFileName

```

## Sentinel
```KQL
let Parameters = dynamic(['http', 'https', 'Encoded', 'EncodedCommand', '-e', '-eC', '-enc', "-w", "://"]);
let SuspiciousChildProcesses = dynamic(['cmd.exe', 'powershell.exe', 'bash.exe', 'csscript.exe', 'mshta.exe', 'msiexec.exe', 'rundll32.exe']);
DeviceProcessEvents
| where InitiatingProcessFileName =~ "explorer.exe" or InitiatingProcessVersionInfoOriginalFileName =~ "explorer.exe"
| where FileName in~ (SuspiciousChildProcesses) or ProcessVersionInfoOriginalFileName in~ (SuspiciousChildProcesses)
| where ProcessCommandLine has_any (Parameters)
| project-reorder TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, AccountUpn, ProcessVersionInfoOriginalFileName
```
