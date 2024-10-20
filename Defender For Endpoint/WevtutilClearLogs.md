# Wevutil Clear Windows Event Logs

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | https://attack.mitre.org/techniques/T1070/001/ |

#### Description
Adversaries may clear Windows Event Logs to hide the activity of an intrusion. Windows Event Logs are a record of a computer's alerts and notifications. There are three system-defined sources of events: System, Application, and Security.

This query lists when one of the three sources of Windows Event is cleared or when an attempt has been made to clear the logs. The logs will not provide if the user that initiated the clear action also had the permissions to succesfully complete the task.

#### Risk
Multiple Threat Actors levarage this technique to hide from defenders

#### References
- https://www.cisa.gov/sites/default/files/publications/aa22-321a_joint_csa_stopransomware_hive.pdf

## Defender XDR
```KQL
DeviceProcessEvents
| extend ProcessCommandLineToLower =  tolower(ProcessCommandLine)
| where ProcessCommandLineToLower has "wevtutil.exe" and ProcessCommandLineToLower has_any ("cl", "clear-log")
| project-reorder Timestamp, DeviceName, AccountSid, ProcessCommandLine, InitiatingProcessCommandLine 
```
## Sentinel
```KQL
DeviceProcessEvents
| extend ProcessCommandLineToLower =  tolower(ProcessCommandLine)
| where ProcessCommandLineToLower has "wevtutil.exe" and ProcessCommandLineToLower has_any ("cl", "clear-log")
| project-reorder TimeGenerated, DeviceName, AccountSid, ProcessCommandLine, InitiatingProcessCommandLine 
```
