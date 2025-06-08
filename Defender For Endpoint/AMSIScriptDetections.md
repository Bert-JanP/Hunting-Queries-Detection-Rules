# AMSI Script Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.001 | Command and Scripting Interpreter: PowerShell | https://attack.mitre.org/techniques/T1059/001/ |

#### Description
The Windows Antimalware Scan Interface (AMSI) is a versatile interface standard that allows your applications and services to integrate with any antimalware product that's present on a machine. AMSI provides enhanced malware protection for your end-users and their data, applications, and workloads.

This detection lists all *AmsiScriptDetection* events that happened in your tenant. Note that those events do not necessary results in incidents in Defender For Endpoint, therefore it is recommended to monitor or report on those actions.

#### Risk
An adversary uses PowerShell to execute malicious scripts in which AMSI detects the script. Since this does not have to be alerted, the adversary might still be unnoticed in your network.

#### References
- https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal

## Defender XDR
```KQL
DeviceEvents 
| where ActionType == "AmsiScriptDetection" 
| extend Description = tostring(parse_json(AdditionalFields).Description) 
| project Timestamp, DeviceName, DeviceId, InitiatingProcessCommandLine, Description, ReportId
```
## Sentinel
```KQL
DeviceEvents 
| where ActionType == "AmsiScriptDetection" 
| extend Description = tostring(parse_json(AdditionalFields).Description) 
| project TimeGenerated, DeviceName, DeviceId, InitiatingProcessCommandLine, Description, ReportId
```
