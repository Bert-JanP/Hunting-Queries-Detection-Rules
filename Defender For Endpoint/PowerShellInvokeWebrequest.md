# PowerShell Invoke-Webrequest

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.001 | Command and Scripting Interpreter: PowerShell | https://attack.mitre.org/techniques/T1059/001/ |

#### Description
Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. The function Invoke-Webrequest can be abused to remotely download script to the local file system for execution. This query can be used to list the commandline downloads. Since this request can be expected for certain workloads in your environment a additional filter is added, to only alert on servers if this executed.

#### Risk
A malicious script is remotely downloaded and executed.

#### References
- https://www.microsoft.com/en-us/security/blog/2022/06/02/exposing-polonium-activity-and-infrastructure-targeting-israeli-organizations/
- https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708

## Defender For Endpoint
```KQL
let AllowedDomains = dynamic(['google.com']);
let Servers = DeviceInfo
    | where Timestamp > ago(30d)
    | summarize arg_max(Timestamp, *) by DeviceId
    | where DeviceType == "Server"
    | distinct DeviceId;
DeviceNetworkEvents
| where InitiatingProcessCommandLine has "Invoke-Webrequest"
| where not(RemoteUrl in (AllowedDomains))
| where ActionType == "ConnectionSuccess"
// Filter line below if you also want to return private requests
| where RemoteIPType == "Public"
// If you only want to include servers in this detection use line below
//| where DeviceId in (Servers)
| project-reorder Timestamp, InitiatingProcessCommandLine, RemoteUrl, ActionType
```
## Sentinel
```KQL
let AllowedDomains = dynamic(['google.com']);
let Servers = DeviceInfo
    | where Timestamp > ago(30d)
    | summarize arg_max(Timestamp, *) by DeviceId
    | where DeviceType == "Server"
    | distinct DeviceId;
DeviceNetworkEvents
| where InitiatingProcessCommandLine has "Invoke-Webrequest"
| where not(RemoteUrl in (AllowedDomains))
| where ActionType == "ConnectionSuccess"
// Filter line below if you also want to return private requests
| where RemoteIPType == "Public"
// If you only want to include servers in this detection use line below
//| where DeviceId in (Servers)
| project-reorder TimeGenerated, InitiatingProcessCommandLine, RemoteUrl, ActionType
```