# PowerShell Invoke-Webrequest

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.001 | Command and Scripting Interpreter: PowerShell | https://attack.mitre.org/techniques/T1059/001/ |

#### Description
Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. The function Invoke-Webrequest can be abused to remotely download script to the local file system for execution. This query can be used to list the commandline downloads. Since this request can be expected for certain workloads in your environment a additional filter is added, to only alert on servers if this executed.

There are additional filters build into this query to only filter on servers, or only filter if the commandline mentions a IPv4 address.

#### Risk
A malicious script is remotely downloaded and executed.

#### References
- https://www.microsoft.com/en-us/security/blog/2022/06/02/exposing-polonium-activity-and-infrastructure-targeting-israeli-organizations/
- https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708

## Defender XDR
```KQL
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
let AllowedDomains = dynamic(['google.com']);
let Servers = DeviceInfo
    | where Timestamp > ago(30d)
    | summarize arg_max(Timestamp, *) by DeviceId
    | where DeviceType == "Server"
    | distinct DeviceId;
DeviceNetworkEvents
| where InitiatingProcessCommandLine has "Invoke-Webrequest"
| extend CommandLineIpv4 = extract(IPRegex, 0, InitiatingProcessCommandLine)
// If you only want to filter on Invoke-Webrequest that retrieve information direct from IPv4 addresses
//| where isnotempty(CommandLineIpv4)
| where not(RemoteUrl in (AllowedDomains))
| where ActionType == "ConnectionSuccess"
// Filter line below if you also want to return private requests
| where RemoteIPType == "Public"
// If you only want to include servers in this detection use line below
//| where DeviceId in (Servers)
| project-reorder Timestamp, InitiatingProcessCommandLine, RemoteUrl, ActionType, CommandLineIpv4
```
## Sentinel
```KQL
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
let AllowedDomains = dynamic(['google.com']);
let Servers = DeviceInfo
    | where Timestamp > ago(30d)
    | summarize arg_max(Timestamp, *) by DeviceId
    | where DeviceType == "Server"
    | distinct DeviceId;
DeviceNetworkEvents
| where InitiatingProcessCommandLine has "Invoke-Webrequest"
| extend CommandLineIpv4 = extract(IPRegex, 0, InitiatingProcessCommandLine)
// If you only want to filter on Invoke-Webrequest that retrieve information direct from IPv4 addresses
//| where isnotempty(CommandLineIpv4)
| where not(RemoteUrl in (AllowedDomains))
| where ActionType == "ConnectionSuccess"
// Filter line below if you also want to return private requests
| where RemoteIPType == "Public"
// If you only want to include servers in this detection use line below
//| where DeviceId in (Servers)
| project-reorder TimeGenerated, InitiatingProcessCommandLine, RemoteUrl, ActionType, CommandLineIpv4
```
