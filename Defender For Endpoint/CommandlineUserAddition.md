# Commandline User Addition

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1136.002 | Create Account: Domain Account | https://attack.mitre.org/techniques/T1136/002/ |

#### Description
This query is aimed to detect users that are added via the commandline. Adding users via the commandline is a common technique used by adversaries to gain persistence on systems. Some examples of commandlines used by aderveraries are shown below.

```PowerShell
net user username \password \domain
net user /add /domain
```
#### Risk
An attacker got access to a system and created an account for persitence.

#### References
- https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708

## Defender XDR
```KQL
DeviceProcessEvents
| where FileName in ("net.exe", "net1.exe")
| where ProcessCommandLine has_all ("add", "user") 
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine
```
## Sentinel
```KQL
DeviceProcessEvents
| where FileName in ("net.exe", "net1.exe")
| where ProcessCommandLine has_all ("add", "user") 
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine
```
