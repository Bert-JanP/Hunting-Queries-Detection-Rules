# Suspicious MSBuild Remote Thread

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1127.001 | Trusted Developer Utilities Proxy Execution: MSBuild | https://attack.mitre.org/techniques/T1127/001/ |

#### Description
Adversaries may use MSBuild.exe to execute/build code through a trusted windows lolbin. In this specific scenario a suspicious MSBuild remote threat is created which indicates Command & Control traffic or Reverse Shell activities.

The enrichment based on *DeviceNetworkEvents* or *DeviceProcessEvents* can be optionally added to the rule to enrich the results for the analysts investigating the alert.

#### Risk
Potential C2 or Reverse Shell activities

#### References
- https://lolbas-project.github.io/lolbas/Binaries/Msbuild/

## Defender XDR
```KQL
DeviceEvents
| where ActionType =~ 'CreateRemoteThreadApiCall'
| where FileName =~ 'MSBuild.exe'
// Exclude Visual Studio
| where not(FolderPath has_all ('Program Files', 'Microsoft Visual Studio', @'MSBuild\Current\Bin'))
// Enrichment based on commandline
| join kind=leftouter (DeviceNetworkEvents | project ConnectionTime = Timestamp, DeviceId, InitiatingProcessCommandLine, RemoteThreadIP = RemoteIP, RemotePort) on $left.ProcessCommandLine == $right.InitiatingProcessCommandLine, DeviceId
| join kind=leftouter (DeviceProcessEvents | summarize ExecutedCommands = make_set(ProcessCommandLine) by DeviceId, InitiatingProcessCommandLine) on $left.ProcessCommandLine == $right.InitiatingProcessCommandLine, DeviceId
| project-reorder Timestamp, ConnectionTime, RemoteThreadIP, ExecutedCommands
```

## Sentinel
```KQL
DeviceEvents
| where ActionType =~ 'CreateRemoteThreadApiCall'
| where FileName =~ 'MSBuild.exe'
// Exclude Visual Studio
| where not(FolderPath has_all ('Program Files', 'Microsoft Visual Studio', @'MSBuild\Current\Bin'))
// Enrichment based on commandline
| join kind=leftouter (DeviceNetworkEvents | project ConnectionTime = TimeGenerated, DeviceId, InitiatingProcessCommandLine, RemoteThreadIP = RemoteIP, RemotePort) on $left.ProcessCommandLine == $right.InitiatingProcessCommandLine, DeviceId
| join kind=leftouter (DeviceProcessEvents | summarize ExecutedCommands = make_set(ProcessCommandLine) by DeviceId, InitiatingProcessCommandLine) on $left.ProcessCommandLine == $right.InitiatingProcessCommandLine, DeviceId
| project-reorder TimeGenerated, ConnectionTime, RemoteThreadIP, ExecutedCommands
```
