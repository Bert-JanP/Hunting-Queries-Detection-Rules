# Potential Beaconing Activity

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1071.001 | Application Layer Protocol: Web Protocols | https://attack.mitre.org/techniques/T1071/001/ |

#### Description
This query detects potential Command & Control (C2) beaconing activity by identifying remote IPs that receive a high average number of connections from a small number of devices. Beaconing is a hallmark of C2 communication where malware regularly checks in with its controller at consistent intervals. The query combines aggregated connection reports with enrichment via `FileProfile` to surface processes with low global prevalence making these repeated outbound connections, reducing false positives from known-good software.

#### Risk
Beaconing activity is a strong indicator of an active C2 channel. An attacker with a foothold on a device may use a C2 framework to maintain persistence, exfiltrate data, and issue commands. Detecting beaconing early can significantly reduce dwell time.

## Defender XDR
```KQL
let DeviceThreshold = 5;
let ConnectionThreshold = 25;
let GlobalPrevalanceThreshold = 250;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where not(ipv4_is_private(RemoteIP))
| where ActionType == 'ConnectionSuccessAggregatedReport'
| extend Connections = toint(parse_json(AdditionalFields).uniqueEventsAggregated)
| summarize Total = count(), Devices = dcount(DeviceId), Domains = make_set(RemoteUrl), AvgConnections = avg(Connections) by RemoteIP, bin(TimeGenerated, 1d)
| where AvgConnections >= ConnectionThreshold and Devices <= DeviceThreshold
| join kind=inner (DeviceNetworkEvents
    | where ActionType == 'ConnectionSuccess'
    | distinct RemoteIP, InitiatingProcessSHA256) on RemoteIP
    | invoke FileProfile(InitiatingProcessSHA256)
    | where GlobalPrevalence <= GlobalPrevalanceThreshold
```

## Sentinel
```KQL
let DeviceThreshold = 5;
let ConnectionThreshold = 25;
let GlobalPrevalanceThreshold = 250;
DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where not(ipv4_is_private(RemoteIP))
| where ActionType == 'ConnectionSuccessAggregatedReport'
| extend Connections = toint(parse_json(AdditionalFields).uniqueEventsAggregated)
| summarize Total = count(), Devices = dcount(DeviceId), Domains = make_set(RemoteUrl), AvgConnections = avg(Connections) by RemoteIP, bin(TimeGenerated, 1d)
| where AvgConnections >= ConnectionThreshold and Devices <= DeviceThreshold
| join kind=inner (DeviceNetworkEvents
    | where ActionType == 'ConnectionSuccess'
    | distinct RemoteIP, InitiatingProcessSHA256) on RemoteIP
    | invoke FileProfile(InitiatingProcessSHA256)
    | where GlobalPrevalence <= GlobalPrevalanceThreshold
```