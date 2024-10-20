# Hunt for the events that have been performed while connected to a Anonymous Proxy

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1090 | Proxy | https://attack.mitre.org/techniques/T1090 |

#### Description
Adversaries may create a proxy to avoid direct connections to a specific environment, the proxies can be used to disguise the source of the malicious activities. In this case it contains all CloudAppEvents where a device was connected to a proxy. This query returns all activities that have been performed while connected to a proxy. 

Common false positive is Iphones connected to Icloud Private Relay to mask your IP address. 

#### Risk
A attacker has taken control over an account and tries to mask its source. 

#### References
- https://support.apple.com/en-us/HT212614

## Defender XDR
```
CloudAppEvents
| where IsAnonymousProxy == 1
| extend UserId = tostring(parse_json(RawEventData).UserId)
| summarize
     TotalActivities = count(),
     ActionsPerformed = make_set(ActionType),
     OSUsed = make_set(OSPlatform),
     IPsUsed = make_set(IPAddress)
     by AccountId, UserId
| project AccountId, UserId, TotalActivities, ActionsPerformed, OSUsed, IPsUsed
| sort by TotalActivities
```
## Sentinel
```
CloudAppEvents
| where IsAnonymousProxy == 1
| extend UserId = tostring(parse_json(RawEventData).UserId)
| summarize
     TotalActivities = count(),
     ActionsPerformed = make_set(ActionType),
     OSUsed = make_set(OSPlatform),
     IPsUsed = make_set(IPAddress)
     by AccountId, UserId
| project AccountId, UserId, TotalActivities, ActionsPerformed, OSUsed, IPsUsed
| sort by TotalActivities
```
