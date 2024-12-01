# List risky IP activities

## Query Information

#### Description
This query activities from a Risky IP

## Defender XDR
```KQL
CloudAppEvents
| where IPCategory == "Risky"
| project Timestamp, ActionType, IPAddress, IPCategory, ISP, RawEventData
```
## Sentinel
```KQL
CloudAppEvents
| where IPCategory == "Risky"
| project TimeGenerated, ActionType, IPAddress, IPCategory, ISP, RawEventData
```
