# Detect risky IP activities

### Defender XDR

```
CloudAppEvents
| where IPCategory == "Risky"
| project Timestamp, ActionType, IPAddress, IPCategory, ISP, RawEventData
```
### Sentinel
```
CloudAppEvents
| where IPCategory == "Risky"
| project TimeGenerated, ActionType, IPAddress, IPCategory, ISP, RawEventData
```
