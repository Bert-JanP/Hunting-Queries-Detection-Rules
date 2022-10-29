# Hunt for the events that have been performed while connected to a Anonymous Proxy

### Defender For Endpoint

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
### Sentinel
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
