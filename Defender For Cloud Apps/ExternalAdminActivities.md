# List the external admin activities

### Defender For Endpoint

```
CloudAppEvents
| where IsExternalUser == 1 and AccountType == "Admin"
| summarize
      TotalActivities = count(),
      ActionsPerformed = make_set(ActionType),
      Applications = make_set(Application),
      IPsUsed = make_set(IPAddress)
      by AccountId
| sort by TotalActivities
```
### Sentinel
```
CloudAppEvents
| where IsExternalUser == 1 and AccountType == "Admin"
| summarize
      TotalActivities = count(),
      ActionsPerformed = make_set(ActionType),
      Applications = make_set(Application),
      IPsUsed = make_set(IPAddress)
      by AccountId
| sort by TotalActivities
```
