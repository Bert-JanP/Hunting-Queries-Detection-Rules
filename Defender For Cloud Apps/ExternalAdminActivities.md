# List the external admin activities

## Query Information

#### Description
This query lists all the external admin activities in your tenant sorted from the account with the most actions performed to the one with the least actions.

#### Risk
External admins can yield a bigger risk to your organisation as they are not internal users.

## Defender XDR
```KQL
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
## Sentinel
```KQL
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
