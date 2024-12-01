# List the top 100 accounts that have performed the most impersonated actions

## Query Information

#### Description
This query lists the top 100 accounts that have performed the most imporsonated actions. The definiation for this field is: *Indicates whether the activity was performed by one user for another (impersonated) user*.

## Defender XDR
```KQL
CloudAppEvents
| where IsImpersonated == 1
| extend
     MailboxOwnerUPN = tostring(parse_json(RawEventData).MailboxOwnerUPN),
     ActionPerformedBy = tostring(parse_json(RawEventData).UserId)
| where MailboxOwnerUPN != ActionPerformedBy
| summarize
     TotalImpersonatedActivities = count(),
     Impersonators = make_set(ActionPerformedBy),
     PerformedActions = make_set(ActionType)
     by MailboxOwnerUPN
| top 100 by TotalImpersonatedActivities
```
## Sentinel
```KQL
CloudAppEvents
| where IsImpersonated == 1
| extend
     MailboxOwnerUPN = tostring(parse_json(RawEventData).MailboxOwnerUPN),
     ActionPerformedBy = tostring(parse_json(RawEventData).UserId)
| where MailboxOwnerUPN != ActionPerformedBy
| summarize
     TotalImpersonatedActivities = count(),
     Impersonators = make_set(ActionPerformedBy),
     PerformedActions = make_set(ActionType)
     by MailboxOwnerUPN
| top 100 by TotalImpersonatedActivities
```