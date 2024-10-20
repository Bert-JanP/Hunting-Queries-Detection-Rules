# List the top 100 accounts that have performed the most impersonated actions

### Defender XDR

```
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
### Sentinel
```
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
