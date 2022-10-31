# List the top 10 accounts that have the most impersonators

### Defender For Endpoint

```
CloudAppEvents
| where IsImpersonated == 1
| extend
     MailboxOwnerUPN = tostring(parse_json(RawEventData).MailboxOwnerUPN),
     ActionPerformedBy = tostring(parse_json(RawEventData).UserId)
| where MailboxOwnerUPN != ActionPerformedBy
| summarize Impersonators = make_set(ActionPerformedBy) by MailboxOwnerUPN
| extend TotalImpersonators = array_length(Impersonators)
| top 10 by TotalImpersonators
```
### Sentinel
```
CloudAppEvents
| where IsImpersonated == 1
| extend
     MailboxOwnerUPN = tostring(parse_json(RawEventData).MailboxOwnerUPN),
     ActionPerformedBy = tostring(parse_json(RawEventData).UserId)
| where MailboxOwnerUPN != ActionPerformedBy
| summarize Impersonators = make_set(ActionPerformedBy) by MailboxOwnerUPN
| extend TotalImpersonators = array_length(Impersonators)
| top 10 by TotalImpersonators
```
