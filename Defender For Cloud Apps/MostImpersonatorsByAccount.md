# List the top 10 accounts that have the most impersonators

## Query Information

#### Description
This query lists the top 10 accounts that have performed the most imporsonated users. The definiation for this field is: *Indicates whether the activity was performed by one user for another (impersonated) user*.

## Defender XDR
```KQL
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
## Sentinel
```KQL
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
