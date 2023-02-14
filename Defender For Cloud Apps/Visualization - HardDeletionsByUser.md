# Visualisation of the users with the most HardDelete actions performed

### Defender For Endpoint

```
CloudAppEvents
| where ActionType == 'HardDelete'
| extend
     Workload = parse_json(RawEventData).Workload,
     UserId = parse_json(RawEventData).UserId,
     ResultStatus = parse_json(RawEventData).ResultStatus,
     AffectedItemsJson = parse_json(RawEventData).AffectedItems
| extend ParentFolderPath = extract('"Path":"([^"]*)"', 1, tostring(AffectedItemsJson))
| where ResultStatus == 'Succeeded'
| where not(ParentFolderPath has_any ("Calendar", 'Agenda')) // Remove personal deletions of Calendar items
| summarize count() by tostring(UserId)
| top 50 by count_
| render columnchart with (title='HardDeletions by User')
```
### Sentinel
```
CloudAppEvents
| where ActionType == 'HardDelete'
| extend
     Workload = parse_json(RawEventData).Workload,
     UserId = parse_json(RawEventData).UserId,
     ResultStatus = parse_json(RawEventData).ResultStatus,
     AffectedItemsJson = parse_json(RawEventData).AffectedItems
| extend ParentFolderPath = extract('"Path":"([^"]*)"', 1, tostring(AffectedItemsJson))
| where ResultStatus == 'Succeeded'
| where not(ParentFolderPath has_any ("Calendar", 'Agenda')) // Remove personal deletions of Calendar items
| summarize count() by tostring(UserId)
| top 50 by count_
| render columnchart with (title='HardDeletions by User')
```
