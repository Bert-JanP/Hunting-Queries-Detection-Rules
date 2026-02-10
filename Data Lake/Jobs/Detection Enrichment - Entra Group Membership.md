# Detection Enrichment - Entra Group Membership Enriched

## Query Information

#### Description
Sentinel Data Lake job to put an aggregated table of group memberships in LAW for filtering/enrichment in detections and automations.

#### References
- https://learn.microsoft.com/en-us/azure/sentinel/datalake/enable-data-connectors


## Sentinel
```KQL
EntraGroupMemberships
| where TimeGenerated > ago(3d)
| summarize arg_max(TimeGenerated, *) by sourceId, targetId
| join kind=leftouter (EntraGroups | where TimeGenerated > ago(3d) |  summarize arg_max(TimeGenerated, TimeGenerated, description, displayName, groupTypes, mailNickname) by id ) on $left.sourceId == $right.id
| project GroupId = sourceId, ObjectId = targetId, tenantId, organizationId, GroupDescription = description, GroupDisplayName = displayName, groupTypes, mailNickname
```
