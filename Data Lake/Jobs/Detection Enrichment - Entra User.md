# Detection Enrichment - Entra User

## Query Information

#### Description
Sentinel Data Lake job to put an aggregated table of entra users in LAW for filtering/enrichment in detections and automations.

#### References
- https://learn.microsoft.com/en-us/azure/sentinel/datalake/enable-data-connectors


## Sentinel
```KQL
EntraUsers
| where TimeGenerated > ago(3d)
| summarize arg_max(TimeGenerated, * ) by id
| project-away _*
| project-rename ObjectId = id
```
