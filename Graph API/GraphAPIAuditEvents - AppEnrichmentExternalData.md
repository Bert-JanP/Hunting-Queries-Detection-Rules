# GraphAPIAuditEvents App Enrichment ExternalData Based 

## Query Information

#### Description
This query enriches the *GraphAPIAuditEvents* with Application information Using the Azure_Application_ID list developed by [@Beercow](https://github.com/Beercow) 1000+ AppIds can be enriched with the [externaldata operator](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/externaldata-operator?pivots=azuredataexplorer) resulting in the query below.

#### References
- https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview#what-data-is-available-in-the-microsoft-graph-activity-logs
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs
- https://kqlquery.com/posts/graphactivitylogs/

## Defender XDR
```KQL
let ApplicationInformation = externaldata (ApplicationName: string, AppId: string, Reference: string ) [h"https://raw.githubusercontent.com/Beercow/Azure-App-IDs/master/Azure_Application_IDs.csv"] with (ignoreFirstRecord=true, format="csv");
GraphAPIAuditEvents
// Your filter here
| take 1000
| lookup kind=leftouter ApplicationInformation on $left.ApplicationId == $right.AppId
| project-reorder ApplicationId, ApplicationName
```
