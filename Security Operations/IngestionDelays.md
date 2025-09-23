# Ingestion Delays

## Query Information

#### Description
This query can be used to calculate ingestion delays of the unified security platform. In this specific case the GraphAPIAuditEvents and MicrosoftGraphActivityLogs are compared, but these tablenames can be changed to any other table. For all EDR logs you can for example use *union withsource=TableName Device* * to filter on all tables starting with Device. 

#### Risk
Ingestion delays should be taken into account when creating detections, these delays can cause gaps in your detections if not handled properly.

#### References
- https://kqlquery.com/posts/graphapiauditevents/

## Defender XDR
```KQL
union withsource=TableName GraphAPIAuditEvents, MicrosoftGraphActivityLogs
| extend IngestionTime = ingestion_time()
| extend IngestionDelay = datetime_diff('minute',  IngestionTime, Timestamp)
| summarize Average = round(avg(IngestionDelay), 1), percentiles(IngestionDelay, 50, 75, 90, 95, 97, 99) by TableName
```

## Sentinel
```KQL
union withsource=TableName GraphAPIAuditEvents, MicrosoftGraphActivityLogs
| extend IngestionTime = ingestion_time()
| extend IngestionDelay = datetime_diff('minute',  IngestionTime, TimeGenerated)
| summarize Average = round(avg(IngestionDelay), 1), percentiles(IngestionDelay, 50, 75, 90, 95, 97, 99) by TableName
```