# Total Events by Table

## Query Information

#### Description
This query returns a table that shows the number of events for each data table that occurred in the last 30 days. This can returns information about the totalevens in all your Sentinel tables. Since you probably ingest more in Sentinel than you know, this query can result in discovering 'new' data sources to investigate.

## Sentinel
```KQL
let TimeFrame = 30d
union *
| where TimeGenerated > startofday(ago(TimeFrame))
| summarize TotalEvents = count() by Type
| sort by TotalEvents asc  
```
