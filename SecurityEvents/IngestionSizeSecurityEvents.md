# Ingestion Size Security Events

## Query Information

#### Description
The query below returns the top 10 Windows Security Events with the biggest footprint in your Sentinel environment. The query can be used to determine value for money, as more events increase the cost of your Sentinel environment. The size of each event depends on the amount of data in the columns.
The query can be used to investigate whether you have detection/forensic needs for the EventIds that ingest the most volume. If not, it may save you some money to aggregate them using summary rules or to filter that particular EventId overall.

#### References
- https://techcommunity.microsoft.com/blog/fasttrackforazureblog/windows-events-how-to-collect-them-in-sentinel-and-which-way-is-preferred-to-det/3997342

## Unified XDR
```KQL
let SearchWindow = 90d;
SecurityEvent
| where TimeGenerated > ago(SearchWindow)
| summarize TotalEvents = count(), Bytes=sum(_BilledSize), GBs= round(sum(_BilledSize) / (1024 * 1024 * 1024), 2) by EventID, Activity
| top 10 by Bytes
```

## Sentinel
```KQL
let SearchWindow = 90d;
SecurityEvent
| where TimeGenerated > ago(SearchWindow)
| summarize TotalEvents = count(), Bytes=sum(_BilledSize), GBs= round(sum(_BilledSize) / (1024 * 1024 * 1024), 2) by EventID, Activity
| top 10 by Bytes
```
