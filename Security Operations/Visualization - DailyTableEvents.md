# Visualize the daily events for each table

## Query Information

#### Description
In MDE or Sentinel there are plenty of tables that generate logs, in order to determine which tables ingest the most logs the queries below can be used. The *TimeRange* variable can be used to select the timerange for your visualization.

Mainly important for Sentinel users is to get insight into the amount of traffic ingested, this query can help you to determine which tables ingest most data. The reference below can be used to get more information about cost management in Sentinel.

### References
- https://learn.microsoft.com/en-us/azure/sentinel/billing-monitor-costs

## Defender XDR
```KQL
let TimeRange = 10d;
search *
| where Timestamp > ago(TimeRange)
| project Timestamp, $table
| summarize Events = count() by $table, bin(Timestamp, 1d)
| render linechart  with (title="Total Daily Events")

```
## Sentinel
```KQL
let TimeRange = 10d;
search *
| where Timestamp > ago(TimeRange)
| project Timestamp, $table
| summarize Events = count() by $table, bin(Timestamp, 1d)
| render columnchart with (title="Total Daily Events", kind=stacked)
```
