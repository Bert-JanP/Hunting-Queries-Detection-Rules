# Visualisation of operations that have been seen in the Cloud App logs in the last 30 days

## Defender XDR

```
CloudAppEvents
| where Timestamp > ago(30d)
| extend Operation = tostring(parse_json(RawEventData).Operation)
| where Operation != "CrmDefaultActivity" //Filter Dynamics 365 activities.
| summarize count() by Operation
| render piechart with(title="Operations last 30 days")
```
## Sentinel
```
CloudAppEvents
| where TimeGenerated > ago(30d)
| extend Operation = tostring(parse_json(RawEventData).Operation)
| where Operation != "CrmDefaultActivity" //Filter Dynamics 365 activities.
| summarize count() by Operation
| render piechart with(title="Operations last 30 days")
```
