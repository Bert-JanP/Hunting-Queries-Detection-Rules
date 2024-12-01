# Visualisation of ActionTypes that have been seen in the Cloud App logs in the last 30 days

## Defender XDR
```
CloudAppEvents
| where Timestamp > ago(30d)
| summarize count() by ActionType
| render piechart with(title="ActionTypes triggered last 30 days")
```

## Sentinel
```
CloudAppEvents
| where TimeGenerated > ago(30d)
| summarize count() by ActionType
| render piechart with(title="ActionTypes triggered last 30 days")
```
