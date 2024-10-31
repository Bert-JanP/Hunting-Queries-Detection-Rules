# Large Number of Virtual Machines started

## Query Information

#### Description
This query detects when a Large Number of Virtual Machines is started within a short timeframe. The query uses two inputs; Threshold and TimeFrame. The threshold determines the number of machines from when the query should output results. The timeframe determines how long the period is to reach the threshold.

The total numbers are calculated based on resourcegroup level.

#### Risk
Actors may abuse compute resources for cryptomining purposes.

## Sentinel
```KQL
let Threshold = 25;
let TimeFrame = 1h;
AzureActivity
| where OperationNameValue =~ "MICROSOFT.COMPUTE/VIRTUALMACHINES/START/ACTION"
| where ActivityStatusValue == "Success"
| extend ResourceName = tostring(parse_json(Properties).resource)
| summarize Total = dcount(ResourceName), ResourceNames = make_set(ResourceName) by bin(TimeGenerated, TimeFrame), SubscriptionId, ResourceId
| where Total >= Threshold
```
