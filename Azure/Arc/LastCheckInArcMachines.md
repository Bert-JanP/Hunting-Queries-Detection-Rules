# Last Heartbeat Arc Machines

## Query Information

#### Description
This query lists the latest heartbeat for each Azure Arc onboarded machine.

## Sentinel
```KQL
let ArcMachines = arg("").Resources
| where type == "microsoft.hybridcompute/machines"
| distinct id;
Heartbeat
| summarize arg_max(TimeGenerated, TimeGenerated, Computer, Resource, ResourceId) by Computer
| where ResourceId in (ArcMachines)
```