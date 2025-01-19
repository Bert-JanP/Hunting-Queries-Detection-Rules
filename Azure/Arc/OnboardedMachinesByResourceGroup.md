# Onboarded Machines by Resource Group

## Query Information

#### Description
This query lists the amount of onboarded Azure Arc Machines for each resourceGroup.

## Sentinel
```KQL
arg("").Resources
| where type == "microsoft.hybridcompute/machines"
| summarize Total = dcount(id), SampleDevices = make_set(name, 10) by resourceGroup
```