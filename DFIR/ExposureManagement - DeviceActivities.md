# List Activities Compromised Device Can Perform as Source

## Sentinel
```KQL
// List activities device can do as source
let DeviceName = "laptop.test.com";
ExposureGraphEdges
| where SourceNodeLabel == "device"
| where SourceNodeName == DeviceName
| summarize Total = dcount(TargetNodeName), Details = make_set(TargetNodeName) by EdgeLabel, SourceNodeName
| project Source = SourceNodeName, Action = EdgeLabel, Details, Tota
```
