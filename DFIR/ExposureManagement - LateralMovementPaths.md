# List Lateral Movements Paths to Compromised Device

## Sentinel
```KQL
// List potential lateralmovement paths to compromised device
let DeviceName = "testdevice.test.com";
ExposureGraphEdges
| where TargetNodeLabel == "device"
| where TargetNodeName == DeviceName
| summarize Total = dcount(SourceNodeName), Details = make_set(SourceNodeName) by EdgeLabel, TargetNodeName
| extend Message = strcat(Total, " details ", EdgeLabel, " ", TargetNodeName)
| project Message, Action = EdgeLabel, Details, Total, Target = TargetNodeName
```



