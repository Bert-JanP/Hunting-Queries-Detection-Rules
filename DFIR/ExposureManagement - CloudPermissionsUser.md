# List all Cloud Permissions of a Compromised User

## Sentinel
```KQL
// Cloud Permissions Compromised User
let UserName = "Bert-Jan Pals";
ExposureGraphEdges
| where EdgeLabel == "has permissions to"
| where SourceNodeName == UserName
| extend Type = extract(@'"name":"(.*?)"', 1, tostring(EdgeProperties))
| project SourceNodeName, EdgeLabel, Type, TargetNodeName, TargetNodeLabel, EdgeProperties
| sort by Type, TargetNodeLabel, TargetNodeName
```



