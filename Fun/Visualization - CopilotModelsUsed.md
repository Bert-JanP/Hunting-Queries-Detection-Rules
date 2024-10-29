# Copilot Models Used

## Query Information

#### Description
This query renders a Piechart based on the models used by Copilot interactions in your environment.

## Defender XDR
```KQL
CloudAppEvents
| where ActionType =~ "CopilotInteraction"
| extend WorkLoad = tostring(parse_json(RawEventData).Workload)
| where WorkLoad =~ "Copilot"
| extend CopilotModel = tostring(parse_json(RawEventData).CopilotEventData.ModelTransparencyDetails[0].ModelName)
| summarize Total = count() by CopilotModel
| render piechart 
```
## Sentinel
```KQL
CloudAppEvents
| where ActionType =~ "CopilotInteraction"
| extend WorkLoad = tostring(parse_json(RawEventData).Workload)
| where WorkLoad =~ "Copilot"
| extend CopilotModel = tostring(parse_json(RawEventData).CopilotEventData.ModelTransparencyDetails[0].ModelName)
| summarize Total = count() by CopilotModel
| render piechart 
```
