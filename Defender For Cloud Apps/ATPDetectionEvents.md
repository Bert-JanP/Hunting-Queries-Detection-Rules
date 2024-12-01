# ATP Detection events triggered

## Query Information

#### Description
Displays the *AtpDetection* events in CloudAppEvents.

## Defender XDR
```KQL
CloudAppEvents
| where ActionType == "AtpDetection"
| extend
     DetectionMethod = parse_json(RawEventData).DetectionMethod,
     EventDeepLink = parse_json(RawEventData).EventDeepLink,
     FileData = parse_json(RawEventData).FileData
| project-reorder
     Timestamp,
     ActionType,
     Application,
     AccountId,
     DetectionMethod,
     FileData,
     EventDeepLink
```
## Sentinel
```KQL
CloudAppEvents
| where ActionType == "AtpDetection"
| extend
     DetectionMethod = parse_json(RawEventData).DetectionMethod,
     EventDeepLink = parse_json(RawEventData).EventDeepLink,
     FileData = parse_json(RawEventData).FileData
| project-reorder
     TimeGenerated,
     ActionType,
     Application,
     AccountId,
     DetectionMethod,
     FileData,
     EventDeepLink
```
