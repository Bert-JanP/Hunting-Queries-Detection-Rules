# Malicious email delivered in Microsoft 365

### Defender For Endpoint

```
CloudAppEvents
| where ActionType == "TIMailData-Inline"
| extend Classification = parse_json(RawEventData).['Verdict']
| extend EmailSubject = parse_json(RawEventData).['Subject']
| extend ClassificationReason = parse_json(RawEventData).['ThreatsAndDetectionTech']
| extend ConfidentialityLevel = parse_json(RawEventData).['PhishConfidenceLevel']
| extend Recipients = parse_json(RawEventData).['Recipients']
| extend InvestigationLink = parse_json(RawEventData).['EventDeepLink']
| project-reorder
     Timestamp,
     EmailSubject,
     Classification,
     ClassificationReason,
     ConfidentialityLevel,
     Recipients,
     InvestigationLink
```
### Sentinel
```
CloudAppEvents
| where ActionType == "TIMailData-Inline"
| extend Classification = parse_json(RawEventData).['Verdict']
| extend EmailSubject = parse_json(RawEventData).['Subject']
| extend ClassificationReason = parse_json(RawEventData).['ThreatsAndDetectionTech']
| extend ConfidentialityLevel = parse_json(RawEventData).['PhishConfidenceLevel']
| extend Recipients = parse_json(RawEventData).['Recipients']
| extend InvestigationLink = parse_json(RawEventData).['EventDeepLink']
| project-reorder
     TimeGenerated,
     EmailSubject,
     Classification,
     ClassificationReason,
     ConfidentialityLevel,
     Recipients,
     InvestigationLink
```
