# Malicious email delivered in Microsoft 365

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566 | Phishing | https://attack.mitre.org/techniques/T1566/ |

#### Description
This query lists all the emails that have been classified as malicious based on Threat Intelligence on the mailbox.

## Defender XDR
```KQL
CloudAppEvents
| where ActionType == "TIMailData-Inline"
| extend Classification = parse_json(RawEventData).['Verdict']
| extend ClassificationReason = parse_json(RawEventData).['ThreatsAndDetectionTech']
| extend ConfidentialityLevel = parse_json(RawEventData).['PhishConfidenceLevel']
| extend InvestigationLink = parse_json(RawEventData).['EventDeepLink'],
    NetworkMessageId = tostring(parse_json(RawEventData).NetworkMessageId)
| join kind=leftouter (EmailEvents | project NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject) on $left.NetworkMessageId == $right.NetworkMessageId
| project-reorder
     Timestamp,
     Classification,
     ClassificationReason,
     ConfidentialityLevel,
     SenderFromAddress,
     Subject,
     RecipientEmailAddress,
     InvestigationLink
```

## Sentinel
```KQL
CloudAppEvents
| where ActionType == "TIMailData-Inline"
| extend Classification = parse_json(RawEventData).['Verdict']
| extend ClassificationReason = parse_json(RawEventData).['ThreatsAndDetectionTech']
| extend ConfidentialityLevel = parse_json(RawEventData).['PhishConfidenceLevel']
| extend InvestigationLink = parse_json(RawEventData).['EventDeepLink'],
    NetworkMessageId = tostring(parse_json(RawEventData).NetworkMessageId)
| join kind=leftouter (EmailEvents | project NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject) on $left.NetworkMessageId == $right.NetworkMessageId
| project-reorder
     Timestamp,
     Classification,
     ClassificationReason,
     ConfidentialityLevel,
     SenderFromAddress,
     Subject,
     RecipientEmailAddress,
     InvestigationLink
```