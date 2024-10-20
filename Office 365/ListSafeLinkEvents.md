# List SafeLink events

## Query Information

#### Description
This query lists all events that have triggered a URL block by safelinks. Those actions can be from multiple workloads: Teams, Office Applications or from email events. The URL click of the user will also generate a indincident itself. This query lists all events in one single view. 

Note: This query will only give results if safe links is enabled in your environment. 

#### Risk
A phishing campaign has started and a user has clicked the url, the URL is blocked so the risk is limited. 

#### References
- https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-links-about?view=o365-worldwide

## Defender XDR
```
UrlClickEvents
| where ActionType == "ClickBlocked"
| project Timestamp, Url, Workload, AccountUpn, ThreatTypes, IsClickedThrough
```
## Sentinel
```
UrlClickEvents
| where ActionType == "ClickBlocked"
| project TimeGenerated, Url, Workload, AccountUpn, ThreatTypes, IsClickedThrough
```

