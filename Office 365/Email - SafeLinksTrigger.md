# Safe Links Email URL Block Trigger

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566.002 | Phishing: Spearphishing Link | https://attack.mitre.org/techniques/T1566/002/ |


#### Description
This query lists the emails that have triggered a URL block by safelinks. This is done by collecting the safelinks logs where the action is ClickBlocked and then joining the email events to collect the information about the mail that was send. The URL click of the user will also generate a indincident itself, this enriches the information required to investigate this incident. 

Note: This query will only give results if safe links is enabled in your environment. 

#### Risk
A phishing campaign has started and a user has clicked the url, the URL is blocked so the risk is limited. 

#### References
- https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-links-about?view=o365-worldwide

## Defender For Endpoint
```
UrlClickEvents
| where ActionType == 'ClickBlocked'
// Only filter on Safe Links actions from mail
| where Workload == 'Email'
// join the email events
| join kind=leftouter (EmailEvents | project NetworkMessageId, Subject, SenderFromAddress) on NetworkMessageId
| project Timestamp, AccountUpn, Product = Workload, Url, ThreatTypes, Subject, SenderFromAddress, UrlChain
```
## Sentinel
```
UrlClickEvents
| where ActionType == 'ClickBlocked'
// Only filter on Safe Links actions from mail
| where Workload == 'Email'
// join the email events
| join kind=leftouter (EmailEvents | project NetworkMessageId, Subject, SenderFromAddress) on NetworkMessageId
| project TimeGenerated, AccountUpn, Product = Workload, Url, ThreatTypes, Subject, SenderFromAddress, UrlChain
```