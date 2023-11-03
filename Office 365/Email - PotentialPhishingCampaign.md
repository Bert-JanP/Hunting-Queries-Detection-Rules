# Potential Phishing Campaign

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566.002 | Phishing: Spearphishing Link | https://attack.mitre.org/techniques/T1566/002/ |

#### Description
The *EmailClusterId* which can be assigned to a mail is the identifier for the group of similar emails clustered based on heuristic analysis of their contents. Therefore this identifier can be leveraged to find related mails. This can for example be from a different sender or the content of the mail has changed from Hello Bob to Hello Alice but the rest of the contents has stayed the same. This query searches for mails that have the same *EmailClusterId* but have different senders. Furthermore only emails that contain a URL are selected by joining the EmailUrlInfo table.

This query needs adjustments to fit in your environment, this can be done using the threshold variables *RareDomainThreshold* and *TotalSenderThreshold*.

#### Risk
A phishing campaign using different email addresses is targetting your organisation.

#### References
- https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-emailevents-table?view=o365-worldwide

## Defender For Endpoint
```KQL
let RareDomainThreshold = 20;
let TotalSenderThreshold = 1;
let RareDomains = EmailEvents
| summarize TotalDomainMails = count() by SenderFromDomain
| where TotalDomainMails <= RareDomainThreshold
| project SenderFromDomain;
EmailEvents
| where EmailDirection == "Inbound"
| where SenderFromDomain in (RareDomains)
| where isnotempty(EmailClusterId)
| join kind=inner EmailUrlInfo on NetworkMessageId
| summarize Subjects = make_set(Subject), Senders = make_set(SenderFromAddress) by EmailClusterId
| extend TotalSenders = array_length(Senders)
| where TotalSenders >= TotalSenderThreshold
```
## Sentinel
```KQL
let RareDomainThreshold = 20;
let TotalSenderThreshold = 1;
let RareDomains = EmailEvents
| summarize TotalDomainMails = count() by SenderFromDomain
| where TotalDomainMails <= RareDomainThreshold
| project SenderFromDomain;
EmailEvents
| where EmailDirection == "Inbound"
| where SenderFromDomain in (RareDomains)
| where isnotempty(EmailClusterId)
| join kind=inner EmailUrlInfo on NetworkMessageId
| summarize Subjects = make_set(Subject), Senders = make_set(SenderFromAddress) by EmailClusterId
| extend TotalSenders = array_length(Senders)
| where TotalSenders >= TotalSenderThreshold
```