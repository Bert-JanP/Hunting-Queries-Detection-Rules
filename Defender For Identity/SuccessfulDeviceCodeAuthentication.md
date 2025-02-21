# Successful device code sign-in

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566.002 | Phishing: Spearphishing Link | https://attack.mitre.org/techniques/T1566/002/ |

#### Description
**Note!!** if you ingest AADSignInEventsBeta or SigninLogs do not use this query. 

This query lists successful Entra ID sign-ins were device code authentication is used.

You can also include a filter for the Microsoft Authentication Broker application, appId = 29d9ed98-a469-4536-ade2-f981bc1d605e. This application can generate a bunch of false positives in the results, due to benign onboarding activities.

#### Risk
An adversary managed to succesfully sign-in to your organization using device code authentication.

#### References
- https://jeffreyappel.nl/how-to-protect-against-device-code-flow-abuse-storm-2372-attacks-and-block-the-authentication-flow/
- https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/

## Defender XDR
```KQL
IdentityLogonEvents 
| where ActionType == @"LogonSuccess"
| where LogonType == @"Cmsi:Cmsi"
| extend Application = tostring(parse_json(AdditionalFields).['ARG.CLOUD_SERVICE']),
         Country = geo_info_from_ip_address(IPAddress).country
| project-reorder Timestamp, AccountUpn, LogonType, ActionType, Application, IPAddress, Country
```

## Sentinel
```KQL
IdentityLogonEvents 
| where ActionType == @"LogonSuccess"
| where LogonType == @"Cmsi:Cmsi"
| extend Application = tostring(parse_json(AdditionalFields).['ARG.CLOUD_SERVICE']),
         Country = geo_info_from_ip_address(IPAddress).country
| project-reorder TimeGenerated, AccountUpn, LogonType, ActionType, Application, IPAddress, Country
```
