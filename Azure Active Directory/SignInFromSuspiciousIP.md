# SignIn From Suspicious IP

## Query Information

#### Description
This query combines threat intelligence feeds with Entra ID sign-in information.

## Defender XDR
```KQL
let IPs = ThreatIntelligenceIndicator
    | where isnotempty( NetworkSourceIP)
    | where ConfidenceScore > 70
    | distinct NetworkSourceIP;
AADSignInEventsBeta
| where IPAddress in (IPs)
| project TimeGenerated, AccountUpn, IPAddress, Country
```
## Sentinel
```KQL
let IPs = ThreatIntelligenceIndicator
    | where isnotempty( NetworkSourceIP)
    | where ConfidenceScore > 70
    | distinct NetworkSourceIP;
SigninLogs
| where IPAddress in (IPs)
| project TimeGenerated, UserPrincipalName, IPAddress, Location
```
