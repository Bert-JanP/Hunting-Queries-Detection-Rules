# EntraTrace - Microsoft Graph UserAgent Matches

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title | Link |
| --- | --- | --- |
| T1087.004 | Account Discovery: Cloud Account | https://attack.mitre.org/techniques/T1087/004/ |
| T1069.003 | Permission Groups Discovery: Cloud Groups | https://attack.mitre.org/techniques/T1069/003/ |

#### Description

Hunts for Microsoft Graph API requests whose `UserAgent` matches an entry extracted from offensive tool profiles in [EntraTrace](https://github.com/Bert-JanP/EntraTrace). The query dynamically retrieves the [UserAgents.csv indicator list](https://github.com/Bert-JanP/EntraTrace/blob/main/Indicator%20Lists/UserAgents.csv) at execution time, so coverage changes as the project updates its profiles.

Not available as a native Defender XDR hunt: `GraphAPIAuditEvents` does not expose `UserAgent` column. 

#### Risk

Offensive tooling can use Microsoft Graph to enumerate cloud accounts, groups, applications, and permissions, identify attack paths, and access tenant data using compromised identities. This hunt surfaces possible tooling activity but does not establish malicious intent or data theft. Pivot to the underlying requests to review identities, applications, source IP addresses, request URIs, permissions, response status codes, and related sign-ins. Validate whether the activity is expected or part of an authorized assessment before escalation.

#### References

- https://github.com/Bert-JanP/EntraTrace
- https://cloudbrothers.info/en/detect-threats-microsoft-graph-logs-part-1/
- https://cloudbrothers.info/en/detect-threats-microsoft-graph-logs-part-2/
- https://kqlquery.com/posts/graphactivitylogs/

## Sentinel

```KQL
let EntraTraceUserAgents = externaldata(Toolname:string,UserAgent:string)["https://raw.githubusercontent.com/Bert-JanP/EntraTrace/refs/heads/main/Indicator%20Lists/UserAgents.csv"] with (format="csv",ignoreFirstRecord=true);
let UniqueUserAgents = EntraTraceUserAgents
| distinct UserAgent;
MicrosoftGraphActivityLogs
| where UserAgent in~ (UniqueUserAgents)
| extend ObjectId = coalesce(ServicePrincipalId, UserId)
| summarize TotalEvents = count(), UniqueObject = dcount(ObjectId), UniqueUsers = dcount(UserId), UniqueServicePrincipals = dcount(ServicePrincipalId) by UserAgent
| join kind=leftouter EntraTraceUserAgents on UserAgent
| project-away *1
```