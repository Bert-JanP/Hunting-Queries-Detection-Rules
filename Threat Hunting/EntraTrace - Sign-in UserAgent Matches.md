# EntraTrace - Sign-in UserAgent Matches

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title | Link |
| --- | --- | --- |
| T1078.004 | Valid Accounts: Cloud Accounts | https://attack.mitre.org/techniques/T1078/004/ |
| T1110.003 | Brute Force: Password Spraying | https://attack.mitre.org/techniques/T1110/003/ |

#### Description

Hunts for Microsoft Entra ID sign-ins whose `UserAgent` matches an entry extracted from offensive tool profiles in [EntraTrace](https://github.com/Bert-JanP/EntraTrace). The query dynamically retrieves the [UserAgents.csv indicator list](https://github.com/Bert-JanP/EntraTrace/blob/main/Indicator%20Lists/UserAgents.csv) at execution time, so coverage changes as the project updates its profiles.

#### Risk

Offensive identity tooling can support password spraying, token abuse, and unauthorized access to cloud accounts. This hunt provides leads for investigating potentially suspicious authentication activity, but a match alone does not establish compromise. Pivot to the underlying sign-in records to examine accounts, source IP addresses, applications, authentication outcomes, Conditional Access decisions, and subsequent Graph activity. Validate whether the activity is expected or part of an authorized assessment before escalation.

#### References

- https://github.com/Bert-JanP/EntraTrace

## Defender XDR

```KQL
let EntraTraceUserAgents = externaldata(Toolname:string,UserAgent:string)["https://raw.githubusercontent.com/Bert-JanP/EntraTrace/refs/heads/main/Indicator%20Lists/UserAgents.csv"] with (format="csv",ignoreFirstRecord=true);
let UniqueUserAgents = EntraTraceUserAgents
| distinct UserAgent;
EntraIdSignInEvents
| where UserAgent in~ (UniqueUserAgents)
| summarize TotalEvents = count(), TotalSuccessfulSignIns = countif(ErrorCode == 0), TotalFailedSignIns = countif(ErrorCode != 0), UniqueUsers = dcount(AccountUpn) by UserAgent
| join kind=leftouter EntraTraceUserAgents on UserAgent
| project-away *1
```

## Sentinel

```KQL
let EntraTraceUserAgents = externaldata(Toolname:string,UserAgent:string)["https://raw.githubusercontent.com/Bert-JanP/EntraTrace/refs/heads/main/Indicator%20Lists/UserAgents.csv"] with (format="csv",ignoreFirstRecord=true);
let UniqueUserAgents = EntraTraceUserAgents
| distinct UserAgent;
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where UserAgent in~ (UniqueUserAgents)
| summarize TotalEvents = count(), TotalSuccessfulSignIns = countif(ResultType == "0"), TotalFailedSignIns = countif(ResultType != "0"), UniqueUsers = dcount(UserPrincipalName) by UserAgent
| join kind=leftouter EntraTraceUserAgents on UserAgent
| project-away *1
```