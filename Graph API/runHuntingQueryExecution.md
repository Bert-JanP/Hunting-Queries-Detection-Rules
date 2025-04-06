# Graph API runHuntingQuery 

## Query Information

#### Description
This query lists successful runHuntingQuery Graph API calls from applications.

#### References
- https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0&tabs=http

## Defender XDR
```KQL
MicrosoftGraphActivityLogs
| where RequestUri has "runHuntingQuery"
// Only list app based results
| where isnotempty(AppId)
| where ResponseStatusCode == 200
| project TimeGenerated, RequestUri, AppId, ResponseStatusCode, ResponseSizeBytes
```

## Sentinel
```KQL
MicrosoftGraphActivityLogs
| where RequestUri has "runHuntingQuery"
// Only list app based results
| where isnotempty(AppId)
| where ResponseStatusCode == 200
| project TimeGenerated, RequestUri, AppId, ResponseStatusCode, ResponseSizeBytes
```
