# New UserAgent used

This query can be used to detect new UserAgents that have been used to perform sign in activities (succesful or failed). If you company only uses windows devices it will be interesting to investigate the other UserAgents that have been used. False positives can be new browser updates that trigger new UserAgents, this will can be detected by a lot of entries for a specific agent.   

### Sentinel
```
let KnownUserAgents = SigninLogs
  | where TimeGenerated > ago(90d) and TimeGenerated < ago(3d)
  | distinct UserAgent;
SigninLogs
| where TimeGenerated > ago(3d)
| where UserAgent !in (KnownUserAgents)
| project TimeGenerated, UserAgent, ResultType, Identity, UserPrincipalName, IPAddress
```
