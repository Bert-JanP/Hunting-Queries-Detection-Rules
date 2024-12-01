# Sign Ins by compromised account

## Query Information

#### Description
List the interactive and noninteractive signins that have been performed by a compromised account. This can be done based on the UPN of the compromised account.

#### References
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/non-interactive-logins-minimizing-the-blind-spot/ba-p/2287932


## Sentinel
```
let CompromisedAccountUPN = "test@test.com";
let SearchWindow = 48h; //Customizable h = hours, d = days
let aadFunc = (tableName: string, email: string) {
    table(tableName)
    | where TimeGenerated > ago(SearchWindow)
    | where ResultType == 0
    | where UserPrincipalName == email
};
let aadSignin = aadFunc("SigninLogs", CompromisedAccountUPN);
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs", CompromisedAccountUPN);
union isfuzzy=true aadSignin, aadNonInt
// In case of all details remove line below
| project TimeGenerated, Category, Location, AppDisplayName, ClientAppUsed, RiskState
```



