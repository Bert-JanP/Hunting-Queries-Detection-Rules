# Function: List EntraID SignIn activities account

## Query Information

#### Description
This function can be used to list both the *SigninLogs* and *AADNonInteractiveUserSignInLogs* based on the account that has been given as intput (*UserAccount*).

#### References
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs

## Sentinel
```
let UserAccount = "test@test.com";
let aadFunc = (tableName: string, email: string) {
    table(tableName)
    | where ResultType == 0
    | where UserPrincipalName == email
};
let aadSignin = aadFunc("SigninLogs", UserAccount);
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs", UserAccount);
union isfuzzy=true aadSignin, aadNonInt
// In case of all details remove line below
| project TimeGenerated, Category, Location, AppDisplayName, ClientAppUsed, RiskState
```

