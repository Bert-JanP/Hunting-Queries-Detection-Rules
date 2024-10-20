# Function: UserRiskStatus()

## Query Information

#### Description
This function returns the RiskState of a UPN, if the results are empty then the user did not have a risky state in the last 90 days. This saves time to not having to lookup the user in Azure Active Directory, by leveraging a log analytics data which saves the content of the risk status of users.

#### References
- https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/functions/user-defined-functions
- https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-custom-functions?view=o365-worldwide
- https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/howto-export-risk-data

## Defender XDR
```
// Function returns the RiskState of a UPN, if the results are empty then the user did not have a risky state in the last 90 days.
let UserRiskStatus = (UPN: string) {
    AADRiskyUsers
    | where Timestamp > ago(90d)
    | where UserPrincipalName =~ UPN
    | summarize arg_max(Timestamp, *) by UserPrincipalName
    | project Timestamp, UserPrincipalName, RiskState, RiskLevel, RiskDetail
};
// Example
UserRiskStatus("test@domain.com")
```
## Sentinel
```
// Function returns the RiskState of a UPN, if the results are empty then the user did not have a risky state in the last 90 days.
let UserRiskStatus = (UPN: string) {
    AADRiskyUsers
    | where TimeGenerated > ago(90d)
    | where UserPrincipalName =~ UPN
    | summarize arg_max(TimeGenerated, *) by UserPrincipalName
    | project TimeGenerated, UserPrincipalName, RiskState, RiskLevel, RiskDetail
};
// Example
UserRiskStatus("test@domain.com")
```

