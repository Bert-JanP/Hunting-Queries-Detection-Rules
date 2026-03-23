# AzureActivity Compromised Account

## Query Information

#### Description
This query list all the actions (ACTION, DELETE, WRITE, etc) by a compromised account.

## Defender XDR
```
let CompromisedAccountUPN = "test@test.com";
let SearchWindow = 48h; //Customizable h = hours, d = days
AzureActivity
| where Caller =~ CompromisedAccountUPN
| where TimeGenerated > ago(SearchWindow)
| summarize TotalEvents = count() by OperationNameValue
| sort by TotalEvents desc 
```
## Sentinel
```
let CompromisedAccountUPN = "test@test.com";
let SearchWindow = 48h; //Customizable h = hours, d = days
AzureActivity
| where Caller =~ CompromisedAccountUPN
| where TimeGenerated > ago(SearchWindow)
| summarize TotalEvents = count() by OperationNameValue
| sort by TotalEvents desc 
```
