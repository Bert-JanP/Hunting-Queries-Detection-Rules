# Office activities performed by a compromised account

## Query Information

#### Description
This query can be used to get a quick overview of all office activities that have been performed by a compromised account. In a IR scenario this can be used to determine if more applications or users need to be investiated. In a Forensic scenario this query can be used to determine which actions have been performed by this account. Microsoft states the following on the information that is stored: Audit logs for Office 365 tenants collected by Azure Sentinel. Including Exchange, SharePoint and Teams logs.

The query can be used with two different input parameters *AccountObjectID* or *AccountUPN*, based on this input is will search for activities that have been performed by this account. The query first lists the statistics and then the details of the activities. The statistics include the count of all operations that are performed.

#### References
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity


## Sentinel
```
// Preferably use ObjectID
let AccountObjectID = "00000000000";
let AccountUPN = "test@test.com";
let SearchWindow = 48h; //Customizable h = hours, d = days
// Collect the statistics for the office activities by the user
let OfficeStats = OfficeActivity
    | where TimeGenerated > ago(SearchWindow)
    | where ((not(isempty(AccountObjectID)) and UserKey == AccountObjectID) or (isempty(AccountObjectID) and tolower(UserId) == tolower(AccountUPN)))
    | summarize TotalActivities = count() by Operation, RecordType;
// Collect the details for the office activities by the user. If this is to much do not show all results.
let Details = OfficeActivity
    | where TimeGenerated > ago(SearchWindow)
    | where ((not(isempty(AccountObjectID)) and UserKey == AccountObjectID) or (isempty(AccountObjectID) and tolower(UserId) == tolower(AccountUPN)));
// Join results of previous queries together into one and first show the statistics, followed by the details.
union isfuzzy=true
 (OfficeStats),
 (Details)
| sort  by TotalActivities
```
