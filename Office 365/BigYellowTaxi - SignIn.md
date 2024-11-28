# Big Yellow Taxi - SignIn Based

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1114 | Email Collection | https://attack.mitre.org/techniques/T1114/ |

#### Description
The Big Yellow Taxi detections are based on the compromise of the state department in 2023. The following information was shared: State Department was the first victim to discover the intrusion when, on June 15, 2023, State’s security operations center (SOC) detected anomalies in access to its mail systems. The next day, State observed multiple security alerts from a custom rule it had created, known internally as “Big Yellow Taxi,” that analyzes data from a log known as MailItemsAccessed, which tracks access to Microsoft Exchange Online mailboxes.

This KQL query detects when an IP with a low successful interactive signin rate synchronizes a mailbox.

Be aware: The query for XDR and Sentinel are build with different tables. Defender XDR uses both CloudAppEvents and AADSignInEventsBeta, while Sentinel is build based on the OfficeActivity and SigninLogs tables.

#### Risk
An actor might have compromised the credentials of an useraccount and synchronizes the mailbox.

#### References
- https://www.cisa.gov/sites/default/files/2024-04/CSRB_Review_of_the_Summer_2023_MEO_Intrusion_Final_508c.pdf
- https://kqlquery.com/posts/ual/

## Defender XDR
```KQL
let DefaultInboxFolders = pack_array("Inbox", "Drafts", "Sent Items", "Archive", "rss", "Inbox", "Deleted Items", "Junk Email");
let BinSize = 30m;
let TimeFrame = 14d;
let MaxSuccess = 10;
let MailBoxSyncOperations = CloudAppEvents
// List all MailItemsAccessed that are created because of a sync audit activity.
// The audit volume for sync operations is huge. So, instead of generating an audit record for each mail item that's synched, we generate an audit event for the mail folder containing items that were synched and assume that all mail items in the synched folder have been compromised.
// Info: https://learn.microsoft.com/en-us/purview/audit-log-investigate-accounts?view=o365-worldwide#auditing-sync-access
| where ActionType == "MailItemsAccessed"
| extend MailAccessType = toint(RawEventData.RecordType), IsThrottled = tostring(parse_json(RawEventData.OperationCount))
| where MailAccessType == 2
// Parse synchronised folders. All FolderNames should be considered compromised.
| extend ParentFolder = parse_json(RawEventData.Item).ParentFolder
| extend SyncedFolder = tostring(ParentFolder.Name), Path = tostring(ParentFolder.Path), MailboxGuid = tostring(parse_json(RawEventData.MailboxGuid)), UserId = tolower(parse_json(RawEventData.UserId))
| summarize TotalFolers = dcount(SyncedFolder), Folders = make_set(SyncedFolder) by bin(TimeGenerated, BinSize), UserId, IPAddress, MailboxGuid;
let LargeSyncOperations = MailBoxSyncOperations
// Filter & enrich results
| where TotalFolers >= array_length(DefaultInboxFolders)
| extend GeoIPInfo = geo_info_from_ip_address(IPAddress)
| extend country = tostring(parse_json(GeoIPInfo).country);
LargeSyncOperations
| join kind=inner (AADSignInEventsBeta | where TimeGenerated > startofday(ago(TimeFrame)) and LogonType == '["interactiveUser"]' | project ErrorCode, AccountUpn = tolower(AccountUpn), IPAddress | summarize TotalSuccess = countif(ErrorCode == 0), TotalFailed = countif(ErrorCode != 0) by AccountUpn, IPAddress) on $left.IPAddress == $right.IPAddress, $left.UserId == $right.AccountUpn
// Filter only on IPs with low successrate 
| where TotalSuccess <= MaxSuccess
```
## Sentinel
```KQL
let DefaultInboxFolders = pack_array("Inbox", "Drafts", "Sent Items", "Archive", "rss", "Inbox", "Deleted Items", "Junk Email");
let BinSize = 30m;
let TimeFrame = 14d;
let MaxSuccess = 10;
let MailBoxSyncOperations =  OfficeActivity
// List all MailItemsAccessed that are created because of a sync audit activity.
// The audit volume for sync operations is huge. So, instead of generating an audit record for each mail item that's synched, we generate an audit event for the mail folder containing items that were synched and assume that all mail items in the synched folder have been compromised.
// Info: https://learn.microsoft.com/en-us/purview/audit-log-investigate-accounts?view=o365-worldwide#auditing-sync-access
| where Operation == "MailItemsAccessed"
| extend MailAccessType = tostring(parse_json(OperationProperties[0]).Value), IsThrottled = tostring(parse_json(OperationProperties[1]).Value)
| where MailAccessType == "Sync"
// Parse synchronised folders. All FolderNames should be considered compromised.
| extend ParentFolder = parse_json(Item).ParentFolder
| extend SyncedFolder = tostring(ParentFolder.Name), Path = tostring(ParentFolder.Path)
| summarize TotalFolers = dcount(SyncedFolder), Folders = make_set(SyncedFolder) by bin(TimeGenerated, BinSize), UserId, Client_IPAddress, MailboxGuid;
let LargeSyncOperations = MailBoxSyncOperations
// Filter & enrich results
| where TotalFolers >= array_length(DefaultInboxFolders)
| extend GeoIPInfo = geo_info_from_ip_address(Client_IPAddress)
| extend country = tostring(parse_json(GeoIPInfo).country);
LargeSyncOperations
| join kind=inner (SigninLogs | where TimeGenerated > startofday(ago(TimeFrame)) | project ResultType, UserPrincipalName, IPAddress | summarize TotalSuccess = countif(ResultType == 0), TotalFailed = countif(ResultType != 0) by UserPrincipalName, IPAddress) on $left.Client_IPAddress == $right.IPAddress, $left.UserId == $right.UserPrincipalName
// Filter only on IPs with low successrate 
| where TotalSuccess <= MaxSuccess
```
