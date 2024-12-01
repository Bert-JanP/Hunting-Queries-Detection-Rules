# MailItemsAccessed by Compromised account

## Query Information

#### Description
This query lists the *MailItemsAccessed* actions performed by a suspicious/compromised account.

#### References
- https://learn.microsoft.com/en-us/purview/audit-log-investigate-accounts

## Defender XDR
```KQL
let InputEmailDirection = pack_array("Inbound","Outbound","Intra-org","Unknown");
let SearchWindow = 48h; //Customizable h = hours, d = days;
let AccountObjectIdInput = "c0a9a020-xxxx-xxxx-xxxx-2b5f0f5aa860";
CloudAppEvents
| where Timestamp > ago(SearchWindow)
| where ActionType == "MailItemsAccessed"
| where AccountObjectId =~ AccountObjectIdInput
| extend Folders = parse_json(RawEventData).Folders
| extend FolderItems = Folders[0].FolderItems, OperationCount = tostring(RawEventData.OperationCount)
| mv-expand FolderItems
| extend InternetMessageId = tostring(FolderItems.InternetMessageId)
| project InternetMessageId, AccountObjectId, AccountDisplayName, DeviceType, MailAccessedTime = Timestamp, OperationCount
// Include MailItemsAccessed accessed mails that can and cannot be enriched with EmailEvents info
| join kind=leftouter (EmailEvents 
    | where EmailDirection in (InputEmailDirection) 
    | project EmailRecieveTime = Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, InternetMessageId, NetworkMessageId) on InternetMessageId
| project-reorder MailAccessedTime, EmailRecieveTime, SenderFromAddress, RecipientEmailAddress, Subject, OperationCount
```

## Sentinel
```KQL
let InputEmailDirection = pack_array("Inbound","Outbound","Intra-org","Unknown");
let SearchWindow = 48h; //Customizable h = hours, d = days;
let AccountObjectIdInput = "c0a9a020-xxxx-xxxx-xxxx-2b5f0f5aa860";
CloudAppEvents
| where TimeGenerated > ago(SearchWindow)
| where ActionType == "MailItemsAccessed"
| where AccountObjectId =~ AccountObjectIdInput
| extend Folders = parse_json(RawEventData).Folders
| extend FolderItems = Folders[0].FolderItems, OperationCount = tostring(RawEventData.OperationCount)
| mv-expand FolderItems
| extend InternetMessageId = tostring(FolderItems.InternetMessageId)
| project InternetMessageId, AccountObjectId, AccountDisplayName, DeviceType, MailAccessedTime = TimeGenerated, OperationCount
// Include MailItemsAccessed accessed mails that can and cannot be enriched with EmailEvents info
| join kind=leftouter (EmailEvents 
    | where EmailDirection in (InputEmailDirection) 
    | project EmailRecieveTime = TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject, InternetMessageId, NetworkMessageId) on InternetMessageId
| project-reorder MailAccessedTime, EmailRecieveTime, SenderFromAddress, RecipientEmailAddress, Subject, OperationCount
```



