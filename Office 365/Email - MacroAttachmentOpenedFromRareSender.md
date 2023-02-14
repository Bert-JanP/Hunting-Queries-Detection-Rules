# Macro attachment opened from rare sender

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566.001 | Phishing: Spearphishing Attachment | https://attack.mitre.org/techniques/T1566/001/ |

#### Description
Adversaries may use macro enabled files go gain access to the network. If the macros are not enabled the attacker will try to convice target to enable them to run the scripts in the background. This query detects when a macro attachment is opened that came from a rare sender from the last 7 days. This is done based on the following substeps:

1. The query collects all senders that have not send more then 10 unique emails that contained a macro attachment (RareSenderThreshold) in the last 30 days. 
2. Collect the SHA256 hashes from the macro attachments that have been send by rare senders. 
3. Search for DeviceFileEvents that containt the SHA256 hash from the macro attachment. 
4. Enrich the results with the email information. 

The query can be adjusted based on the needs of your organization by changing the RareSenderThreshold. If you want to see results from longer then 7 days ago, increase the LookupPeriod.

A false positive can be a new benign sender that has not send any macro attachments in the last 30 days. 

#### Risk
A actor uses a macro file to gain initial access in the network. This macro must be executed with the macros enabled to gain access for the adversary. 

#### References
- https://www.trendmicro.com/en_us/research/19/b/trickbot-adds-remote-application-credential-grabbing-capabilities-to-its-repertoire.html
- https://www.crowdstrike.com/blog/timelining-grim-spiders-big-game-hunting-tactics/
- https://redcanary.com/blog/how-one-hospital-thwarted-a-ryuk-ransomware-outbreak/

## Defender For Endpoint
```
// Adjust the threshold based on your organisation.
let RareSenderThreshold = 10;
let LookupPeriod = 7d;
let MacroExtensions = dynamic(['xlsm', 'xstm', 'docm', 'dotm', 'pptm', 'ppsm', 'xll', 'xlsb']);
// If you also want to include older attachments use
// let MacroExtensions = dynamic(['xlsm', 'xstm', 'docm', 'dotm', 'pptm', 'ppsm', 'xll', 'xlsb', 'doc', 'xsl', 'svg']);
// Step 1
let RareMacroSenders = EmailAttachmentInfo
| where Timestamp > ago(30d)
// Extract the file extension for each filename
| extend FileExtension = tostring(extract(@'.*\.(.*)', 1, FileName))
// Remove empty file extensions and SHA256 hashes, they will otherwise cause a lot of false positives
| where isnotempty(FileExtension) and isnotempty(SHA256)
// Filter only on marco extensions
| where FileExtension in~ (MacroExtensions)
| summarize TotalMacroAttachmentsSend = dcount(NetworkMessageId) by SenderObjectId
// Filter on rare senders
| where TotalMacroAttachmentsSend < RareSenderThreshold
| project SenderObjectId;
// Step 2
let RecievedMacros = EmailAttachmentInfo
| where Timestamp > ago(LookupPeriod)
// Filter on rare senders. Senders that often user macro's are filtered.
| where SenderObjectId in (RareMacroSenders)
// Extract the file extension for each filename
| extend FileExtension = tostring(extract(@'.*\.(.*)', 1, FileName))
// Remove empty file extensions and SHA256 hashes, they will otherwise cause a lot of false positives
| where isnotempty(FileExtension) and isnotempty(SHA256)
// Filter only on marco extensions
| where FileExtension in~ (MacroExtensions)
| project SHA256;
// Step 3
DeviceFileEvents
| where ActionType == 'FileCreated'
// Search for devices that have FileEvents with macros recieved from emails.
| where SHA256 in (RecievedMacros)
| summarize TotalDevices = dcount(DeviceName), FileLocations = make_set(FolderPath) by SHA256
// Collect the email events, to enrich the results. Step 4
| join kind=inner (EmailAttachmentInfo | project RecipientEmailAddress, NetworkMessageId, SHA256) on $left.SHA256 == $right.SHA256
| join kind=inner (EmailEvents | project SenderFromAddress, Subject, NetworkMessageId, EmailDirection) on $left.NetworkMessageId == $right.NetworkMessageId
// Only search for inbound mail
| where EmailDirection == 'Inbound'
| summarize ['Targeted Mailboxes'] = make_set(RecipientEmailAddress) by SHA256, TotalDevices, tostring(FileLocations), Subject, SenderFromAddress
```
## Sentinel
```
// Adjust the threshold based on your organisation.
let RareSenderThreshold = 10;
let LookupPeriod = 7d;
let MacroExtensions = dynamic(['xlsm', 'xstm', 'docm', 'dotm', 'pptm', 'ppsm', 'xll', 'xlsb']);
// If you also want to include older attachments use
// let MacroExtensions = dynamic(['xlsm', 'xstm', 'docm', 'dotm', 'pptm', 'ppsm', 'xll', 'xlsb', 'doc', 'xsl', 'svg']);
// Step 1
let RareMacroSenders = EmailAttachmentInfo
| where TimeGenerated > ago(30d)
// Extract the file extension for each filename
| extend FileExtension = tostring(extract(@'.*\.(.*)', 1, FileName))
// Remove empty file extensions and SHA256 hashes, they will otherwise cause a lot of false positives
| where isnotempty(FileExtension) and isnotempty(SHA256)
// Filter only on marco extensions
| where FileExtension in~ (MacroExtensions)
| summarize TotalMacroAttachmentsSend = dcount(NetworkMessageId) by SenderObjectId
// Filter on rare senders
| where TotalMacroAttachmentsSend < RareSenderThreshold
| project SenderObjectId;
// Step 2
let RecievedMacros = EmailAttachmentInfo
| where TimeGenerated > ago(LookupPeriod)
// Filter on rare senders. Senders that often user macro's are filtered.
| where SenderObjectId in (RareMacroSenders)
// Extract the file extension for each filename
| extend FileExtension = tostring(extract(@'.*\.(.*)', 1, FileName))
// Remove empty file extensions and SHA256 hashes, they will otherwise cause a lot of false positives
| where isnotempty(FileExtension) and isnotempty(SHA256)
// Filter only on marco extensions
| where FileExtension in~ (MacroExtensions)
| project SHA256;
// Step 3
DeviceFileEvents
| where ActionType == 'FileCreated'
// Search for devices that have FileEvents with macros recieved from emails.
| where SHA256 in (RecievedMacros)
| summarize TotalDevices = dcount(DeviceName), FileLocations = make_set(FolderPath) by SHA256
// Collect the email events, to enrich the results. Step 4
| join kind=inner (EmailAttachmentInfo | project RecipientEmailAddress, NetworkMessageId, SHA256) on $left.SHA256 == $right.SHA256
| join kind=inner (EmailEvents | project SenderFromAddress, Subject, NetworkMessageId, EmailDirection) on $left.NetworkMessageId == $right.NetworkMessageId
// Only search for inbound mail
| where EmailDirection == 'Inbound'
| summarize ['Targeted Mailboxes'] = make_set(RecipientEmailAddress) by SHA256, TotalDevices, tostring(FileLocations), Subject, SenderFromAddress
```