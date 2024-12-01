# Find all attachments that have been send from a compromised mailbox and which devices have opened that attachment.  
----
## Defender XDR

```
let CompromisedMailbox = "test@test.com";
let SearchWindow = 48h; //Customizable h = hours, d = days
EmailEvents
| where Timestamp > ago(SearchWindow)
| where SenderFromAddress == CompromisedMailbox
| where AttachmentCount > 0
| join kind=leftouter EmailAttachmentInfo on NetworkMessageId
| project
     Timestamp,
     NetworkMessageId,
     SenderFromAddress,
     RecipientEmailAddress,
     Subject,
     ThreatTypes,
     SHA256
| join kind=leftouter DeviceFileEvents on SHA256
| summarize
     EmailReciepients = make_set(RecipientEmailAddress),
     Subject= make_set(Subject),
     FileOnDevices = make_set(DeviceName)
     by SHA256, NetworkMessageId
| extend
     TotalReciepients = array_length(EmailReciepients),
     DeviceWithFileInteraction = array_length(FileOnDevices)
```
## Sentinel
```
let CompromisedMailbox = "test@test.com";
let SearchWindow = 48h; //Customizable h = hours, d = days
EmailEvents
| where TimeGenerated > ago(SearchWindow)
| where SenderFromAddress == CompromisedMailbox
| where AttachmentCount > 0
| join kind=leftouter EmailAttachmentInfo on NetworkMessageId
| project
     TimeGenerated,
     NetworkMessageId,
     SenderFromAddress,
     RecipientEmailAddress,
     Subject,
     ThreatTypes,
     SHA256
| join kind=leftouter DeviceFileEvents on SHA256
| summarize
     EmailReciepients = make_set(RecipientEmailAddress),
     Subject= make_set(Subject),
     FileOnDevices = make_set(DeviceName)
     by SHA256, NetworkMessageId
| extend
     TotalReciepients = array_length(EmailReciepients),
     DeviceWithFileInteraction = array_length(FileOnDevices)
```



