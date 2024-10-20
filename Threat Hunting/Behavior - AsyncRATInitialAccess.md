# AsyncRAT Initial Access Campaign via OneNote files

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566.001 | Phishing: Spearphishing Attachment | https://attack.mitre.org/techniques/T1566/001/ |

#### Description
In recent days there has been a increase in malicious OneNote files to deliver AsyncRAT. This query can be used to start a hunt for malicious files in your environment. The OneNote files have to be delivered by mail and have to be opened in order to pop-up in the results of this query. This will indicate that a user has opened the attachment from the mail. From there a investigation needs to be started to determin if the file is benign or malicious. 

This query cannot determine if the OneNote file was malicious. It will only give an indication based on the sender and filename. 

#### Risk
An malicious OneNote file was opened and resulted in running AsyncRAT

#### References
- https://blog.osarmor.com/319/onenote-attachment-delivers-asyncrat-malware/
- https://resources.infosecinstitute.com/topic/asyncrat-escapes-security-defenses/

### Defender XDR

```
EmailEvents
// Only select inbound mails
| where EmailDirection == "Inbound"
// Join the attachment information where onenote files have been send
| join kind=inner (EmailAttachmentInfo
     | where FileType == "one;onenote")
     on NetworkMessageId
| project SenderFromAddress, RecipientEmailAddress, Subject, FileName, SHA256
// Join the file events, which means that the attachment has been opened.
| join kind=inner (DeviceFileEvents
     | project DeviceName, SHA256, FolderPath)
     on SHA256
```
### Sentinel
```
EmailEvents
// Only select inbound mails
| where EmailDirection == "Inbound"
// Join the attachment information where onenote files have been send
| join kind=inner (EmailAttachmentInfo
     | where FileType == "one;onenote")
     on NetworkMessageId
| project SenderFromAddress, RecipientEmailAddress, Subject, FileName, SHA256
// Join the file events, which means that the attachment has been opened.
| join kind=inner (DeviceFileEvents
     | project DeviceName, SHA256, FolderPath)
     on SHA256
```



