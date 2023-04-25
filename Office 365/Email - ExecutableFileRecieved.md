# Executable Fileattachment recieved

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566.001 | Phishing: Spearphishing Attachment | https://attack.mitre.org/techniques/T1566/001/ |

#### Description
Adversaries may use executable files to gain initial access. A tactic that is used is to send executable files, when opening the files a script is directly run. This query detects a subset of the exectuble file extensions in Windows. The list can be increaded by appending additional extensions that you want to query. Some of those executable file extensions are already blocked by default in outlook, however administrators can change this behaviour.

#### Risk
An actor gains initial access via a attachment that is send to a mailbox, which someone has opened. 

#### References
- https://support.microsoft.com/en-us/office/blocked-attachments-in-outlook-434752e1-02d3-4e90-9124-8b81e49a8519
- https://support.microsoft.com/en-us/topic/outlook-blocked-access-to-the-following-potentially-unsafe-attachments-c5c4a480-041e-2466-667f-e98d389ff822
- https://www.bleepingcomputer.com/news/security/the-most-common-malicious-email-attachments-infecting-windows/

## Defender For Endpoint
```
let ExecutableFileExtentions = dynamic(['bat', 'cmd', 'com', 'cpl', 'dll', 'ex', 'exe', 'jse', 'lnk','msc', 'ps1', 'reg', 'vb', 'vbe', 'ws', 'wsf']);
EmailEvents
// Only display inbound emails
| where EmailDirection == 'Inbound'
// Join the email events with the attachment information, that the email must have an attachment.
| join kind=inner EmailAttachmentInfo on NetworkMessageId
// extract the file extension from the filename
| extend FileExtension = tostring(extract(@'.*\.(.*)', 1, FileName))
| where isnotempty(FileExtension)
// Filter on executable file extensions
| where FileExtension in~ (ExecutableFileExtentions)
| summarize ['Target Mailboxes'] = make_set(RecipientEmailAddress), ['Sender Addresses'] = make_set(SenderFromAddress), ['Email Subject'] = make_set(Subject) by SHA256, FileName
```
## Sentinel
```
let ExecutableFileExtentions = dynamic(['bat', 'cmd', 'com', 'cpl', 'dll', 'ex', 'exe', 'jse', 'lnk','msc', 'ps1', 'reg', 'vb', 'vbe', 'ws', 'wsf']);
EmailEvents
// Only display inbound emails
| where EmailDirection == 'Inbound'
// Join the email events with the attachment information, that the email 
must have an attachment.
| join kind=inner EmailAttachmentInfo on NetworkMessageId
// extract the file extension from the filename
| extend FileExtension = tostring(extract(@'.*\.(.*)', 1, FileName))
| where isnotempty(FileExtension)
// Filter on executable file extensions
| where FileExtension in~ (ExecutableFileExtentions)
| summarize ['Target Mailboxes'] = make_set(RecipientEmailAddress), ['Sender Addresses'] = make_set(SenderFromAddress), ['Email Subject'] = make_set(Subject) by SHA256, FileName
```
