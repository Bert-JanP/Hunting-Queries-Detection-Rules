# List the 20 most rare file extensions recieved from emails

## Query Information

#### Description
This query list the 20 rarest file extentions that have been used in email attachments. 

#### Risk
Rare file extensions may incidacte that an actor is trying trick users in opening malicious files.

## Defender XDR
```KQL
EmailEvents
// Only display inbound emails
| where EmailDirection == 'Inbound'
// Join the email events with the attachment information, that the email must have an attachment.
| join kind=inner EmailAttachmentInfo on NetworkMessageId
// extract the file extension from the filename
| extend FileExtension = tostring(extract(@'.*\.(.*)', 1, FileName))
| where isnotempty(FileExtension)
| summarize Total = count() by FileExtension
| top 20 by Total asc
```

## Sentinel
```KQL
EmailEvents
// Only display inbound emails
| where EmailDirection == 'Inbound'
// Join the email events with the attachment information, that the email must have an attachment.
| join kind=inner EmailAttachmentInfo on NetworkMessageId
// extract the file extension from the filename
| extend FileExtension = tostring(extract(@'.*\.(.*)', 1, FileName))
| where isnotempty(FileExtension)
| summarize Total = count() by FileExtension
| top 20 by Total asc
```
