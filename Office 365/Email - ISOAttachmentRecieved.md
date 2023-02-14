# List inboxes that recieved an ISO attachment

## Query Information

#### Description
Adversaries may use ISO files as email attachment to trick users into opening those malicious files. Trend Micro has done reaches on spam campgains that use ISO image files to deliver Lokibot and NanoCore malware onto victems devices. Recieving the ISO does not mean that the user is infected, depending on the malware, the user is mostly only infected after the ISO has been mapped or if files on the ISO have been opened. This query detects all inbound emails that contain a ISO image. 

By default ISO files are blocked in Exchange, your admin can unblock those file extensions. Thus this query should only trigger if a ISO is recieved and your admin has configured your environment in a way that ISO files are accepted. 

#### Risk
A user opens the ISO file that contains malware and grants the adversery initial access to the network.

#### References
- https://www.netskope.com/blog/lokibot-nanocore-iso-disk-image-files
- https://www.trendmicro.com/vinfo/it/security/news/cybercrime-and-digital-threats/malicious-spam-campaign-uses-iso-image-files-to-deliver-lokibot-and-nanocore
- https://support.microsoft.com/en-us/office/blocked-attachments-in-outlook-434752e1-02d3-4e90-9124-8b81e49a8519

## Defender For Endpoint
```
EmailEvents
| where EmailDirection == 'Inbound'
| join kind=inner EmailAttachmentInfo on NetworkMessageId
| project
     Timestamp,
     NetworkMessageId,
     SenderFromAddress,
     SenderIPv4,
     SenderIPv6,
     RecipientEmailAddress,
     Subject,
     FileName,
     FileType,
     ThreatNames
| where FileName endswith ".iso"
```

## Sentinel
```
EmailEvents
| where EmailDirection == 'Inbound'
| join kind=inner EmailAttachmentInfo on NetworkMessageId
| project
     TimeGenerated,
     NetworkMessageId,
     SenderFromAddress,
     SenderIPv4,
     SenderIPv6,
     RecipientEmailAddress,
     Subject,
     FileName,
     FileType,
     ThreatNames
| where FileName endswith ".iso"
```