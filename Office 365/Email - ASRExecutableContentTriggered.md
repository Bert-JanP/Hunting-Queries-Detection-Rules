# ASR Executable Content triggered

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566.001 | Phishing: Spearphishing Attachment | https://attack.mitre.org/techniques/T1566/001/ |

#### Description
The ASR rule in this query has the following description: This rule blocks the following file types from launching from email opened within the Microsoft Outlook application, or Outlook.com and other popular webmail providers:

- Executable files (such as .exe, .dll, or .scr)
- Script files (such as a PowerShell .ps1, Visual Basic .vbs, or JavaScript .js file)

This query uses the ASR trigger as input and joins that with the available email information. This can then be used the find the source of the mail, which can then be blocked. Adverseries may use this technique to trick users into opening executable files that give the attacker initial access.

#### Risk
If this rule is on block mode the action is blocked, if the rul is on audit mode then the user was tricked into running executable content. This can result in an actor gaining initial access.

#### References
- https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide
- https://unit42.paloaltonetworks.com/ukraine-targeted-outsteel-saintbot/

## Defender XDR
```
DeviceEvents
| where ActionType in ("AsrExecutableEmailContentBlocked", "AsrExecutableEmailContentAudited")
// join the information from the email attachment
| join kind=inner (EmailAttachmentInfo
     | project NetworkMessageId, FileName, SHA256, FileSize)
     on $left.FileName == $right.FileName
// join the email information     
| join kind=inner (EmailEvents
     | project SenderFromAddress, Subject, NetworkMessageId)
     on $left.NetworkMessageId == $right.NetworkMessageId
| project-reorder SenderFromAddress, Subject, FileName, FileSize, SHA256
```
## Sentinel
```
DeviceEvents
| where ActionType in ("AsrExecutableEmailContentBlocked", "AsrExecutableEmailContentAudited")
// join the information from the email attachment
| join kind=inner (EmailAttachmentInfo
     | project NetworkMessageId, FileName, SHA256, FileSize)
     on $left.FileName == $right.FileName
// join the email information     
| join kind=inner (EmailEvents
     | project SenderFromAddress, Subject, NetworkMessageId)
     on $left.NetworkMessageId == $right.NetworkMessageId
| project-reorder SenderFromAddress, Subject, FileName, FileSize, SHA256
```
