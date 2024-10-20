# Runas with saved credentials

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1134.002 | Access Token Manipulation: Create Process with Token | https://attack.mitre.org/techniques/T1134/002 |

#### Description
Adversaries may create a new process with a different token to escalate privileges and bypass access controls. Processes can be created with the token and resulting security context of another user using features such as runas. This query detects all commands that have been executed while using saved credentials. With savedcred the password only needs to be inserted once, after that the password can reused (for malicious purposes).

#### Risk
A actor can use saved credentials to gain privilige escallation.

#### References
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc771525(v=ws.11)
- https://superuser.com/questions/581548/runas-savecred-ask-for-password-if-another-user-runs-the-same-batch-file/903881#903881

## Defender XDR
```
DeviceProcessEvents
| where FileName == "runas.exe"
// Collect the account under which the command would be executed by runas
| extend TargetAccount = extract(@'user:(.*?) ', 1, ProcessCommandLine)
// Detect commandlines that contain savedcred this line can be removed to display all runas commands
| where ProcessCommandLine contains "/savecred"
| project Timestamp, DeviceName, TargetAccount, ProcessCommandLine
```
## Sentinel
```
DeviceProcessEvents
| where FileName == "runas.exe"
// Collect the account under which the command would be executed by runas
| extend TargetAccount = extract(@'user:(.*?) ', 1, ProcessCommandLine)
// Detect commandlines that contain savedcred this line can be removed to display all runas commands
| where ProcessCommandLine contains "/savecred"
| project TimeGenerated, DeviceName, TargetAccount, ProcessCommandLine
```
