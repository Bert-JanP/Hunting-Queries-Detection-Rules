# Malicious PowerShell Executions From Clipboard Copy-and-Paste

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1204.001 | User Execution: Malicious Link| https://attack.mitre.org/techniques/T1204/001/ |

#### Description
This query is to hunt for the threat of Fake CAPTCHA / Bot verification social engineering techniques used by the actor to lure the victim to click copy-and-paste button on the website with malicious powershell for the retrieval of the second stage payload and subsequently executed on the victim's device. The idea of the query is to detect the events of clipboard data being accessed and followed by PowerShell execution under 1 minute of time window.

#### Risk
This query is to hunt for Fake CAPTCHA / Bot verification social engineering malicious powershell execution.

#### Author
Github: [ch4meleon](https://github.com/ch4meleon)

#### References
- https://pkcert.gov.pk/advisory/24-19.pdf
- https://www.mcafee.com/blogs/other-blogs/mcafee-labs/behind-the-captcha-a-clever-gateway-of-malware/
- https://www.cloudsek.com/blog/unmasking-the-danger-lumma-stealer-malware-exploits-fake-captcha-pages
- https://labs.guard.io/deceptionads-fake-captcha-driving-infostealer-infections-and-a-glimpse-to-the-dark-side-of-0c516f4dc0b6

## Defender XDR
```
let clipboardEvents = 
    DeviceEvents
    | where ActionType contains "GetClipboardData" 
    and InitiatingProcessFileName contains "explorer.exe";
let powershellEvents = 
    DeviceProcessEvents
    | where (FileName contains "powershell.exe" and (ProcessCommandLine contains "hidden") and ProcessCommandLine contains "http" and ProcessCommandLine !contains "http://localhost") or (FileName contains "mshta.exe" and ProcessCommandLine contains "http" and ProcessCommandLine !contains "http://localhost");
clipboardEvents
| join kind=inner (powershellEvents) on DeviceName
| where abs(datetime_diff('minute', TimeGenerated, TimeGenerated1)) <= 1
| summarize by DeviceName
```

## Sentinel
```
let clipboardEvents = 
    DeviceEvents
    | where ActionType contains "GetClipboardData" 
    and InitiatingProcessFileName contains "explorer.exe";
let powershellEvents = 
    DeviceProcessEvents
    | where (FileName contains "powershell.exe" and (ProcessCommandLine contains "hidden") and ProcessCommandLine contains "http" and ProcessCommandLine !contains "http://localhost") or (FileName contains "mshta.exe" and ProcessCommandLine contains "http" and ProcessCommandLine !contains "http://localhost");
clipboardEvents
| join kind=inner (powershellEvents) on DeviceName
| where abs(datetime_diff('minute', TimeGenerated, TimeGenerated1)) <= 1
| summarize by DeviceName
```

