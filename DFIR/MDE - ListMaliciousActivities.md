# List Malicious Activities

## Query Information

#### Description
This query combines multiple malicious activities that have been performed by a compromised device into one query. This query can be used to get a quick overview if more malicious activities have been performed on a device. The data that is queries does mostly not trigger an incident itself. The data that is included in the query:
- ASR Triggers
- SmartScreen Events
- Antivirus Detections
- Tampering Detections
- Exploit Guard Triggers
- AMSI Events

In order for this query to succesfully execute the CompromisedDevice needs to be changed to the compromised device you want to investigate. 

#### References
- https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide
- https://learn.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-smartscreen/microsoft-defender-smartscreen-overview
- https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection?view=o365-worldwide
- https://learn.microsoft.com/en-us/mem/configmgr/protect/deploy-use/create-deploy-exploit-guard-policy
- https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal

```
let CompromisedDevice = "laptop1";
let SearchWindow = 48h; //Customizable h = hours, d = days
// Collect all ASR triggers from the compromised device
let ASREvents = DeviceEvents
     | where Timestamp > ago(SearchWindow)
     | where DeviceName == CompromisedDevice
     | where ActionType startswith "ASR"
     | project Timestamp,ActionType, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, AccountDomain, AccountName;
// Collect all SmartScreen events from the compromised device
let SmartScreenEvents = DeviceEvents
     | where Timestamp > ago(SearchWindow)
     | where DeviceName == CompromisedDevice
     | where ActionType in ('SmartScreenAppWarning', 'SmartScreenUrlWarning')
     | extend SmartScreenTrigger = iff(ActionType == "SmartScreenUrlWarning", RemoteUrl, FileName), ReasonForTrigger = parse_json(AdditionalFields).Experience
     | project Timestamp, DeviceName, ActionType, SmartScreenTrigger, ReasonForTrigger, InitiatingProcessCommandLine;
// List all AV detections from the compromised device
let AntivirusDetections = DeviceEvents
     | where Timestamp > ago(SearchWindow)
     | where DeviceName == CompromisedDevice
     | where ActionType == "AntivirusDetection"
     | extend ThreatName = tostring(parse_json(AdditionalFields).ThreatName)
     | project Timestamp, DeviceName, ActionType, ThreatName, FileName, FolderPath, SHA1, InitiatingProcessAccountSid;
// List all tampering actions from a compromised device
let TamperingAttempts = DeviceEvents
     | where Timestamp > ago(SearchWindow)
     | where DeviceName == CompromisedDevice
     | where ActionType == "TamperingAttempt"
     | extend TamperingAction = tostring(parse_json(AdditionalFields).TamperingAction), Status = tostring(parse_json(AdditionalFields).Status), Target = tostring(parse_json(AdditionalFields).Target)
     | project Timestamp, DeviceName, ActionType, TamperingAction, Status, Target, InitiatingProcessCommandLine;
// List all exploit guard events
let ExploitGuardEvents = DeviceEvents
     | where Timestamp > ago(SearchWindow)
     | where DeviceName == CompromisedDevice
     | where ActionType startswith "ExploitGuard"
     | project Timestamp, DeviceName, ActionType, FileName, FolderPath, RemoteUrl;
// List all amsi events
let AMSIEvents = DeviceEvents
     | where Timestamp > ago(SearchWindow)
     | where DeviceName == CompromisedDevice
     | where ActionType contains "Amsi"
     | extend Description = tostring(parse_json(AdditionalFields).Description)
     | project Timestamp, DeviceName, ActionType, Description, FolderPath;
// Combine all results into one output
(union isfuzzy=true
     (ASREvents),
     (SmartScreenEvents),
     (AntivirusDetections),
     (TamperingAttempts),
     (ExploitGuardEvents),
     (AMSIEvents)
     | sort by Timestamp
)
```

## Sentinel
```
let CompromisedDevice = "laptop1";
let SearchWindow = 48h; //Customizable h = hours, d = days
// Collect all ASR triggers from the compromised device
let ASREvents = DeviceEvents
     | where TimeGenerated > ago(SearchWindow)
     | where DeviceName == CompromisedDevice
     | where ActionType startswith "ASR"
     | project TimeGenerated,ActionType, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, AccountDomain, AccountName;
// Collect all SmartScreen events from the compromised device
let SmartScreenEvents = DeviceEvents
     | where TimeGenerated > ago(SearchWindow)
     | where DeviceName == CompromisedDevice
     | where ActionType in ('SmartScreenAppWarning', 'SmartScreenUrlWarning')
     | extend SmartScreenTrigger = iff(ActionType == "SmartScreenUrlWarning", RemoteUrl, FileName), ReasonForTrigger = parse_json(AdditionalFields).Experience
     | project TimeGenerated, DeviceName, ActionType, SmartScreenTrigger, ReasonForTrigger, InitiatingProcessCommandLine;
// List all AV detections from the compromised device
let AntivirusDetections = DeviceEvents
     | where TimeGenerated > ago(SearchWindow)
     | where DeviceName == CompromisedDevice
     | where ActionType == "AntivirusDetection"
     | extend ThreatName = tostring(parse_json(AdditionalFields).ThreatName)
     | project TimeGenerated, DeviceName, ActionType, ThreatName, FileName, FolderPath, SHA1, InitiatingProcessAccountSid;
// List all tampering actions from a compromised device
let TamperingAttempts = DeviceEvents
     | where TimeGenerated > ago(SearchWindow)
     | where DeviceName == CompromisedDevice
     | where ActionType == "TamperingAttempt"
     | extend TamperingAction = tostring(parse_json(AdditionalFields).TamperingAction), Status = tostring(parse_json(AdditionalFields).Status), Target = tostring(parse_json(AdditionalFields).Target)
     | project Timestamp, DeviceName, ActionType, TamperingAction, Status, Target, InitiatingProcessCommandLine;
// List all exploit guard events
let ExploitGuardEvents = DeviceEvents
     | where TimeGenerated > ago(SearchWindow)
     | where DeviceName == CompromisedDevice
     | where ActionType startswith "ExploitGuard"
     | project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, RemoteUrl, InitiatingProcessCommandLine;
// List all amsi events
let AMSIEvents = DeviceEvents
     | where TimeGenerated > ago(SearchWindow)
     | where DeviceName == CompromisedDevice
     | where ActionType contains "Amsi"
     | extend Description = tostring(parse_json(AdditionalFields).Description)
     | project TimeGenerated, DeviceName, ActionType, Description, FolderPath;
// Combine all results into one output
(union isfuzzy=true
     (ASREvents),
     (SmartScreenEvents),
     (AntivirusDetections),
     (TamperingAttempts),
     (ExploitGuardEvents),
     (AMSIEvents)
     | sort by TimeGenerated
)
```



