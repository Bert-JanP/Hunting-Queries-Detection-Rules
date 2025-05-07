# ClickFix Triage Query

## Query Information

#### Description
To efficiently triage ClickFix incidents the *ClickFix Triage KQL Query* below is developed. The KQL query has the following input:
- VictimDeviceId: DeviceId of the device that triggered the ClickFix incident
- TopXEvents: Amount of events you want to collect before and after the Windows Run execution.
- TimeFrame: Min and max timeframe between the Windows Run execution and the last event collected.

These variables can be adjusted to your needs.

```KQL
let VictimDeviceId = "xxxxxxxxx";
let TopXEvents = 15;
let TimeFrame = 5m;
```
Based on these variables the KQL query collects the following information:
- 🛜 The *TopXEvents* network events before the compromise, they will most likely point to the infected (WordPress) site that hosted the fake captcha.
- ☢️ The RUNMRU event itself and the related registry key changes.
- 🛜 The *TopXEvents* post-compromise network events.
- ♻️ The *TopXEvents* post-compromise process events.
- 📁 The *TopXEvents* post-compromise file events.

## Defender XDR
```KQL
// Input variables
let VictimDeviceId = "ad99bd95733f62294b5b76bb63b113bff44d06ef";
let TopXEvents = 15;
let TimeFrame = 5m;
// Input parameters for the forensic hunting query
let Parameters = dynamic(['http', 'https', 'Encoded', 'EncodedCommand', '-e', '-eC', '-enc', "-w"]);
let Executables = dynamic(["cmd", "powershell", "curl", "mshta"]);
let FilteredSIDs = dynamic(["S-1-5-18"]);
let RegKeyEvents =
 DeviceRegistryEvents
 | where DeviceId =~ VictimDeviceId
 | where ActionType == "RegistryValueSet"
 | where RegistryKey has "RunMRU"
 | where RegistryValueData has_any (Parameters) and RegistryValueData has_any (Executables)
 | extend LogType = "☢️ RunMRU Event"
 | project Timestamp, DeviceId, DeviceName, RegistryValueData, RegistryKey, LogType;
let RegKeyEventTimestamp = toscalar (RegKeyEvents | summarize Timestamp = max(Timestamp));
let NetworkEventsParser = materialize (DeviceNetworkEvents
 | where DeviceId =~ VictimDeviceId
 | where not(InitiatingProcessAccountSid in~ (FilteredSIDs))
 | where isnotempty(RemoteUrl)
 | extend MatchTimeStamp = RegKeyEventTimestamp
 | project Timestamp, RemoteIP, RemoteUrl, ReportId, DeviceId, DeviceName, MatchTimeStamp, InitiatingProcessCommandLine);
let PreInfectionNetworkEvents =
 NetworkEventsParser
 | where Timestamp between ((MatchTimeStamp - TimeFrame) .. MatchTimeStamp)
 | top TopXEvents by Timestamp desc
 | extend LogType = "🛜 Pre Infection Network Event";
let PostInfectionNetworkEvents =
 NetworkEventsParser
 | where Timestamp between (MatchTimeStamp .. (MatchTimeStamp + TimeFrame))
 | top TopXEvents by Timestamp asc
 | extend LogType = "🛜 Post Infection Network Event";
let PostInfectionProcessEvents = DeviceProcessEvents
 | where DeviceId =~ VictimDeviceId
 | where Timestamp between (RegKeyEventTimestamp .. (RegKeyEventTimestamp + TimeFrame))
 | top TopXEvents by Timestamp asc
 | where not(InitiatingProcessAccountSid in~ (FilteredSIDs))
 | extend LogType = "♻️ Post Infection Process Event"
 | project Timestamp, ReportId, LogType, DeviceId, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine;
let PostInfectionFileEvents = DeviceFileEvents
 | where DeviceId =~ VictimDeviceId
 | where Timestamp between (RegKeyEventTimestamp .. (RegKeyEventTimestamp + TimeFrame))
 | top TopXEvents by Timestamp asc
 | where not(InitiatingProcessAccountSid in~ (FilteredSIDs))
 | extend LogType = "📁 Post Infection File Event"
 | project Timestamp, ReportId, LogType, DeviceId, DeviceName, ActionType, InitiatingProcessCommandLine, FolderPath;
union isfuzzy=false PreInfectionNetworkEvents,RegKeyEvents, PostInfectionNetworkEvents, PostInfectionProcessEvents, PostInfectionFileEvents
| sort by Timestamp asc
| project-reorder Timestamp, DeviceId, DeviceName, LogType, RemoteUrl, RegistryValueData, ProcessCommandLine, FolderPath, InitiatingProcessCommandLine
```

## Sentinel
```KQL
// Input variables
let VictimDeviceId = "xxxxxxxxx";
let TopXEvents = 15;
let TimeFrame = 5m;
// Input parameters for the forensic hunting query
let Parameters = dynamic(['http', 'https', 'Encoded', 'EncodedCommand', '-e', '-eC', '-enc', "-w", "Hidden"]);
let Executables = dynamic(["cmd", "powershell", "curl", "mshta"]);
let FilteredSIDs = dynamic(["S-1-5-18"]);
let RegKeyEvents =
    DeviceRegistryEvents
    | where DeviceId =~ VictimDeviceId
    | where ActionType == "RegistryValueSet"
    | where RegistryKey has "RunMRU"
    | where RegistryValueData has_any (Parameters) and RegistryValueData has_any (Executables)
    | extend LogType = "☢️ RunMRU Event"
    | project TimeGenerated, DeviceId, DeviceName, RegistryValueData, RegistryKey, LogType;
let RegKeyEventTimestamp = toscalar (RegKeyEvents | summarize Timestamp = max(TimeGenerated));
let NetworkEventsParser = materialize (DeviceNetworkEvents
    | where DeviceId =~ VictimDeviceId
    | where not(InitiatingProcessAccountSid in~ (FilteredSIDs))
    | where isnotempty(RemoteUrl)
    | extend MatchTimeStamp = RegKeyEventTimestamp
    | project TimeGenerated, RemoteIP, RemoteUrl, ReportId, DeviceId, DeviceName, MatchTimeStamp, InitiatingProcessCommandLine);
let PreInfectionNetworkEvents =
    NetworkEventsParser
    | where TimeGenerated between ((MatchTimeStamp - TimeFrame) .. MatchTimeStamp)
    | top TopXEvents by TimeGenerated desc
    | extend LogType = "🛜 Pre Infection Network Event";
let PostInfectionNetworkEvents =
    NetworkEventsParser
    | where TimeGenerated between (MatchTimeStamp .. (MatchTimeStamp + TimeFrame))
    | top TopXEvents by TimeGenerated asc
    | extend LogType = "🛜 Post Infection Network Event";
let PostInfectionProcessEvents = DeviceProcessEvents
    | where DeviceId =~ VictimDeviceId
    | where TimeGenerated between (RegKeyEventTimestamp .. (RegKeyEventTimestamp + TimeFrame))
    | top TopXEvents by TimeGenerated asc
    | where not(InitiatingProcessAccountSid in~ (FilteredSIDs))
    | extend LogType = "♻️ Post Infection Process Event"
    | project TimeGenerated, ReportId, LogType, DeviceId, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine;
let PostInfectionFileEvents = DeviceFileEvents
    | where DeviceId =~ VictimDeviceId
    | where TimeGenerated between (RegKeyEventTimestamp .. (RegKeyEventTimestamp + TimeFrame))
    | top TopXEvents by TimeGenerated asc
    | where not(InitiatingProcessAccountSid in~ (FilteredSIDs))
    | extend LogType = "📁 Post Infection File Event"
    | project TimeGenerated, ReportId, LogType, DeviceId, DeviceName, ActionType, InitiatingProcessCommandLine, FolderPath;
union isfuzzy=false PreInfectionNetworkEvents,RegKeyEvents, PostInfectionNetworkEvents, PostInfectionProcessEvents, PostInfectionFileEvents
| sort by TimeGenerated asc
| project-reorder TimeGenerated, DeviceId, DeviceName, LogType, RemoteUrl, RegistryValueData, ProcessCommandLine, FolderPath, InitiatingProcessCommandLine
```