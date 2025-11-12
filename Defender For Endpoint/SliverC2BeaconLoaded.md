# Sliver C2 Beacon Loaded

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1134.002 | Application Layer Protocol | https://attack.mitre.org/techniques/T1071/ |

#### Description
A Sliver C2 beacon performs the below activities in sequence within a second. The detection combines these sigals in that particular sequence to detect a loaded beacon.

1. Outbound connection to C2 Server
2. \wkssvc namedpipe created
3. Security Access Manager loaded (samlib.dll)

#### Risk
C2 Beacon loaded giving an adversary hands on keyboard access to the device.

#### References
- https://sliver.sh/

## Defender XDR
```KQL
let ImageLoads = DeviceImageLoadEvents
| where ActionType == 'ImageLoaded'
| where FileName =~ "samlib.dll"
| where isnotempty(InitiatingProcessSHA256)
| invoke FileProfile(InitiatingProcessSHA256, 1000)
| where GlobalPrevalence <= 50 or isempty(GlobalPrevalence)
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessAccountSid, ReportId;
let UniqueHashes = toscalar (ImageLoads|summarize make_set(InitiatingProcessSHA256)); 
let NamedPipes = DeviceEvents
| where ActionType == 'NamedPipeEvent'
| where InitiatingProcessSHA256 in (UniqueHashes)
| join kind=inner (ImageLoads | distinct InitiatingProcessSHA256) on InitiatingProcessSHA256
| where parse_json(AdditionalFields).PipeName == @"\Device\NamedPipe\wkssvc"
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessAccountSid, PipeName = parse_json(AdditionalFields).PipeName, ReportId;
let Connection = DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessSHA256 in (UniqueHashes)
| join kind=inner (ImageLoads | distinct InitiatingProcessSHA256) on InitiatingProcessSHA256
| project Timestamp, DeviceId, DeviceName, ActionType, RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessAccountSid, ReportId;
union NamedPipes, ImageLoads, Connection
| sort by DeviceId, Timestamp asc, InitiatingProcessSHA256
| scan with_match_id=Id declare (Step:string, Delta:timespan) with (
    step InitialConnection: ActionType == "ConnectionSuccess" => Step = "s1";
    step NamedPipe: ActionType == 'NamedPipeEvent' and DeviceId == InitialConnection.DeviceId and InitiatingProcessSHA256 == InitialConnection.InitiatingProcessSHA256 and Timestamp between (Timestamp .. datetime_add('second', 1, InitialConnection.Timestamp)) and InitiatingProcessAccountSid == InitialConnection.InitiatingProcessAccountSid => Step = 's2', Delta = Timestamp - InitialConnection.Timestamp;
    step ImageLoad: ActionType == 'ImageLoaded' and DeviceId == NamedPipe.DeviceId and InitiatingProcessSHA256 == NamedPipe.InitiatingProcessSHA256 and Timestamp between (Timestamp .. datetime_add('second', 1, NamedPipe.Timestamp)) and InitiatingProcessAccountSid == NamedPipe.InitiatingProcessAccountSid  => Step = 's3', Delta = Timestamp - NamedPipe.Timestamp;
)
| where Step == 's3'
```