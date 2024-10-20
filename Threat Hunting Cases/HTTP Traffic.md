# HTTP Traffic

This Threat Hunting case is based on the DeviceNetworkEvents table. The goal is to find malicious HTTP traffic.

## Step 1: Summarize HTTP Methods used

The first step is to investigate the amount of HTTP requests and classify them by HTTP Method. This will give insights into the behaviour of your environment. 

### Defender XDR
```
DeviceNetworkEvents
| where ActionType == "NetworkSignatureInspected"
| extend
     SignatureName = tostring(parse_json(AdditionalFields).SignatureName),
     SignatureMatchedContent = tostring(parse_json(AdditionalFields).SignatureMatchedContent),
     SamplePacketContent = tostring(parse_json(AdditionalFields).SamplePacketContent)
| where SignatureName == "HTTP_Client"
| extend HTTP_Request_Method = tostring(split(SignatureMatchedContent, " /", 0)[0])
| summarize count() by HTTP_Request_Method

```
### Sentinel
```
DeviceNetworkEvents
| where ActionType == "NetworkSignatureInspected"
| extend
     SignatureName = tostring(parse_json(AdditionalFields).SignatureName),
     SignatureMatchedContent = tostring(parse_json(AdditionalFields).SignatureMatchedContent),
     SamplePacketContent = tostring(parse_json(AdditionalFields).SamplePacketContent)
| where SignatureName == "HTTP_Client"
| extend HTTP_Request_Method = tostring(split(SignatureMatchedContent, " /", 0)[0])
| summarize count() by HTTP_Request_Method
```

## Step 2: Investigate HTTP GET Requests

The next step is to dive into the files that have been downloaded with HTTP GET requests. This is done by summarizing all file extensions that have been downloaded.

### Defender XDR
```
DeviceNetworkEvents
| where ActionType == "NetworkSignatureInspected"
| extend
     SignatureName = tostring(parse_json(AdditionalFields).SignatureName),
     SignatureMatchedContent = tostring(parse_json(AdditionalFields).SignatureMatchedContent),
     SamplePacketContent = tostring(parse_json(AdditionalFields).SamplePacketContent)
| where SignatureName == "HTTP_Client"
| extend HTTP_Request_Method = tostring(split(SignatureMatchedContent, " /", 0)[0])
| where HTTP_Request_Method == "GET"
| extend DownloadedContent = extract(@'.*/(.*)HTTP', 1, SignatureMatchedContent)
| extend DownloadContentFileExtention = extract(@'.*\.(.*)$', 1, DownloadedContent)
// limit DownloadContentFileExtention size to reduce false positives
| where isnotempty(DownloadContentFileExtention) and string_size(DownloadContentFileExtention) < 8
| summarize count() by DownloadContentFileExtention
| sort by count_
```
### Sentinel
```
DeviceNetworkEvents
| where ActionType == "NetworkSignatureInspected"
| extend
     SignatureName = tostring(parse_json(AdditionalFields).SignatureName),
     SignatureMatchedContent = tostring(parse_json(AdditionalFields).SignatureMatchedContent),
     SamplePacketContent = tostring(parse_json(AdditionalFields).SamplePacketContent)
| where SignatureName == "HTTP_Client"
| extend HTTP_Request_Method = tostring(split(SignatureMatchedContent, " /", 0)[0])
| where HTTP_Request_Method == "GET"
| extend DownloadedContent = extract(@'.*/(.*)HTTP', 1, SignatureMatchedContent)
| extend DownloadContentFileExtention = extract(@'.*\.(.*)$', 1, DownloadedContent)
// limit DownloadContentFileExtention size to reduce false positives
| where isnotempty(DownloadContentFileExtention) and string_size(DownloadContentFileExtention) < 8
| summarize count() by DownloadContentFileExtention
| sort by count_
```

## Step 3: Investigate Downloaded Executables

Based on a shortlist we dive into the executable files that may contain suspicious/malicious content by listing all executable files that have been downloaded using HTTP.

### Defender XDR
```
let ExecutableFileExtentions = dynamic(['bat', 'cmd', 'com', 'cpl', 'ex', 'exe', 'jse', 'lnk','msc', 'ps1', 'reg', 'vb', 'vbe', 'ws', 'wsf']);
DeviceNetworkEvents
| where ActionType == "NetworkSignatureInspected"
| extend
     SignatureName = tostring(parse_json(AdditionalFields).SignatureName),
     SignatureMatchedContent = tostring(parse_json(AdditionalFields).SignatureMatchedContent),
     SamplePacketContent = tostring(parse_json(AdditionalFields).SamplePacketContent)
| where SignatureName == "HTTP_Client"
| extend HTTP_Request_Method = tostring(split(SignatureMatchedContent, " /", 0)[0])
| where HTTP_Request_Method == "GET"
| extend DownloadedContent = extract(@'.*/(.*)HTTP', 1, SignatureMatchedContent)
| extend DownloadContentFileExtention = extract(@'.*\.(.*)$', 1, DownloadedContent)
| where isnotempty(DownloadContentFileExtention) and string_size(DownloadContentFileExtention) < 8
| where DownloadContentFileExtention has_any (ExecutableFileExtentions)
| project-reorder Timestamp, DeviceName, DownloadedContent, HTTP_Request_Method, RemoteIP
```
### Sentinel
```
let ExecutableFileExtentions = dynamic(['bat', 'cmd', 'com', 'cpl', 'ex', 'exe', 'jse', 'lnk','msc', 'ps1', 'reg', 'vb', 'vbe', 'ws', 'wsf']);
DeviceNetworkEvents
| where ActionType == "NetworkSignatureInspected"
| extend
     SignatureName = tostring(parse_json(AdditionalFields).SignatureName),
     SignatureMatchedContent = tostring(parse_json(AdditionalFields).SignatureMatchedContent),
     SamplePacketContent = tostring(parse_json(AdditionalFields).SamplePacketContent)
| where SignatureName == "HTTP_Client"
| extend HTTP_Request_Method = tostring(split(SignatureMatchedContent, " /", 0)[0])
| where HTTP_Request_Method == "GET"
| extend DownloadedContent = extract(@'.*/(.*)HTTP', 1, SignatureMatchedContent)
| extend DownloadContentFileExtention = extract(@'.*\.(.*)$', 1, DownloadedContent)
| where isnotempty(DownloadContentFileExtention) and string_size(DownloadContentFileExtention) < 8
| where DownloadContentFileExtention has_any (ExecutableFileExtentions)
| project-reorder TimeGenerated, DeviceName, DownloadedContent, HTTP_Request_Method, RemoteIP
```

## Step 4: Perform File Analysis (MDE Only)

If you found a suspicious file you can use the filename to investigate this file, using the FileProfile function. This enables us to list the file information (ThreatName, GlobalPrevalence, Signer) and a list with devices and file locations.

### Defender XDR
```
let SuspiciousDownloadName = 'GoogleUpdateSetup.exe';
DeviceFileEvents
| where FileName == SuspiciousDownloadName
| summarize
     arg_max(Timestamp, *),
     DeviceList = make_set(DeviceName),
     FileLocations = make_set(FolderPath)
     by SHA1
// Add file details, for more details see: https://docs.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-fileprofile-function?view=o365-worldwide
| invoke FileProfile(SHA1, 1000)
| project-reorder
     Timestamp,
     SHA1,
     // GlobalPrevalence = Number of instances of the entity observed by Microsoft globally. The more instances, the more likely it is benign.
     GlobalPrevalence,
     GlobalFirstSeen,
     Signer,
     ThreatName,
     DeviceList,
     FileLocations
```
## Found Something Interesting?

If you found malicious activities take a look at the [DFIR Queries](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/tree/main/DFIR) they can help by the investigation of an incident.
