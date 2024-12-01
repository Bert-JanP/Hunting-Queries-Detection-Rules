# Executable File Extentions downloaded via HTTP GET

## Query Information

#### Description
List Executable File Extentions downloaded via HTTP GET

## Defender XDR
```KQL
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

## Sentinel
```KQL
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
