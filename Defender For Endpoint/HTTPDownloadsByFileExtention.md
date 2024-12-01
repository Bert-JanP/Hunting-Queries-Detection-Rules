# List the file extentions that have been used during a HTTP GET request

#### Description
List the file extentions that have been used during a HTTP GET request

## Defender XDR
```KQL
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
| summarize Total = count() by DownloadContentFileExtention
| sort by Total
```

## Sentinel
```KQL
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
| summarize Total = count() by DownloadContentFileExtention
| sort by Total
```
