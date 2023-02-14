# HTTP Request Methods Statistics
----
### Defender For Endpoint

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



