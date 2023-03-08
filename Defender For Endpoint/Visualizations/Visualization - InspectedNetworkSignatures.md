# Display the Inspected Network Signatures


### Defender For Endpoint

```
DeviceNetworkEvents
| where ActionType == "NetworkSignatureInspected"
| extend
     SignatureName = parse_json(AdditionalFields).SignatureName,
     SignatureMatchedContent = 
parse_json(AdditionalFields).SignatureMatchedContent
| summarize count() by tostring(SignatureName)
| render piechart with(title="Inspected Network Signatures")

```
### Sentinel
```
DeviceNetworkEvents
| where ActionType == "NetworkSignatureInspected"
| extend
     SignatureName = parse_json(AdditionalFields).SignatureName,
     SignatureMatchedContent = 
parse_json(AdditionalFields).SignatureMatchedContent
| summarize count() by tostring(SignatureName)
| render piechart with(title="Inspected Network Signatures")
```



