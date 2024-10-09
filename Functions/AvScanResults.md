# Function: AVScanResults()

## Query Information

#### Description
The KQL function *AVScanResults()* collects this information, the function uses two input variables *DeviceIdInput* and *AvScanType*. *DeviceIdInput* is the DeviceId from the device you want to list results, the *AvScanType* can be either Quick, Full or Custom.

#### References
- https://learn.microsoft.com/en-us/defender-endpoint/schedule-antivirus-scans

## Defender XDR
```KQL
// AvScanType can be: Quick, Custom or Full
let AVScanResults = (DeviceIdInput:string, AvScanType:string) {
 DeviceTvmInfoGathering
 | where DeviceId == DeviceIdInput
 | extend AvScanResults = extractjson("$", tostring(AdditionalFields.AvScanResults))
 | mv-expand todynamic(AvScanResults)
 | extend Results = AvScanResults[AvScanType]
 | extend ScanStatus = extractjson("$.ScanStatus", tostring(Results)), ErrorCode = extractjson("$.ErrorCode", tostring(Results)), Timestamp = extractjson("$.Timestamp", tostring(Results))
 | where isnotempty(ScanStatus)
 | project DeviceId, DeviceName, ScanStatus, Timestamp, ErrorCode, AvScanResults
 };
AVScanResults("70da955b16e5717fc3xxxxxxxxxxxxx", "Full")
```

