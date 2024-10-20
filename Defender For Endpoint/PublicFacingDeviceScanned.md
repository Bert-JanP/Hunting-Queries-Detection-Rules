# List detected devices by external scan 

## Query Information

#### Description
The reason for this detection is stated by Microsoft: As threat actors continuously scan the web to detect exposed devices they can exploit to gain a foothold in internal corporate networks, mapping your organization’s external attack surface is a key part of your security posture management. Devices that can be connected to or are approachable from the outside pose a threat to your organization.

Microsoft Defender for Endpoint automatically identifies and flags onboarded, exposed, internet-facing devices in the Microsoft 365 Defender portal. This critical information provides increased visibility into an organization's external attack surface and insights into asset exploitability.

This query lists all devices which have been scanned and list when, their DeviceName, the IP that it had and the port that was open. This information can then be used to add firewall rules if those services should not be publicly available. 

#### Risk
Adversaries can get access trough open (vulnerable) services. 

#### References
- https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/internet-facing-devices?view=o365-worldwide

## Defender XDR
```

DeviceNetworkEvents
// Filter on devices that have been scanned
| where ActionType == "InboundInternetScanInspected"
| extend AdditionalFieldsDynamic = todynamic(AdditionalFields)
// Extract all additionalfields
| evaluate bag_unpack(AdditionalFieldsDynamic)
| project Timestamp, DeviceName, PublicScannedIp, PublicScannedPort
```
## Sentinel
```
DeviceNetworkEvents
// Filter on devices that have been scanned
| where ActionType == "InboundInternetScanInspected"
| extend AdditionalFieldsDynamic = todynamic(AdditionalFields)
// Extract all additionalfields
| evaluate bag_unpack(AdditionalFieldsDynamic)
| project TimeGenerated, DeviceName, PublicScannedIp, PublicScannedPort
```

