# Visualize Phishing Detection Reasons

## Query Information

#### Description
This query visualizes the phishing detection reasons in a piechart. This is based on the EmailPostDeliveryEvents table. This table in the advanced hunting schema contains information about post-delivery actions taken on email messages processed by Microsoft 365. Based on this information the differnt detection reasons are visualized.

#### References
- https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-emailpostdeliveryevents-table?view=o365-worldwide

## Defender XDR
```KQL
EmailPostDeliveryEvents
| where ThreatTypes == "Phish"
| extend DetectionMethod = tostring(extract(@'Phish":\["(.*?)"]', 1, DetectionMethods))
| summarize TotalEvents = count() by DetectionMethod
| render piechart with(title="Phishing Detection Reason Overview")
```
## Sentinel
```KQL
EmailPostDeliveryEvents
| where ThreatTypes == "Phish"
| extend DetectionMethod = tostring(extract(@'Phish":\["(.*?)"]', 1, DetectionMethods))
| summarize TotalEvents = count() by DetectionMethod
| render piechart with(title="Phishing Detection Reason Overview")
```
