# KQL Advanced Hunting Queries & Analytics Rules [![Tweet](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?text=KQL%20Threat%20Hunting%20and%20Analytics%20Rules!%20DFE%20and%20Sentinel!&url=https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules)

## Threat Hunting and Detection rules for Defender For Endpoint & Azure Sentinel
This repository will be used to publish Hunting Queries or Detection rules that can be used within Azure Sentinel or Defender For Endpoint. The queries are written in KQL they can be used within Sentinel to build Analytics Rules or in Defender For Endpoint (with minor adjustments). If you have any questions feel free to reach out to me on twitter @BertJanCyber. 


## The queries are split into the following categories:

- [Zero Day Detection](./Zero%20Day%20Detection)
- [Threat Hunting](./Threat%20Hunting)
- [Defender For Endpoint detection rules](./Defender%20For%20Endpoint)
- [Defender For Identity detection rules](./Defender%20For%20Identity)
- [Vulnerability Management](./Vulnerability%20Management)
- [DFIR (Digital Forensics and Incident Response)](./DFIR)
- [Azure Active Directory](./Azure%20Active%20Directory)

## How to use KQL in Defender For Endpoint & Sentinel?

### Defender For Endpoint
* Open  [security.microsoft.com](https://www.security.microsoft.com)
* Hunting
* Advanced Hunting

### Sentinel
* Open [portal.azure.com](https://www.portal.azure.com)
* Search for Sentinel
* Open Sentinel
* Logs

## KQL Defender For Endpoint vs Sentinel

KQL queries can be used in both Defender For Endpoint and Azure Sentinel. The syntax is almost the same. The main difference is the field that indicates the time. It must be adjusted according to the product used. In Sentinel, the 'TimeGenerated' field is used. In DFE it is 'Timestamp'. The queries below show both in DFE and in Azure Sentinel 10 DeviceEvents of the last 7 days.

Quickstart Defender For Endpoint
----------
    DeviceEvents
    | where Timestamp > ago(7d)
    | take 10


----------------------
Quickstart Azure Sentinel
----------
    DeviceEvents
    | where TimeGenerated > ago(7d)
    | take 10
----------------------

## Threat Hunting and Detection rules for Defender For Endpoint & Azure Sentinel
This repository will be used to publish Hunting Queries or Detection rules that can be used within Azure Sentinel or Defender For Endpoint. The queries are written in KQL they can be used within Sentinel to build Analytics Rules or in Defender For Endpoint (with minor adjustments). If you have any questions feel free to reach out to me on twitter @BertJanCyber. 

## How to use KQL in Defender For Endpoint & Sentinel?

### Defender For Endpoint
* Open  [security.microsoft.com](https://www.security.microsoft.com)
* Hunting
* Advanced Hunting

### Sentinel
* Open [portal.azure.com](https://www.portal.azure.com)
* Search for Sentinel
* Open Sentinel
* Logs

## KQL Defender For Endpoint vs Sentinel

KQL queries can be used in both Defender For Endpoint and Azure Sentinel. The syntax is almost the same. The main difference is the field that indicates the time. It must be adjusted according to the product used. In Sentinel, the 'TimeGenerated' field is used. In DFE it is 'Timestamp'. The queries below show both in DFE and in Azure Sentinel 10 DeviceEvents of the last 7 days.

Quickstart Defender For Endpoint
----------
    DeviceEvents
    | where Timestamp > ago(7d)
    | take 10


----------------------
Quickstart Azure Sentinel
----------
    DeviceEvents
    | where TimeGenerated > ago(7d)
    | take 10
----------------------

