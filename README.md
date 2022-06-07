# Welcome!

## Threat Hunting and Detection rules for Defender For Endpoint & Azure Sentinel
This repository will be used to publish Hunting Queries or Detection rules that can be used within Azure Sentinel or Defender For Endpoint. The queries are written in KQL they can be used within Sentinel to build Analytics Rules or in Defender For Endpoint (with minor adjustments). If you have any questions feel free to reach out to me on twitter @BertJanCyber. 

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

## Currently the following rules have been added:

- Follina Detection
