# MITRE ATT&CK Mapping

This page includes the mapping of KQL queries to the [MITRE ATT&CK](https://attack.mitre.org/) framework. The framework is a knowledge base of adversary tactics and techniques based on real-world observations.

This section only includes references to queries that can be mapped in the MITRE ATT&CK Framework.

## Reconnaissance
to be implemented
## Resource Development
to be implemented
## Initial Access

| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1078.004 | Valid Accounts: Cloud Accounts |[NewAuthenticationAppDetected](../Azure%20Active%20Directory/NewAuthenticationAppDetected.md)|

## Execution
to be implemented
## Persistence
to be implemented
## Privilege Escalation

| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1078.002 | Valid Accounts: Domain Accounts|[UserAddedToSensitiveGroup](../Defender%20For%20Identity/UserAddedToSensitiveGroup.md)|
| T1134.002 | Access Token Manipulation: Create Process with Token | [RunasWithSavedCredentials](../Defender%20For%20Endpoint/RunasWithSavedCredentials.md) |
| T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching|[UsersAddedToSudoersGroup](../Defender%20For%20Endpoint/Linux/Linux%20-%20UsersAddedToSudoersGroup.md))|

## Defense Evasion

| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1134.002 | Access Token Manipulation: Create Process with Token | [RunasWithSavedCredentials](../Defender%20For%20Endpoint/RunasWithSavedCredentials.md) |
## Credential Access
to be implemented
## Discovery

| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1018 | Remote System Discovery | [AnomalousSMBSessionsCreated](../Defender%20For%20Endpoint/AnomalousSMBSessionsCreated.md)|
| T1069.003 | Permission Groups Discovery: Cloud Groups | [AzureADDownloadAllUsers](../Azure%20Active%20Directory/AzureADDownloadAllUsers.md) |
| T1087.004 | Account Discovery: Cloud Account |[AzureADDownloadAllUsers](../Azure%20Active%20Directory/AzureADDownloadAllUsers.md)|
| T1615 | Group Policy Discovery |[AnomalousGroupPolicyDiscovery](../Defender%20For%20Identity/AnomalousGroupPolicyDiscovery.md)|


## Lateral Movement

| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | [SMB File Copy](../Defender%20For%20Identity/SMBFileCopy.md)|

## Collection
to be implemented
## Command and Control

| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1071.001 | Application Layer Protocol: Web Protocols | [Behavior - TelegramC2](../Threat%20Hunting/Behavior%20-%20TelegramC2.md) |
| T1090 | Proxy | [AnonymousProxyEvents](../Defender%20For%20Cloud%20Apps/AnonymousProxyEvents.md) |


## Exfiltration
to be implemented
## Impact
| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1486 | Data Encrypted for Impact |[AsrRansomware](../Defender%20For%20Endpoint/AsrRansomware.md)|