# MITRE ATT&CK Mapping

This page includes the mapping of KQL queries to the [MITRE ATT&CK](https://attack.mitre.org/) framework. The framework is a knowledge base of adversary tactics and techniques based on real-world observations.

This section only includes references to queries that can be mapped in the MITRE ATT&CK Framework. Reconnaissance and Resource Development are out of scope. 

## Initial Access
| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1078.004 | Valid Accounts: Cloud Accounts |[New Authentication AppDetected](../Azure%20Active%20Directory/NewAuthenticationAppDetected.md)|
| T1566.001 | Phishing: Spearphishing Attachment |[Executable Email Attachment Recieved](../Office%20365/Email%20-%20ExecutableFileRecieved.md)|
| T1566.001 | Phishing: Spearphishing Attachment | [Macro Attachment Opened From Rare Sender](../Office%20365/Email%20-%20MacroAttachmentOpenedFromRareSender.md)|
| T1566.001 | Phishing: Spearphishing Attachment | [ASR Executable Content Triggered](../Office%20365/Email%20-%20ASRExecutableContentTriggered.md) |
| T1566.002 | Phishing: Spearphishing Link | [Email Safe Links Trigger](../Office%20365/Email%20-%20SafeLinksTrigger.md) |

## Execution
to be implemented
## Persistence

| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1136.001 | Create Account: Local Account | [Local Account Creation](../Defender%20For%20Endpoint/LocalAccountCreated.md) |
| T1136.003 | Create Account: Cloud Account | [Cloud Persistence Activity By User AtRisk](../Azure%20Active%20Directory/CloudPersistenceActivityByUserAtRisk.md) |
|  T1078.004 | Valid Accounts: Cloud Accounts | [Cloud Persistence Activity By User AtRisk](../Azure%20Active%20Directory/CloudPersistenceActivityByUserAtRisk.md)|

## Privilege Escalation

| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1078.002 | Valid Accounts: Domain Accounts|[User Added To Sensitive Group](../Defender%20For%20Identity/UserAddedToSensitiveGroup.md)|
| T1134.002 | Access Token Manipulation: Create Process with Token | [Runas With Saved Credentials](../Defender%20For%20Endpoint/RunasWithSavedCredentials.md) |
| T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching|[Users Added To Sudoers Group](../Defender%20For%20Endpoint/Linux/Linux%20-%20UsersAddedToSudoersGroup.md)|

## Defense Evasion

| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1027 | Obfuscated Files or Information | [PowerShell Encoded Commands Executed By Device](../Defender%20For%20Endpoint/PowerShellEncodedCommandsByDevice.md)|
| T1027 | Obfuscated Files or Information | [All encoded Powershell Executions](../Defender%20For%20Endpoint/PowerShellEncodedCommandsExecuted.md)|
| T1027 | Obfuscated Files or Information | [Encoded PowerShell with WebRequest](../Defender%20For%20Endpoint/PowerShellEncodedDownloads.md)|
| T1027 | Obfuscated Files or Information | [Encoded Powershell Discovery Requests](../Defender%20For%20Endpoint/PowerShellEncodedReconActivities.md) |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | [Security Log Cleared](../Defender%20For%20Endpoint/SecurityLogCleared.md) |
| T1134.002 | Access Token Manipulation: Create Process with Token | [Runas With Saved Credentials](../Defender%20For%20Endpoint/RunasWithSavedCredentials.md) |
| T1218.010 | System Binary Proxy Execution: Regsvr32 | [Regsvr32 Started as Office Child](../Defender%20For%20Endpoint/Regsvr32StartedByOfficeApplication.md) |
| T1553.005 | Subvert Trust Controls: Mark-of-the-Web Bypass | [Hunt for rare ISO files](../Defender%20For%20Endpoint/RareISOFile.md)|

## Credential Access
to be implemented
## Discovery

| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1018 | Remote System Discovery | [Anomalous SMB Sessions Created](../Defender%20For%20Endpoint/AnomalousSMBSessionsCreated.md)|
| T1040 | Network Sniffing | [Windows Network Sniffing](../Defender%20For%20Endpoint/WindowsNetworkSniffing.md) |
| T1069.003 | Permission Groups Discovery: Cloud Groups | [Azure AD Download All Users](../Azure%20Active%20Directory/AzureADDownloadAllUsers.md) |
| T1087.004 | Account Discovery: Cloud Account |[Azure AD Download All Users](../Azure%20Active%20Directory/AzureADDownloadAllUsers.md)|
| T1087.004 | Account Discovery: Cloud Account | [Encoded Powershell Discovery Requests](../Defender%20For%20Endpoint/PowerShellEncodedReconActivities.md) |
| T1615 | Group Policy Discovery |[Anomalous Group Policy Discovery](../Defender%20For%20Identity/AnomalousGroupPolicyDiscovery.md)|


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
| T1090 | Proxy | [Anonymous Proxy Events Cloud App](../Defender%20For%20Cloud%20Apps/AnonymousProxyEvents.md) |
| T1219 | Remote Access Software | [AnyDesk Remote Connections](../Defender%20For%20Endpoint/Network%20-%20AnyDeskConnectionToPublicIP.md) |


## Exfiltration
to be implemented
## Impact
| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1486 | Data Encrypted for Impact |[AsrRansomware](../Defender%20For%20Endpoint/AsrRansomware.md)|
| T1486 | Data Encrypted for Impact | [Ransomware Double Extention](../Defender%20For%20Endpoint/RansomwareDoubleExtention.md) |
| T1490 | Inhibit System Recovery | [Shadow Copy Deletion](../Defender%20For%20Endpoint/ShadowCopyDeletion.md)|