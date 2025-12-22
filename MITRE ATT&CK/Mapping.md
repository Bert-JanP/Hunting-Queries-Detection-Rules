# MITRE ATT&CK Mapping

This page includes the mapping of KQL queries to the [MITRE ATT&CK](https://attack.mitre.org/) framework. The framework is a knowledge base of adversary tactics and techniques based on real-world observations.

This section only includes references to queries that can be mapped in the MITRE ATT&CK Framework. Reconnaissance and Resource Development are out of scope. 

# Statistics
| Tactic | Entry Count |
| --- | --- |
| Initial Access | 14 |
| Execution | 10 |
| Persistence | 12 |
| Privilege Escalation | 6 |
| Defense Evasion | 28 |
| Credential Access | 7 |
| Discovery | 23 |
| Lateral Movement | 2 |
| Collection | 3 |
| Command and Control | 8 |
| Exfiltration | 1 |
| Impact | 6 |

## Initial Access
| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1078.004 | Valid Accounts: Cloud Accounts |[New Authentication AppDetected](../Azure%20Active%20Directory/NewAuthenticationAppDetected.md)|
| T1078.004 | Valid Accounts: Cloud Accounts | [Conditional Access Application Failures](../Azure%20Active%20Directory/ConditionalAccess%20-%20ApplicationFailures.md)|
| T1078.004 | Valid Accounts: Cloud Accounts | [Conditional Access User Failures](../Azure%20Active%20Directory/ConditionalAccess%20-%20UserFailures.md)|
| T1190 | Exploit Public-Facing Application| [Internet Facing Devices With Available Exploits](../Vulnerability%20Management/InternetFacingDevicesWithAvailableExploits.md) |
| T1190 | Exploit Public-Facing Application | [New Active CISA Known Exploited Vulnerability Detected](../Vulnerability%20Management/NewActiveCISAKnownExploitedVulnerabilityDetected.md) |
| T1566 | Phishing | [Typosquatted Email Received](../Office%20365/Email%20-%20TyposquattedEmailRecieved.md) |
| T1566 | Phishing | [Malicious Email Delivered In Mailbox](../Defender%20For%20Cloud%20Apps/MaliciousEmailDeliveredInMailbox.md) |
| T1566.001 | Phishing: Spearphishing Attachment |[Executable Email Attachment Recieved](../Office%20365/Email%20-%20ExecutableFileRecieved.md)|
| T1566.001 | Phishing: Spearphishing Attachment | [Macro Attachment Opened From Rare Sender](../Office%20365/Email%20-%20MacroAttachmentOpenedFromRareSender.md)|
| T1566.001 | Phishing: Spearphishing Attachment | [ASR Executable Content Triggered](../Office%20365/Email%20-%20ASRExecutableContentTriggered.md) |
| T1566.001 | Phishing: Spearphishing Attachment | [Hunt: AsyncRAT OneNote Delivery](../Threat%20Hunting/Behavior%20-%20AsyncRATInitialAccess.md) |
| T1566.002 | Phishing: Spearphishing Link | [Email Safe Links Trigger](../Office%20365/Email%20-%20SafeLinksTrigger.md) |
| T1566.002 | Phishing: Spearphishing Link | [Potential Phishing Campaign](../Office%20365/Email%20-%20PotentialPhishingCampaign.md) |
| T1566.002 | Phishing: Spearphishing Link | [Successful Device Code Authentication Unmanaged Device](../Azure%20Active%20Directory/SuccessfulDeviceCodeAuthenticationUnmanagedDevice.md) |

## Execution

| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1047 | Windows Management Instrumentation | [WMIC Remote Command Execution](../Defender%20For%20Endpoint/Living%20Off%20The%20Land/WMICRemoteCommand.md) |
| T1047 | Windows Management Instrumentation | [WMIC Antivirus Discovery](../Defender%20For%20Endpoint/WMICAntivirusDiscovery.md) |
| T1059 | Command and Scripting Interpreter | [Suspicious Browser Child Process](../Defender%20For%20Endpoint/SuspiciousBrowserChildProcess.md)|
| T1059 | Command and Scripting Interpreter | [Suspicious Explorer Child Process](../Defender%20For%20Endpoint/SuspiciousExplorerChildProcess.md)|
| T1059.001 | Command and Scripting Interpreter: PowerShell | [PowerShell Launching Scripts From WindowsApps Directory (FIN7)](../Defender%20For%20Endpoint/ttp_t1059-001_powershell_windowsappsdir_fin7.md)|
| T1059.001 | Command and Scripting Interpreter: PowerShell | [AMSI Script Detection](../Defender%20For%20Endpoint/AMSIScriptDetections.md) |
| T1059.001 | Command and Scripting Interpreter: PowerShell | [PowerShell Invoke-Webrequest](../Defender%20For%20Endpoint/PowerShellInvokeWebrequest.md) |
| T1204.002 | User Execution: Malicious Link | [PowerShell Executions From Clipboard](../Defender%20For%20Endpoint/PowerShellExecutionsFromClipboard.md) |
| T1204.002 | User Execution: Malicious File | [File Containing Malware Detected](../Defender%20For%20Cloud%20Apps/FileContainingMalwareDetected.md) |
| T1204.002 | User Execution: Malicious File | [Malware File Detected Office 365](../Office%20365/MalwareFileDetected.md) |

## Persistence

| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1098 | Account Manipulation | [Account With Password Never Expires Enabled](../Defender%20For%20Identity/AccountWithPasswordNeverExpiresEnabled.md)|
| T1098 | Account Manipulation | [Password Change After Succesful Brute Force](../Defender%20For%20Identity/PasswordChangeAfterSuccesfulBruteForce.md)|
| T1136.001 | Create Account: Local Account | [Local Account Creation](../Defender%20For%20Endpoint/LocalAccountCreated.md) |
| T1136.001 | Create Account: Local Account | [Local Administrator Account Creations](../Defender%20For%20Endpoint/LocalAdminAdditions.md) |
| T1136.003 | Create Account: Cloud Account | [Cloud Persistence Activity By User AtRisk](../Azure%20Active%20Directory/CloudPersistenceActivityByUserAtRisk.md) |
| T1136.002 | Create Account: Domain Account | [Commandline User Addition](../Defender%20For%20Endpoint/CommandlineUserAddition.md) |
| T1078.004 | Valid Accounts: Cloud Accounts | [Cloud Persistence Activity By User AtRisk](../Azure%20Active%20Directory/CloudPersistenceActivityByUserAtRisk.md)|
| T1137 | Office Application Startup | [ASR Executable Office Content](../Defender%20For%20Endpoint/ASR%20Rules/AsrExecutableOfficeContent.md) |
| T1505.003 | Server Software Component: Web Shell | [WebShell Detection](../Defender%20For%20Endpoint/WebshellDetection.md) |
| T1543 | Create or Modify System Process  | [Azure ARC Related Persistence Detection](../Defender%20For%20Endpoint/nf_ttp_t1543_scattered-spider_azure_arc_persistence.md) |
| T1556 | Modify Authentication Process | [Deletion Conditional Access Policy](../Azure%20Active%20Directory/ConditionalAccess%20-%20DeletePolicy.md) |
| T1556 | Modify Authentication Process | [Change Conditional Access Policy](../Azure%20Active%20Directory/ConditionalAccess%20-%20ChangePolicy.md) |

## Privilege Escalation

| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1078.002 | Valid Accounts: Domain Accounts|[User Added To Sensitive Group](../Defender%20For%20Identity/UserAddedToSensitiveGroup.md)|
| T1078.002 | Valid Accounts: Domain Accounts | [Multiple Sentitive Group Additions From Commandline](../Defender%20For%20Endpoint/MultipleSentitiveGroupAdditions.md) |
| T1098 | Account Manipulation | [*.All Graph Permissions Added](../Azure%20Active%20Directory/AllGraphPermissionsAdded.md) |
| T1098.007 | Account Manipulation: Additional Local or Domain Groups | [Commandline Group Addition](../Defender%20For%20Endpoint/CommandlineGroupAddition.md) |
| T1134.002 | Access Token Manipulation: Create Process with Token | [Runas With Saved Credentials](../Defender%20For%20Endpoint/RunasWithSavedCredentials.md) |
| T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching|[Users Added To Sudoers Group](../Defender%20For%20Endpoint/Linux/Linux%20-%20UsersAddedToSudoersGroup.md)|

## Defense Evasion

| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1027 | Obfuscated Files or Information | [PowerShell Encoded Commands Executed By Device](../Defender%20For%20Endpoint/PowerShellEncodedCommandsByDevice.md)|
| T1027 | Obfuscated Files or Information | [All encoded Powershell Executions](../Defender%20For%20Endpoint/PowerShellEncodedCommandsExecuted.md)|
| T1027 | Obfuscated Files or Information | [Encoded PowerShell with WebRequest](../Defender%20For%20Endpoint/PowerShellEncodedWebRequests.md)|
| T1027 | Obfuscated Files or Information | [Encoded Powershell Discovery Requests](../Defender%20For%20Endpoint/PowerShellEncodedReconActivities.md) |
| T1127.001 | Trusted Developer Utilities Proxy Execution: MSBuild | [Suspicious network connection from MSBuild](../Defender%20For%20Endpoint/ttp_t1127-001_suspNetworkConnMSBuild.md)|
| T1127.001 | Trusted Developer Utilities Proxy Execution: MSBuild | [Suspicious MSBuild Remote Thread](../Defender%20For%20Endpoint/SuspiciousMSBuildRemoteThread.md) |
| T1027.010 | Obfuscated Files or Information: Command Obfuscation | [PowerShell Encoded Command](../Defender%20For%20Endpoint/ttp_t1027-010_powershellEncodedCommand.md)|
| T1070.001 | Indicator Removal| [Custom Detection Deletion](../Defender%20XDR/CustomDetectionDeletion.md) |
| T1070.001 | Indicator Removal| [Custom Detection Disabling](../Defender%20XDR/CustomDetectionDisabled.md) |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | [Security Log Cleared](../Defender%20For%20Endpoint/SecurityLogCleared.md) |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | [Wevutil Clear Windows Event Logs](../Defender%20For%20Endpoint/WevtutilClearLogs.md) |
| T1134.002 | Access Token Manipulation: Create Process with Token | [Runas With Saved Credentials](../Defender%20For%20Endpoint/RunasWithSavedCredentials.md) |
| T1218 | System Binary Proxy Execution| [WMIC Remote Command Execution](../Defender%20For%20Endpoint/Living%20Off%20The%20Land/WMICRemoteCommand.md) |
| T1218 | System Binary Proxy Execution | [New LOL Bin External Connection](../Defender%20For%20Endpoint/Living%20Off%20The%20Land/NewLOLBinExternalConnection.md) |
| T1218 | System Binary Proxy Execution | [Certutil Remote Download](../Defender%20For%20Endpoint/Living%20Off%20The%20Land/CertutilRemoteDownload.md) |
| T1218 | System Binary Proxy Execution | [LOLBin Remote IP CommandLine](../Defender%20For%20Endpoint/Living%20Off%20The%20Land/LOLBinRemoteIPCommandLine.md) |
| T1218.005| System Binary Proxy Execution: Mshta | [mshta executions](../Defender%20For%20Endpoint/MshtaExecutions.md) |
| T1218.010 | System Binary Proxy Execution: Regsvr32 | [Regsvr32 Started as Office Child](../Defender%20For%20Endpoint/Regsvr32StartedByOfficeApplication.md) |
| T1553.005 | Subvert Trust Controls: Mark-of-the-Web Bypass | [Hunt for rare ISO files](../Defender%20For%20Endpoint/RareISOFile.md)|
| T1562 | Impair Defenses | [Alert Supression Added](../Defender%20XDR/AlertSupressionAdded.md) |
| T1562.001 | Impair Defenses: Disable or Modify Tool | [XDR Advanced Feature Disabled](../Defender%20XDR/AdvancedFeatureDisabled.md)|
| T1562.001 | Impair Defenses: Disable or Modify Tools | [Abusing PowerShell to disable Defender components](../Defender%20For%20Endpoint/ttp_t1562-001_disabledefender.md)|
| T1562.001 | Impair Defenses: Disable or Modify Tools | [Scattered Spider Defense Evasion via Conditional Access Policies Detection](../Azure%20Active%20Directory/nf_ttp_t1562.001_scattered-spider_abuse%20conditional_access_trusted_locations.md) |
| T1562.001 | Impair Defenses: Disable or Modify Tools | [Defender For Endpoint Offboarding Package Downloaded](../Defender%20XDR/OffboardingPackageDownloaded.md) |
| T1562.001 | Impair Defenses: Disable or Modify Tools | [Large Number Of Analytics Rules Deleted](../Sentinel/LargeNumberOfAnalyticsRulesDeleted.md) |
| T1562.008 | Impair Defenses: Disable or Modify Cloud Logs | [Sentinel Workspace Disconnected](../Defender%20XDR/SentinelWorkspaceDisconnected.md) |
| T1562.010 | Impair Defenses: Downgrade Attack | [Potential Kerberos Encryption Downgrade](../Defender%20For%20Identity/PotentialKerberosEncryptionDowngrade.md) |
| T1578.002 | Modify Cloud Compute Infrastructure: Create Cloud Instance | [Large Number Of VMs Started](../Azure/Compute/LargeNumberOfVMsStarted.md) |

## Credential Access

| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1003 |OS Credential Dumping: NTDS | [NTDS.DIT File Modifications](../Defender%20For%20Endpoint/NTDSDitFileModifications.md) |
| T1110 | Brute Force | [Password Change After Succesful Brute Force](../Defender%20For%20Identity/PasswordChangeAfterSuccesfulBruteForce.md) |
| T1110 | Brute Force | [Multiple Accounts Locked](../Azure%20Active%20Directory/MultipleAccountsLocked.md) |
| T1552 | Unsecured Credentials | [Commandline with cleartext password](../Defender%20For%20Endpoint/CommandlineWithClearTextPassword.md) |
| T1557 | Adversary-in-the-Middle | [STORM-0539 URL Paths Email](../Threat%20Hunting/STORM-0539%20URLPathsEmail.md) |
| T1557 | Adversary-in-the-Middle | [Potential Adversary in The Middle Phishing](../Azure%20Active%20Directory/PotentialAiTMPhishing.md) |
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | [Potential Kerberos Encryption Downgrade](../Defender%20For%20Identity/PotentialKerberosEncryptionDowngrade.md) |

## Discovery

| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1018 | Remote System Discovery | [Anomalous SMB Sessions Created](../Defender%20For%20Endpoint/AnomalousSMBSessionsCreated.md)|
| T1040 | Network Sniffing | [Windows Network Sniffing](../Defender%20For%20Endpoint/WindowsNetworkSniffing.md) |
| T1046 | Network Service Discovery | [Database Discovery](../Defender%20For%20Endpoint/Discovery%20-%20DatabaseServices.md) |
| T1069 | Permission Groups Discovery | [Net(1).exe Discovery Activities](../Defender%20For%20Endpoint/NetDiscoveryActivities.md) |
| T1069 | Permission Groups Discovery | [Net(1).exe Discovery Activities Detected](../Defender%20For%20Endpoint/NetDiscoveryActivitiesDetected.md) |
| T1069.001 | Permission Groups Discovery: Local Groups | [Local Group Discovery](../Defender%20For%20Endpoint/LocalGroupDiscovery.md) |
| T1069.003 | Permission Groups Discovery: Cloud Groups | [Azure AD Download All Users](../Azure%20Active%20Directory/AzureADDownloadAllUsers.md) |
| T1069.003 | Permission Groups Discovery: Cloud Groups | [Cloud Discovery By User At Risk](../Azure%20Active%20Directory/CloudDiscoveryByUserAtRisk.md) |
| T1069.003| Permission Groups Discovery: Cloud Groups | [AzureHound](../Graph%20API/AzureHound.md) |
| T1069.003| Permission Groups Discovery: Cloud Groups | [GraphAPIAuditEvent - AzureHound](../Graph%20API/GraphAPIAuditEvents%20-%20AzureHound.md) |
| T1087 | Account Discovery | [Net(1).exe Discovery Activities](../Defender%20For%20Endpoint/NetDiscoveryActivities.md) |
| T1087 | Account Discovery | [Net(1).exe Discovery Activities Detected](../Defender%20For%20Endpoint/NetDiscoveryActivitiesDetected.md) |
| T1087.002 | Account Discovery: Domain Account | [Anomalous LDAP Traffic](../Defender%20For%20Identity/AnomalousLDAPTraffic.md) |
| T1087.004 | Account Discovery: Cloud Account |[Azure AD Download All Users](../Azure%20Active%20Directory/AzureADDownloadAllUsers.md)|
| T1087.004 | Account Discovery: Cloud Account | [Encoded Powershell Discovery Requests](../Defender%20For%20Endpoint/PowerShellEncodedReconActivities.md) |
| T1087.004 | Account Discovery: Cloud Account | [GraphAPIAuditEvent - AzureHound](../Graph%20API/GraphAPIAuditEvents%20-%20AzureHound.md) |
| T1518.001 | Software Discovery: Security Software Discovery| [WMIC Antivirus Discovery](../Defender%20For%20Endpoint/WMICAntivirusDiscovery.md)|
| T1518.001 | Software Discovery: Security Software Discovery| [Defender Discovery Activities](../Defender%20For%20Endpoint/DefenderDiscoveryActivities.md)|
| T1201 | Password Policy Discovery | [Net(1).exe Discovery Activities](../Defender%20For%20Endpoint/NetDiscoveryActivities.md) |
| T1201 | Password Policy Discovery | [Net(1).exe Discovery Activities Detected](../Defender%20For%20Endpoint/NetDiscoveryActivitiesDetected.md) |
| T1482 | Domain Trust Discovery | [Security Events - Nltest Discovery Activities](../SecurityEvents/NltestDiscovery.md) |
| T1482 | Domain Trust Discovery | [MDE - Nltest Discovery Activities](../Defender%20For%20Endpoint/NltestDiscovery.md) |
| T1615 | Group Policy Discovery |[Anomalous Group Policy Discovery](../Defender%20For%20Identity/AnomalousGroupPolicyDiscovery.md)|

## Lateral Movement

| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | [SMB File Copy](../Defender%20For%20Identity/SMBFileCopy.md)|
| T1210 | Exploitation of Remote Services | [LDAPNightmare Exploitation Attempt](../Vulnerability%20Exploitation/CVE-2024-49113%20-%20LDAPNightmare.md) |

## Collection

| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1005 | Data from Local System | [File From Host Collected](../Defender%20XDR/FileFromHostCollected.md) |
| T1114 | Email Collection | [Big Yellow Taxi - SignIn Based ](../Office%20365/BigYellowTaxi%20-%20SignIn.md) |
| T1530 | Data from Cloud Storage | [OneDrive Sync From Rare IP](../Defender%20For%20Cloud%20Apps/OneDriveSyncFromRareIP.md) |

## Command and Control

| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1071.001 | Application Layer Protocol: Web Protocols | [Behavior - TelegramC2](../Threat%20Hunting/Behavior%20-%20TelegramC2.md) |
| T1090 | Proxy | [Anonymous Proxy Events Cloud App](../Defender%20For%20Cloud%20Apps/AnonymousProxyEvents.md) |
| T1105| Ingress Tool Transfer | [Certutil Remote Download](../Defender%20For%20Endpoint/Living%20Off%20The%20Land/CertutilRemoteDownload.md)|
| T1134.002 | Application Layer Protocol | [Sliver C2 Beacon Loaded](../Defender%20For%20Endpoint/SliverC2BeaconLoaded.md) |
| T1219 | Remote Access Software | [AnyDesk Remote Connections](../Defender%20For%20Endpoint/Network%20-%20AnyDeskConnectionToPublicIP.md) |
| T1219 | Remote Access Software | [Detect Known RAT RMM Process Patterns](../Defender%20For%20Endpoint/Detect_Known_RAT_RMM_Process_Patterns.md) |
| T1219 | Remote Access Software | [NetSupport running from unexpected directory (FIN7)](../Defender%20For%20Endpoint/ttp_t1219_netsupportrat_fin7.md)|
| T1219 | Remote Access Software | [Remote Monitoring and Management Tool with connections](../Defender%20For%20Endpoint/Living%20Off%20The%20Land/RMMConnection.md) |

## Exfiltration
to be implemented
## Impact
| Technique ID | Title    | Query    |
| ---  | --- | --- |
| T1485 | Data Destruction | [(Mass) Cloud Resource Deletion](../Cloud%20Audit%20Events/CloudResourceDeletion.md) |
| T1486 | Data Encrypted for Impact |[ASR Ransomware](../Defender%20For%20Endpoint/ASR%20Rules/AsrRansomware.md)|
| T1486 | Data Encrypted for Impact | [Ransomware Double Extention](../Defender%20For%20Endpoint/Ransomware/RansomwareDoubleExtention.md) |
| T1486 | Data Encrypted for Impact | [Known Ransomware Extension Found](../Defender%20For%20Endpoint/Ransomware/RansomwareExtensionFound.md) |
| T1489 | Service Stop | [Kill SQL Processes](../Threat%20Hunting/Behaviour%20-%20KillSQLProcesses.md) |
| T1490 | Inhibit System Recovery | [Shadow Copy Deletion](../Defender%20For%20Endpoint/ShadowCopyDeletion.md)|

