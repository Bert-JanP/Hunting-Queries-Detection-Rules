# Suspicious Encoded Powershell

Powershell can be used encoded to obfucstate the commands that have been executed. An attacker can choose encoding to hide the downloading of malicious files, or to prevent simple string matching detections. In this Threat Hunting case the goal is to identify the systems that execute encoded powershell and to classify the traffic as benign or suspicious.

## Step 1: List the devices that execute encoded PowerShell

In this step we list the devices that execute Powershell by the amount of encoded PowerShell commands executed. This can give an indication on which device needs to be investigated further. 

## Defender XDR
```
let EncodedList = dynamic(['-encodedcommand', '-enc']); // -e and -en can also be added, be aware of FPs
let TimeFrame = 48h; //Customizable h = hours, d = days
DeviceProcessEvents
| where Timestamp > ago(TimeFrame)
| where ProcessCommandLine contains "powershell" or InitiatingProcessCommandLine contains "powershell"
| where ProcessCommandLine has_any (EncodedList) or InitiatingProcessCommandLine has_any (EncodedList)
| extend base64String = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, ProcessCommandLine)
| extend DecodedCommandLine = base64_decode_tostring(base64String)
| where not(isempty(base64String) and isempty(DecodedCommandLine))
| summarize TotalEncodedExecutions = count() by DeviceName
| sort by TotalEncodedExecutions
```
## Sentinel
```
let EncodedList = dynamic(['-encodedcommand', '-enc']); // -e and -en can also be added, be aware of FPs
let TimeFrame = 48h; //Customizable h = hours, d = days
DeviceProcessEvents
| where TimeGenerated > ago(TimeFrame)
| where ProcessCommandLine contains "powershell" or InitiatingProcessCommandLine contains "powershell"
| where ProcessCommandLine has_any (EncodedList) or InitiatingProcessCommandLine has_any (EncodedList)
| extend base64String = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, ProcessCommandLine)
| extend DecodedCommandLine = base64_decode_tostring(base64String)
| where not(isempty(base64String) and isempty(DecodedCommandLine))
| summarize TotalEncodedExecutions = count() by DeviceName
| sort by TotalEncodedExecutions
```

## Step 2 Investigate encoded PowerShell commands

This is done by decoding the commands in order to be investigated. This is then listed by DeviceName the amount of unique queries that have been executed in the TimeFrame. 

## Defender XDR
```
let EncodedList = dynamic(['-encodedcommand', '-enc']); // -e and -en can also be added, be aware of FPs
let TimeFrame = 48h; //Customizable h = hours, d = days
DeviceProcessEvents
| where Timestamp > ago(TimeFrame)
| where ProcessCommandLine contains "powershell" or InitiatingProcessCommandLine contains "powershell"
| where ProcessCommandLine has_any (EncodedList) or InitiatingProcessCommandLine has_any (EncodedList)
| extend base64String = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, ProcessCommandLine)
| extend DecodedCommandLine = base64_decode_tostring(base64String)
| extend DecodedCommandLineReplaceEmptyPlaces = replace_string(DecodedCommandLine, '\u0000', '')
| where isnotempty(base64String) and isnotempty(DecodedCommandLineReplaceEmptyPlaces)
| summarize UniqueExecutionsList = make_set(DecodedCommandLineReplaceEmptyPlaces) by DeviceName
| extend TotalUniqueEncodedCommandsExecuted = array_length(UniqueExecutionsList)
| project DeviceName, TotalUniqueEncodedCommandsExecuted, UniqueExecutionsList
| sort by TotalUniqueEncodedCommandsExecuted
```
## Sentinel
```
let EncodedList = dynamic(['-encodedcommand', '-enc']); // -e and -en can also be added, be aware of FPs
let TimeFrame = 48h; //Customizable h = hours, d = days
DeviceProcessEvents
| where TimeGenerated > ago(TimeFrame)
| where ProcessCommandLine contains "powershell" or InitiatingProcessCommandLine contains "powershell"
| where ProcessCommandLine has_any (EncodedList) or InitiatingProcessCommandLine has_any (EncodedList)
| extend base64String = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, ProcessCommandLine)
| extend DecodedCommandLine = base64_decode_tostring(base64String)
| extend DecodedCommandLineReplaceEmptyPlaces = replace_string(DecodedCommandLine, '\u0000', '')
| where isnotempty(base64String) and isnotempty(DecodedCommandLineReplaceEmptyPlaces)
| summarize UniqueExecutionsList = make_set(DecodedCommandLineReplaceEmptyPlaces) by DeviceName
| extend TotalUniqueEncodedCommandsExecuted = array_length(UniqueExecutionsList)
| project DeviceName, TotalUniqueEncodedCommandsExecuted, UniqueExecutionsList
| sort by TotalUniqueEncodedCommandsExecuted
```

## Step 3: Reconnaissance Activities

The next step is to investigate if reconnaissance commands have been executed. The actor can hide the reconnaissance commands encoded to stay undetected. New items can be added to the ReconVariables list.

## Defender XDR
```
let EncodedList = dynamic(['-encodedcommand', '-enc']); // -e and -en can also be added, be aware of FPs
let ReconVariables = dynamic(['Get-ADGroupMember', 'Get-ADComputer', 'Get-ADUser', 'Get-NetGPOGroup', 'net user', 'whoami', 'net group', 'hostname', 'netsh firewall', 'tasklist', 'arp', 'systeminfo']);
let TimeFrame = 48h; //Customizable h = hours, d = days
DeviceProcessEvents
| where Timestamp > ago(TimeFrame)
| where ProcessCommandLine contains "powershell" or InitiatingProcessCommandLine contains "powershell"
| where ProcessCommandLine has_any (EncodedList) or InitiatingProcessCommandLine has_any (EncodedList)
| extend base64String = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, ProcessCommandLine)
| extend DecodedCommandLine = base64_decode_tostring(base64String)
| extend DecodedCommandLineReplaceEmptyPlaces = replace_string(DecodedCommandLine, '\u0000', '')
| where isnotempty(base64String) and isnotempty(DecodedCommandLineReplaceEmptyPlaces)
| where DecodedCommandLineReplaceEmptyPlaces has_any (ReconVariables)
| project
     Timestamp,
     ActionType,
     DecodedCommandLineReplaceEmptyPlaces,
     ProcessCommandLine,
     InitiatingProcessCommandLine,
     DeviceName,
     AccountName,
     AccountDomain

```
## Sentinel
```
let EncodedList = dynamic(['-encodedcommand', '-enc']); // -e and -en can also be added, be aware of FPs
let ReconVariables = dynamic(['Get-ADGroupMember', 'Get-ADComputer', 'Get-ADUser', 'Get-NetGPOGroup', 'net user', 'whoami', 'net group', 'hostname', 'netsh firewall', 'tasklist', 'arp', 'systeminfo']);
let TimeFrame = 48h; //Customizable h = hours, d = days
DeviceProcessEvents
| where TimeGenerated > ago(TimeFrame)
| where ProcessCommandLine contains "powershell" or InitiatingProcessCommandLine contains "powershell"
| where ProcessCommandLine has_any (EncodedList) or InitiatingProcessCommandLine has_any (EncodedList)
| extend base64String = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, ProcessCommandLine)
| extend DecodedCommandLine = base64_decode_tostring(base64String)
| extend DecodedCommandLineReplaceEmptyPlaces = replace_string(DecodedCommandLine, '\u0000', '')
| where isnotempty(base64String) and isnotempty(DecodedCommandLineReplaceEmptyPlaces)
| where DecodedCommandLineReplaceEmptyPlaces has_any (ReconVariables)
| project
     TimeGenerated,
     ActionType,
     DecodedCommandLineReplaceEmptyPlaces,
     ProcessCommandLine,
     InitiatingProcessCommandLine,
     DeviceName,
     AccountName,
     AccountDomain
```

## Step 4: Encoded Downloads

The last step is to investigate the connections that have been made via the encoded command. This can be C2 traffic or the download of a malicious tool that can be used by the actor. 

## Defender XDR
```
let EncodedList = dynamic(['-encodedcommand', '-enc']); // -e and -en can also be added, be aware of FPs
let DownloadVariables = dynamic(['WebClient', 'DownloadFile', 'DownloadData', 'DownloadString', 'WebRequest', 'Shellcode', 'http', 'https']);
let TimeFrame = 48h; //Customizable h = hours, d = days
DeviceProcessEvents
| where Timestamp > ago(TimeFrame)
| where ProcessCommandLine contains "powershell" or InitiatingProcessCommandLine contains "powershell"
| where ProcessCommandLine has_any (EncodedList) or InitiatingProcessCommandLine has_any (EncodedList)
| extend base64String = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, ProcessCommandLine)
| extend DecodedCommandLine = base64_decode_tostring(base64String)
| extend DecodedCommandLineReplaceEmptyPlaces = replace_string(DecodedCommandLine, '\u0000', '')
| where isnotempty(base64String) and isnotempty(DecodedCommandLineReplaceEmptyPlaces)
| where DecodedCommandLineReplaceEmptyPlaces has_any (DownloadVariables)
| project
     Timestamp,
     ActionType,
     DecodedCommandLineReplaceEmptyPlaces,
     ProcessCommandLine,
     InitiatingProcessCommandLine,
     DeviceName,
     AccountName,
     AccountDomain
```
## Sentinel
```
let EncodedList = dynamic(['-encodedcommand', '-enc']); // -e and -en can also be added, be aware of FPs
let DownloadVariables = dynamic(['WebClient', 'DownloadFile', 'DownloadData', 'DownloadString', 'WebRequest', 'Shellcode', 'http', 'https']);
let TimeFrame = 48h; //Customizable h = hours, d = days
DeviceProcessEvents
| where TimeGenerated > ago(TimeFrame)
| where ProcessCommandLine contains "powershell" or InitiatingProcessCommandLine contains "powershell"
| where ProcessCommandLine has_any (EncodedList) or InitiatingProcessCommandLine has_any (EncodedList)
| extend base64String = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, ProcessCommandLine)
| extend DecodedCommandLine = base64_decode_tostring(base64String)
| extend DecodedCommandLineReplaceEmptyPlaces = replace_string(DecodedCommandLine, '\u0000', '')
| where isnotempty(base64String) and isnotempty(DecodedCommandLineReplaceEmptyPlaces)
| where DecodedCommandLineReplaceEmptyPlaces has_any (DownloadVariables)
| project
     TimeGenerated,
     ActionType,
     DecodedCommandLineReplaceEmptyPlaces,
     ProcessCommandLine,
     InitiatingProcessCommandLine,
     DeviceName,
     AccountName,
     AccountDomain
```

## Found Something Interesting?

If you found malicious activities take a look at the [DFIR Queries](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/tree/main/DFIR) they can help by the investigation of an incident.
