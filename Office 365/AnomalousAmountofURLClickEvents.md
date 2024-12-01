# Anomalous Amount of URLClickEvents

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566.001 | Phishing: Spearphishing Attachment | https://attack.mitre.org/techniques/T1566/001/ |

#### Description
In the dynamic world of cybersecurity, proactive threat hunting and anomaly detection are key to staying ahead of potential threats. One powerful tool that aids in this process is the **UrlClickEvents table in Microsoft Sentinel**. This table can help us hunt for several cybersecurity attack vectors related to URL click activities. Let's delve into some examples:

1. *Phishing Attacks* - T1556: Phishing attacks often involve sending emails with malicious URLs to victims. If a user clicks on the URL, they might be taken to a fake login page where their credentials can be stolen. The UrlClickEvents table can help you identify unusual URL click activities that might indicate a phishing attack.

2. *Malware Downloads*: Malicious URLs can also lead to websites that automatically download malware onto a user’s device. By analyzing the UrlClickEvents table, you can potentially identify URLs that are associated with malware downloads.

3. *Command and Control (C2) Traffic*: - TA0011 In some cases, malware on a compromised device can communicate with a command and control server via HTTP/HTTPS requests. These requests can sometimes be identified by analyzing URL click events.

4. *Data Exfiltration*: - TA0010 In some advanced attacks, data exfiltration might occur through HTTP/HTTPS requests to specific URLs. The UrlClickEvents table can help you identify suspicious URL click activities that might indicate data exfiltration.

5. *Suspicious Redirects*: Attackers might use URL redirects to hide malicious activities. By analyzing the UrlClickEvents table, you can potentially identify suspicious redirect activities.

#### Risk
A user has clicked and opened a malicious link.

#### Author
- **Name: Guy Sukerman**
- **Github: https://github.com/guys1444**
- **LinkedIn: https://www.linkedin.com/in/guy-sukerman-2002451aa/**

## Defender XDR
```
let startDate = ago(30d);
let endDate = now();
UrlClickEvents
| where ActionType != 'ClickAllowed'
| where Timestamp between (startDate .. endDate)
| make-series ClickCount=count() on Timestamp from startDate to endDate step 1d
| extend (anomalies, score, baseline) = series_decompose_anomalies(ClickCount)
| mv-expand Timestamp to typeof(datetime), ClickCount to typeof(long), anomalies to typeof(double), score to typeof(double), baseline to typeof(long)
| where score > 0.1
// Only If needed | where anomalies > 0
| project Timestamp, ClickCount, anomalies, score, baseline
```

## Sentinel
```
let startDate = ago(30d);
let endDate = now();
UrlClickEvents
| where ActionType != 'ClickAllowed'
| where TimeGenerated between (startDate .. endDate)
| make-series ClickCount=count() on TimeGenerated from startDate to endDate step 1d
| extend (anomalies, score, baseline) = series_decompose_anomalies(ClickCount)
| mv-expand TimeGenerated to typeof(datetime), ClickCount to typeof(long), anomalies to typeof(double), score to typeof(double), baseline to typeof(long)
| where score > 0.1
// Only If needed | where anomalies > 0
| project TimeGenerated, ClickCount, anomalies, score, baseline
```

