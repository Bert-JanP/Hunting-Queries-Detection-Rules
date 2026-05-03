# *Outbound Command-and-Control Pattern: Many External IPs on Same Port (High)*

## Query Information
**Why it matters:** Botnets often beacon to lots of IPs/hosts on a common port (443/8080/etc.).

**Logic**: One internal host connects to many external IPs over a short window.

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1102.002 | Web Service: Bidirectional Communication | https://attack.mitre.org/techniques/T1102/002/ |

#### Description
Adversaries may use an existing, legitimate external Web service as a means for sending commands to and receiving output from a compromised system over the Web service channel. Compromised systems may leverage popular websites and social media to host command and control (C2) instructions. Those infected systems can then send the output from those commands back over that Web service channel. The return traffic may occur in a variety of ways, depending on the Web service being utilized. For example, the return traffic may take the form of the compromised system posting a comment on a forum, issuing a pull request to development project, updating a document hosted on a Web service, or by sending a Tweet.

Popular websites and social media acting as a mechanism for C2 may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection.

#### Risk
1. Potential for Data Breaches: Outbound traffic can be used to exfiltrate sensitive data, such as financial data, credentials, and personally identifiable information (PII), which can be used for illicit sales, financial fraud, and identity theft. 

2. Participation in Botnets: Unfiltered outbound traffic can allow infected machines to participate in larger-scale attacks, such as Distributed Denial of Service (DDoS) attacks. 

3. Masking Malicious Activity: Attackers can manipulate outbound traffic to appear as though it's originating from different IP addresses, hiding their activities. 

4. Reconnaissance by Attackers: Cybercriminals can use this information to map out your network, identifying potential targets for exploitation.

#### Author <Optional>
- **Name: Ravi Nandan Ray**
- **Github: https://github.com/Rajaravi99**
- **Twitter:**
- **LinkedIn: www.linkedin.com/in/ravi-nandan-ray-605465163**
- **Website:**

#### References
- https://attack.mitre.org/techniques/T1102/002/
- https://intrusion.com/blog/why-you-need-to-monitor-and-control-outbound-traffic/

## Defender XDR
```KQL
// ---- Tunables ----
let Lookback = 1h;     // how far back the query searches
let TimeWindow = 15m;    // grouping window for burst behavior
let MinDistinctExtIPs = 25;     // threshold: number of unique external IPs
let MinTotalSessions = 100;    // threshold: total connections/sessions
let ExcludedPorts = dynamic([
    80, 443, 53, 123,              // common web/DNS/NTP
    25, 465, 587, 110, 143, 993, 995, // mail
    22, 3389                        // admin (optional)
]);

CommonSecurityLog
| where TimeGenerated >= ago(Lookback)
| where isnotempty(SourceIP) and isnotempty(DestinationIP) and isnotempty(DestinationPort)

// Outbound filtering: CommunicationDirection valid values 0=Inbound, 1=Outbound
| where CommunicationDirection in ("1", "Outbound")

// Focus on successful/allowed traffic (field depends on vendor, keep both)
| where SimplifiedDeviceAction =~ "Allow"
   or DeviceAction has_any ("allow", "accept", "permit")

// Internal -> External scope (public IP filter)
| where ipv4_is_private(SourceIP) == true
| where ipv4_is_private(DestinationIP) == false

// Same-port pattern, usually more interesting on non-standard ports
| where DestinationPort >= 1024
| where DestinationPort !in (ExcludedPorts)

// Aggregate per internal host + destination port + time window
| summarize
    TotalSessions        = count(),
    DistinctExternalIPs  = dcount(DestinationIP),
    ExternalIPSet        = make_set(DestinationIP, 256),
    DestHostSet          = make_set(DestinationHostName, 64),
    DestDomainSet        = make_set(DestinationDnsDomain, 64),
    ProtocolSet          = make_set(Protocol, 16),
    FirstSeen            = min(TimeGenerated),
    LastSeen             = max(TimeGenerated)
  by
    SourceIP,
    DestinationPort,
    DeviceVendor,
    DeviceProduct,
    DeviceName,
    Computer,
    bin(TimeGenerated, TimeWindow)

// Apply thresholds
| where DistinctExternalIPs >= MinDistinctExtIPs
| where TotalSessions >= MinTotalSessions

// Output shaping for Sentinel incident & entity mapping
| extend
    Host = coalesce(DeviceName, Computer),
    timestamp = FirstSeen,
    IPCustomEntity = SourceIP

| project
    timestamp,
    FirstSeen,
    LastSeen,
    Host,
    SourceIP,
    DestinationPort,
    DistinctExternalIPs,
    TotalSessions,
    ProtocolSet,
    DestHostSet,
    DestDomainSet,
    ExternalIPSet,
    DeviceVendor,
    DeviceProduct
```

## Sentinel
```KQL
// ---- Tunables ----
let Lookback = 1h;     // how far back the query searches
let TimeWindow = 15m;    // grouping window for burst behavior
let MinDistinctExtIPs = 25;     // threshold: number of unique external IPs
let MinTotalSessions = 100;    // threshold: total connections/sessions
let ExcludedPorts = dynamic([
    80, 443, 53, 123,              // common web/DNS/NTP
    25, 465, 587, 110, 143, 993, 995, // mail
    22, 3389                        // admin (optional)
]);

CommonSecurityLog
| where TimeGenerated >= ago(Lookback)
| where isnotempty(SourceIP) and isnotempty(DestinationIP) and isnotempty(DestinationPort)

// Outbound filtering: CommunicationDirection valid values 0=Inbound, 1=Outbound
| where CommunicationDirection in ("1", "Outbound")

// Focus on successful/allowed traffic (field depends on vendor, keep both)
| where SimplifiedDeviceAction =~ "Allow"
   or DeviceAction has_any ("allow", "accept", "permit")

// Internal -> External scope (public IP filter)
| where ipv4_is_private(SourceIP) == true
| where ipv4_is_private(DestinationIP) == false

// Same-port pattern, usually more interesting on non-standard ports
| where DestinationPort >= 1024
| where DestinationPort !in (ExcludedPorts)

// Aggregate per internal host + destination port + time window
| summarize
    TotalSessions        = count(),
    DistinctExternalIPs  = dcount(DestinationIP),
    ExternalIPSet        = make_set(DestinationIP, 256),
    DestHostSet          = make_set(DestinationHostName, 64),
    DestDomainSet        = make_set(DestinationDnsDomain, 64),
    ProtocolSet          = make_set(Protocol, 16),
    FirstSeen            = min(TimeGenerated),
    LastSeen             = max(TimeGenerated)
  by
    SourceIP,
    DestinationPort,
    DeviceVendor,
    DeviceProduct,
    DeviceName,
    Computer,
    bin(TimeGenerated, TimeWindow)

// Apply thresholds
| where DistinctExternalIPs >= MinDistinctExtIPs
| where TotalSessions >= MinTotalSessions

// Output shaping for Sentinel incident & entity mapping
| extend
    Host = coalesce(DeviceName, Computer),
    timestamp = FirstSeen,
    IPCustomEntity = SourceIP

| project
    timestamp,
    FirstSeen,
    LastSeen,
    Host,
    SourceIP,
    DestinationPort,
    DistinctExternalIPs,
    TotalSessions,
    ProtocolSet,
    DestHostSet,
    DestDomainSet,
    ExternalIPSet,
    DeviceVendor,
    DeviceProduct
```

## Furthure fine-tuning suggestions
1. Add or exclude known ports or any host machine which is allowed to perform this kind of activityaccording to your need or your organizational network firewall configuration.
2. Adjust thresholds if your perimeter is noisy.
3. Any specific group of users or groups who are allowed to perform such acitivity for any vulnurability scanning.
