# MS Exchange Zero Day (Sept 2022)

Blog about the (unconfirmed) zero day in Exchange: [Link](https://www.gteltsc.vn/blog/warning-new-attack-campaign-utilized-a-new-0day-rce-vulnerability-on-microsoft-exchange-server-12715.html). 



### Defender For Endpoint
```
let C2IP = '137.184.67.33';
let DownloadIP = '206.188.196.77';
let RelatedIP = dynamic(['125.212.220.48', '5.180.61.17', '47.242.39.92', '61.244.94.85', '86.48.6.69', '94.140.8.48', '86.48.12.64', '94.140.8.113', '103.9.76.208', '103.9.76.211', '104.244.79.6', '112.118.48.186', '122.155.174.188', '125.212.241.134', '185.220.101.182', '194.150.167.88','212.119.34.11']); //These can be left out, they can generate a lot of false positives.
let SHA256IOC = dynamic(['c838e77afe750d713e67ffeb4ec1b82ee9066cbe21f11181fd34429f70831ec1', '65a002fe655dc1751add167cf00adf284c080ab2e97cd386881518d3a31d27f5', 'b5038f1912e7253c7747d2f0fa5310ee8319288f818392298fd92009926268ca', 'c838e77afe750d713e67ffeb4ec1b82ee9066cbe21f11181fd34429f70831ec1', 
'be07bd9310d7a487ca2f49bcdaafb9513c0c8f99921fdf79a05eaba25b52d257', '074eb0e75bb2d8f59f1fd571a8c5b76f9c899834893da6f7591b68531f2b5d82', 
'45c8233236a69a081ee390d4faa253177180b2bd45d8ed08369e07429ffbe0a9', '9ceca98c2b24ee30d64184d9d2470f6f2509ed914dafb87604123057a14c57c0', 
'29b75f0db3006440651c6342dc3c0672210cfb339141c75e12f6c84d990931c3']);
(union isfuzzy=true
     (DeviceNetworkEvents
     | where RemoteIP == C2IP
     | extend TriggerReason = 'C2 IP Found'),
     (DeviceNetworkEvents
     | where RemoteIP == DownloadIP
     | extend TriggerReason = 'Download Payload IP Found'),
     (DeviceNetworkEvents
     | where RemoteIP in (RelatedIP)
     | extend TriggerReason = 'Related IP Found'),
     (DeviceFileEvents
     | where SHA256 in (SHA256IOC)
     | extend TriggerReason = 'SHA256 IOC Found')
| project-reorder TriggerReason // Displays which IOC triggered the rule
)

```
### Sentinel
```
let C2IP = '137.184.67.33';
let DownloadIP = '206.188.196.77';
let RelatedIP = dynamic(['125.212.220.48', '5.180.61.17', '47.242.39.92', '61.244.94.85', '86.48.6.69', '94.140.8.48', '86.48.12.64', '94.140.8.113', '103.9.76.208', '103.9.76.211', '104.244.79.6', '112.118.48.186', '122.155.174.188', '125.212.241.134', '185.220.101.182', '194.150.167.88','212.119.34.11']); //These can be left out, they can generate a lot of false positives.
let SHA256IOC = dynamic(['c838e77afe750d713e67ffeb4ec1b82ee9066cbe21f11181fd34429f70831ec1', '65a002fe655dc1751add167cf00adf284c080ab2e97cd386881518d3a31d27f5', 'b5038f1912e7253c7747d2f0fa5310ee8319288f818392298fd92009926268ca', 'c838e77afe750d713e67ffeb4ec1b82ee9066cbe21f11181fd34429f70831ec1', 
'be07bd9310d7a487ca2f49bcdaafb9513c0c8f99921fdf79a05eaba25b52d257', '074eb0e75bb2d8f59f1fd571a8c5b76f9c899834893da6f7591b68531f2b5d82', 
'45c8233236a69a081ee390d4faa253177180b2bd45d8ed08369e07429ffbe0a9', '9ceca98c2b24ee30d64184d9d2470f6f2509ed914dafb87604123057a14c57c0', 
'29b75f0db3006440651c6342dc3c0672210cfb339141c75e12f6c84d990931c3']);
(union isfuzzy=true
     (DeviceNetworkEvents
     | where RemoteIP == C2IP
     | extend TriggerReason = 'C2 IP Found'),
     (DeviceNetworkEvents
     | where RemoteIP == DownloadIP
     | extend TriggerReason = 'Download Payload IP Found'),
     (DeviceNetworkEvents
     | where RemoteIP in (RelatedIP)
     | extend TriggerReason = 'Related IP Found'),
     (DeviceFileEvents
     | where SHA256 in (SHA256IOC)
     | extend TriggerReason = 'SHA256 IOC Found')
| project-reorder TriggerReason // Displays which IOC triggered the rule
)
```
