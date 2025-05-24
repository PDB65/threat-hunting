# Threat Event: Unauthorized Install and Usage of Wireshark

### Incident: 
An internal or external bad actor installed Wireshark on a corporate VM with the intention of capturing internal network traffic, potentially to extract sensitive data or bypass network monitoring tools.

### Policy: 
For employees of the organization, there is a policy against installing packet capture tools. The organization and aims to identify and investigate potential insider threats or policy violations.

---





## The actions of the internal or external threat:
1. Download Wireshark from the website: https://www.wireshar.org 
2. Located the file: ```Wireshark-4.4.6-x64.exe```
3. Copy the file to the Temp folder: `“C:\Temp\Wireshark-4.4.6-x64.exe"`
4. Delete the file in the download folder to give the impression that the file was deleted and not used.
5. Launch PowerShell with admin credentials and run Wireshark in silent mode. To go undetected, the script will not add an icon on the Desktop and install additional components. Wait.
6. A few minutes later, install the additional components, such as `npcap`, and during the this installation, select the option to not install an icon on the Desktop. 

---
## 🕵️‍♂️ Threat Hunting

## Tables Used to Detect IoCs:

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Detect Wireshark download, installation, as well as the deletion and reinstalling the software again. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceNetworkevents-table|
| **Purpose**| Detect network activity. The bad actor ran Wireshark and scanned the network. A connection was established on TCP remote port 443, HTTP port 80, and DNS UDP port 53.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table|
| **Purpose**| Detect the silent installation of Wireshark as well as active use of Wireshark or its command-line utilities (tshark, dumpcap). Also, detect if other users may have downloaded and launched Wireshark manually.|

---




## Related Queries:
```kql


//Wireshark File Created, deleted, and then reinstalled again
DeviceFileEvents   
| where DeviceName == "burwell-new-vm"  
| where FileName contains "" "Wireshark.exe"
| where Timestamp >= datetime(2025-05-21T21:11:07.6958531Z)
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

//The user “Doreen” installed Wireshark additional components `(npcap)`.
DeviceFileEvents  
| where DeviceName == "burwell-new-vm"  
| where FileName contains "Npcap"
| order by Timestamp desc  


//Active use of Wireshark or its command-line utilities (tshark, dumpcap)
DeviceProcessEvents
| where DeviceName == "burwell-new-vm"  
| where FileName in~ ("wireshark.exe", "tshark.exe", "dumpcap.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath, ProcessCommandLine, AccountName

//It appears other bad actors downloaded Wireshark on the corporate VM too. 
DeviceProcessEvents
| where FileName in~ ("wireshark.exe", "tshark.exe")
| extend Parent = InitiatingProcessFileName
| where Parent in~ ("powershell.exe", "cmd.exe", "explorer.exe", "chrome.exe", "firefox.exe")
| project Timestamp, DeviceName, FileName, FolderPath, Parent, InitiatingProcessCommandLine
| order by Timestamp desc  


//The user ran Wireshark and scanned the network. A connection was established on TCP remote port 443, HTTP port 80, and DNS UDP port 53. 
DeviceNetworkEvents  
| where DeviceName == "burwell-new-vm"   
| where RemotePort in ("80", "53", "443") 
| project Timestamp, DeviceName, ActionType, RemotePort


```

---

## Created By:
- **Author Name**: Pamela Burwell
- **Author Contact**: https://www.linkedin.com/in/pam-b-b8453188/
- **Date**: May 24, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `May 24, 2025`  | `Pamela Burwell`   
