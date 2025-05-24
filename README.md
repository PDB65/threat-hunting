   <img width="800" src="https://github.com/user-attachments/assets/623483cc-034e-4982-9c39-401fb76680ae" alt="Wireshark logo"/>




# Threat Hunt Report: Unauthorized Installation and Usage of Wireshark
- [Scenario Creation](https://github.com/PDB65/threat-hunting/blob/main/threat-hunting-scenario-Wireshark-event-creation.md)


## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Wireshark 

##  Scenario

Management suspects that an insider or compromised user installed Wireshark to inspect network traffic from within a VM, possibly for reconnaissance or exfiltration. Also, management suspects that other bad actors could have installed Wireshark.
The goal is to detect any Wireshark usage and analyze related security incidents to mitigate potential risks. 
Note: The organization has a policy against installing packet capture tools.

### High-Level Wireshark-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any "Wireshark.exe" file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections using known Wireshark ports.
---

## Investigation Steps:

## 1.	Confirm Installation Source

- Determine if PowerShell, EXE, or portable version was used.

- Check hash against known software repositories

## 2.	Identify Process Creation Events

- Search for execution of Wireshark or dumpcap.

- Review parent process tree (browser, installer, etc.).

## 3.	Check Network Traffic

- Look for outbound connections during capture window.

- DNS resolution of suspicious domains (file-sharing services).

## 4.	Privilege Escalation Check

- Was Wireshark installed by other bad actors? 

- Did the user run as an administrator? 

---

### 1. Searched the `DeviceFileEvents` Table

To confirm installation, searched for any files that had the string "wireshark.exe", "tshark.exe" in it. It determined an employee by name of: "Doreen" downloaded Wireshark. The user initially installed Wireshark with the option of not installing an icon on the Desktop and no extra components. This event began on `2025-05-21T21:11:07.6958531Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "burwell-new-vm"  
| where FileName contains "Wireshark.exe"
| where Timestamp >= datetime(2025-05-21T21:11:07.6958531Z)
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```

![image](https://github.com/user-attachments/assets/a1b8d39e-81fb-458a-8aa5-c728a10dd892)

---

**Second KQL query used to locate `DeviceFileEvents`:**

The Wireshard software was installed, the file was created on the VM, deleted, and then reinstalled. 

![image](https://github.com/user-attachments/assets/7a11b20f-5136-40ca-a2da-894783b9dfe5)

---
**Third KQL query used to locate `DeviceFileEvents`:**

After further investigation, it was discovered the user “Doreen” installed Wireshark additional components (npcap) for Wireshark on 5/21/2025.

```kql
DeviceFileEvents  
| where DeviceName == "burwell-new-vm"  
| where FileName contains "Npcap"
| order by Timestamp desc  

```
![image](https://github.com/user-attachments/assets/d6ab6ddd-3ae8-4d04-b8c9-6373120ffefd)

---

### 2. Searched the `DeviceProcessEvents` Table

To identify execution, searched for any `ProcessCommandLine` that contained the string ""wireshark.exe", "tshark.exe", "dumpcap.exe"for the employee "Doreen" on the "burwell-new-vm" device and identify active use of Wireshark or its command-line utilities (tshark, dumpcap)

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "burwell-new-vm"  
| where FileName in~ ("wireshark.exe", "tshark.exe", "dumpcap.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath, ProcessCommandLine, AccountName

```

![image](https://github.com/user-attachments/assets/eeb55829-ed3d-4122-901c-067df5674d27)

---


### 3. Searched the `DeviceNetworkEvents` Table for Wire Network Connections

Searched and there is an indication that the employee "Doreen" on the "burwell-new-vm" device successfully established a connection, ran Wireshark, and scanned the network. A connection was established on TCP remote port 443, HTTP port 80, and DNS UDP port 53. 

**Query used to locate events:**

```kql

DeviceNetworkEvents  
| where DeviceName == "burwell-new-vm"   
| where RemotePort in ("80", "53", "443") 
| project Timestamp, DeviceName, ActionType, RemotePort

```
![image](https://github.com/user-attachments/assets/b0472ad6-ac81-421d-8eed-424b2a4fd874)



---

### 4. Searched for additonal bad actors 

Determine that the unauthorized installation of Wireshark was downloaded by other bad actors who may have admin rights. 
Wireshark was installed on other corporate devices such as "vm-final-lab-kr' on May 21, 2025, and "jd-win10" on May 19th and again on May 20, 2025. 
The owners of those devices are employees who have admin right to their devices too.


**Query used to locate events:**

```kql

DeviceProcessEvents
| where FileName in~ ("wireshark.exe", "tshark.exe")
| extend Parent = InitiatingProcessFileName
| where Parent in~ ("powershell.exe", "cmd.exe", "explorer.exe", "chrome.exe", "firefox.exe")
| project Timestamp, DeviceName, FileName, FolderPath, Parent, InitiatingProcessCommandLine
| order by Timestamp desc  

```

![image](https://github.com/user-attachments/assets/3554d825-9e55-4355-95ff-9e35cd9e9917)

---

## Chronological Event Timeline 

### 1. File Download - Wireshark

- **Timestamp:** `2025-05-21T21:11:07.6958531Z`
- **Event:** The user "Doreen" downloaded a file named `Wireshark-4.4.6-x64.exe` to the Downloads folder.
- **Action:** File download detected, deleted and reinstalled.
- **File Path:** `C:\Users\Doreen\Downloads\Wireshark-4.4.6-x64.exe`

### 2. Process Execution - Wireshark Installation

- **Timestamp:** `2025-05-21T21:11:10.6958531Z` - Time to Check
- **Event:** The user "Doreen" executed the file `Wireshark-4.4.6-x64.exe`,
- **Copy the file to the installerPath** = “C:\Temp\Wireshark-4.4.6-x64.exe"
-  **installation directory $installDir** = "C:\Program Files\Wireshark"
-  Use PowerShell silent mode to initiating a background installation of Wireshark.
- **Silent Installer Command:** `Start-Process -FilePath $installerPath -ArgumentList $arguments -Wait -PassThru`
`

### 3. Process Execution - Wireshark Launch

- **Timestamp:** `2025-05-21T21:11:10.6958531` - Time to Check
- **Event:** User "Doreen" launched Wireshark and installed additional components such as `npcap`. After installing the `npcap` components, the user chose to created a Wireshark shortcut on the Desktop. 
- **Action:** Process creation of Wireshark executables detected.
- **File Path:** `C:\Users\Dooreen\Desktop\Wireshark-4.4.6-x64.ex`

### 4. Network Connection - TOR Network - TO DO

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity - Network scanned

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List - 

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

Confirmed the user "Doreen" on the endpoint "burwell-new-vm" device initiated and completed the installation of Wireshark. The bad actor scanned the network, establish connections using Wireshark. This sequence of activities indicates that the user actively installed, configured, and used Wireshark. Also, furhter investigation determined other employees downloaded and installed Wireshark prior to the user "Doreen." 

---

## Response Action Taken

- The device was isolated.
- The software was blocked by EDR policy.
- Notified the user's manager
- Determine if the Security Team requires the credentials to be blocked pending further investigations.

---
## Preventive & Detective Controls:

- VM baseline software inventory monitoring
- Restrict administrative privileges on VMs
- Alert on packet sniffing tool executions

---
## Documentation & Reporting:

- Record timeline of events
- User identity and privilege level
- Evidence collected (logs)
- Post-incident lessons learned

