   <img width="800" src="https://github.com/user-attachments/assets/623483cc-034e-4982-9c39-401fb76680ae" alt="Wireshark logo"/>




# Threat Hunt Report: Unauthorized Installation and Usage of Wireshark
- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Wireshark 

##  Scenario

Management suspects that an insider or compromised user installed Wireshark to inspect network traffic from within a VM, possibly for reconnaissance or exfiltration. Also, management suspects that other bad actors could have installed Wireshark. The goal is to detect any Wireshark usage and analyze related security incidents to mitigate potential risks. 

### High-Level Wireshark-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any "Wireshark.exe" file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of installation or usage.
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

To confirm installation, searched for any file that had the string "wireshark.exe", "tshark.exe" in it and discovered what looks like the an employee with the name: "Doreen" downloaded Wireshark. The employee installed Wireshark to not install an icon on the Desktop and no extra components. This event began on `2025-05-21T21:11:07.6958531Z`.

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

Determine that the unauthorized installation of Wireshark was download and launch on other corporate VM devices such as "vm-final-lab-kr' on May 21, 2025 and "jd-win10" on May 19th and again on May 20, 2025.  

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
- **Event:** The user "Doreen" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
