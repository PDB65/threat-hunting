  # Threat Hunt Report: An Unauthorized Installation and Usage


   ![image](https://github.com/user-attachments/assets/5ba2f85c-e3e7-4d60-9313-665cd7daed03)

   

### Click the link to view the scenario and related queries:

- [Scenario Creation](https://github.com/PDB65/threat-hunting/blob/main/threat-hunting-scenario-Wireshark-event-creation.md)

---
## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Wireshark
- PowerShell
- Script https://github.com/PDB65/Burwell_P/blob/main/PowerShell%20Files/Wireshark
  


##  Scenario

Management suspects that an insider or compromised user installed a third party software called: Wireshark to inspect network traffic from within a VM, possibly for reconnaissance or exfiltration. 
Also, management suspects that other bad actors could have installed Wireshark.
The goal is to detect any Wireshark usage and analyze related security incidents to mitigate potential risks. 
** Note: The organization has a policy against users installing packet capture tools without authorization.

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

To confirm installation, searched for any files that had the string "wireshark.exe" in it. It determined an employee by name of: "Doreen" downloaded Wireshark. The user initially installed Wireshark with the option of not installing an icon on the Desktop and no extra components. This event began on `2025-05-21T20:29:00.1204569Z` where the user actually installed Wireshark, deleted it, and then reinstalled the software.

**Query used to locate events:**

```kql
//Wireshark install, delete, and reinstalled again.
DeviceFileEvents  
| where DeviceName == "burwell-new-vm"  
| where FileName contains "Wireshark-4.4.6-x64.exe"
| where Timestamp >= datetime(2025-05-21T20:29:00.1204569Z)
| order by Timestamp asc   
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName


```

![image](https://github.com/user-attachments/assets/15fc77fe-0721-416e-8da5-6a83247e1ba8)


---

**Second KQL query used to locate `DeviceFileEvents`:**

The Wireshark software was installed, the file was created on the VM, deleted, and then reinstalled from the Temp foler using PowerShell. 

![image](https://github.com/user-attachments/assets/7a11b20f-5136-40ca-a2da-894783b9dfe5)

---

**Another KQL query used to locate `DeviceFileEvents`:**
![image](https://github.com/user-attachments/assets/a75248f3-badb-48b6-b9fc-65f624d55bd4)


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

#### Additional KQL query in the `DeviceNetworkEvents` Table to correlate PowerShell events and or suspicious Remote URL.

```kql

DeviceNetworkEvents
| where DeviceName == "burwell-new-vm" 
| where Timestamp >= datetime(2025-05-21T20:22:13.7670562Z)
| where InitiatingProcessFileName in~ ("wireshark.exe", "tshark.exe", "powershell.exe")
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName, RemotePort, Protocol


```

![image](https://github.com/user-attachments/assets/38532668-19be-4a4a-a4bd-4d4db5d45296)


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

- **Timestamp:** `2025-05-21T20:29:00.1204569ZZ`
- **Event:** The user "Doreen" downloaded a file named `Wireshark-4.4.6-x64.exe` to the Downloads folder.
- **Action:** File download detected, deleted and reinstalled.
- **File Path:** `C:\Users\Doreen\Downloads\Wireshark-4.4.6-x64.exe`
- **New File Path:** C:\Temp\Wireshark-4.4.6-x64.exe

### 2. Process Execution - Wireshark Installation

- **Timestamp:** `2025-05-21T21:07:21.8015708Z` 
- **Event:** The user "Doreen" executed the file `Wireshark-4.4.6-x64.exe`,
- **Copy the file to the installerPath** = “C:\Temp\Wireshark-4.4.6-x64.exe"
-  **installation directory $installDir** = "C:\Program Files\Wireshark"
-  Use PowerShell silent mode to initiating a background installation of Wireshark.
- **Silent Installer Command:** `Start-Process -FilePath $installerPath -ArgumentList $arguments -Wait -PassThru`
`

### 3. Process Execution - Wireshark Launch

- **Timestamp:** `2025-05-21T21:04:16.0173232Z`
- **Event:** User "Doreen" launched Wireshark and installed additional components such as `npcap`. After installing the `npcap` components, the user chose to created a Wireshark shortcut on the Desktop. 
- **Action:** Process creation of Wireshark executables detected.
- **File Path:** `C:\Users\Dooreen\Desktop\Wireshark-4.4.6-x64.exe`

### 4. Network Connection

- **Timestamp:** `2025-05-21T21:04:16.1398035Z`
- **Event:** A network connection using device "burwell-new-vm" acknowledge and established using `Wireshark.exe`.
- **Action:** Connection success and a scan was performed.
- **Process:** `Wireshark.exe`
- **File Path:** `C:\Users\Dooreen\Desktop\Wireshark-4.4.6-x64.exe`

### 5. Additional Network Connections - Wireshark

- **Timestamps:** `2025-05-21T20:49:51.9749746Z` and `2025-05-21T21:04:21.3290732Z`
- **Connection:** Connected to `as.dl.wireshark.org` on port `443`.
- **Connection:** Connection to `c.pki.goog` on port `80`.
- **Event:** Additional network connections to Wireshark sites were established indicating ongoing activity by user "Doreen".
- **Action:** Multiple successful connections detected.

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
## 📄 Documentation & Reporting:

- Record timeline of events
- User identity and privilege level
- Evidence collected (logs)
- Post-incident lessons learned

---


 ### 🧩 MITRE ATT&CK Mapping: Wireshark Installed on Corporate device                                                            

| **Phase:** Initial Access | - | **Technique:** Valid Accounts| - | **ID:** T1078| - |**Description:** User uses legitimate credentials to log into the device |



