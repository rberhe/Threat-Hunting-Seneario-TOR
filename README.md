# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/rberhe/Threat-Hunting-Seneario-TOR/blob/main/Threat-Hunting-TOR)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the DeviceFileEvents TableIdentified that user machinewithme on device windows19-rora downloaded the TOR installer and copied TOR-related files to the desktop.

Query Used:

DeviceEvents
| where DeviceName == "windows19-rora"
| where FileName contains "tor"
| order by Timestamp desc

![Step1 img](https://github.com/user-attachments/assets/60f56339-ab21-4faf-92e4-3f111cf2fb35)


2. Searched DeviceProcessEvents TableConfirmed execution of tor-browser-windows-x86_64-portable-14.5.3 (1).exe from the Downloads folder at 2025-06-23T13:58:00Z.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "windows19-rora"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.3"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/c7e70824-c095-4711-b490-be2803097ebe)



---

### 2. Searched the `DeviceProcessEvents` Table

Confirmed execution of tor-browser-windows-x86_64-portable-14.5.3 (1).exe from the Downloads folder at 2025-06-23T13:58:00Z.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "windows19-rora"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.3"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![Step2 img](https://github.com/user-attachments/assets/a554c954-1493-4a5f-a0f9-2c69ce4d3060)



---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Found instances of tor.exe running from the Tor Browser directory on the desktop, confirming active usage by the user.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "windows19-rora"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
![STep 3img](https://github.com/user-attachments/assets/1546c28f-ea42-4174-b086-60138863a232)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Confirmed successful outbound connection from tor.exe to IP 195.246.230.153 on port 9001.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "windows19-rora"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
![Step4 img](https://github.com/user-attachments/assets/f0261e0b-14b8-4d3c-82e6-bdf04aa089fc)


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
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

The user "employee" on the "windows19-rora" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `windows19-rora` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
