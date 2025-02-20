Below is the English version of the forensic table with all locations and descriptions.

---

## Windows Incident Response / Digital Forensics Important Files and Records – English Table

### 1. Memory and Disk Related Data

| **File/Record**           | **Location**                                                                  | **Description**                                             |
|---------------------------|-------------------------------------------------------------------------------|-------------------------------------------------------------|
| RAM Dump                  | Manual acquisition (e.g., dumpit, winpmem)                                      | Memory dump for analyzing running processes                 |
| Pagefile.sys / Hiberfil.sys | `C:\pagefile.sys`, `C:\hiberfil.sys`                                           | Contains memory remnants and hibernation data               |
| Master File Table (MFT)   | `C:\$MFT`                                                                     | NTFS file system metadata                                   |
| $LogFile                  | `C:\$LogFile`                                                                 | NTFS change log                                             |
| $UsnJrnl ($J)             | `C:\$Extend\$UsnJrnl`                                                          | File change journal; can show deleted file activities       |
| Volume Shadow Copies      | `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX`                             | Provides access to previous versions of files               |

---

### 2. User and Browser Data

| **File/Record**   | **Location**                                                                                   | **Description**                                                      |
|-------------------|-------------------------------------------------------------------------------------------------|----------------------------------------------------------------------|
| NTUSER.DAT        | `C:\Users\<User>\NTUSER.DAT`                                                                      | Personal user settings                                               |
| USRCLASS.DAT      | `C:\Users\<User>\AppData\Local\Microsoft\Windows\UsrClass.dat`                                    | Additional user settings                                             |
| Jump Lists        | `C:\Users\<User>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`                 | Tracks recently opened files and applications                        |
| ShellBags         | Registry: `HKCU\Software\Microsoft\Windows\Shell\BagMRU`                                          | History of opened folders                                            |
| LNK Files         | `C:\Users\<User>\AppData\Roaming\Microsoft\Windows\Recent\`                                       | Shortcut files                                                       |
| MRU Lists         | Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`                   | Recently used files                                                  |
| **UserAssist**    | NTUSER.DAT: `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`                      | Usage statistics for executed applications                           |
| **TypedPaths**    | NTUSER.DAT: `Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`                      | Manually entered paths in Windows Explorer                           |

---

### 3. Running and Recently Used Applications

| **File/Record**                               | **Location**                                                                                      | **Description**                                                      |
|-----------------------------------------------|----------------------------------------------------------------------------------------------------|----------------------------------------------------------------------|
| AmCache                                       | `C:\Windows\AppCompat\Programs\Amcache.hve`                                                        | Record of executed applications                                      |
| ShimCache (AppCompatCache)                    | Registry: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`                    | Traces of executed applications                                      |
| SRUM (System Resource Usage Monitor)          | `C:\Windows\System32\sru\SRUDB.dat`                                                                 | System and network usage records                                     |
| Prefetch                                      | `C:\Windows\Prefetch\`                                                                             | Application preloading and execution history                         |
| Windows Timeline                              | `C:\Users\<User>\AppData\Local\ConnectedDevicesPlatform\`                                          | Timeline of user activities                                           |
| **BAM/DAM (Background & Desktop Activity Monitor)** | Registry: `SYSTEM\CurrentControlSet\Services\bam\State\UserSessionID`                        | Timestamps for background and desktop activities                      |

---

### 4. Windows Registry Keys

| **File/Record**          | **Location**                                                                                             | **Description**                                                |
|--------------------------|----------------------------------------------------------------------------------------------------------|----------------------------------------------------------------|
| Run Keys & RunOnce       | Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`                                          | Applications set to run at startup                              |
| Last Shutdown Time       | Registry: `HKLM\SYSTEM\CurrentControlSet\Control\Windows`                                               | Timestamp of the last system shutdown                           |
| Mounted Devices          | Registry: `HKLM\SYSTEM\MountedDevices`                                                                   | History of attached devices                                      |
| USB Devices (USBSTOR)    | Registry: `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`                                                   | Records of attached USB devices                                  |
| Network Connections      | Registry: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`                        | History of network connections                                   |
| TypedURLs                | Registry: `HKCU\Software\Microsoft\Internet Explorer\TypedURLs`                                          | Manually entered web addresses                                   |
| **WMI Persistence**      | Registry: `SOFTWARE\Microsoft\Wbem\CIMOM`                                                                | Persistence mechanism via WMI                                     |
| **Service Records**      | Registry: `HKLM\SYSTEM\CurrentControlSet\Services`                                                       | Service records                                                  |
| **BITS Jobs**            | Registry: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\BITS`                                          | Background transfer processes (BITS)                             |

---

### 5. Windows Logs and Event Records

| **File/Record**                                            | **Location**                                                                                                                          | **Description**                                                         |
|------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------|
| Security Event Log                                         | `C:\Windows\System32\winevt\Logs\Security.evtx`                                                                                      | Log of security events                                                  |
| Application Event Log                                      | `C:\Windows\System32\winevt\Logs\Application.evtx`                                                                                   | Log of application events                                               |
| System Event Log                                           | `C:\Windows\System32\winevt\Logs\System.evtx`                                                                                        | Log of system events                                                    |
| **Microsoft-Windows-PowerShell/Operational.evtx**          | `C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx`                                                      | Executed PowerShell commands                                            |
| **PowerShell Command History (PSReadLine)**                | `C:\Users\<User>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`                                    | History of PowerShell commands entered by the user                      |
| **PowerShell Command History (Event ID 4103, 4104)**       | Event Log (detailed records)                                                                                                           | Event logs for PowerShell script and command executions (based on IDs)    |
| **Recent Activity**                                        | `C:\Users\<User>\AppData\Local\Microsoft\Windows\History`                                                                             | User recent activity (activity log)                                     |
| **Scheduled Tasks**                                        | `C:\Windows\System32\Tasks\`                                                                                                           | File records of scheduled tasks                                         |
| **Windows Error Reporting (WER) Logs**                   | `C:\ProgramData\Microsoft\Windows\WER\ReportQueue`                                                                                    | Windows error reporting files                                           |
| **Clipboard History**                                      | Event ID 1001 (ClipboardUserService)                                                                                                   | Log record of clipboard history                                         |
| **Windows Defender Logs (MpCmdRun.log)**                   | `C:\ProgramData\Microsoft\Windows Defender\Support\`                                                                                  | Antivirus logs                                                          |
| **Sysmon Logs (Sysmon.evtx)**                              | `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx`                                                          | Process monitoring logs                                                 |

---

### 6. Network & Remote Access

| **File/Record**                 | **Location/Command**                                     | **Description**                                       |
|---------------------------------|----------------------------------------------------------|-------------------------------------------------------|
| Windows Firewall Logs           | `C:\Windows\System32\LogFiles\Firewall\pfirewall.log`      | Logs of incoming and outgoing connections           |
| RDP Cache                       | `C:\Users\<User>\AppData\Local\Microsoft\Terminal Server Client\Cache\` | Cache of Remote Desktop connections                |
| **NetBIOS & SMB Connections**    | Registry: `HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters` | NetBIOS and SMB connection details                   |
| **DNS Cache**                   | Command: `ipconfig /displaydns`                          | DNS cache records                                    |
| **Remote Desktop (RDP) Logs**     | Event IDs 4624, 4776, 1149                                | Log records related to RDP connections               |
| **Shared Network Drives**       | Registry: `HKEY_USERS\...\Network`                        | Information on shared network drives                 |
| **Wi-Fi Profiles**              | Command: `netsh wlan show profiles`                      | Wireless network profiles                            |
| **netstat**                     | Command: `netstat -ano`                                  | List of open network connections                     |

---

### 7. USB & External Device Records

| **File/Record**                            | **Location**                                                                                     | **Description**                                          |
|--------------------------------------------|---------------------------------------------------------------------------------------------------|----------------------------------------------------------|
| USB Device History (USBSTOR)               | Registry: `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`                                             | History of connected USB devices                         |
| **Connected Devices**                      | Registry: `HKLM\SYSTEM\CurrentControlSet\Enum\USB`                                                 | Records of other connected devices                       |
| **Removable Devices (MountPoints2)**       | NTUSER.DAT: `Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`                      | History of USB/removable device connections              |

---

### 8. File System & Data Recovery

| **File/Record**                    | **Location/Command**         | **Description**                                               |
|------------------------------------|------------------------------|---------------------------------------------------------------|
| Recycle Bin                        | `C:\$Recycle.Bin`            | Recycle Bin for deleted files                                  |
| **Alternate Data Streams (ADS)**   | Command: `dir /R`            | Hidden data stored within files                                |

---

### 9. Authentication & Encryption Data

| **File/Record**                              | **Location/Command**                                                                              | **Description**                                               |
|----------------------------------------------|---------------------------------------------------------------------------------------------------|---------------------------------------------------------------|
| Windows Credentials (Credentials)          | `%AppData%\Microsoft\Credentials`                                                                | Stored user credentials (passwords)                           |
| **Vault Records**                          | `%SystemRoot%\System32\config\systemprofile\AppData\Local\Microsoft\Vault`                          | Location where saved passwords are stored                     |
| **LSASS Memory Dump**                      | `C:\Windows\System32\lsass.exe`                                                                    | Dump from the LSASS process (risk of plaintext passwords in memory) |
| **RDP History & Connection Info**          | NTUSER.DAT: `Software\Microsoft\Terminal Server Client\Default`                                   | RDP connection history and configuration                       |
| **Windows Credentials Manager**            | Command: `rundll32.exe keymgr.dll,KRShowKeyMgr`                                                   | Stored credentials via terminal command                        |

---

### 10. Malware & Exploitation Traces

| **File/Record**                 | **Location**                  | **Description**                                           |
|---------------------------------|-------------------------------|-----------------------------------------------------------|
| Memory Dumps                    | `C:\Windows\Minidump\`          | System minidump files (crash dump, exploitation traces)   |

---
