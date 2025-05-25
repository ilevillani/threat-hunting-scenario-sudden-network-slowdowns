# Threat Hunt Report: Sudden Network Slowdowns

---

## 📋 Executive Summary  
A performance degradation investigation within the 10.0.0.0/16 network led to discovery of internal port-scanning activity originating from `ile-vm-threathu`.  After isolating the host and confirming execution of an unauthorized `portscan.ps1` script, the device was contained, scanned, and slated for rebuild.  This report details the hypothesis, data-collection queries, timeline, TTP mappings, and response/remediation steps.

---

## 🛠️ 1. Preparation  
**Goal:** Define hunt hypothesis  
**Hypothesis:** Unrestricted internal traffic and PowerShell usage may enable lateral movement or internal scanning of large file transfers.  

---

## 📊 2. Data Collection  
**Sources:**  
- `DeviceNetworkEvents`  
- `DeviceProcessEvents`  
- `DeviceFileEvents`

**Ensure:** Logs cover recent 7 days and traffic within `10.0.0.0/16`.

---

## 📅 Timeline & Findings  

1. **Failed Connection Summary**  
   ```kql
   DeviceNetworkEvents
   | where ActionType == "ConnectionFailed"
   | summarize FailedConnectionAttempts=count() by DeviceName, LocalIP, RemoteIP
   | order by FailedConnectionAttempts desc
    ```

`ile-vm-threathu` failed 46 connections to `10.0.0.5`.

![image](https://github.com/user-attachments/assets/e6eebdcf-b35d-45e0-a0cb-08ce75f79f9d)

2. **Port‐scan Identification**  

After observing failed connection requests from a suspected host `10.0.0.60` in chronological order, a portscan was found taking place - evidence is the sequential order of the ports. There were several portscans being conducted:

   ```kql
   let IPInQuestion = "10.0.0.60";
   DeviceNetworkEvents
   | where ActionType == "ConnectionFailed"
   | where LocalIP == IPInQuestion
   | order by Timestamp desc

   ```

The portscan likely started at 8:03:11 with a scan of most common ports:

![image](https://github.com/user-attachments/assets/c7d87693-97bf-4a44-9d78-e5c8c2514524)

3. **Process Pivot for Script Execution**
   
I pivoted to the `DeviceProcessEvents` table to check if I could see anything that was suspicious around the time the port scan started. A PowerShell script named `portscan.ps1` launching at `2025-05-25T06:02:35.6613149Z` was found on the logs

   ```kql
let VMName = "ile-vm-threathu";
let specificTime = datetime(2025-05-25T06:03:11.150501Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine

   ```

  ![image](https://github.com/user-attachments/assets/39af8138-3628-49d2-965b-b0f81a32f3ef)

  I logged into the suspect machine and observed the PowerShell script that was used to conduct the port scan.

  ![image](https://github.com/user-attachments/assets/0a472341-06a1-46c2-8303-959eb2bb731f)

  The above query was expanded to include the AccountName who launched the portscan. It was observed that the script was launched by one of the accounts in the organization. The machine could run malware and       further investigation is required. 

   ```kql
let VMName = "ile-vm-threathu";
let specificTime = datetime(2025-05-25T06:03:11.150501Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName

   ```
    

![image](https://github.com/user-attachments/assets/cfd3792e-22de-42f9-8b16-9afd47f23ee9)


4. **File‐Event Confirmation**

The device was isolated to avoid the spread of the infection and a malware scan was run.

The malware scan produced no results. The DeviceFileEvents table was also checked to investigate when and how the script was created. 

   ```kql
let VMName = "ile-vm-threathu";
DeviceFileEvents
| where DeviceName == VMName
| where FolderPath contains "portscan"

   ```
This confirmed the time and AccountName highlighted by previous queries, and suggested the script was created and launched from the PowerShell ISE

![image](https://github.com/user-attachments/assets/9f261387-8d88-4b40-a451-effec7cce866)

Out of caution, I kept the device isolated and put in a ticket to have it reimaged/rebuilt. The threat hunt resulted in an investigation into the AccountName above to check for any suspicious behaviour.

## 🎯 MITRE ATT&CK Mappings

| Tactic            | Technique ID   | Technique Name               |
|-------------------|----------------|------------------------------|
| Reconnaissance    | T1595.001      | Active Scanning              |
| Reconnaissance    | T1046          | Network Service Scanning     |
| Execution         | T1059.001      | PowerShell                   |
| Execution         | T1204.002      | Malicious File               |
| Initial Access    | T1078          | Valid Accounts               |
| Command & Control | T1105          | Ingress Tool Transfer        |


## 🛡️ Response & Remediation

### Containment
- **Isolate Host**  
  - Place `ile-vm-threathu` in a forensics VLAN or disconnect from network.
- **Terminate Sessions**  
  - Kill any active PowerShell or remote sessions for the implicated account.
---

### Eradication
- **Remove Malicious Script**  
  ```powershell
  Remove-Item -Path "C:\Path\To\portscan.ps1" -Force

---

### Clean Up Persistence
- **Scheduled Tasks & Run Keys**  
  Delete any Scheduled Tasks or Registry Run keys that reference `portscan.ps1`.
- **PowerShell Profiles**  
  Audit and clean PowerShell profile scripts (`$PROFILE`) for unauthorized imports or functions.

---

### Credential & Account Hardening
- **Rotate Credentials**  
  Reset the password for the user who executed `portscan.ps1`.
- **Enforce MFA**  
  Require multi-factor authentication for all remote and elevated logins.
- **Lockout Policy**  
  Configure account lockout after **5** failed login attempts.

---

### Policy & Configuration
- **Constrain PowerShell**  
  ```powershell
  Set-ExecutionPolicy AllSigned –Scope LocalMachine

- **Block Unauthorized Scripts**
  Use AppLocker or Windows Defender Application Control to allow only signed, approved scripts.

### Monitoring & Detection
- **Alert on Script Execution**
  Detect any invocation of portscan.ps1.

- **Network IDS/IPS**
  Block or throttle hosts exhibiting sequential port-fail patterns.

- **File‐Creation Alerts**
  Alert on new .ps1 files created in user or non-standard script folders.

### Recovery & Validation
- **Malware Re-scan**
  Run a deep scan with updated EDR/AV signatures.

- **Reimage if Necessary**
  Rebuild from a known-good image if any doubt remains.

- **Integrity Checks**
  Verify critical binaries (e.g., powershell.exe) against trusted hashes.
