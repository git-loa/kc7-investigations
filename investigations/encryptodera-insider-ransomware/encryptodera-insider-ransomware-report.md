
# **Encryptodera Insider Threat & Ransomware Attack – KC7 Investigation**

## **Executive Summary**
Encryptodera Financial Solutions found itself in a perfect storm: internal tension from layoff rumors, a disgruntled employee acting out, and a stealthy attacker quietly moving through the network. What began as workplace frustration quickly escalated into a coordinated ransomware attack that impacted more than 300 systems.

Our investigation revealed a **multi‑stage intrusion** involving both **external threat actors** and **insider activity**. A compromised employee account was used to launch a phishing campaign, which opened the door for lateral movement, credential theft, and ultimately, domain‑wide ransomware deployment. At the same time, a separate insider was quietly exfiltrating crypto‑related data for personal gain.

This report reconstructs the full attack path, identifies compromised accounts and systems, and highlights the techniques used by the adversaries.

---

# **Objectives**
- Determine how the ransomware attack began  
- Identify compromised accounts and systems  
- Trace attacker movement and privilege escalation  
- Assess whether insider activity contributed to the incident  
- Identify data exfiltration activity  
- Provide a clear, narrative explanation of the attack  

---

# **Data Sources**
- Employees  
- Email  
- AuthenticationEvents  
- OutboundNetworkEvents  
- InboundNetworkEvents  
- PassiveDns  
- ProcessEvents  
- FileCreationEvents  
- NetworkFlow  

---

# **Investigation Walkthrough**

## **Initial Context**
Encryptodera was already under stress. Layoff rumors were circulating, morale was low, and employees were understandably anxious. In the middle of this tension, confidential documents leaked to the media — and one employee, **Barry Shmelly**, began acting out in ways that raised red flags.

This is where our investigation began.

---

## **Early Warning Signs: Barry’s Behavior**
Barry, normally a quiet “StackOverflow Copy Paster,” suddenly became hostile. On January 16th, he emailed several Social Media Managers saying he was “sick of this place.” Two days later, he sent an angry message to the CEO with the subject:

**“YOU ARE A GREEDY PIG!!!! WHAT IS WRONG WITH YOU?????”**

Barry quit that same day.  
But his account didn’t.

---

## **Barry’s Suspicious Activity Before Quitting**
Barry’s browsing history showed a pattern:

- Researching secure file transfer methods  
- Downloading 7‑Zip  
- Reading about USB flash drives  
- Accessing sensitive internal documents  

He downloaded:

- **SECRET_MergersAndAcquisitions_Strategy2025.docx**  
- **ExecutiveSalaryNegotiations.docx**  
- **Encryptodera_Proprietary_Algorithms.zip**

He zipped files using the password **securePass123** and stored them on **E:\SchmellyDrive**.

This was clear insider‑threat behavior.

---

## **Ransomware Deployment**
On February 17th, a ransom note named **YOU_GOT_CRYTOED_SO_GIMME_CRYPTO.txt** appeared across the network — eventually landing on **306 machines**. The first sighting was on **UL8R‑MACHINE** at **02:34:54Z**.

Shortly before that, the ransomware payload **files_go_byebye.exe** appeared on the same machine.

The encryption extension used was **.umadbro**, and 50 files were encrypted on the first host.

The command that triggered encryption was:

```
start /b C:\ProgramData\files_go_byebye.exe -encrypt -target C:\Users\ -ext .umadbro
```

This wasn’t random malware — it was coordinated.

---

## **How the Ransomware Spread**
A base64‑encoded PowerShell command downloaded the ransomware from:

**notification-finance-services.com**

Immediately before that, the attacker ran:

**gpupdate /force**

This was the smoking gun.

Running gpupdate /force across the network meant the attacker had likely compromised the **domain controller** and pushed a malicious Group Policy Object (GPO) to hundreds of machines.

And that’s exactly what happened.

---

## **Discovery and Lateral Movement**
The attacker spent **15 days** quietly exploring the network before launching ransomware.

They ran **systeminfo** on 8 machines — the first being **41QI‑LAPTOP** on February 2nd.

They then used:

```
nltest /dclist:encryptoderafinancial.com
```

to locate the domain controller.

Moments later, they logged into:

**DOMAIN_CONTROLLER_SERVER**  
using stolen credentials: **lihenry_domain_admin**

This was the turning point of the attack.

---

## **Where the Domain Admin Credentials Came From**
The domain admin credentials were stolen from:

**GJ95‑LAPTOP**, owned by **Valerie Orozco**, a System Administrator.

On her machine, the attacker ran:

```
totally_not_mimikatz.exe "sekurlsa::logonpasswords"
```

Valerie had been targeted by Barry’s compromised account — but she never clicked the phishing link.  
The attacker reached her machine through **lateral movement**, not phishing.

---

## **Tracing the Initial Compromise**
Barry’s account was accessed from an external IP:

**143.38.175.105**  
on **February 1st at 00:00Z**

From there, the attacker sent **9 phishing emails** to employees.

One of those employees — **Robin Kirby** — clicked the malicious link at **03:59:30Z**.

Robin’s machine became the attacker’s foothold inside the network.

From Robin → Valerie → Domain Admin → Domain Controller → Entire Network.

The chain was complete.

---

## **Secondary Incident: Crypto Theft**
While investigating the ransomware, we uncovered a **separate insider threat**.

### **Jane Smith**, a blockchain contractor, was quietly exfiltrating data to:

**182.56.23.121** (FTP server)

She transferred **208,138 bytes** of data over **27 days**.

She searched for:

**cold storage crypto wallets**

She communicated with:

**elboss@westealurcrypto.com**

She downloaded:

- **ftp_client.exe**  
- **crypto_stealer.exe**

Her exfiltration command pointed to:

**C:\Users\jasmith\ToTheMoon\\**

and used the password:

**Ugot2muchCRYTOw3llt4k3it0FFurH4ND5**

This was a completely separate insider‑driven theft attempt.

---

# **Key Findings**
- Barry’s account was compromised and used for phishing  
- Robin was successfully phished  
- Attacker moved laterally to Valerie’s machine  
- Domain admin credentials were dumped using Mimikatz  
- Domain controller was compromised  
- Ransomware deployed to **306 machines** via malicious GPO  
- Jane Smith conducted independent crypto‑related data exfiltration  
- FTP server **182.56.23.121** used for exfiltration  
- Attack combined insider threat + external attacker + ransomware  

---

# **MITRE ATT&CK Mapping (With Explanations + Technique IDs)**

## **Reconnaissance (TA0043)**  
The attacker spent time learning about the environment before taking action.

- **Active Scanning** *(T1595)* —  
  The attacker ran `systeminfo` and `nltest /dclist` to understand OS versions, domain structure, and the location of the domain controller.

- **Gather Victim Organization Information** *(T1591)* —  
  Jane Smith searched Encryptodera’s internal site for **cold storage crypto wallets**, indicating targeted reconnaissance for financial theft.

---

## **Resource Development (TA0042)**  
The attacker prepared infrastructure and tools before launching the attack.

- **Acquire Infrastructure** *(T1583)* —  
  The ransomware payload was hosted on **notification-finance-services.com**, and the exfiltration server was **182.56.23.121**.

- **Develop Capabilities** *(T1587)* —  
  The attacker used custom tools:  
  - `files_go_byebye.exe`  
  - `crypto_stealer.exe`  
  - `ftp_client.exe`  

---

## **Initial Access (TA0001)**  
The attacker gained their first foothold through phishing.

- **Phishing: Spearphishing Link** *(T1566.002)* —  
  Barry’s compromised account sent **9 phishing emails**, including the malicious file `Employee_Contact_List_Updated_March_2024.docx.exe`.  
  **Robin Kirby** clicked the link, giving the attacker internal access.

---

## **Execution (TA0002)**  
The attacker executed malicious code on compromised systems.

- **PowerShell** *(T1059.001)* —  
  A base64‑encoded PowerShell command downloaded the ransomware payload.

- **User Execution: Malicious File** *(T1204)* —  
  The `.xlsx.exe` double‑extension file tricked users into running malware.

---

## **Persistence (TA0003)**  
- **Remote Access Software** *(T1219)* —  
  `screenconnect_client.exe` appeared on **3 devices**, indicating the attacker installed remote access tools for persistence.

---

## **Privilege Escalation (TA0004)**  
- **OS Credential Dumping** *(T1003)* —  
  On Valerie’s machine, the attacker ran Mimikatz to steal **domain admin credentials**.

---

## **Lateral Movement (TA0008)**  
- **Valid Accounts** *(T1078)* —  
  The attacker used stolen credentials (`rokirby`, `systadmi_local_admin`, `lihenry_domain_admin`) to move from Robin → Valerie → Domain Controller.

---

## **Credential Access (TA0006)**  
- **OS Credential Dumping** *(T1003)* —  
  Mimikatz was used to extract domain admin credentials from memory.

---

## **Discovery (TA0007)**  
- **System Information Discovery** *(T1082)* —  
  `systeminfo` was run on 8 machines.

- **Domain Trust Discovery** *(T1482)* —  
  `nltest /dclist` was used to locate the domain controller.

---

## **Impact (TA0040)**  
- **Data Encrypted for Impact** *(T1486)* —  
  Ransomware encrypted files using the `.umadbro` extension.

- **Exfiltration Over Unencrypted Channel** *(T1041)* —  
  Jane Smith exfiltrated data via **FTP** to **182.56.23.121**.

---

# **Diamond Model Analysis**

## **Adversary**
- External attacker leveraging Barry’s account  
- Insider (Jane Smith) conducting crypto theft  

## **Infrastructure**
- notification-finance-services.com  
- 182.56.23.121 (FTP server)  
- Malicious GPO  
- ScreenConnect  

## **Capability**
- Phishing  
- Credential theft  
- Lateral movement  
- Ransomware deployment  
- Data exfiltration  

## **Victim**
- Encryptodera Financial Solutions  
- 306 encrypted machines  
- Multiple compromised employees  

---

# **Timeline**

| Timestamp | Event |
|----------|--------|
| Jan 16 | Barry sends hostile email |
| Jan 18 | Barry quits |
| Feb 1 00:00Z | Barry’s account compromised |
| Feb 1 03:59Z | Robin phished |
| Feb 2 03:32Z | systeminfo first run |
| Feb 2 03:32Z | Domain controller accessed |
| Feb 2 08:03Z | Mimikatz executed |
| Feb 5 | Large FTP exfiltration detected |
| Feb 17 02:30Z | Ransomware payload appears |
| Feb 17 02:32Z | Encryption begins |
| Feb 17 | Ransom note deployed to 306 machines |

---

# **Conclusion**
This incident was the result of a rare but dangerous combination: a compromised employee account, a frustrated insider, and an attacker who knew exactly how to move through a Windows domain.

The attacker used phishing, credential theft, and lateral movement to reach the domain controller — the crown jewel of the network — and from there deployed ransomware to hundreds of systems. Meanwhile, a separate insider was quietly siphoning crypto‑related data for personal gain.

Encryptodera’s experience underscores the importance of:

- Enforcing MFA  
- Monitoring for unusual login patterns  
- Detecting credential dumping early  
- Restricting local admin usage  
- Watching for abnormal outbound data flows  
- Maintaining strong insider‑threat programs  

This investigation provides a full picture of what happened — and a roadmap for preventing it from happening again.
