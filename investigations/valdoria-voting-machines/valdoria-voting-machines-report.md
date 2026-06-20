
# **Valdoria Voting Machines – KC7 Investigation**

## **Executive Summary**
This investigation analyzed claims that Valdoria’s voting machines had been compromised by a malicious hacking group. Although the machines are air‑gapped and physically isolated, the attackers accidentally exposed their operational IP address in a propaganda poster. This OPSEC failure allowed analysts to trace their activity across multiple log sources.

Through analysis of network telemetry, passive DNS, email logs, authentication events, and AI chatbot interactions, we identified a fraudulent domain used for phishing, confirmed that an employee entered credentials into the fake site, and observed the threat actor using those credentials to access internal accounts. The attackers attempted to gather information about voting machines, impersonated the Election Commissioner, and contacted the vendor for technical details. Despite these efforts, the attackers were unable to compromise the air‑gapped voting machines and ultimately shifted to creating a disinformation narrative. The investigation confirmed that **no votes were altered**.

---

# **Objectives**
- Determine whether voting machines were compromised  
- Identify how the threat actor gained access  
- Identify compromised accounts  
- Map attacker activity and intent  
- Validate or refute claims of election interference  

---

# **Data Sources**
- Employees  
- Email  
- AuthenticationEvents  
- OutboundNetworkEvents  
- InboundNetworkEvents  
- PassiveDNS  
- ProcessEvents  
- FileCreationEvents  
- SecurityAlerts  
- AIPrompts  

---

# **Investigation Walkthrough**

## **Initial Context**
Valdoria prepared for a major election, hiring new poll workers and reassuring the public that voting machines were secure. Meanwhile, malicious actors attempted to undermine trust in the election.

## **Employee & System Baseline Checks**
- Identified **Barry Schmelly** (Temp Election Support Staff Supervisor)  
- Verified his email, IP, username, and hostname  
- Counted emails received (37)  
- Checked commands run on his machine  
- Identified URLs visited by employees named William (217)  
- Counted authentication attempts for users named William (183)

## **Threat Actor OPSEC Failure**
Attackers leaked their IP in a poster: **55.49.227.170**.

## **Network Pivot**
- No inbound traffic from that IP  
- Passive DNS shows two domains resolving to it:  
  - `valdoriavotesgov.com` (fraudulent)  
  - `shadow-hackers-r.us`  

## **Fraudulent Domain Analysis**
- Fake domain resolves to 3 IPs:  
  - `214.85.104.248`  
  - `55.49.227.170`  
  - `157.100.244.104`  
- Observed threat actor browsing Valdoria employee pages  
- Reconnaissance confirmed  

## **Threat Actor Motives**
Browsing history shows interest in:
- New hires  
- Election interference  
- Voting machines  
- Technical manual  

## **Phishing Domain Activity**
- Employee visited `valdoriavotesgov.com`  
- First visit: **2024‑10‑07T10:46:45Z**  
- Credentials submitted: **2024‑10‑07T10:46:47Z**  
- Username captured: **ansnooper**

## **Compromised Employee: Anderson Snooper**
- IP: `10.10.0.4`  
- Role: Temp Election Support Staff Lead  
- MFA: Disabled  
- Threat actor login: **2024‑10‑07T15:46:45Z**

## **Email Abuse**
- Snooper exchanged emails with **Barry Schmelly**  
- Asked how to access voting machines  
- Claimed he needed access to “do my job though”  
- Schmelly mentioned an AI system  

## **AI Chatbot Interaction**
Threat actor brute‑forced subdomains:
- `ai`  
- `ol-mcdonald-had-a-farm-ai-ai-oh`  
- `allen iverson`  
- First 200 OK: `elections-chatbot`

Chatbot interaction:
- 6 questions asked  
- Conversation ID: `94bd6162-1323-402d-bccd-8fceaee5f230`  
- Bot jokingly advised bringing a **flashlight** and a **banana**  
- Confirmed machines are **not connected to the internet**  
- Votes calculated using a **calculator**  
- Suggested contacting vendor: Dominos Voting Systems  

## **Compromise of Election Commissioner**
Vendor only speaks with **Election Commissioner**.

- Employee: **Arrack Bobama**  
- Username: `arbobama`  
- Email: `arrack_bobama@valdoriavotes.gov`

Threat actor login:
- Timestamp: **2024‑10‑16T00:00:00Z**  
- Source IP: **214.85.104.248**

## **Vendor Impersonation**
Threat actor (as Bobama) emailed:
- `help@dominosvotingsystems.com`

Vendor confirmed:
- Machines are **air‑gapped**  
- Provided a PDF (technical reference)

## **Final Attacker Activity**
Unable to hack machines remotely, attackers:
- Collected information  
- Created a fear‑mongering video  
- Attempted to undermine trust in the election  

---

# **Key Findings**
- Fraudulent domain: `valdoriavotesgov.com`  
- Malicious IP: `55.49.227.170`  
- Associated IPs: `214.85.104.248`, `157.100.244.104`  
- Compromised accounts:  
  - Anderson Snooper (phished)  
  - Arrack Bobama (impersonated)  
- Voting machines remained uncompromised  
- Attackers shifted to disinformation  

---

# **MITRE ATT&CK Mapping**

## **1. Reconnaissance (TA0043)**  
The adversary gathered information about the organization and its people.

- **Gather Victim Identity Information** (T1589)  
  - Browsed Valdoria employee pages  
  - Looked up new hires  

- **Gather Victim Organization Information** (T1591)  
  - Researched election processes  
  - Looked for “election interference” details  
  - Sought the technical manual for voting machines  

- **Active Scanning** (T1595)  
  - Brute‑forced subdomains (`ai`, `allen iverson`, `ol-mcdonald-had-a-farm-ai-ai-oh`)  
  - Attempted to discover internal services (`elections-chatbot`)  

---

## **2. Resource Development (TA0042)**  
The adversary prepared infrastructure for the operation.

- **Acquire Infrastructure** (T1583)  
  - Registered fraudulent domain: `valdoriavotesgov.com`  
  - Operated from multiple IPs: `55.49.227.170`, `214.85.104.248`, `157.100.244.104`  

- **Develop Capabilities** (T1587)  
  - Built a phishing page to harvest credentials  

---

## **3. Initial Access (TA0001)**  
The adversary gained entry through social engineering.

- **Phishing: Spearphishing Link** (T1566.002)  
  - Employee visited `valdoriavotesgov.com`  
  - Submitted credentials at **2024‑10‑07T10:46:47Z**  

---

## **4. Credential Access (TA0006)**  
The adversary captured and used valid credentials.

- **Credentials from Web‑Based Login** (T1555)  
  - Username/password captured via fake login page  

- **Valid Accounts** (T1078)  
  - Logged into Snooper’s account  
  - Later logged into Bobama’s account  

---

## **5. Discovery (TA0007)**  
The adversary explored the environment using legitimate access.

- **Account Discovery** (T1087)  
  - Identified the Election Commissioner role  
  - Targeted Arrack Bobama  

- **Network Service Discovery** (T1046)  
  - Subdomain probing to find internal services  

---

## **6. Lateral Movement (TA0008)**  
The adversary moved to higher‑value accounts.

- **Valid Accounts** (T1078)  
  - Used Snooper’s credentials  
  - Pivoted to Bobama’s privileged account  

---

## **7. Collection (TA0009)**  
The adversary attempted to gather sensitive information.

- **Gather Victim Organization Information** (T1591)  
  - Attempted to obtain the voting machine technical manual  
  - Asked the AI chatbot how to access voting machines  

---

## **8. Impact / Influence (TA0040 – Influence Operations)**  
*(Not part of Enterprise ATT&CK, but relevant to this scenario.)*

- **Disinformation Operations**  
  - Created a fear‑mongering video  
  - Attempted to undermine trust in election integrity  

---

# **Diamond Model Analysis**

## **Adversary**
Unknown hacking group attempting to undermine trust in Valdoria’s election.

## **Infrastructure**
- Fraudulent domain: `valdoriavotesgov.com`  
- IPs: `55.49.227.170`, `214.85.104.248`, `157.100.244.104`  
- Additional domain: `shadow-hackers-r.us`  
- Phishing page  
- Subdomain probing  

## **Capability**
- Phishing  
- Credential harvesting  
- Account takeover  
- Impersonation  
- Reconnaissance  
- Disinformation  

## **Victim**
- Anderson Snooper (phished)  
- Arrack Bobama (impersonated)  
- Valdoria Board of Elections  
- Public trust in election integrity  

---

# **Timeline**

| Timestamp | Event |
|----------|--------|
| 2024‑10‑07 10:46:45Z | Employee browses phishing domain |
| 2024‑10‑07 10:46:47Z | Credentials submitted |
| 2024‑10‑07 15:46:45Z | Threat actor logs into Snooper’s account |
| 2024‑10‑08 | Threat actor uses Snooper’s email |
| 2024‑10‑08 | Threat actor interacts with AI chatbot |
| 2024‑10‑16 00:00:00Z | Threat actor logs into Bobama’s account |
| 2024‑10‑16 | Email sent to vendor |

---

# **KQL Queries Used**
Paste all your queries here exactly as you wrote them.

---

# **Conclusion**
The investigation confirmed that the threat actor successfully harvested credentials and accessed internal accounts but **failed to compromise the air‑gapped voting machines**. Their final objective shifted to creating a fear‑based narrative rather than altering votes. The election infrastructure remained secure, and the threat actor’s impact was limited to reconnaissance and disinformation.
