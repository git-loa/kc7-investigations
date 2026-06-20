
# **Valdoria Voting Machines – KQL Evidence Walkthrough**

Below is a structured, investigation‑ready KQL walkthrough with explanations and findings for each query.

---

## **Deputy Commissioner Lookup**

This query checks the Employees table for anyone with the role *Deputy Commissioner*.

```kql
Employees
| where role == "Deputy Commissioner"
```

**Finding:** Deputy Commissioner identified.

---

## **Lookup for Employee: Dora Thomas**

This retrieves the record for employee *Dora Thomas*.

```kql
Employees
| where name == "Dora Thomas"
```

**Finding:** Dora Thomas located in the Employees table.

---

## **Employees with Supervisor Roles**

This identifies all employees whose role contains the word *supervisor*.

```kql
Employees
| where role contains "supervisor"
```

**Finding:** Supervisor‑related roles returned.

---

## **Employee Details: Barry Schmelly**

This retrieves the full employee record for *Barry Schmelly*.

```kql
Employees
| where name == "Barry Schmelly"
```

**Finding:**  
- Email: barry_schmelly@valdoriavotes.gov  
- IP: 10.10.0.12  
- Username: baschmelly  
- Hostname: GCH3-DESKTOP  

---

## **Emails Received by Barry Schmelly**

This counts how many emails Barry received.

```kql
Email
| where recipient == "barry_schmelly@valdoriavotes.gov"
| count
```

**Finding:** Barry received **37 emails**.

---

## **Distinct Commands Run on Barry’s Machine**

This identifies unique command lines executed on his workstation.

```kql
ProcessEvents
| where hostname == "GCH3-DESKTOP"
| distinct process_commandline
```

**Finding:** Distinct commands listed.

---

## **Distinct URLs Visited by Employees Named William**

This identifies all URLs visited by employees with the first name *William*.

```kql
let wills_ips =
Employees
| where name has "William"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (wills_ips)
| distinct url
```

**Finding:** **217 distinct URLs** visited.

---

## **Authentication Attempts for Employees Named William**

This counts authentication attempts for all William‑named users.

```kql
let w_username = Employees
| where name has "William"
| distinct username;
AuthenticationEvents
| where username in (w_username)
```

**Finding:** **183 authentication attempts**.

---

## **Which Table Shows Emails Barry Received?**

This confirms where email logs are stored.

```kql
Email
| take 10
```

**Finding:** The **Email** table contains this information.

---

## **Which Table Shows Bank Website Visits?**

This samples outbound browsing logs.

```kql
OutboundNetworkEvents
| take 10
```

**Finding:** **OutboundNetworkEvents** shows browsing activity.

---

## **Which Table Shows Malicious File Creation?**

This samples file creation logs.

```kql
FileCreationEvents
| take 10
```

**Finding:** **FileCreationEvents** shows file creation activity.

---

## **Which Table Shows File Execution?**

This samples process execution logs.

```kql
ProcessEvents
| take 10
```

**Finding:** **ProcessEvents** shows file execution.

---

## **Which Table Shows Malware Detection?**

This samples security alert logs.

```kql
SecurityAlerts
| take 10
```

**Finding:** **SecurityAlerts** shows detections.

---

## **Inbound Traffic From Attacker IP**

This checks whether the attacker directly interacted with the network.

```kql
InboundNetworkEvents
| where src_ip == "55.49.227.170"
```

**Finding:** **No inbound traffic** from this IP.

---

## **Domains Resolving to Attacker IP**

This identifies attacker‑controlled infrastructure.

```kql
PassiveDns
| where ip == "55.49.227.170"
```

**Finding:**  
- valdoriavotesgov.com  
- shadow-hackers-r.us  

---

## **IP Addresses for Fake Valdoria Domain**

This reveals additional attacker‑controlled IPs.

```kql
PassiveDns
| where domain == "valdoriavotesgov.com"
```

**Finding:** Fake domain resolved to **3 IPs**:  
- 214.85.104.248  
- 55.49.227.170  
- 157.100.244.104  

---

## **Inbound Requests From Fake Domain IPs**

This checks whether the attacker probed internal systems.

```kql
let fakedomain_ips = PassiveDns
| where domain == "valdoriavotesgov.com"
| distinct ip;
InboundNetworkEvents
| where src_ip in (fakedomain_ips)
```

**Finding:** Inbound traffic observed.

---

## **Threat Actor Browsing Interests**

This reveals what the attacker was researching inside the organization.

```kql
InboundNetworkEvents
| where src_ip in (fakedomain_ips)
| project src_ip, url
```

**Findings:**  
- Group researched: **New hires**  
- Prevention topic: **Election interference**  

---

## **Employee Visits to Fake Domain**

This checks whether any employee visited the phishing site.

```kql
OutboundNetworkEvents
| where url contains "valdoriavotesgov.com"
```

**Finding:** **Yes**, employees visited the phishing domain.

---

## **Identify Employee Who Entered Credentials**

This identifies the employee whose IP submitted credentials.

```kql
Employees
| where ip_addr == "10.10.0.4"
```

**Findings:**  
- Name: **Anderson Snooper**  
- Role: Temp Election Support Staff Lead  

---

## **Threat Actor Login Using Stolen Credentials**

This shows when the attacker logged into Snooper’s account.

```kql
AuthenticationEvents
| where username == "ansnooper"
| where timestamp between(datetime(2024-10-05T10:46:47Z) .. datetime(2024-10-11T10:46:47Z))
```

**Finding:** Login occurred on **2024‑10‑07T15:46:45Z**.

---

## **Snooper Email Conversation on Oct 8**

This identifies who Snooper communicated with.

```kql
Email
| where timestamp between(datetime(2024-10-08T00:00:00Z) .. datetime(2024-10-08T23:59:59Z))
| where sender == "anderson_snooper@valdoriavotes.gov" or recipient == "anderson_snooper@valdoriavotes.gov"
| extend other_person = iff(sender == "anderson_snooper@valdoriavotes.gov", recipient, sender)
| project timestamp, sender, recipient, other_person
| summarize count() by other_person
| order by count_
```

**Finding:** Snooper conversed with **Barry Schmelly**.

---

## **Snooper’s URL Guessing Activity**

This shows the attacker brute‑forcing subdomains.

```kql
InboundNetworkEvents
| where src_ip == "10.10.0.4"
| project timestamp, url, status_code
```

**Findings:**  
- Term at end of URLs: **gpt‑4o**  
- First subdomain guessed: **ai**  
- Nursery rhyme subdomain: **ol-mcdonald-had-a-farm-ai-ai-oh**  
- Basketball subdomain: **allen iverson**  
- First 200 OK: **elections-chatbot**  

---

## **Chatbot Questions About Voting Machines**

```kql
AIPrompts
| where prompt contains "How do I access the voting machines"
```

**Finding:** Conversation ID identified.

---

## **Chatbot Banana Response**

```kql
AIPrompts
| where conversation_id == "94bd6162-1323-402d-bccd-8fceaee5f230"
| where response contains "banana"
```

**Finding:** Bot told them to bring a **flashlight** and a **banana**.

---

## **Voting Machines Not Connected to Internet**

```kql
AIPrompts
| where response contains "internet"
```

**Finding:** Votes are calculated using a **calculator**.

---

## **Vendor Lookup (Election Commissioner Required)**

```kql
Employees
| where role == "Election Commissioner"
```

**Finding:** Employee identified: **Arrack Bobama**.

---

## **Threat Actor Login to Bobama’s Account**

```kql
let fakedomain_ips = PassiveDns
| where domain == "valdoriavotesgov.com"
| distinct ip;
AuthenticationEvents
| where hostname == "QDPG-DESKTOP"
| where src_ip in (fakedomain_ips)
| where result contains "successful"
```

**Findings:**  
- Login date: **2024‑10‑16T00:00:00Z**  
- Source IP: **214.85.104.248**  

---

## **Email Sent to Vendor**

```kql
Email
| where sender == "arrack_bobama@valdoriavotes.gov"
| where subject contains "voting"
```

**Finding:** Email sent to **help@dominosvotingsystems.com**.

---

## **PDF Received From Vendor**

```kql
Email
| where sender == "help@dominosvotingsystems.com"
| where attachments contains ".pdf"
```

**Finding:** Vendor provided a **technical reference PDF**.
