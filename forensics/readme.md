# 🔍 Case 01 — Geek Squad Phishing → Remote Access → C2 Compromise

**Date of Incident:** 2024-05-15  
**Type:** Phishing / Tech Support Scam / Remote Access Trojan / C2 Beacon  
**Collection Method:** KAPE Triage  
**Investigator:** *Samir Aliguliyev*  
**Status:** ✅ Complete

## Scenario

A user self-reported receiving a suspicious email on **15 May 2024** claiming she was being charged for a **Geek Squad subscription renewal**. She never had such a subscription.

The email warned she had 24 hours to cancel. She called the listed number and was instructed to:
1. Visit a website
2. Download software granting remote access to her computer — supposedly to "remove Geek Squad access software"

She complied. ~30–45 minutes later, a co-worker urged her to report it to the SOC immediately.

**SOC Response:** System was taken offline and a triage collection was performed using **KAPE**. The user was **not connected to VPN** during the event — no SIEM data or PCAP available. Investigation is **artifact-only**.

---

## Investigation Methodology

---

## Tools Used

| Tool | Purpose |
|------|---------|
| **KAPE** | Triage collection |
| **Registry Explorer** | Parse registry hives (NTUSER.DAT, SOFTWARE) |
| **MFTECmd** | Parse $MFT for file timeline |
| **BrowsingHistoryView** | Browser history analysis |
| **Hindsight** | Chrome/Edge browser artifact analysis |
| **EZViewer** | View parsed artifact files (CSV, JSON) |
| **Timeline Explorer** | Visualize and filter MFT/event timelines |
| **Event Log Explorer** | Windows event log analysis |
shellbags explorer
regripper

---

## Findings — Q&A

### 1. User & System Profile

**Q: What user profile was used during this event?**
> 🔍 *Artifact: Registry — ProfileList*
> **A: Vickey**

![](./screenshots/Screenshot_1.png)

---

### 2. Browser & Email Forensics

**Q: What browser does the user primarily use?**  
> **A:** `Google Chrome`

![](./screenshots/Screenshot_2.png)

---

**Q: What webmail service did the user use?**  
> 🔍 *Artifact: Browser history*  
> **A:** `Gmail`

![](./screenshots/Screenshot_3.png)

---

**Q: What email address was the user using?**  
> **A:** `8ugz.mail@gmail.com`

![](./screenshots/Screenshot_3.png)

---

**Q: What is the name of the email attachment the user downloaded?**  
> 🔍 *Artifact: Browser downloads history*  
> **A:** `new.zip`

![](./screenshots/Screenshot_4.png)
![](./screenshots/Screenshot_5.png)

---

**Q: What tool did the user download?**
**A:** `Teamviewer`

![](./screenshots/Screenshot_6.png)
![](./screenshots/Screenshot_7.png)

---

**Q: How did the user initially access the site for remote management tool?**
**A:** `Typed URL`

![](./screenshots/Screenshot_8.png)

---

**Q: How did the user access espn.com?**
**A:** `Link`

![](./screenshots/Screenshot_9.png)

---

**Q: What ransomware family did CISA report on in the article on Bleeping Computer?**
**A:** `Black Basta`

![](./screenshots/Screenshot_10.png)

---

**Q: Is there a persistence mechanism?**
**A:** `Yes`

---

**Q: If yes, what is the flag for the persistence mechanism?**
> 🔍 *Artifact: Persistence Run key in Registry Explorer*  
**A:** `FLAG061`

![](./screenshots/Screenshot_11.png)

---

**Q: Is prefetch enabled on the system?**
**A:** `Yes`

![](./screenshots/Screenshot_12.png)

---

**Q: Was command and control beacon established?**
> 🔍 *Artifact: C2 beacon network connection in Sysmon logs*  
**A:** `Yes`

---

**Q: If C2 was established, what is the name of the beacon?**
**A:** `COURAGEOUS_DRAGSTER.exe`

![](./screenshots/Screenshot_13.png)

---

**Q: What was the flag placed in the Downloads folder at 2024-05-15 12:36:40.830 (UTC)?**
**A:** `FLAG007`

![](./screenshots/Screenshot_14.png)

---

**Q: What was the flag downloaded to the Downloads folder at 2024-05-15 12:39:01.615 (UTC)?**
**A:** `FLAG714`

![](./screenshots/Screenshot_15.png)

---

**Q: What enumeration command was executed at 2024-05-15 12:45:21.857 (UTC)? [Command 1]**
**A:** `whoami`

![](./screenshots/Screenshot_16.png)

---

**Q: What enumeration command was executed at 2024-05-15 12:45:40.962 (UTC)? [Command 2]**
**A:** `ipconfig`

![](./screenshots/Screenshot_17.png)

---

**Q: What executable was used to download the C2 beacon?**
**A:** `certutil.exe`

![](./screenshots/Screenshot_18.png)

---

**Q: What IP address was FLAG734 downloaded from?**
**A:** `192.168.1.198`

![](./screenshots/Screenshot_19.png)

---

**Q: What is the file path for where FLAG734 was downloaded to?**
**A:** `C:\Windows\Temp`

![](./screenshots/Screenshot_20.png)

---

**Q: What port number did the reverse shell use?**
**A:** `1337`

![](./screenshots/Screenshot_21.png)

---

**Q: What is the IP address for raw.githubusercontent.com?**
**A:** `185.199.108.133`

![](./screenshots/Screenshot_22.png)
![](./screenshots/Screenshot_23.png)

---

**Q: What was the name of the malware that was restored from quarantine?**
**A:** `VirTool:Win32/Sliver.D!MTB`

![](./screenshots/Screenshot_24.png)

---

**Q: What time was TeamViewer executed?**
> 🔍 *Artifact: TeamViewer execution time in UserAssist*  
**A:** `2024-05-15 12:32:11`

![](./screenshots/Screenshot_25.png)

---

**Q: What time (in UTC) did the TeamViewer session end?**
**A:** `2024-05-15 12:47:40.553`

![](./screenshots/Screenshot_26.png)

---

**Q: What did the malicious actor disable shortly after making the remote connection?**
**A:** `Microsoft Defender Antivirus Real-time Protection`

![](./screenshots/Screenshot_27.png)

---

**Q: What is the name of the .zip file accessed at 2024-05-15 12:30:10?**
**A:** `new.zip`

![](./screenshots/Screenshot_28.png)

---

**Q: What is the flag in the Temp directory that was last accessed at 2024-05-15 12:43:32?**
**A:** `FLAG099`

![](./screenshots/Screenshot_29.png)

---
