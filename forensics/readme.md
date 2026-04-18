# 🔍 Case 01 — Geek Squad Phishing → Remote Access → C2 Compromise

**Date of Incident:** 2024-05-15  
**Type:** Phishing / Tech Support Scam / Remote Access Trojan / C2 Beacon  
**Collection Method:** KAPE Triage  
**Investigator:** *Samir Aliguliyev*  
**Status:** ✅ Complete

---

## 📋 Table of Contents

1. [Scenario](#scenario)
2. [Investigation Methodology](#investigation-methodology)
3. [Tools Used](#tools-used)
4. [Timeline of Events](#timeline-of-events)
5. [Findings — Q&A](#findings--qa)
   - [User & System Profile](#1-user--system-profile)
   - [Browser & Email Forensics](#2-browser--email-forensics)
   - [Malware & Remote Access](#3-malware--remote-access)
   - [C2 & Network Activity](#4-c2--network-activity)
   - [Persistence Mechanism](#5-persistence-mechanism)
   - [Enumeration Commands](#6-enumeration-commands)
   - [CTF Flags](#7-ctf-flags)
6. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
7. [Screenshots](#screenshots)
8. [Lessons Learned](#lessons-learned)

---

## Scenario

A user self-reported receiving a suspicious email on **15 May 2024** claiming she was being charged for a **Geek Squad subscription renewal**. She never had such a subscription.

The email warned she had 24 hours to cancel. She called the listed number and was instructed to:
1. Visit a website
2. Download software granting remote access to her computer — supposedly to "remove Geek Squad access software"

She complied. ~30–45 minutes later, a co-worker urged her to report it to the SOC immediately.

**SOC Response:** System was taken offline and a triage collection was performed using **KAPE**. The user was **not connected to VPN** during the event — no SIEM data or PCAP available. Investigation is **artifact-only**.

---

## Investigation Methodology

```
KAPE Collection
      │
      ├── Browser Artifacts     → Chrome/Edge/Firefox history, downloads, cache
      ├── Registry Hives        → NTUSER.DAT, SOFTWARE, SYSTEM
      ├── Prefetch Files        → Execution evidence
      ├── $MFT / File System    → File creation/modification timestamps
      ├── Event Logs            → Windows Security/System/Application logs
      └── Scheduled Tasks / Run Keys → Persistence mechanisms
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| **KAPE** | Triage collection |
| **Registry Explorer** | Parse registry hives (NTUSER.DAT, SOFTWARE) |
| **MFTECmd** | Parse $MFT for file timeline |
| **LECmd** | Parse LNK / shortcut files |
| **PECmd** | Parse Prefetch files |
| **BrowsingHistoryView** | Browser history analysis |
| **Hindsight** | Chrome/Edge browser artifact analysis |
| **EZViewer** | View parsed artifact files (CSV, JSON) |
| **Timeline Explorer** | Visualize and filter MFT/event timelines |
| **Event Log Explorer** | Windows event log analysis |

---

## Timeline of Events

| Time (UTC) | Event |
|------------|-------|
| ~Morning | User receives phishing email (Geek Squad renewal) |
| *TBD* | User calls number from email |
| *TBD* | User visits remote access tool website |
| *TBD* | Remote access tool downloaded & executed |
| *TBD* | Attacker gains remote access |
| 2024-05-15 12:36:40 | FLAG planted in Downloads folder |
| 2024-05-15 12:39:01 | Second file downloaded to Downloads folder |
| 2024-05-15 12:45:21 | Enumeration command #1 executed |
| 2024-05-15 12:45:21 | Enumeration command #2 executed |
| 2024-05-15 12:45:40 | Enumeration command #3 executed |
| *TBD* | C2 beacon established |
| *TBD* | Malware restored from AV quarantine |
| *TBD* | User reports to co-worker → SOC alerted |
| *TBD* | System taken offline |

---

## Findings — Q&A

### 1. User & System Profile

**Q: What user profile was used during this event?**
> 🔍 *Artifact: Registry — ProfileList*
> **A: Vickey**

![ProfileList showing Vickey user profile](./screenshots/Screenshot_1.png)

---

### 2. Browser & Email Forensics

**Q: What browser does the user primarily use?**  
> **A:** `Google Chrome`

![ProfileList showing Vickey user profile](./screenshots/Screenshot_2.png)

---

**Q: What webmail service did the user use?**  
> 🔍 *Artifact: Browser history*  
> **A:** `Gmail`

![ProfileList showing Vickey user profile](./screenshots/Screenshot_3.png)

---

**Q: What email address was the user using?**  
> **A:** `8ugz.mail@gmail.com`

![ProfileList showing Vickey user profile](./screenshots/Screenshot_3.png)

---

**Q: What is the name of the email attachment the user downloaded?**  
> 🔍 *Artifact: Browser downloads history*  
> **A:** `new.zip`

![ProfileList showing Vickey user profile](./screenshots/Screenshot_4.png)
![ProfileList showing Vickey user profile](./screenshots/Screenshot_5.png)

---

**Q: How did the user access espn.com?**  
> 🔍 *Artifact: Browser history — check transition type (typed / link / redirect)*  
> **A:** `[YOUR ANSWER]`

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|----|---------|
| Initial Access | Phishing | T1566.002 | Geek Squad email with callback number |
| Execution | User Execution | T1204 | User downloaded & ran remote access tool |
| Command & Control | Remote Access Software | T1219 | Remote access tool installed by attacker |
| Command & Control | Ingress Tool Transfer | T1105 | C2 beacon downloaded via executable |
| Discovery | System Owner/User Discovery | T1033 | Enumeration commands executed |
| Discovery | System Network Config Discovery | T1016 | Enumeration commands executed |
| Persistence | *TBD* | *TBD* | Registry Run key / Scheduled Task |
| Defense Evasion | Restore from Quarantine | T1562 | Malware restored from Defender quarantine |

---

## Lessons Learned

### 🔴 Attacker Techniques Observed
- **Tech Support Scam** is a classic social engineering vector — urgency + fear drives victim compliance
- Attacker used legitimate remote access software to avoid initial AV detection
- C2 beacon was downloaded and executed **after** gaining initial access via the legitimate RAT
- Malware was **restored from AV quarantine** — attacker had enough access to interact with Defender

### 🔵 Defensive Recommendations
- Block unknown remote access tools at endpoint (application allowlisting)
- Alert on AV quarantine restore events (Event ID 1009 / Defender logs)
- Require VPN for all corporate endpoints — would have enabled SIEM visibility
- User awareness training for callback phishing (vishing)

### 🟡 Forensic Notes
- KAPE triage was effective even without network telemetry
- $MFT timestamps were critical for establishing the attack timeline
- Prefetch files confirmed execution of tools that left no other trace
