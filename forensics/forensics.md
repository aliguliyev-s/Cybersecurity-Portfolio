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
| **BrowsingHistoryView / hindsight** | Browser history analysis |
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
> 🔍 *Artifact: Registry — `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`*  
> **A:** `[YOUR ANSWER]`

---

**Q: Is Prefetch enabled on the system?**  
> 🔍 *Artifact: Registry — `SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters`*  
> **A:** `[YOUR ANSWER]`

---

### 2. Browser & Email Forensics

**Q: What browser does the user primarily use?**  
> 🔍 *Artifact: Browser profile folders / UserAssist registry key*  
> **A:** `[YOUR ANSWER]`

---

**Q: What webmail service did the user use?**  
> 🔍 *Artifact: Browser history*  
> **A:** `[YOUR ANSWER]`

---

**Q: What email address was the user using?**  
> 🔍 *Artifact: Browser history / cached data*  
> **A:** `[YOUR ANSWER]`

---

**Q: What is the name of the email attachment the user downloaded?**  
> 🔍 *Artifact: Browser downloads history / $MFT*  
> **A:** `[YOUR ANSWER]`

---

**Q: How did the user access espn.com?**  
> 🔍 *Artifact: Browser history — check transition type (typed / link / redirect)*  
> **A:** `[YOUR ANSWER]`

---

**Q: What ransomware family did CISA report on in the article on Bleeping Computer?**  
> 🔍 *Artifact: Browser history — visit to bleepingcomputer.com*  
> **A:** `[YOUR ANSWER]`

---

### 3. Malware & Remote Access

**Q: What tool did the user download?**  
> 🔍 *Artifact: Browser downloads / $MFT*  
> **A:** `[YOUR ANSWER]`

---

**Q: How did the user initially access the site for the remote management tool?**  
> 🔍 *Artifact: Browser history — check referrer / transition type*  
> **A:** `[YOUR ANSWER]`

---

**Q: What executable was used to download the C2 beacon?**  
> 🔍 *Artifact: Prefetch / Event Logs / $MFT*  
> **A:** `[YOUR ANSWER]`

---

**Q: What was the name of the malware that was restored from quarantine?**  
> 🔍 *Artifact: Windows Defender logs / Event Log*  
> **A:** `[YOUR ANSWER]`

---

### 4. C2 & Network Activity

**Q: Was a command and control beacon established?**  
> **A:** `[YES / NO]`

---

**Q: What is the name of the beacon?**  
> 🔍 *Artifact: Prefetch / $MFT / Event Logs*  
> **A:** `[YOUR ANSWER]`

---

**Q: What IP address was FLAG734 downloaded from?**  
> 🔍 *Artifact: Browser history / PowerShell logs / $MFT*  
> **A:** `[YOUR ANSWER]`

---

**Q: What is the file path for where FLAG734 was downloaded to?**  
> 🔍 *Artifact: $MFT / Browser downloads*  
> **A:** `[YOUR ANSWER]`

---

**Q: What port number did the reverse shell use?**  
> 🔍 *Artifact: PowerShell script content / Event Logs*  
> **A:** `[YOUR ANSWER]`

---

**Q: What is the IP address for raw.githubusercontent.com?**  
> 🔍 *Artifact: DNS cache / hosts file / PowerShell logs*  
> **A:** `[YOUR ANSWER]`

---

### 5. Persistence Mechanism

**Q: Is there a persistence mechanism?**  
> **A:** `[YES / NO]`

---

**Q: If yes, what is the flag for the persistence mechanism?**  
> 🔍 *Artifact: Registry Run keys — `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run` / Scheduled Tasks*  
> **A:** `[YOUR ANSWER]`

---

### 6. Enumeration Commands

**Q: What enumeration command was executed at 2024-05-15 12:45:21.857 (UTC)? [Command 1]**  
> 🔍 *Artifact: Prefetch (cmd.exe or powershell.exe) / Event Log 4688*  
> **A:** `[YOUR ANSWER]`

---

**Q: What enumeration command was executed at 2024-05-15 12:45:21.857 (UTC)? [Command 2]**  
> 🔍 *Artifact: Prefetch / Event Log 4688*  
> **A:** `[YOUR ANSWER]`

---

**Q: What enumeration command was executed at 2024-05-15 12:45:40.962 (UTC)?**  
> 🔍 *Artifact: Prefetch / Event Log 4688*  
> **A:** `[YOUR ANSWER]`

---

### 7. CTF Flags

**Q: What was the flag placed in Downloads at 2024-05-15 12:36:40.830 (UTC)?**  
> 🔍 *Artifact: $MFT → sort by Created timestamp*  
> **A:** `[YOUR ANSWER]`

---

**Q: What was the flag downloaded to Downloads at 2024-05-15 12:39:01.615 (UTC)?**  
> 🔍 *Artifact: $MFT / Browser downloads*  
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

## Screenshots

> 📁 Place your screenshots in `./screenshots/` and reference them below.

```
screenshots/
├── 01-kape-collection-structure.png
├── 02-browser-history-webmail.png
├── 03-downloads-remote-tool.png
├── 04-mft-flags-timeline.png
├── 05-persistence-registry-key.png
├── 06-c2-beacon-prefetch.png
└── 07-enumeration-commands-eventlog.png
```

**Browser history showing webmail access:**  
![Browser history](./screenshots/02-browser-history-webmail.png)

**$MFT — Flag file timestamps:**  
![MFT timeline](./screenshots/04-mft-flags-timeline.png)

**Persistence — Registry Run key:**  
![Registry persistence](./screenshots/05-persistence-registry-key.png)

*(Add screenshots as you find evidence — they are the most important part!)*

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
