# Website Defacement | Po1s0n1vy Group vs imreallynotbatman.com

**Date of Incident:** Lab-based scenario (Splunk BOTS v1 dataset)

**Type:** Web Application Attack / Vulnerability Scanning / Website Defacement

**Collection Method:** Web/Stream logs → Splunk SIEM

**Investigator:** *Samir Aliguliyev*

**Status:** 🟡 In Progress

---

## 📋 Table of Contents

1. [Scenario](#scenario)
2. [Investigation Methodology](#investigation-methodology)
3. [Tools Used](#tools-used)
4. [Findings - Q&A](#findings---qa)
5. [Lessons Learned](#lessons-learned)

---

## Scenario

Today is Alice's first day at the Wayne Enterprises' Security Operations Center. Lucius sits Alice down and gives her first assignment: a memo from the **Gotham City Police Department (GCPD)**.

GCPD found evidence online ([pastebin.com/Gw6dWjS9](http://pastebin.com/Gw6dWjS9)) that the website **www.imreallynotbatman.com** - hosted on Wayne Enterprises' IP address space - has been compromised. The threat actor group behind this, known as **Po1s0n1vy**, has multiple objectives, but a key part of their modus operandi is to **deface websites** in order to embarrass their victims.

Lucius has asked Alice to determine if www.imreallynotbatman.com (the personal blog of Wayne Enterprises' CEO) was really compromised.

**Investigation scope:** Web traffic logs (`stream:http`) analyzed via Splunk SIEM.

## Investigation Methodology

| Data Source | Type | Purpose |
|---|---|---|
| `stream:http` | Web traffic | Identify scanning activity, user-agents, HTTP requests to the site |

## Tools Used

| Tool | Purpose |
|------|---------|
| **Splunk** | SIEM platform - log ingestion, search & correlation (SPL queries) |
| **Splunk Stream** | Network traffic capture parsed into HTTP/DNS events |

---

## Findings - Q&A

### 1. Reconnaissance / Vulnerability Scanning

**Q: What is the likely IPv4 address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?**
> 🔍 *Artifact: stream:http - http_user_agent field*

```spl
index=botsv1 sourcetype=stream:http site="imreallynotbatman.com"
| stats count by http_user_agent
| sort + count
```

Sorting the results by ascending count surfaced a large number of rare, non-browser `http_user_agent` values - many of them containing malformed strings typical of automated vulnerability scanning (SQL injection payloads, command injection attempts, blind time-based SQLi tests).

The common marker across nearly all of these entries was the string **`acunetix_wvs_security_test`**, which is a known signature of the **Acunetix Web Vulnerability Scanner (WVS)** injecting test payloads directly into the User-Agent header while probing for injection vulnerabilities.

To pinpoint the source, we filtered on this signature and pivoted to the source IP:

```spl
index=botsv1 sourcetype=stream:http site="imreallynotbatman.com"  http_user_agent="\";print(md5(acunetix_wvs_security_test));$a=\""
```

**A:** `40.80.148.42`

![User-Agent field analysis](./screenshots/Screenshot_1.png)
![Source IP identified from Acunetix signature](./screenshots/Screenshot_2.png)

---

<!-- Следующие вопросы будут добавлены сюда -->

---
