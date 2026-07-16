# Injection Series Part 4 | Blue Team Labs Online

**Type:** Reverse Engineering
**Investigator:** *Samir Aliguliyev*
**Status:** 🟡 In Progress

---

## Scenario

Reverse engineer the given malware sample and understand its behavior. Any disassembler can be used to complete this challenge.

## Tools Used

| Tool | Purpose |
|------|---------|
| **Ghidra** | Disassembly and decompilation of the sample |

---

## Findings - Q&A

### 1. Initial Process Creation

**Q: What is the process that would be first spawned by the sample? And what is the API used?**

In `Symbol Tree → Imports → KERNEL32.DLL`, the function `CreateProcessA` was found. Following its XREF led to `FUN_00401000`, where the decompiled code shows the actual call:

```c
CreateProcessA((LPCSTR)0x0, "c:\\windows\\syswow64\\notepad.exe", ...);
```

**A:** `notepad.exe, CreateProcessA`

![](./screenshots/Screenshot_1.png)

---

### 2. CreateProcessA Flag

**Q: The value 4 has been pushed as a parameter to this API, what does that denote?**

Matching the pushed parameters against the `CreateProcessA` signature, the value `4` corresponds to the `dwCreationFlags` parameter. Checking Microsoft's documentation, `0x00000004` is `CREATE_SUSPENDED` - the process is created but its main thread is paused before any code runs.

This is an early sign of **process hollowing**: the malware creates a legitimate process in a suspended state so it can later replace its memory with malicious code before it ever executes.

**A:** `CREATE_SUSPENDED`

![](./screenshots/Screenshot_2.png)

---
....
