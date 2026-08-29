## IDS Lab - Suricata + Zeek + tshark

Home lab for practicing SOC detection skills: identifying
network attacks at different layers - Suricata signatures, Zeek
metadata, and packet-level analysis with tshark. Each scenario is a
real attack run between the lab VMs, followed by alert and log
analysis.

---

## Lab Topology

| Host              | IP              | Role                              |
|-------------------|-----------------|-------------------------------------|
| Windows 11        | 192.168.56.103  | Normal host                         |
| Ubuntu Desktop    | 192.168.56.102  | Attacker                            |
| Ubuntu Server     | 192.168.56.101  | Sensor: Suricata + Zeek + tshark    |

All hosts sit on the same isolated VirtualBox network (host-only /
internal network). Traffic is mirrored through the interface
monitored by Suricata and Zeek.

---

## Tools

| Host              | IP              |
|-------------------|-----------------|
| **Suricata**        | IDS, alert mode  | 
| **Zeek**     | Network log generation  |
| **tshark**     | Packet capture and low-level traffic analysis |
| **nmap**     | attacker-side tool for reconnaissance scenarios |

---

##  Scenarios

| #  | Scenario                                                    | Tools                  | Status         |
|----|---------------------------------------------------------------|--------------------------|----------------|
| 01 | [Nmap Reconnaissance](#scenario-01--nmap-reconnaissance)      | Suricata, Zeek, tshark   | 🟡 In Progress |

---

### Scenario 01 - Nmap Reconnaissance

**Goal:** detect port scanning and service version detection activity
from the attacker host.

**Attacker host:** Ubuntu Desktop (192.168.56.102)

**Attack commands:**

```bash
# TCP SYN scan of all ports
sudo nmap -sS -p- 192.168.56.101

# Service version detection on open ports
sudo nmap -sV 192.168.56.101

# Aggressive scan
sudo nmap -A 192.168.56.101
```
