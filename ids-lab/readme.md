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

| #  | Scenario                                                      | Status         |
|----|---------------------------------------------------------------|----------------|
| 01 | Nmap Reconnaissance  | ✅ Complete |
| 02 | SSH Brute-Force  | ✅ Complete |
| 03 | Malware C2 traffic  | In progress |

---

### Scenario 01 - Nmap Reconnaissance

**Goal:** detect port scanning and service version detection activity
from the attacker host.

**Attacker host:** Ubuntu Desktop (192.168.56.102)

**Attack commands:**

```bash
sudo nmap -sS -p- 192.168.56.101
```

**Before - no detection**

![](./screenshots/Screenshot_2.png)

The screenshot below shows the initial state before any custom rule
was in place. The attacker (192.168.56.102) launches a
TCP SYN scan against the sensor.
tshark clearly captures the SYN packets hitting the target across
multiple ports, confirming the scan traffic is present on the wire -
but Suricata's fast.log stays empty. At this point Suricata had no
signature capable of matching this specific behavior, so the scan went
completely undetected despite being visible at the packet level.

**After - custom detection rule**

![](./screenshots/Screenshot_3.png)

To close this gap, a custom rule was written to detect SYN-based port
scanning based on connection rate rather than a single packet:

```bash
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Possible Nmap SYN Portscan"; tcp.flags:S; detection_filter: track by_src, count 30, seconds 5; sid:100001; rev:1;)
```

The rule triggers when a single source sends 30 or more SYN packets
within a 5-second window toward the protected network
($HOME_NET). Using detection_filter instead of alerting on every
single SYN packet reduces noise and avoids flooding the log with one
alert per port, while still reliably catching the scan as a pattern.
After reloading Suricata and re-running the same *nmap -sS -p-*
command, fast.log now shows the alert firing in real time,
confirming the detection gap identified before has been
closed.


### Scenario 02 - SSH Brute Force

**Goal:** detect repeated failed SSH authentication attempts against
the sensor, indicating a brute-force attack.

**Attacker host:** Ubuntu Desktop (192.168.56.102)

**Attack commands:**

```bash
hydra -t 4 -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.101
```

**Before - no detection**

![](./screenshots/Screenshot_4.png)

The screenshot below shows the initial state before any custom rule
was in place. The attacker (192.168.56.102) launches a Hydra
brute-force attack against the SSH service on the sensor, rapidly
attempting many username/password combinations. tshark captures the
repeated TCP connections to port 22, confirming the brute-force
traffic is present on the wire - but Suricata's fast.log stays empty.
At this point Suricata had no signature capable of matching this
specific behavior, so the attack went completely undetected despite
being visible at the packet level.

**After - custom detection rule**

![](./screenshots/Screenshot_5.png)

To close this gap, a custom rule was written to detect SSH
brute-forcing based on connection rate to port 22 rather than
inspecting individual packets:

```bash
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg: "Possible SSH Brute Force"; app-layer-protocol: ssh; detection_filter: track by_src, count 10, seconds 60; sid: 100002; rev: 1;)
```

The rule triggers when a single source sends 10 or more new
connection attempts to port 22 within a 60-second window toward the
protected network ($HOME_NET). Using detection_filter instead of
alerting on every single connection reduces noise from normal login
retries and avoids flooding the log with one alert per attempt, while
still reliably catching the sustained brute-force pattern. After
reloading Suricata and re-running the same *hydra* command, fast.log
now shows the alert firing in real time, confirming the detection gap
identified before has been closed.
