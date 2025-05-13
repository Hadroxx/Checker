# SOC Analyst Project: Checker 🔍🛡️

## 📌 Overview
**Checker** is a bash-based offensive security automation tool designed as part of a SOC Analyst project. It allows the user to simulate three different types of network attacks in a controlled lab environment. Each action is logged and stored for review, supporting cybersecurity education and demonstration.

## ✨ Features
- ✅ **Root Check & System Prep**  
  Ensures script is executed with root privileges and offers optional Kali Linux update.

- 🖥️ **Input-Driven Setup**  
  User provides network range, output directory, and optional wordlists (fallback to `rockyou.txt` if unspecified).

- 🔎 **Nmap Scanning**  
  Scans a target network and extracts live host IPs.

- 🔐 **Hydra Brute Force Attack**  
  Performs SSH brute force using supplied or default credentials.

- 🌐 **Hping3 Denial of Service**  
  Simulates a TCP SYN flood attack in background execution.

- 🕵️ **ARP Spoofing (MITM)**  
  Enables ARP-based Man-in-the-Middle attack via `arpspoof`.

- 🧭 **Menu-Driven Selection**  
  Interactive menu to choose attack targets and vectors without restarting the script.

- 📁 **Comprehensive Logging**  
  All attacks, IPs, and results are logged with timestamps in structured folders.

---

## ⚙️ Requirements

- **OS**: Kali Linux
- **Tools**:
  - `nmap`
  - `hydra`
  - `hping3`
  - `dsniff` (for `arpspoof`)
- **Privileges**: Must be run as `root`

---

## 🚀 Usage

```bash
./Checker.sh
```

Follow the on-screen prompts to:
- Enter a network range to scan
- Define where to save output
- Select attacks and targets

---

## 📂 Example Output Structure

```
output_directory/
├── nmap_results.txt
├── targets.txt
├── hydra_results.txt
├── dos_results.txt
├── arp_results.txt
├── target.txt
├── gateway.txt
└── logfile.txt
```

---

## 🧠 Educational Purpose

This script is created for **learning and demonstration** in secure, isolated environments (e.g., VMs). It is **not intended for use on public or unauthorized networks.**

---

## 📄 License
This project is distributed for educational use only. Use responsibly.

---

Project created by **Hadroxx**