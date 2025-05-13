# Checker – SOC Analyst Offensive Security Script 🛡️

Checker is a modular Bash-based attack simulation script designed for educational use in penetration testing labs and SOC analyst training. It allows the user to select and execute network attacks with real-time logging, clear interface prompts, and customizable inputs.

---

## 📚 Table of Contents
1. [Overview](#overview)
2. [Features](#features)
3. [Prerequisites](#prerequisites)
4. [Tested On](#tested-on)
5. [Usage](#usage)
6. [Script Workflow](#script-workflow)

---

## 🧭 Overview

**Checker** automates the following attack types and analysis steps:

- 🔐 **Hydra SSH Brute Force**  
- 🌐 **Hping3 Denial-of-Service (SYN Flood)**  
- 🕵️ **ARP Spoofing / MITM using arpspoof**  
- 🧪 **Nmap-based target discovery**  
- 📁 **Full output and log storage per session**

Use this script to learn, demo, and document network attack behavior in isolated environments.

---

## ✨ Features

1. **User-Driven Configuration**
   - Network range selection
   - Custom output directory
   - Custom or default credential lists

2. **Nmap Target Discovery**
   - Discovers live hosts and extracts IPs

3. **Three Modular Attacks**
   - Brute Force (Hydra)
   - Denial of Service (Hping3)
   - ARP Spoofing (Arpspoof)

4. **Menu-Driven Execution**
   - Pick attack type and target interactively

5. **Structured Logging**
   - Logs written per attack to organized subfiles

---

## 🔧 Prerequisites

Ensure the following tools are installed:

- `nmap` – host discovery
- `hydra` – brute force attack engine
- `hping3` – packet generator / DoS tester
- `dsniff` – includes `arpspoof`
- Root permissions required

> All tools are available by default in Kali Linux.

---

## 🖥️ Tested On

- ✅ Kali Linux (rolling)
- ✅ Ubuntu 22.04 with manual tool install

---

## 🚀 Usage

```bash
# Make it executable
chmod +x Checker.sh

# Run as root
sudo ./Checker.sh
```

Follow the prompts:
- Enter your network range (e.g., `192.168.1.0/24`)
- Choose the output directory
- Pick credential lists or use defaults
- Select a discovered IP
- Choose the attack type

---

## 🔄 Script Workflow

1. **START**
   - Root check
   - Keyboard setup
   - Optional OS update

2. **INPUT**
   - User defines scan range, logs directory, and credential lists

3. **SCAN**
   - Nmap performs open port discovery and lists live hosts

4. **MENU**
   - Displays targets, lets user choose attack

5. **HYDRA / HPING / ARP**
   - Performs selected attack and saves logs

6. **LOG**
   - Final log review and directory content listing

---

## ⚠️ Disclaimer

This script is intended **strictly for educational use** in isolated or virtual lab environments. Do not run against networks without explicit permission.

---

**Author**: Hadroxx
