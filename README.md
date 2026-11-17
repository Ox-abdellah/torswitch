<div align="center">

#  TorSwitch v2.0

**Transparent Tor proxy toggle and system-wide anonymity manager for Kali / Debian systems.**

[![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Kali%20%2F%20Debian-orange.svg)](https://www.kali.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## 📌 About The Project

**TorSwitch** is an advanced Python tool built for Kali / Debian systems. It turns your entire system into a **Transparent Tor Proxy**, routing all system TCP traffic and DNS requests securely through the Tor network with a single command.

## 🚀 Features

* **Transparent Routing:** Forces all system TCP and DNS traffic through Tor automatically via `iptables`.
* **Kill Switch Protection:** Blocks non-Tor traffic and rejects `IPv6` requests to prevent identity leaks if the connection drops.
* **Interactive Live Dashboard (`status`):** Real-time monitoring of your protection state, public IP, exit country, active Tor circuits, traffic stats, and uptime.
* **Quick Identity Switching (`newnym`):** Request a new Tor identity and exit node directly from the command line or dashboard.
* **Self-Healing & Doctor:** Automatically checks dependencies (`tor`, `iptables`, `ip6tables`), fixes common configuration conflicts, and includes a full system health check (`torswitch doctor`).
* **Safe & Reversible:** Automatically backs up your firewall rules and configuration files before making changes, with a dedicated emergency recovery mode (`torswitch recover`).

## 📦 Installation

1. Clone the repository:
```bash
git clone https://github.com/Ox-abdellah/torswitch.git
cd torswitch
```

2. Run the install command with root privileges:
```bash
sudo python3 torswitch_v2.py install
```
*(This copies the script to `/usr/local/bin/torswitch` and sets up the necessary execution links).*

## 📖 Usage Guide

All commands require `sudo` privileges:

* **Enable Tor routing system-wide:**
```bash
sudo torswitch on
```

* **Disable Tor and restore normal network:**
```bash
sudo torswitch off
```

* **Open the live interactive dashboard:**
```bash
sudo torswitch status
```
*(Inside the dashboard: press `1` for New Identity, `2` for Help, `3` for Recover, or `0` to Exit).*

* **Request a new Tor identity (New IP/Circuit):**
```bash
sudo torswitch newnym
```

* **Run a full system health check:**
```bash
sudo torswitch doctor
```

* **Emergency recovery mode (if internet connection gets stuck):**
```bash
sudo torswitch recover
```

## ⚙️ Requirements

* Debian-based Linux distribution (**Kali Linux**, **Debian**, **Ubuntu**).
* `tor` and `iptables` (automatically installed by the script if missing).



Developed by **Ox-abdellah**.

