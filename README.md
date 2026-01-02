<div align="center">

  <img src="Assets/Project_banner.jpeg" alt="Aether Framework Logo" width="100%" style="border-radius: 10px;">
  
  <br><br>

  ![Rust](https://img.shields.io/badge/Implant-Rust_1.70+-orange?style=for-the-badge&logo=rust)
  ![Python](https://img.shields.io/badge/Server-Python_3.10+-blue?style=for-the-badge&logo=python)
  ![Security](https://img.shields.io/badge/Encryption-AES256_%2B_ECDH-critical?style=for-the-badge&logo=lock)
  ![Type](https://img.shields.io/badge/Category-Red_Team_Ops-blueviolet?style=for-the-badge&logo=hackthebox)

 <br><br>

  <a href="https://tryhackme.com/p/256AndreiX">
    <img src="https://tryhackme-badges.s3.amazonaws.com/256AndreiX.png" alt="TryHackMe Badge" />
  </a>

</div>

---

## 📜 Executive Summary

**AETHER C2** is a custom engineered Command & Control framework designed to demonstrate advanced offensive security concepts. Unlike standard reverse shells, Aether project operates on a **Full Duplex, End-to-End Encrypted** channel, utilizing direct WinAPI syscalls for evasion and a modular architecture for scalability.

> **⚠️ SECURITY NOTICE:** To prevent misuse by unauthorized actors, the specific decryption routines and injection logic in this public release have been **redacted/abstracted**. This repository serves as a technical portfolio demonstrating architecture, OPSEC logic, and software engineering skills.

---

## 🧠 Technical Architecture


### 🛡️ The Implant (Rust)
* **Memory Safety:** Built in Rust to prevent buffer overflows and ensure stability during operations.
* **Evasion:** * **Jitter:** Randomized sleep intervals to defeat heuristic traffic analysis.
    * **WinHTTP:** Uses direct system calls, bypassing high-level proxy hooks.
* **Identity:** Generates unique, persistent cryptographically secure identities for each agent.

### 📡 The Server (Python)
* **Asynchronous Handling:** Multi-threaded listener capable of handling concurrent beacons.
* **Crypto Protocol (Phantom v6):** * **ECDH (P-256):** Ephemeral Key Exchange per session.
    * **AES-256-GCM:** Authenticated Encryption for all payloads.

---

## 🛠️ Installation & Usage (Educational)

Edit `Implant/main.rs` to set your listener IP:
```rust
const C2_IP_ADDRESS: &str = "127.0.0.1";


cd Implant
cargo build --release



cd Server
python server_apt.py




⚖️ Legal Disclaimer
This software is developed solely for educational purposes and authorized security research. This tool demonstrates how C2 infrastructures work to help Blue Teams develop better detection rules.

Certified Original Code • 2026 • Andrei Costin


