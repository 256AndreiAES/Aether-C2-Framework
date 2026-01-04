# C2 Architecture Research (Rust/Python)

This repo is a playground for exploring custom C2 TTPs, specifically focusing on how rust implants can bypass common EDR telemetry by staying away from high-level abstractions. 

It's currently a work-in-progress research project. The primary goal was to see how much I could reduce the forensic footprint by building a "homegrown" transport stack.

**Note:** I opted for a custom WinHTTP implementation and an ECDH+AES handshake. It’s definitely not a finished product, but it's more about testing protocol stealth than feature-stuffing.

## Operational Logic & Tradecraft

### Agent (Rust)
Built to be lightweight and avoid the typical "loud" signatures of standard Rust networking crates.

* **Transport & OPSEC:** Direct `WinHTTP.dll` calls via `windows-rs`. I skipped `reqwest` or `hyper` because I wanted to control the IAT (Import Address Table) and avoid unnecessary library hooks. 
* **Key Exchange:** Per-session **ECDH (NIST P-256)**. I'm using HKDF-SHA256 for the session key derivation.
* **Payload Encryption:** **AES-256-GCM**. Every task/response is encrypted in transit.
* **Evasion (Basic):** * Compile-time string obfuscation (`obfstr`) to mess with static analysis.
    * Randomized jitter to break up beaconing patterns (so it doesn't look like a heartbeat on the wire).
    * *Still looking into more advanced memory scanning bypasses; for now, it's pretty baseline.*

### C2 Listener (Python)
A simple async listener. It’s mostly just a "dumb" pipe to validate the protocol right now.

* Manages the ECDH exchange and maintains per-agent key material.
* **Status:** No database persistence or fancy UI yet. I'm just using it to catch beacons and verify the crypto logic doesn't break under load.
* *Probably will rewrite some of this later to handle more concurrent sessions.*

## Project Structure
* `/Implant` — The Rust agent (the core of the research).
* `/Server` — Python controller/listener.
* `/Assets` — Some screenshots.

## Current Limitations
* Redacted thread injection logic in `injector.rs` for public safety.
* No automated persistence modules yet.
* TLS certificate pinning is on the roadmap but not implemented.

---

**Disclaimer:** This project is for educational use and lab environments. Don't be a script kiddie.

<a href="https://tryhackme.com/p/256AndreiX" target="_blank">
  <img src="https://tryhackme-badges.s3.amazonaws.com/256AndreiX.png" alt="TryHackMe Badge" />
</a>
