# Threat Hunt Report: Unauthorized Tor Browser Usage
### Log(N) Pacific | Security Operations

**Analyst:** Symone-Marie Priester
**Date:** April 13, 2026
**Platform:** Microsoft Defender for Endpoint (MDE)
**Query Language:** Kusto Query Language (KQL)
**Device:** win11-tor-symon
**User:** Symone

---

## Objective

Investigate potential unauthorized Tor Browser activity on endpoint `win11-tor-symon` after suspicious file events were identified during routine threat hunting in the DeviceFileEvents table.

---

## Chronological Timeline of Events

### 9:26:17 AM - Tor Browser Installer Downloaded

The user "symone" downloaded the Tor Browser portable installer (`tor-browser-windows-x86_64-portable-15.0.9.exe`) to their Downloads folder. File events indicate the installer was present at `C:\Users\Symone\Downloads\`.

**File Hash (SHA256):** `2f7dea5cb68c538ed0cf257b5fe3f0e6dd4cdb82d065dd099c82790e2b101622`

**KQL Query Used:**
```kql
DeviceFileEvents
| where FileName startswith "tor"
| where InitiatingProcessAccountName == "symone"
| where DeviceName == "win11-tor-symon"
| where Timestamp >= datetime(2026-04-13T16:26:17.2611803Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

---

### 9:26:21 AM - Silent Installation Executed

The user executed the Tor Browser installer from the Downloads folder. Process creation logs show the installer was run with the `/S` flag, indicating a silent (unattended) installation. This bypasses the standard installation wizard and suppresses all user prompts.

| Field | Value |
|-------|-------|
| Process | `tor-browser-windows-x86_64-portable-15.0.9.exe` |
| Path | `C:\Users\Symone\Downloads\` |
| Command | `tor-browser-windows-x86_64-portable-15.0.9.exe /S` |
| SHA256 | `2f7dea5cb68c538ed0cf257b5fe3f0e6dd4cdb82d065dd099c82790e2b101622` |

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "win11-tor-symon"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.9.exe"
| project DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

---

### 9:36:29 AM - Tor Browser Files Extracted to Desktop

The installation process extracted the full Tor Browser directory structure to `C:\Users\Symone\Desktop\Tor Browser\`. Key files created include:

| Timestamp | File | Path |
|-----------|------|------|
| 9:36:29 AM | `tor.txt` | `...\Tor Browser\Browser\TorBrowser\Docs\Licenses\tor.txt` |
| 9:36:29 AM | `Torbutton.txt` | `...\Tor Browser\Browser\TorBrowser\Docs\Licenses\Torbutton.txt` |
| 9:36:29 AM | `Tor-Launcher.txt` | `...\Tor Browser\Browser\TorBrowser\Docs\Licenses\Tor-Launcher.txt` |
| 9:36:30 AM | `tor.exe` | `...\Tor Browser\Browser\TorBrowser\Tor\tor.exe` |
| 9:36:35 AM | `Tor Browser.lnk` | `...\Desktop\Tor Browser\Tor Browser.lnk` |

**tor.exe Hash (SHA256):** `176c9cb6131fb49fa5e982e823766947e5ce673177c7fff339f5e7a9d330ebf3`

---

### 9:41:24 AM - Tor Browser Launched

The user launched the Tor Browser by executing `firefox.exe` from the Desktop installation path. Two parent `firefox.exe` processes were created simultaneously, followed by `tor.exe` spawning at 9:41:34 AM and multiple child `firefox.exe` content processes (tabs, GPU, RDD, utility) spawning between 9:41:32 AM and 9:41:35 AM.

**tor.exe command line:**
```
tor.exe -f "C:\Users\Symone\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor\torrc"
  DataDirectory "C:\Users\Symone\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor"
  +__ControlPort 127.0.0.1:9151
  +__SocksPort "127.0.0.1:9150 ExtendedErrors IPv6Traffic PreferIPv6 KeepAliveIsolateSOCKSAuth"
  __OwningControllerProcess 9828
  DisableNetwork 1
```

This confirms the Tor SOCKS proxy was configured to listen on `127.0.0.1:9150` with a control port on `127.0.0.1:9151`.

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "win11-tor-symon"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```

---

### 9:41:35 AM - Local Tor Control Connection Established

The Tor Browser's `firefox.exe` process successfully connected to the local Tor control port at `127.0.0.1:9151`. An initial SOCKS proxy connection attempt to `127.0.0.1:9150` failed at 9:42:05 AM while the Tor circuit was still being established.

| Timestamp | Action | Remote IP | Port | Process |
|-----------|--------|-----------|------|---------|
| 9:41:35 AM | ConnectionSuccess | 127.0.0.1 | 9151 | firefox.exe |
| 9:42:05 AM | ConnectionFailed | 127.0.0.1 | 9150 | firefox.exe |

---

### 9:43:33 AM - Tor Network Connection Established (External)

The `tor.exe` process successfully connected to an external Tor relay node at `185.244.129.163` on port 9001. This is the first confirmed outbound connection to the Tor network. A second connection was made to the same IP and associated with the URL `https://www.ps7dhii4lsjinvhla.com`, indicating the user was actively browsing through the Tor network.

| Timestamp | Action | Remote IP | Port | URL | Process |
|-----------|--------|-----------|------|-----|---------|
| 9:43:33 AM | ConnectionSuccess | 185.244.129.163 | 9001 | | tor.exe |
| 9:43:34 AM | ConnectionAcknowledged | 185.244.129.163 | 9001 | | |
| 9:43:34 AM | ConnectionSuccess | 185.244.129.163 | 9001 | `https://www.ps7dhii4lsjinvhla.com` | tor.exe |

---

### 9:44:03 AM - Additional Tor Relay Connection

A second Tor relay node was contacted at `51.89.242.29` on port 9001, with an associated URL of `https://www.ezqjon7eux4clx.com`. This indicates active multi-hop Tor circuit usage for browsing.

| Timestamp | Action | Remote IP | Port | URL | Process |
|-----------|--------|-----------|------|-----|---------|
| 9:44:03 AM | ConnectionSuccess | 51.89.242.29 | 9001 | | tor.exe |
| 9:44:03 AM | ConnectionAcknowledged | 51.89.242.29 | 9001 | | |
| 9:44:03 AM | ConnectionSuccess | 51.89.242.29 | 9001 | `https://www.ezqjon7eux4clx.com` | tor.exe |

---

### 9:44:08 AM - SOCKS Proxy Connection Successful

The `firefox.exe` process successfully connected to the local Tor SOCKS proxy at `127.0.0.1:9150`, confirming the Tor circuit was now fully operational and the browser was actively routing traffic through the Tor network.

| Timestamp | Action | Remote IP | Port | Process |
|-----------|--------|-----------|------|---------|
| 9:44:08 AM | ConnectionSuccess | 127.0.0.1 | 9150 | firefox.exe |

**KQL Query Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "win11-tor-symon"
| where RemotePort in (9001, 9030, 9050, 9051, 9150, 9151)
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
```

---

### 9:44:09 AM - 9:47:35 AM - Active Tor Browsing Session

Between 9:44:09 AM and 9:47:35 AM, multiple `firefox.exe` content processes (tabs) were created from the Desktop Tor Browser installation, indicating sustained browsing activity through the Tor network. A total of 20 tab processes were spawned during this session.

---

### 10:03:07 AM - Suspicious File Created

The user created a file named `tor-shopping-list.txt` on the Desktop, followed by a recent file shortcut (`tor-shopping-list.lnk`) at 10:03:08 AM. The file name suggests the user was compiling a list related to purchases made or intended to be made over the Tor network.

| Timestamp | File | Path | SHA256 |
|-----------|------|------|--------|
| 10:03:07 AM | `tor-shopping-list.txt` | `C:\Users\Symone\Desktop\` | `380e259525262b036047be5e448e7e2cb7d0e0894b144b78f8a4a11252e32423` |
| 10:03:08 AM | `tor-shopping-list.lnk` | `...\Windows\Recent\` | `3f0372227508c6f1072ac20b671dec1aa941916e25a4d510a002af75d3a87bb4` |

---

## Evidence of Prior Tor Usage (Downloads Folder)

Log analysis also revealed an earlier Tor Browser session originating from the Downloads folder (`C:\Users\Symone\Downloads\Tor Browser\`) before the user relocated the installation to the Desktop. At 8:53:17 AM, `firefox.exe` was launched from the Downloads path, `tor.exe` spawned at 8:53:31 AM, and a control port connection to `127.0.0.1:9151` succeeded at 8:53:32 AM. A SOCKS proxy connection attempt to `127.0.0.1:9150` failed at 8:54:02 AM. Multiple tab processes were created through 8:53:36 AM. This indicates the user initially ran Tor from the Downloads folder, then moved the installation to the Desktop and launched it again.

---

## Indicators of Compromise

| Indicator | Type | Context |
|-----------|------|---------|
| `tor-browser-windows-x86_64-portable-15.0.9.exe` | File | Tor Browser installer |
| `2f7dea5cb68c538ed0cf257b5fe3f0e6dd4cdb82d065dd099c82790e2b101622` | SHA256 | Installer hash |
| `176c9cb6131fb49fa5e982e823766947e5ce673177c7fff339f5e7a9d330ebf3` | SHA256 | tor.exe hash |
| `ef09a491d65b51f1f304145f6914a6682acd5c6226d0a241361730881134de35` | SHA256 | firefox.exe (Tor Browser) hash |
| `185.244.129.163` | IP | Tor relay node (port 9001) |
| `51.89.242.29` | IP | Tor relay node (port 9001) |
| `tor-shopping-list.txt` | File | User-created file on Desktop |
| `380e259525262b036047be5e448e7e2cb7d0e0894b144b78f8a4a11252e32423` | SHA256 | tor-shopping-list.txt hash |

---

## Summary

On April 13, 2026, the user "symone" on device `win11-tor-symon` downloaded, silently installed, and actively used the Tor Browser to route network traffic through the Tor anonymity network. The user initially ran the browser from the Downloads folder at approximately 8:53 AM, then relocated the installation to the Desktop and launched a second session at 9:41 AM. During the second session, `tor.exe` successfully established outbound connections to two external Tor relay nodes (`185.244.129.163` and `51.89.242.29`) on port 9001, confirming active Tor circuit usage. The Tor Browser's SOCKS proxy became fully operational at 9:44 AM, and the user sustained an active browsing session with approximately 20 browser tabs open through 9:47 AM. At 10:03 AM, the user created a file named `tor-shopping-list.txt` on the Desktop, suggesting potential procurement activity conducted over the Tor network. The use of the `/S` silent installation flag and the relocation of the browser from Downloads to the Desktop may indicate an attempt to reduce visibility of the installation process.

---

## Author

**Symone-Marie Priester** | Cybersecurity Analyst, Log(N) Pacific
- LinkedIn: [linkedin.com/in/symone-mariepriester](https://linkedin.com/in/symone-mariepriester)
- GitHub: [github.com/Symone-Marie](https://github.com/Symone-Marie)
