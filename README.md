# WinSentry (🛡️)

> **High-Velocity Windows Storage Reclamation & Endpoint Security Auditing Engine**

WinSentry is a memory-safe, multi-threaded systems desktop utility built in Rust that unifies two traditionally siloed domains: **high-throughput storage telemetry** and **deep endpoint security auditing**. 

Conventional disk utilities focus exclusively on byte-level capacity or duplicate elimination while remaining blind to access control misconfigurations, dormant malware, and deceptive binaries. Conversely, security scanners evaluate threat indicators and privilege escalation vectors without accounting for physical cluster allocation, duplicate bloat, or safe space reclamation. WinSentry bridges these domains by interfacing directly with the Windows NT kernel, the Win32 security subsystem, and modern endpoint security pipelines.

---

## 🏛️ Architectural Overview

WinSentry is structured as a decoupled four-stage asynchronous pipeline:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   STAGE 1: KERNEL TRAVERSAL ENGINE                     │
│  • Win32 FindFirstFileExW (FindExInfoBasic + FIND_FIRST_EX_LARGE_FETCH)│
│  • Extended-path '\\?\' prefix (supports paths up to 32,767 chars)     │
│  • Reparse cycle guard (symlinks, directory junctions, volume mounts)  │
│  • Cloud recall protection (OneDrive/iCloud offline placeholders)      │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │
                 ┌───────────────────┴───────────────────┐
                 ▼                                       ▼
┌─────────────────────────────────┐   ┌──────────────────────────────────┐
│   STAGE 2: STORAGE ENGINE       │   │    STAGE 3: SECURITY AUDITOR     │
│ • NTFS cluster physical sizing  │   │ • DACL LPE privilege checks      │
│ • Alternate Data Streams (ADS)  │   │ • SeriousSAM / HiveNightmare     │
│ • Two-Stage Edge-Chunk Prehash  │   │ • Magic byte masquerading & RTLO │
│ • Blake3 / SHA-256 deduplication│   │ • Authenticode WinVerifyTrust    │
│ • Perceptual image hashing      │   │ • AMSI dynamic script scanning   │
│ • Action tiers: [SAFE]/[REVIEW] │   │ • Ransomware command signatures  │
└────────────────┬────────────────┘   └──────────────────┬───────────────┘
                 │                                       │
                 └───────────────────┬───────────────────┘
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│              STAGE 4: REPORTING & SAFE REMEDIATION                     │
│  • Standalone offline D3.js interactive squarified treemaps (HTML)     │
│  • Machine-readable JSON and CSV analytics telemetry exports           │
│  • Windows Restart Manager (rstrtmgr.dll) process lock resolution      │
│  • Protected Reference Folders (immutable master copies)               │
│  • Safe Recycle Bin disposal with Explorer Undo support (FOF_ALLOWUNDO)│
│  • NTFS Hardlink & Symlink space reclamation                           │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Key Features

### 1. High-Velocity Filesystem Traversal
- **Kernel Directory Streaming:** Bypasses standard runtime wrappers and invokes `FindFirstFileExW` directly with `FindExInfoBasic` (skips legacy 8.3 short filename queries) and `FIND_FIRST_EX_LARGE_FETCH` (allocates 64 KB kernel query buffers).
- **Extended Path Syntax:** Normalizes all paths to `\\?\` (and `\\?\UNC\`), bypassing the legacy `MAX_PATH` (260 characters) limitation to support paths up to 32,767 characters.
- **Reparse Point Cycle Guards:** Inspects `dwFileAttributes` and `dwReserved0` (`IO_REPARSE_TAG_SYMLINK`, `IO_REPARSE_TAG_MOUNT_POINT`) to log symbolic links and directory junctions without following them, eliminating infinite traversal loops.
- **Cloud Recall Protection:** Flags `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS`, `FILE_ATTRIBUTE_RECALL_ON_OPEN`, and `FILE_ATTRIBUTE_OFFLINE` to record local physical allocation as 0 bytes and strictly exclude un-hydrated OneDrive and iCloud files from disk reads, preventing accidental gigabyte downloads.

### 2. Precision Cluster Accounting & Deduplication
- **True Physical Footprint:** Calls `GetDiskFreeSpaceW` to compute exact sectors-per-cluster (default 4 KB cluster) and `GetCompressedFileSizeW` for compressed and sparse files.
- **Alternate Data Stream (ADS) Inspection:** Invokes `FindFirstStreamW` and `FindNextStreamW` to uncover hidden secondary NTFS streams (`:streamname:$DATA`).
- **Two-Stage Elimination Funnel:**
  1. *Size Floor Filter:* Enforces a default 8 KB threshold (configurable down to 1 byte).
  2. *Size Bucketing:* Eliminates non-duplicates without reading a single byte.
  3. *Edge-Chunk Prehashing:* Reads 4 KB from the file head and 4 KB from the file tail, computing a fast partial Blake3 digest.
  4. *Full Cryptographic Hashing:* Computes multi-threaded Blake3 and SHA-256 across matching candidate cohorts.
  5. *Perceptual Media Matching:* Computes 64-bit difference hashes (`dHash`) to identify resized, watermarked, or re-compressed near-duplicate photos.

### 3. Heuristic Space Reclamation Tiers
- **`[SAFE]` Tier (Deterministic Purge):** Package manager caches (`uv`, `pip`, `npm/_cacache`, `pnpm-cache`, `.cargo/registry/cache`, `nuget/packages`), GPU shader caches (`DXCache`, `ShaderCache`), crash dumps (`.dmp`), temporary files (`.tmp`), zero-byte empty files, and broken links.
- **`[REVIEW]` Tier (Contextual Audit):** Extracted archives (`.zip`, `.tar.gz`, `.7z`) sitting adjacent to an extracted sibling folder, rebuildable build trees (`target/`, `node_modules/`, `.venv/`, `bin/Debug/`), and dormant cold storage (> 100 MB unmodified for > 180 days).
- **`[ADVISORY]` Tier (System Check):** Volume Shadow Copies (VSS) queried via `vssadmin` with advisory notes protecting Windows System Restore points.

### 4. Multi-Layered Security & Vulnerability Auditing
- **Win32 DACL / ACL Auditing:** Interacts with `advapi32.dll` to detect weak file/directory permissions granted to `BUILTIN\Users`, `Everyone`, or `Authenticated Users` in system, `Program Files`, or `PATH` locations (Critical Local Privilege Escalation).
- **SeriousSAM / HiveNightmare Detection:** Audits `sam`, `system`, and `security` registry hives for unauthorized low-privilege read access.
- **Binary Authenticity & Masquerading:** Detects deceptive double extensions (`invoice.pdf.exe`), Unicode Right-to-Left Override (`U+202E`) tricks, and executable `MZ` headers disguised as documents or media.
- **Authenticode Verification:** Evaluates PE digital signatures via `WinVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2`.
- **Dynamic Script Inspection via AMSI:** Directly calls `amsi.dll` (`AmsiScanBuffer` with 32-bit ULONG ABI) to detect obfuscated PowerShell, VBScript, and JScript malware, while explicitly trapping `0x80070015` (`ERROR_NOT_READY`) when Windows Defender Real-Time Protection is disabled.
- **Static Pattern Matching:** Detects ransomware staging commands (`vssadmin delete shadows`, `bcdedit recoveryenabled No`), exposed AWS access keys (`AKIA...`), and unencrypted private keys.

### 5. Safe Remediation Workflows
- **Protected Reference Folders:** Designates master archives as immutable; files inside reference folders can never be selected for automated deletion.
- **Windows Restart Manager:** Uses `rstrtmgr.dll` (`RmStartSession`, `RmRegisterResources`, `RmGetList`) to detect active process locks and identify locking Process IDs (PIDs) and application names before cleanup begins.
- **Recycle Bin Disposal with Undo:** Uses `SHFileOperationW` with `FOF_ALLOWUNDO` so deleted files go safely to `$RECYCLE.BIN`, enabling full Windows Explorer `Ctrl+Z` Undo restoration.
- **NTFS Hardlink Deduplication:** Replaces redundant copies with NTFS hardlinks (`CreateHardLinkW`), reclaiming 100% of duplicate physical disk clusters while keeping application paths intact.
- **Crash-Resilient Cache:** Bounded binary serialization (1 GB safety ceiling) with atomic sibling file write (`.cache.tmp`) and SHA-256 checksum verification.

---

## 🛠️ Commands & Usage Guide

### Prerequisites
- Windows 10 or Windows 11 (64-bit)
- Rust toolchain (1.80+ or latest stable)

### Building the Project
Clone the repository and build the optimized production binary:
```powershell
git clone https://github.com/Arhanpg/WinSentry.git
cd WinSentry
cargo build --release
```
The compiled executable will be located at:
```powershell
.\target\release\winsentry.exe
```

---

### Command Reference

#### 1. Full Storage & Security Scan
Scans directories, computes exact physical cluster footprints, identifies duplicate files, checks security vulnerabilities, and optionally exports interactive reports:
```powershell
# Scan current directory with default settings
.\target\release\winsentry.exe scan

# Scan specific directories and export an interactive D3 HTML treemap report
.\target\release\winsentry.exe scan --path C:\Users\Username\Downloads C:\Projects --report-html scan_report.html --report-json scan_report.json --report-csv scan_report.csv

# Inspect Alternate Data Streams (ADS) and skip AMSI if needed
.\target\release\winsentry.exe scan --path D:\Data --ads --skip-amsi
```

#### 2. Dedicated Cryptographic Deduplication
Identifies duplicate files using start/end edge prehashing and Blake3, with optional Reference Folder protection:
```powershell
# Find duplicates in Downloads with an 8 KB minimum size floor
.\target\release\winsentry.exe dedup --path C:\Users\Username\Downloads --minimal-size 8192

# Protect a Master Photos archive from being deleted
.\target\release\winsentry.exe dedup --path C:\Users\Username\Downloads C:\Photos\Master --reference C:\Photos\Master

# Deduplicate by replacing duplicates with NTFS hardlinks (reclaims physical clusters)
.\target\release\winsentry.exe dedup --path D:\Workspace --hardlink
```

#### 3. Dedicated Endpoint Security Audit
Performs Win32 DACL privilege checks, Authenticode verification, AMSI dynamic script scanning, and static secret detection:
```powershell
# Run security audit on system and program locations
.\target\release\winsentry.exe security --path C:\ProgramData C:\Users\Username\AppData\Local\Temp
```

#### 4. Safe Space Reclamation & Cleanup
Removes `[SAFE]` tier caches, temporary files, and dumps, verifying open process locks with the Windows Restart Manager before sending items to the Recycle Bin:
```powershell
# Dry run preview (no files touched)
.\target\release\winsentry.exe clean --path C:\Users\Username\AppData\Local\Temp --dry-run

# Safe cleanup (routes files to $RECYCLE.BIN with Explorer Undo support)
.\target\release\winsentry.exe clean --path C:\Users\Username\AppData\Local\Temp --safe-only

# Quarantine suspicious or clean targets to a separate folder with JSON manifest
.\target\release\winsentry.exe clean --path D:\SuspiciousFolder --quarantine D:\QuarantineStaging
```

#### 5. Volume Shadow Copy (VSS) Advisory
Inspects shadow copy storage consumption and provides system restore point safety guidance:
```powershell
.\target\release\winsentry.exe vss
```

#### 6. Interactive Local Web Dashboard & Live Treemap
Launches the embedded local web server to interactively control scans and explore visual treemaps directly in your browser:
```powershell
.\target\release\winsentry.exe serve --port 7878
```
Navigate to `http://127.0.0.1:7878` in Chrome, Edge, or Firefox.

---

## 🧪 Running Automated Tests

Run the complete suite of unit and integration tests:
```powershell
cargo test
```

All 9 integration and unit tests validate:
- Extended path normalization (`\\?\`) and prefix handling
- NTFS cluster allocation and physical size calculation
- Heuristic classification rules (`[SAFE]`, `[REVIEW]`, `[ADVISORY]`)
- Two-stage edge-chunk prehashing and Blake3 full hashing
- Protected Reference Folder immutability
- 64-bit difference perceptual image hashing
- Security masquerading, RTLO character, and double extension checks
- Static pattern, secret leak, and threat intelligence hash matching
- Crash-resilient bounded cache integrity and corrupted payload rejection

---

## ⚖️ License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.
