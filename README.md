# curiosity.sh - Domestic Kitten Countermeasure Framework
### Ghidra Curiosity Shovel Edition v3

> Find, quarantine, and deliberately deconstruct Domestic Kitten / APT-C-50 / FurBall payloads.
> Defensive research tool. Lab use only.

**Author:** Olivian Security Collective
**Target Threat:** APT-C-50 (Domestic Kitten) - Android spyware using Telegram Bot API for C2
**Platform:** Termux (collector/triage) + Linux x86_64 (Ghidra deep analysis)

---

### What It Does

`curiosity.sh` is a Termux-native framework that turns your device into a malware hunting shovel:

1. **FIND** - YARA + ClamAV hunt across storage
2. **QUARANTINE** - Auto-copies hits to `~/quarantine/`
3. **DECONSTRUCT** - Unpacks APKs and extracts intel
    - `apktool` - AndroidManifest + resources
    - `jadx` - Java decompilation (works in Termux)
    - `strings` - Raw string extraction
    - **Ghidra Headless** - Function + C2 auto-tagging via custom Python script
4. **CONTROL** - Block C2, sinkhole DNS, fake C2 honeypot for lab analysis
5. **REPORT** - Generates intel + PSA

All reports go to `~/shovel_reports/<sample_name>/`

### Install

```bash
pkg update && pkg upgrade -y
pkg install git -y
git clone <your-repo>
cd curiosity.sh
chmod +x curiosity.sh
./curiosity.sh
```
# Select [1] Install dependencies on first run

curiosity © TGDK 2023-2026
