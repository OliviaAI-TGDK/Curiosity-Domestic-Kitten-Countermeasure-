# shovel.sh - Domestic Kitten Countermeasure Framework
### Ghidra Shovel Edition v4

> Find, quarantine, and deliberately deconstruct Domestic Kitten / APT-C-50 / FurBall payloads.
> Defensive research tool. Lab use only.

**Author:** Olivian Security Collective
**Target Threat:** APT-C-50 (Domestic Kitten) - Android spyware using Telegram Bot API for C2
**Platform:** Termux (collector/triage) + Linux x86_64 (Ghidra deep analysis)

### What It Does

`shovel.sh` is a Termux-native framework that turns your device into a malware hunting shovel:

1. **FIND** - YARA recursive hunt across storage
2. **QUARANTINE** - Auto-copies hits to `~/quarantine/`
3. **DECONSTRUCT** - Unpacks APKs and extracts intel
   - `apktool` - AndroidManifest + resources
   - `jadx` - Java decompilation
   - `strings` - Raw string extraction
   - **Ghidra Headless** - Depth Perception + Quantumlineation scoring
4. **WATCH** - Constant recursive monitor, never stops
5. **REPORT** - Generates intel in `~/shovel_reports/<sample>/`

Reports include:
- `depth_bash.txt` / `depth.txt` - Depth Perception (permission + call depth)
- `quantum_bash.txt` / `quantum.txt` - Quantumlineation (entropy-per-line, catches obfuscated bot tokens)
- `shovel_report.txt` - Ghidra interesting funcs

### Install

```bash
pkg update && pkg upgrade -y
pkg install git -y
git clone <your-repo>
cd shovel
chmod +x shovel.sh
./shovel.sh setup
./shovel.sh watch ~/storage/downloads

SHOVEL © TGDK 2023-2026
