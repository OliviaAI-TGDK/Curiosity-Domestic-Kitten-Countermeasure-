#!/bin/bash
# Curiosity Shovel - FIXED for Termux - v3.2

GHIDRA_HOME="$HOME/ghidra_11.2_PUBLIC"
PROJECT_DIR="$HOME/shovel_project"
QUARANTINE="$HOME/quarantine"
REPORT_DIR="$HOME/shovel_reports"
# Termux-safe temp file
TMP_LOG="$PREFIX/tmp/curiosity_hits.log"
YARA_FILE="domestic_kitten.yar"

ensure_env() {
    mkdir -p $QUARANTINE $REPORT_DIR $PROJECT_DIR $HOME/shovel_scripts $PREFIX/tmp
    touch $TMP_LOG
    # Auto-write YARA if missing
    if [ ! -f "$YARA_FILE" ]; then
        echo "[*] Writing first YARA file: $YARA_FILE"
        cat > "$YARA_FILE" << 'YARA'
import "android"
rule DomesticKitten_APK_FurBall_Core {
    meta:
        description = "Domestic Kitten FurBall core"
        author = "Olivian Security"
    strings:
        $c2_a = "api.telegram.org/bot" nocase
        $c2_b = "telegram-bot.com/api" nocase
        $c2_c = /bot[0-9]{8,12}:[A-Za-z0-9_-]{30,50}/
        $pkg_a = "com.furball" nocase
        $exfil_a = "getExternalStorageDirectory"
    condition:
        uint16(0) == 0x4B50 and 2 of them
}
YARA
    fi
}

setup_shovel() {
    ensure_env
    pkg install -y jadx apktool dex2jar binutils yara > /dev/null 2>&1
    echo "[+] Shovel dirs: $QUARANTINE | $REPORT_DIR"
    echo "[+] Temp log: $TMP_LOG"
    echo "[+] YARA: $YARA_FILE"
}

find_and_triage() {
    ensure_env
    TARGET=${1:-$HOME/storage/downloads}
    echo "[*] Hunting with YARA: $TARGET"
    echo "[*] Logging to: $TMP_LOG"
    yara -r "$YARA_FILE" "$TARGET" 2>/dev/null | tee "$TMP_LOG"
    if [ ! -s "$TMP_LOG" ]; then
        echo "[+] No hits - clean"
        return 0
    fi
    while IFS= read -r line; do
        file=$(echo "$line" | awk '{print $NF}')
        [ -z "$file" ] && continue
        [ ! -f "$file" ] && continue
        echo "[!] HIT: $file"
        qfile="$QUARANTINE/$(basename "$file").$(date +%s)"
        cp "$file" "$qfile" 2>/dev/null
        deconstruct "$qfile"
    done < "$TMP_LOG"
}

deconstruct() {
    ensure_env
    SAMPLE=$1
    if [ -z "$SAMPLE" ]; then echo "Usage: ./curiosity.sh deconstruct <apk>"; return 1; fi
    BASE=$(basename "$SAMPLE")
    OUT="$REPORT_DIR/$BASE"
    mkdir -p "$OUT"
    echo "[*] Deconstructing: $SAMPLE -> $OUT"
    strings "$SAMPLE" > "$OUT/strings.txt"
    echo "[+] Strings dumped"
    if [[ "$SAMPLE" == *.apk ]]; then
        echo "[*] apktool..."
        apktool d "$SAMPLE" -o "$OUT/apktool_out" -f > /dev/null 2>&1
        echo "[+] apktool unpacked"
        echo "[*] jadx..."
        jadx -d "$OUT/jadx_out" "$SAMPLE" > /dev/null 2>&1
        echo "[+] jadx decompiled"
        echo "=== C2 INTEL ===" > "$OUT/intel.txt"
        grep -Rin "telegram\|bot.*api\|api.telegram.org" "$OUT/jadx_out" 2>/dev/null | head -n 100 >> "$OUT/intel.txt"
        cat "$OUT/intel.txt"
    fi
    echo "[+] Done. Report: $OUT"
}

case $1 in
    setup) setup_shovel ;;
    find) find_and_triage $2 ;;
    deconstruct) deconstruct $2 ;;
    *) echo "Usage: $0 {setup|find |deconstruct [apk]}" ;;
esac