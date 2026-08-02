5        $ex_a = "READ_SMS" $ex_b = "READ_CONTACTS" $ex_c = "RECORD_AUDIO" $ex_d = "getExternalStorageDirectory"
    condition: uint16(0) == 0x4B50 and (2 of ($c2_*) and 2 of ($ex_*))
}
YARA
    fi

    # Production Ghidra Script - Depth Perception
    cat > "$SCRIPT_DIR/DeconstructDomesticKitten.py" << 'PY'
# @category Olivian.Shovel.Prod
# Depth Perception + Quantumlineation Report
import math
from ghidra.program.model.symbol import *

args = getScriptArgs()
out_dir = args[0] if args else "/tmp"
report_path = out_dir + "/ghidra_report.txt"
depth_path = out_dir + "/depth_perception.txt"
quantum_path = out_dir + "/quantumlineation.txt"

def entropy(s):
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    return -sum((count/len(s)) * math.log2(count/len(s)) for count in freq.values())

with open(report_path, "w") as f, open(depth_path, "w") as df, open(quantum_path, "w") as qf:
    f.write(f"Program: {currentProgram.getName()}\n")
    f.write(f"Language: {currentProgram.getLanguage()}\n")

    # DEPTH PERCEPTION - call graph depth
    fm = currentProgram.getFunctionManager()
    funcs = list(fm.getFunctions(True))
    f.write(f"Total Functions: {len(funcs)}\n")
    df.write("=== DEPTH PERCEPTION ===\n")
    for func in funcs:
        name = func.getName().lower()
        if any(x in name for x in ["telegram","send","exfil","upload","sms","contact","http","socket","bot","record","location"]):
            depth = 0
            try:
                depth = len(list(func.getCalledFunctions(monitor)))
            except: pass
            df.write(f"DEPTH:{depth} FUNC:{func.getName()} @ {func.getEntryPoint()} CALLS:{depth}\n")
            f.write(f"INTERESTING: {func.getName()} depth={depth}\n")

    # QUANTUMLINEATION - entropy per string / obfuscation detection
    qf.write("=== QUANTUMLINEATION - Entropy per String ===\n")
    listing = currentProgram.getListing()
    for data in listing.getDefinedData(True):
        if data.hasStringValue():
            val = str(data.getValue())
            if len(val) > 8:
                ent = entropy(val)
                # High entropy > 4.5 = likely encrypted/obfuscated or token
                if ent > 4.5 or "telegram" in val.lower() or "bot" in val.lower():
                    qf.write(f"ENT:{ent:.2f} ADDR:{data.getAddress()} VAL:{val[:200]}\n")
                    if "telegram" in val.lower():
                        f.write(f"C2 STRING ENT:{ent:.2f} {val} @ {data.getAddress()}\n")

print(f"Reports: {report_path}, {depth_path}, {quantum_path}")
PY
}

setup_shovel() {
    ensure_env
    echo -e "${BLUE}[*] Installing deps...${NC}"
    pkg update -y > /dev/null 2>&1; pkg install -y jadx apktool dex2jar binutils yara python termux-api > /dev/null 2>&1
    pip install --quiet yara-python 2>/dev/null; echo -e "${GREEN}[+] Production env ready${NC}"
    echo -e "${CYAN} Quarantine: $QUARANTINE${NC}\n Reports: $REPORT_DIR\n YARA: $YARA_FILE${NC}"
}

# QUANTUMLINEATION - line-level entropy analysis in bash
quantumlineation_scan() {
    local file=$1; local out=$2
    local qfile="$out/quantumlineation_bash.txt"
    echo "=== QUANTUMLINEATION BASH ===" > "$qfile"
    # Get all strings, calculate entropy with python
    python3 - "$file" "$qfile" << 'PYEOF'
import math, sys, collections
from pathlib import Path
def entropy(s):
    if not s: return 0
    freq = collections.Counter(s)
    l = len(s)
    return -sum((c/l)*math.log2(c/l) for c in freq.values())
path=sys.argv[1]; out=sys.argv[2]
try:
    data=open(path,'rb').read()
    # Scan printable strings > 10 chars
    import re
    strs = re.findall(b"[ -~]{10,}", data)
    with open(out,'a') as o:
        for s in strs[:2000]:
            try:
                ds=s.decode()
                e=entropy(ds)
                if e>4.6 or "telegram" in ds.lower() or "bot" in ds.lower() or "/sdcard" in ds.lower():
                    o.write(f"ENT:{e:.2f} {ds[:300]}\n")
            except: pass
except Exception as e:
    print(e)
PYEOF
    echo "[+] Quantumlineation: $qfile"
}

# DEPTH PERCEPTION - dex/manifest depth analysis
depth_perception_scan() {
    local apk=$1; local out=$2
    local dfile="$out/depth_perception_bash.txt"
    echo "=== DEPTH PERCEPTION BASH ===" > "$dfile"
    echo "[*] Analyzing manifest + dex depth..." >> "$dfile"
    if [[ -d "$out/apktool_out" ]]; then
        echo "--- Permissions Depth ---" >> "$dfile"
        grep -o "android.permission.[A-Z_]*" "$out/apktool_out/AndroidManifest.xml" 2>/dev/null | sort | uniq -c | sort -nr >> "$dfile"
        echo "--- Services / Receivers Depth ---" >> "$dfile"
        grep -E "service|receiver" "$out/apktool_out/AndroidManifest.xml" 2>/dev/null | head -n 50 >> "$dfile"
    fi
    if [[ -d "$out/jadx_out" ]]; then
        echo "--- Call Depth - Exfil APIs ---" >> "$dfile"
        grep -Rrn "getDeviceId\|getSubscriberId\|getLine1Number\|READ_SMS\|RECORD_AUDIO\|sendTextMessage\|HttpURLConnection\|OkHttp\|Telegram" "$out/jadx_out" 2>/dev/null | head -n 100 >> "$dfile"
    fi
    echo "[+] Depth Perception: $dfile"
}

deconstruct() {
    ensure_env
    local SAMPLE=$1; [[ -z "$SAMPLE" ]] && echo "Usage: $0 deconstruct <apk>" && return 1
    [[! -f "$SAMPLE" ]] && echo "[!] Not found: $SAMPLE" && return 1
    local BASE=$(basename "$SAMPLE"); local OUT="$REPORT_DIR/$BASE"; mkdir -p "$OUT"
    [[ -f "$OUT/.done" ]] && echo "[=] Already done: $OUT" && return 0

    echo -e "${BLUE}[*] Deconstructing $BASE -> $OUT${NC}"
    strings "$SAMPLE" > "$OUT/strings.txt" 2>/dev/null

    if [[ "$SAMPLE" == *.apk ]]; then
        echo -e "${CYAN}[*] apktool + jadx...${NC}"
        apktool d "$SAMPLE" -o "$OUT/apktool_out" -f > /dev/null 2>&1
        jadx -d "$OUT/jadx_out" "$SAMPLE" > /dev/null 2>&1
        echo "=== C2 INTEL ===" > "$OUT/intel.txt"
        grep -Rin "telegram\|bot.*api\|api.telegram.org\|/sdcard\|exfil" "$OUT/jadx_out" 2>/dev/null | head -n 150 >> "$OUT/intel.txt"
    fi

    quantumlineation_scan "$SAMPLE" "$OUT"
    depth_perception_scan "$SAMPLE" "$OUT"

    if [[ -d "$GHIDRA_HOME" ]]; then
        echo -e "${YELLOW}[*] Ghidra Headless - Depth+Quantum...${NC}"
        $GHIDRA_HOME/support/analyzeHeadless "$PROJECT_DIR" ShovelProject -import "$SAMPLE" -scriptPath "$SCRIPT_DIR" -postScript DeconstructDomesticKitten.py "$OUT" -deleteProject > "$OUT/ghidra_log.txt" 2>&1
        cat "$OUT/ghidra_report.txt" 2>/dev/null
        cat "$OUT/depth_perception.txt" 2>/dev/null
        cat "$OUT/quantumlineation.txt" 2>/dev/null | head -n 30
    fi

    touch "$OUT/.done"
    echo -e "${GREEN}[+] Done: $OUT${NC}"
    ls -lh "$OUT"/*.txt 2>/dev/null
}

find_and_triage() {
    ensure_env
    local TARGET=${1:-$HOME/storage/downloads}
    echo -e "${BLUE}[*] Recursive YARA scan: $TARGET${NC}"
    yara -r "$YARA_FILE" "$TARGET" 2>/dev/null | tee "$TMP_LOG"
    if [[! -s "$TMP_LOG" ]]; then echo -e "${GREEN}[+] Clean - no hits${NC}"; return 0; fi
    while IFS= read -r line; do
        local file=$(echo "$line" | awk '{print $NF}'); [[ -z "$file" ||! -f "$file" ]] && continue
        [[ "$file" == *"$QUARANTINE"* ]] && continue
        echo -e "${RED}[!] HIT: $file${NC}"
        local qfile="$QUARANTINE/$(basename "$file").$(date +%s).apk"
        cp "$file" "$qfile" 2>/dev/null && deconstruct "$qfile"
    done < "$TMP_LOG"
}

watch_mode() {
    ensure_env
    local TARGET=${1:-$HOME/storage}
    echo -e "${RED}[*] === PRODUCTION WATCH MODE ===${NC}"
    echo -e " Target: $TARGET\n Interval: ${WATCH_INTERVAL}s\n Quarantine: $QUARANTINE\n Depth: ON\n Quantumlineation: ON"
    echo -e "${YELLOW} Press CTRL+C to stop${NC}\n"
    local count=0
    while true; do
        count=$((count+1))
        echo -e "${BLUE}[$(date '+%H:%M:%S')] Scan #$count: $TARGET${NC}"
        find_and_triage "$TARGET"
        echo -e "${CYAN}[$(date '+%H:%M:%S')] Sleep $WATCH_INTERVAL${NC}\n"
        sleep "$WATCH_INTERVAL"
    done
}

case $1 in
    setup) setup_shovel ;;
    find) find_and_triage "${2:-}" ;;
    watch) watch_mode "${2:-}" ;;
    deconstruct) deconstruct "${2:-}" ;;
    clean) rm -rf "$QUARANTINE" "$REPORT_DIR" "$PROJECT_DIR" "$SCRIPT_DIR" "$TMP_LOG"./curiosity.sh; echo "cleaned" ;;
    *) echo -e "Usage: $0 {setup|find [path]|watch [path]|deconstruct [apk]|clean}\n\nPRODUCTION FLAGS:\n Depth Perception: call-graph depth + permission depth + service depth\n Quantumlineation: entropy-per-string scoring to catch obfuscated C2 tokens";;
esac
