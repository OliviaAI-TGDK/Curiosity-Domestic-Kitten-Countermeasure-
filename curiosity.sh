#!/bin/bash
# =============================================
# Domestic Kitten Countermeasure Framework v3
# Ghidra Curiosity Shovel Edition
# Defensive / Lab Use Only
# =============================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

C2_DOMAIN="telegram-bot.com"
HONEYPOT_IP="192.168.1.100"
YARA_FILE="domestic_kitten.yar"
QUARANTINE="$HOME/quarantine"
REPORT_DIR="$HOME/shovel_reports"
PROJECT_DIR="$HOME/shovel_project"
GHIDRA_HOME="$HOME/ghidra_11.2_PUBLIC"

check_termux() {
    [ ! -d "$PREFIX" ] && { echo -e "${RED}[!] Run this in Termux.${NC}"; exit 1; }
}

install_deps() {
    echo -e "${BLUE}[*] Installing dependencies...${NC}"
    pkg update -y && pkg upgrade -y > /dev/null 2>&1
    pkg install -y python git wget curl tcpdump clamav yara nmap termux-tools jadx apktool dex2jar binutils -y > /dev/null 2>&1
    pip install --upgrade pip > /dev/null 2>&1
    pip install flask scapy requests > /dev/null 2>&1
    mkdir -p $QUARANTINE $REPORT_DIR $PROJECT_DIR $HOME/shovel_scripts
    freshclam > /dev/null 2>&1
    echo -e "${GREEN}[+] Dependencies installed + shovel dirs created.${NC}"
}

create_yara_rule() {
    cat > $YARA_FILE << 'YARA'
import "android"
rule DomesticKitten_APK_v3 {
    meta:
        description = "Detects Domestic Kitten / FurBall"
        author = "Olivian Security"
        reference = "APT-C-50"
    strings:
        $a = "telegram-bot.com/api" nocase
        $b = /bot[0-9]{8,10}:AA[a-zA-Z0-9_-]{30,}/
        $c = "com.furball" nocase
        $d = "getExternalStorageDirectory"
        $e = "android.permission.READ_SMS"
    condition:
        uint16(0) == 0x4B50 and 2 of ($a,$b,$c,$d,$e)
}
YARA
    echo -e "${GREEN}[+] YARA rule created: $YARA_FILE${NC}"
}

scan_and_triage() {
    TARGET=${1:-$HOME/storage/downloads}
    echo -e "${BLUE}[*] Scanning: $TARGET${NC}"
    [ ! -f "$YARA_FILE" ] && create_yara_rule
    yara -r "$YARA_FILE" "$TARGET" 2>/dev/null | tee yara_hits.log
    echo -e "${BLUE}[*] ClamAV quick scan...${NC}"
    clamscan -r --infected "$TARGET" --log=clamav.log 2>/dev/null
    echo -e "${GREEN}[+] Done. See yara_hits.log / clamav.log${NC}"
}

block_c2_domains() {
    if [ "$(id -u)" = "0" ]; then
        echo -e "${BLUE}[*] Blocking $C2_DOMAIN via iptables...${NC}"
        iptables -A OUTPUT -p tcp -d "$C2_DOMAIN" -j DROP
        iptables -A OUTPUT -p udp -d "$C2_DOMAIN" -j DROP
        echo -e "${GREEN}[+] Blocked via iptables.${NC}"
    else
        echo -e "${BLUE}[*] Non-root fallback: hosts file...${NC}"
        grep -q "$C2_DOMAIN" $PREFIX/etc/hosts || echo "$HONEYPOT_IP $C2_DOMAIN" >> $PREFIX/etc/hosts
        echo -e "${GREEN}[+] $C2_DOMAIN -> $HONEYPOT_IP in $PREFIX/etc/hosts${NC}"
    fi
}

start_dns_spoof() {
    if [ "$(id -u)" != "0" ]; then echo -e "${RED}[!] DNS spoof needs root (lab only).${NC}"; return; fi
    cat > dns_spoof.py << PYEOF
from scapy.all import *
HONEYPOT_IP = "$HONEYPOT_IP"
C2 = b"$C2_DOMAIN"
def dns_spoof(pkt):
    if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0 and C2 in pkt[DNSQR].qname:
        print(f"[+] Spoofing {pkt[DNSQR].qname.decode()} -> {HONEYPOT_IP}")
        spoofed = IP(dst=pkt[IP].src, src=pkt[IP].dst)/UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, an=DNSRR(rrname=pkt[DNSQR].qname, ttl=300, rdata=HONEYPOT_IP))
        send(spoofed, verbose=0)
print(f"[*] DNS spoof running for {C2.decode()} -> {HONEYPOT_IP}")
sniff(filter="udp port 53", prn=dns_spoof, store=0)
PYEOF
    echo -e "${GREEN}[+] dns_spoof.py created. Run: sudo python dns_spoof.py${NC}"
}

start_fake_c2() {
    cat > fake_c2.py << 'PYEOF'
from flask import Flask, request, jsonify
import datetime
app = Flask(__name__)
@app.route("/api/<path:path>", methods=["GET","POST"])
def sinkhole(path):
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    log = f"{datetime.datetime.now()} | IP: {request.remote_addr} | Path: {path} | Data: {data}\n"
    print(log, end='')
    open("honeypot_c2.log","a").write(log)
    return jsonify({"command": "NOOP"})
if __name__ == "__main__":
    print("[*] Fake C2 honeypot on 0.0.0.0:8080 - ISOLATED LAB ONLY")
    app.run(host="0.0.0.0", port=8080)
PYEOF
    echo -e "${GREEN}[+] fake_c2.py created. Run: python fake_c2.py${NC}"
}

setup_ghidra_shovel() {
    mkdir -p $HOME/shovel_scripts
    cat > $HOME/shovel_scripts/DeconstructDomesticKitten.py << 'PY'
# @category Olivian.Shovel
# Ghidra auto-deconstruction script for Domestic Kitten
report_path = getScriptArgs()[0] + "/ghidra_report.txt"
with open(report_path, "w") as f:
    f.write(f"Program: {currentProgram.getName()}\n")
    f.write(f"Language: {currentProgram.getLanguage()}\n\n")
    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        name = func.getName().lower()
        if any(x in name for x in ["telegram","send","exfil","upload","sms","contact","http","socket","steal"]):
            f.write(f"INTERESTING FUNC: {func.getName()} @ {func.getEntryPoint()}\n")
    for s in currentProgram.getListing().getDefinedData(True):
        if s.hasStringValue():
            val = str(s.getValue())
            if "telegram" in val.lower() or "bot" in val.lower():
                f.write(f"C2 STRING: {val} @ {s.getAddress()}\n")
print(f"[+] Report: {report_path}")
PY
    echo -e "${GREEN}[+] Ghidra script created: ~/shovel_scripts/DeconstructDomesticKitten.py${NC}"
    echo -e "${YELLOW}[!] Set GHIDRA_HOME to your Ghidra install. On Termux, install Ghidra on a PC and use Termux as collector.${NC}"
}

curiosity_find() {
    echo -ne "${BLUE}Target to hunt [default: $HOME/storage/downloads]: ${NC}"
    read target
    target=${target:-$HOME/storage/downloads}
    echo -e "${CYAN}[*] Hunting...${NC}"
    [ ! -f "$YARA_FILE" ] && create_yara_rule
    yara -r "$YARA_FILE" "$target" 2>/dev/null | while read line; do
        file=$(echo $line | awk '{print $NF}')
        base=$(basename "$file")
        qfile="$QUARANTINE/${base}.$(date +%s)"
        echo -e "${RED}[!] HIT: $file${NC}"
        cp "$file" "$qfile" 2>/dev/null
        curiosity_deconstruct "$qfile"
    done
}

curiosity_deconstruct() {
    SAMPLE=${1:-$(echo -ne "${BLUE}Path to APK/sample: ${NC}"; read s; echo $s)}
    [ ! -f "$SAMPLE" ] && { echo -e "${RED}[!] File not found: $SAMPLE${NC}"; return; }
    BASE=$(basename "$SAMPLE")
    OUT="$REPORT_DIR/$BASE"
    mkdir -p "$OUT"
    echo -e "${CYAN}[*] Deconstructing: $SAMPLE${NC}"
    echo -e "${BLUE}[*] Strings...${NC}"
    strings "$SAMPLE" > "$OUT/strings.txt"
    if [[ "$SAMPLE" == *.apk ]]; then
        echo -e "${BLUE}[*] apktool...${NC}"
        apktool d "$SAMPLE" -o "$OUT/apktool_out" -f > /dev/null 2>&1
        echo -e "${BLUE}[*] jadx...${NC}"
        jadx -d "$OUT/jadx_out" "$SAMPLE" > /dev/null 2>&1
        echo "=== INTEL ===" > "$OUT/intel.txt"
        grep -Rin "telegram\|bot.*api\|api.telegram.org" "$OUT/jadx_out" 2>/dev/null | head -n 100 >> "$OUT/intel.txt"
        grep -Rin "READ_SMS\|READ_CONTACTS\|RECORD_AUDIO" "$OUT/apktool_out/AndroidManifest.xml" 2>/dev/null >> "$OUT/intel.txt"
        cat "$OUT/intel.txt"
    fi
    if [ -d "$GHIDRA_HOME" ]; then
        echo -e "${BLUE}[*] Ghidra Headless...${NC}"
        $GHIDRA_HOME/support/analyzeHeadless $PROJECT_DIR ShovelProject -import "$SAMPLE" -scriptPath "$HOME/shovel_scripts" -postScript DeconstructDomesticKitten.py "$OUT" -deleteProject > /dev/null 2>&1
        cat "$OUT/ghidra_report.txt" 2>/dev/null
    else
        echo -e "${YELLOW}[!] GHIDRA_HOME not set. Skipping deep analysis. Run option 7 first.${NC}"
    fi
    echo -e "${GREEN}[+] Report saved: $OUT${NC}"
}

generate_psa() {
    cat > PSA.txt << PSAEOF
🚨 PSA: DOMESTIC KITTEN NEUTRALIZED 🚨
Issued by: Olivian Security
Date: $(date)
Severity: CRITICAL

Threat: APT-C-50 / Domestic Kitten / FurBall - Android spyware via Telegram Bot C2
Targets: Activists, journalists, military

Actions:
1. YARA: $YARA_FILE
2. Block: $C2_DOMAIN -> $HONEYPOT_IP
3. Deconstruct: quarantine/ + shovel_reports/

Protect:
yara -r $YARA_FILE /sdcard/
jadx -d out suspect.apk

Credit: Olivian Security Collective
#DomesticKitten
PSAEOF
    echo -e "${GREEN}[+] PSA.txt generated.${NC}"
}

main_menu() {
    clear
    echo -e "${BLUE}

    Domestic Kitten Countermeasure Framework v3
    Ghidra Curiosity Shovel Edition

    ${NC}"
    echo -e "${YELLOW}[1]${NC} Install dependencies"
    echo -e "${YELLOW}[2]${NC} Create YARA rule"
    echo -e "${YELLOW}[3]${NC} Scan / Triage"
    echo -e "${YELLOW}[4]${NC} Block C2 domains"
    echo -e "${YELLOW}[5]${NC} Start DNS spoof (lab/root only)"
    echo -e "${YELLOW}[6]${NC} Start fake C2 honeypot (lab only)"
    echo -e "${YELLOW}[7]${NC} Setup Ghidra shovel scripts"
    echo -e "${YELLOW}[8]${NC} Curiosity Shovel - FIND"
    echo -e "${YELLOW}[9]${NC} Curiosity Shovel - DECONSTRUCT sample"
    echo -e "${YELLOW}[10]${NC} Generate PSA"
    echo -e "${YELLOW}[11]${NC} Run ALL defensive (1,2,3,4,7,10)"
    echo -e "${YELLOW}[0]${NC} Exit"
    echo -ne "${BLUE}Select an option: ${NC}"
    read -r option
    case $option in
        1) install_deps ;;
        2) create_yara_rule ;;
        3) scan_and_triage ;;
        4) block_c2_domains ;;
        5) start_dns_spoof ;;
        6) start_fake_c2 ;;
        7) setup_ghidra_shovel ;;
        8) curiosity_find ;;
        9) curiosity_deconstruct ;;
        10) generate_psa ;;
        11)
            install_deps
            create_yara_rule
            scan_and_triage
            block_c2_domains
            setup_ghidra_shovel
            generate_psa
            ;;
        0) exit 0 ;;
        *) echo -e "${RED}[!] Invalid option.${NC}" ;;
    esac
    echo -e "\n${CYAN}Press Enter to return to menu...${NC}"; read
}

check_termux
while true; do main_menu; done
