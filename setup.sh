#!/bin/bash
# ==================================================
#  RUNAKO PREMIUM AUTOSCRIPT V4.0 (FINAL)
#  Features: GUI Bot, Web Link, Precise Layout
# ==================================================

# 1. INITIAL SETUP & DEPENDENCIES
echo "[+] Installing Dependencies..."
apt update -y
apt install curl socat zip unzip wget nano jq net-tools bsdmainutils python3 python3-pip -y
pip3 install pyTelegramBotAPI psutil requests

# 2. SETUP DATABASE & FOLDERS
echo "[+] Setting up Database..."
mkdir -p /etc/xray/db
mkdir -p /var/www/html/akun
touch /etc/xray/db/vmess
touch /etc/xray/db/vless
touch /etc/xray/db/trojan
touch /etc/xray/db/ssh

# 3. INPUT DOMAIN (Jika belum ada)
if [ ! -f /etc/xray/domain ]; then
    echo "---------------------------------------------------"
    read -p "Masukkan Domain VPS (cth: sg.runako.biz.id): " domain
    echo "$domain" > /etc/xray/domain
else
    domain=$(cat /etc/xray/domain)
fi

# 4. INSTALL XRAY CORE (Jika belum ada)
echo "[+] Installing Xray..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# 5. CONFIG XRAY STANDARD (Jangkar untuk Inject)
cat > /usr/local/etc/xray/config.json << END
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": 10001, "listen": "127.0.0.1", "protocol": "vmess",
      "settings": { "clients": [] },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "/vmess" } }
    },
    {
      "port": 10002, "listen": "127.0.0.1", "protocol": "vless",
      "settings": { "clients": [], "decryption": "none" },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "/vless" } }
    },
    {
      "port": 10003, "listen": "127.0.0.1", "protocol": "trojan",
      "settings": { "clients": [] },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "/trojan" } }
    }
  ],
  "outbounds": [ { "protocol": "freedom" } ]
}
END

# 6. SETUP HELPER SCRIPTS (BACKEND)
# Script ini yang bekerja di belakang layar bot dan menu

# --- Helper VMESS (JSON Output + Web File) ---
cat > /usr/bin/bot-add-vmess << 'EOF'
#!/bin/bash
domain=$(cat /etc/xray/domain)
user=$1
exp=$2
uuid=$(cat /proc/sys/kernel/random/uuid)
isp=$(curl -s ipinfo.io/org)
city=$(curl -s ipinfo.io/city)
sed -i '/"clients": \[/a \ { "id": "'${uuid}'", "email": "'${user}'" },' /usr/local/etc/xray/config.json
systemctl restart xray

# Links
json_tls='{"add":"'$domain'","port":"443","id":"'$uuid'","aid":"0","net":"ws","path":"/vmess","tls":"tls","ps":"'$user'"}'
link_tls="vmess://$(echo $json_tls | base64 -w 0)"
json_none='{"add":"'$domain'","port":"80","id":"'$uuid'","aid":"0","net":"ws","path":"/vmess","tls":"none","ps":"'$user'"}'
link_none="vmess://$(echo $json_none | base64 -w 0)"
json_grpc='{"add":"'$domain'","port":"443","id":"'$uuid'","aid":"0","net":"grpc","path":"vmess-grpc","tls":"tls","ps":"'$user'"}'
link_grpc="vmess://$(echo $json_grpc | base64 -w 0)"

# Save to Web & DB
mkdir -p /var/www/html/akun
echo -e "VMess Account\nUser: $user\nUUID: $uuid\n\nTLS:\n$link_tls\n\nHTTP:\n$link_none\n\ngRPC:\n$link_grpc" > /var/www/html/akun/$user.txt
echo "$user" >> /etc/xray/db/vmess
file_url="http://$domain:80/akun/$user.txt"

echo "{\"user\": \"$user\", \"uuid\": \"$uuid\", \"domain\": \"$domain\", \"isp\": \"$isp\", \"city\": \"$city\", \"link_tls\": \"$link_tls\", \"link_none\": \"$link_none\", \"link_grpc\": \"$link_grpc\", \"file_url\": \"$file_url\"}"
EOF

# --- Helper VLESS ---
cat > /usr/bin/bot-add-vless << 'EOF'
#!/bin/bash
domain=$(cat /etc/xray/domain)
user=$1
exp=$2
uuid=$(cat /proc/sys/kernel/random/uuid)
isp=$(curl -s ipinfo.io/org)
city=$(curl -s ipinfo.io/city)
sed -i '/"clients": \[/a \ { "id": "'${uuid}'", "email": "'${user}'" },' /usr/local/etc/xray/config.json
systemctl restart xray

link_tls="vless://${uuid}@${domain}:443?path=/vless&security=tls&encryption=none&type=ws#${user}"
link_none="vless://${uuid}@${domain}:80?path=/vless&security=none&encryption=none&type=ws#${user}"
link_grpc="vless://${uuid}@${domain}:443?mode=gun&security=tls&encryption=none&type=grpc&serviceName=vless-grpc#${user}"

mkdir -p /var/www/html/akun
echo -e "Vless Account\nUser: $user\n\nTLS:\n$link_tls\n\nHTTP:\n$link_none\n\ngRPC:\n$link_grpc" > /var/www/html/akun/$user.txt
echo "$user" >> /etc/xray/db/vless
file_url="http://$domain:80/akun/$user.txt"

echo "{\"user\": \"$user\", \"uuid\": \"$uuid\", \"domain\": \"$domain\", \"isp\": \"$isp\", \"city\": \"$city\", \"link_tls\": \"$link_tls\", \"link_none\": \"$link_none\", \"link_grpc\": \"$link_grpc\", \"file_url\": \"$file_url\"}"
EOF

# --- Helper TROJAN ---
cat > /usr/bin/bot-add-trojan << 'EOF'
#!/bin/bash
domain=$(cat /etc/xray/domain)
user=$1
exp=$2
uuid=$(cat /proc/sys/kernel/random/uuid)
isp=$(curl -s ipinfo.io/org)
city=$(curl -s ipinfo.io/city)
sed -i '/"clients": \[/a \ { "password": "'${uuid}'", "email": "'${user}'" },' /usr/local/etc/xray/config.json
systemctl restart xray

link_tls="trojan://${uuid}@${domain}:443?path=%2Ftrojan&security=tls&type=ws&sni=${domain}#${user}"
link_grpc="trojan://${uuid}@${domain}:443?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc&sni=${domain}#${user}"

mkdir -p /var/www/html/akun
echo -e "Trojan Account\nUser: $user\n\nTLS:\n$link_tls\n\ngRPC:\n$link_grpc" > /var/www/html/akun/$user.txt
echo "$user" >> /etc/xray/db/trojan
file_url="http://$domain:80/akun/$user.txt"

echo "{\"user\": \"$user\", \"uuid\": \"$uuid\", \"domain\": \"$domain\", \"isp\": \"$isp\", \"city\": \"$city\", \"link_tls\": \"$link_tls\", \"link_none\": \"-\", \"link_grpc\": \"$link_grpc\", \"file_url\": \"$file_url\"}"
EOF

# --- Helper SSH ---
cat > /usr/bin/bot-add-ssh << 'EOF'
#!/bin/bash
user=$1
pass=$2
exp=$3
exd=$(date -d "$exp days" +"%Y-%m-%d")
useradd -e $exd -M -s /bin/false $user
echo "$user:$pass" | chpasswd
echo "$user" >> /etc/xray/db/ssh
echo "Host: $(cat /etc/xray/domain) | User: $user | Pass: $pass | Exp: $exd"
EOF

# --- Helper DELETE ---
cat > /usr/bin/bot-del-user << 'EOF'
#!/bin/bash
# Usage: bot-del-user <protocol> <user>
prot=$1
user=$2
if [ "$prot" == "ssh" ]; then
    userdel -f $user
else
    sed -i "/\"email\": \"$user\"/d" /usr/local/etc/xray/config.json
    systemctl restart xray
fi
# Hapus dari DB & File Web
sed -i "/^$user$/d" /etc/xray/db/$prot
rm -f /var/www/html/akun/$user.txt
echo "Deleted"
EOF

chmod +x /usr/bin/bot-add-* /usr/bin/bot-del-*

# 7. MEMBUAT MENU CLI (TAMPILAN TERMINAL)
cat > /usr/bin/menu << 'EOF'
#!/bin/bash
[[ -f /etc/funny/bot.conf ]] && source /etc/funny/bot.conf
domain=$(cat /etc/xray/domain)
ip=$(curl -s ifconfig.me)
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Info System
ram_used=$(free -m | grep Mem | awk '{print $3}')
ram_total=$(free -m | grep Mem | awk '{print $2}')
uptime=$(uptime -p | sed 's/up //;s/ hours,/j/;s/ minutes/m/')
# Hitung dari DB
ssh=$(cat /etc/xray/db/ssh | wc -l)
vmess=$(cat /etc/xray/db/vmess | wc -l)
vless=$(cat /etc/xray/db/vless | wc -l)
trojan=$(cat /etc/xray/db/trojan | wc -l)

# Status Service
check_service() { systemctl is-active "$1" >/dev/null 2>&1 && echo -e "${GREEN}ON ${NC}" || echo -e "${RED}OFF${NC}"; }
s_ssh=$(check_service ssh)
s_nginx=$(check_service nginx)
s_xray=$(check_service xray)

clear
echo -e ""
echo -e "${CYAN}┌─────────────────────────────────────────────────────────┐${NC}"
printf "${CYAN}│${NC}  ${RED}↘${NC} %-14s = %-36s ${CYAN}│${NC}\n" "OS" "Ubuntu 20.04 LTS"
printf "${CYAN}│${NC}  ${RED}↘${NC} %-14s = %-36s ${CYAN}│${NC}\n" "RAM" "$ram_used / $ram_total MB"
printf "${CYAN}│${NC}  ${RED}↘${NC} %-14s = %-36s ${CYAN}│${NC}\n" "IP" "$ip"
printf "${CYAN}│${NC}  ${RED}↘${NC} %-14s = %-36s ${CYAN}│${NC}\n" "Domain" "$domain"
echo -e "${CYAN}└─────────────────────────────────────────────────────────┘${NC}"
echo -e "${BLUE}───────────────────────────────────────────────────────────${NC}"
printf "      %-15s = %-5s   ACCOUNT PREMIUM\n" "SSH/OPENVPN" "$ssh"
printf "      %-15s = %-5s   ACCOUNT PREMIUM\n" "VMESS/GRPC" "$vmess"
printf "      %-15s = %-5s   ACCOUNT PREMIUM\n" "VLESS/GRPC" "$vless"
printf "      %-15s = %-5s   ACCOUNT PREMIUM\n" "TROJAN/GRPC" "$trojan"
echo -e "${BLUE}───────────────────────────────────────────────────────────${NC}"
echo -e "${CYAN}┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐${NC}"
printf "${CYAN}│${NC} SSH     : %b   ${CYAN}│ │${NC} NGINX   : %b   ${CYAN}│ │${NC} XRAY    : %b   ${CYAN}│${NC}\n" "$s_ssh" "$s_nginx" "$s_xray"
echo -e "${CYAN}└─────────────────┘ └─────────────────┘ └─────────────────┘${NC}"
echo -e "${CYAN}┌─────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${NC} [01] SSH MENU        ${CYAN}|${NC} [09] AUTO REBOOT     ${CYAN}|${NC} [17] RESTART     ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} [02] VMESS MENU      ${CYAN}|${NC} [10] INFO PORT       ${CYAN}|${NC} [18] SET DOMAIN  ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} [03] VLESS MENU      ${CYAN}|${NC} [11] SPEEDTEST       ${CYAN}|${NC} [19] RENEW SSL   ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} [04] TROJAN MENU     ${CYAN}|${NC} [12] CEK RUNNING     ${CYAN}|${NC} [20] INS. UDP    ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} [05] SHADOWSOCKS     ${CYAN}|${NC} [13] CLEAR LOG       ${CYAN}|${NC} [21] CLEAR CACHE ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} [06] TRIAL ACCOUNT   ${CYAN}|${NC} [14] BACKUP BOT      ${CYAN}|${NC} [22] BANDWIDTH   ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} [07] CEK RAM/CPU     ${CYAN}|${NC} [15] BACKUP LOCAL    ${CYAN}|${NC} [23] UPDATE SC   ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} [08] DELETE EXP      ${CYAN}|${NC} [16] REBOOT VPS      ${CYAN}|${NC} [24] BOT MENU    ${CYAN}│${NC}"
echo -e "${CYAN}└─────────────────────────────────────────────────────────┘${NC}"
read -p " Select Menu : " opt

# Simple handling untuk menu CLI
case $opt in
    24) 
       clear
       echo "SETUP BOT TELEGRAM"
       read -p "Token: " t
       read -p "ID Admin: " i
       mkdir -p /etc/funny
       echo "BOT_TOKEN='$t'" > /etc/funny/bot.conf
       echo "ADMIN_CHAT='$i'" >> /etc/funny/bot.conf
       systemctl restart vpsbot
       echo "Bot Connected." ; sleep 2 ; menu ;;
    *) echo "Gunakan Bot Telegram untuk fitur lengkap!" ; sleep 2 ; menu ;;
esac
EOF
chmod +x /usr/bin/menu

# 8. MEMBUAT BOT PYTHON (GUI PREMIUM)
cat > /usr/bin/premium_bot.py << 'EOF'
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
import subprocess
import os
import psutil
import sys
import json
import datetime

# Config
CONFIG_FILE = "/etc/funny/bot.conf"
try:
    cfg = {}
    with open(CONFIG_FILE) as f:
        for l in f:
            if "=" in l:
                k, v = l.strip().split("=", 1)
                cfg[k] = v.strip("'\"")
    TOKEN = cfg.get("BOT_TOKEN")
    ADMIN_ID = str(cfg.get("ADMIN_CHAT"))
except:
    sys.exit()

bot = telebot.TeleBot(TOKEN)

def get_sys():
    ip = subprocess.getoutput("curl -s ifconfig.me")
    dom = subprocess.getoutput("cat /etc/xray/domain")
    ram = psutil.virtual_memory()
    os_v = subprocess.getoutput("cat /etc/os-release | grep PRETTY_NAME | cut -d'\"' -f2")
    return ip, dom, os_v

def count():
    s = subprocess.getoutput("cat /etc/xray/db/ssh | wc -l")
    m = subprocess.getoutput("cat /etc/xray/db/vmess | wc -l")
    l = subprocess.getoutput("cat /etc/xray/db/vless | wc -l")
    t = subprocess.getoutput("cat /etc/xray/db/trojan | wc -l")
    return s, m, l, t

def main_kb():
    m = InlineKeyboardMarkup()
    m.row(InlineKeyboardButton("SSH", callback_data="menu_ssh"), InlineKeyboardButton("Vmess", callback_data="menu_vmess"))
    m.row(InlineKeyboardButton("Vless", callback_data="menu_vless"), InlineKeyboardButton("Trojan", callback_data="menu_trojan"))
    m.row(InlineKeyboardButton("Info", callback_data="info"), InlineKeyboardButton("Settings", callback_data="settings"))
    return m

def sub_kb(p):
    m = InlineKeyboardMarkup()
    m.row(InlineKeyboardButton("Trial", callback_data=f"try_{p}"), InlineKeyboardButton("Create", callback_data=f"add_{p}"))
    m.row(InlineKeyboardButton("Renew", callback_data=f"rnw_{p}"), InlineKeyboardButton("Delete", callback_data=f"del_{p}"))
    m.row(InlineKeyboardButton("List Member", callback_data=f"lst_{p}"))
    m.row(InlineKeyboardButton("‹ Back ›", callback_data="home"))
    return m

@bot.message_handler(commands=['start', 'menu'])
def start(m):
    if str(m.chat.id) != ADMIN_ID: return
    ip, dom, os_v = get_sys()
    s, vm, vl, tr = count()
    msg = f"<b>✧⟨ ❇️ ROBOT PRIVATE ❇️ ⟩✧</b>\n━━━━━━━━━━━━━━━━\n<b>» OS:</b> {os_v}\n<b>» IP:</b> <code>{ip}</code>\n<b>» Domain:</b> <code>{dom}</code>\n\n<b>🌀 » Total Akun:</b>\n🏷️ <b>SSH:</b> {s} | 🏷️ <b>Vmess:</b> {vm}\n🏷️ <b>Vless:</b> {vl} | 🏷️ <b>Trojan:</b> {tr}"
    bot.send_message(m.chat.id, msg, parse_mode='HTML', reply_markup=main_kb())

@bot.callback_query_handler(func=lambda c: True)
def cb(c):
    if str(c.message.chat.id) != ADMIN_ID: return
    d = c.data
    
    if d == "home": start(c.message)
    elif d.startswith("menu_"):
        p = d.split("_")[1]
        bot.edit_message_text(chat_id=c.message.chat.id, message_id=c.message.message_id, text=f"<b>⚙️ {p.upper()} SERVICE</b>", parse_mode='HTML', reply_markup=sub_kb(p))
    
    elif d.startswith("add_"):
        p = d.split("_")[1]
        msg = bot.send_message(c.message.chat.id, f"<b>CREATE {p.upper()}</b>\nMasukkan Username:", parse_mode='HTML')
        bot.register_next_step_handler(msg, get_user, p)
        
    elif d.startswith("del_"):
        p = d.split("_")[1]
        l = subprocess.getoutput(f"cat /etc/xray/db/{p}")
        msg = bot.send_message(c.message.chat.id, f"<b>DELETE {p.upper()}</b>\nList:\n<code>{l}</code>\n\nKetik Username:", parse_mode='HTML')
        bot.register_next_step_handler(msg, do_del, p)
        
    elif d.startswith("lst_"):
        p = d.split("_")[1]
        l = subprocess.getoutput(f"cat /etc/xray/db/{p}")
        bot.send_message(c.message.chat.id, f"<b>LIST {p.upper()}</b>\n{l}", parse_mode='HTML')

def get_user(m, p):
    u = m.text
    msg = bot.reply_to(m, "Expired (hari):")
    bot.register_next_step_handler(msg, get_exp, p, u)

def get_exp(m, p, u):
    e = m.text
    if p == "ssh":
        bot.reply_to(m, "Password:")
        bot.register_next_step_handler(m, do_ssh, u, e)
        return
    
    bot.send_message(m.chat.id, "⏳ Generating...")
    try:
        raw = subprocess.check_output(f"bash /usr/bin/bot-add-{p} {u} {e}", shell=True).decode()
        data = json.loads(raw)
        exp_date = (datetime.datetime.now() + datetime.timedelta(days=int(e))).strftime("%Y-%m-%d")
        
        msg = f"""
<b>◇⟨{p.upper()} ACCOUNT⟩◇</b>
────────────────
<b>» Username :</b> <code>{u}</code>
<b>» Domain :</b> <code>{data['domain']}</code>
<b>» City :</b> {data['city']}
<b>» ISP :</b> {data['isp']}
────────────────
<b>» URL TLS :</b>
<code>{data['link_tls']}</code>

<b>» URL HTTP :</b>
<code>{data['link_none']}</code>
────────────────
<b>(Link Save Account)</b>
<a href="{data['file_url']}">{data['file_url']}</a>
────────────────
<b>» Expired :</b> <code>{exp_date}</code>
"""
        bot.send_message(m.chat.id, msg, parse_mode='HTML')
    except Exception as z:
        bot.send_message(m.chat.id, f"Error: {z}")

def do_ssh(m, u, e):
    pw = m.text
    try:
        out = subprocess.check_output(f"bash /usr/bin/bot-add-ssh {u} {pw} {e}", shell=True).decode()
        bot.send_message(m.chat.id, f"<b>SSH Created</b>\n{out}", parse_mode='HTML')
    except: pass

def do_del(m, p):
    u = m.text
    try:
        subprocess.check_output(f"bash /usr/bin/bot-del-user {p} {u}", shell=True)
        bot.send_message(m.chat.id, f"✅ <b>{u}</b> Deleted from {p.upper()}", parse_mode='HTML')
    except: pass

bot.polling()
EOF

# 9. ENABLE SERVICE BOT
cat > /etc/systemd/system/vpsbot.service << END
[Unit]
Description=Premium GUI Bot
After=network.target
[Service]
ExecStart=/usr/bin/python3 /usr/bin/premium_bot.py
Restart=always
User=root
[Install]
WantedBy=multi-user.target
END

systemctl daemon-reload
systemctl enable vpsbot
systemctl restart vpsbot

# 10. FINISH
clear
echo "=========================================="
echo "   FULL PREMIUM SCRIPT INSTALLED"
echo "=========================================="
echo " 1. Ketik 'menu' -> Pilih 24 -> Masukkan Token & ID"
echo " 2. Buka Telegram -> Ketik /start"
echo " 3. Upload script ini ke GitHub dengan nama 'setup.sh'"
echo "=========================================="
