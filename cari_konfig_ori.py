import socket
import ssl
import json
import time
import os
import sys
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- KONFIGURASI ---
SSH_FILE = 'ssh_accounts.json'
MAX_THREADS = 20 

class Col:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    FAIL = '\033[91m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# --- 1. SMART RESOLVER ---
def get_socket_target(bug_input):
    # Deteksi apakah input adalah IP atau Domain
    try:
        socket.inet_aton(bug_input)
        return bug_input, "IP_ADDRESS"
    except socket.error:
        try:
            ip = socket.gethostbyname(bug_input)
            return ip, "DOMAIN"
        except:
            return None, "ERROR"

# --- 2. USER AGENT ---
class UserAgentManager:
    def generate(self, provider_code):
        av = random.choice(["10", "11", "12", "13"])
        cv = f"{random.randint(110,125)}.0.{random.randint(4000,6000)}.{random.randint(50,150)}"
        base_ua = f"Mozilla/5.0 (Linux; Android {av}; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{cv} Mobile Safari/537.36"
        uas = {
            "1": {"name": "Telkomsel", "ua": f"MyTelkomsel/9.{random.randint(0,9)}.0 {base_ua}"},
            "2": {"name": "XL/Axis", "ua": f"MyXL/8.{random.randint(5,15)}.0 {base_ua}"},
            "3": {"name": "Indosat", "ua": f"myIM3/10.{random.randint(1,10)}.0 {base_ua}"},
            "4": {"name": "Universal", "ua": base_ua}
        }
        return uas.get(provider_code, uas["4"])

# --- 3. PAYLOAD GENERATOR ---
class PayloadGenerator:
    def __init__(self):
        self.methods = [
            "GET", "HEAD", "POST", "CONNECT", "OPTIONS", "TRACE", 
            "PUT", "DELETE", "PATCH", "PROPFIND"
        ]

    def get_raw_templates(self):
        return {
            "1": {"name": "Normal (Single Host)", "raw": "[method] http://[host_primary]/ HTTP/1.1[crlf]Host: [host_primary][crlf]User-Agent: [ua][crlf]Connection: Keep-Alive[crlf][crlf]"},
            "2": {"name": "WS (Single Host)",     "raw": "[method] / HTTP/1.1[crlf]Host: [host_primary][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf][crlf]"},
            "3": {"name": "WS (Double Host)",     "raw": "[method] / HTTP/1.1[crlf]Host: [host_primary][crlf]Upgrade: websocket[crlf]Host: [host_secondary][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf][crlf]"},
            "4": {"name": "Split (Mix Host)",     "raw": "[method] / HTTP/1.1[crlf]Host: [host_primary][crlf]X-Online-Host: [host_secondary][crlf]User-Agent: [ua][crlf][crlf]"},
            "5": {"name": "CF Trace (CDN)",       "raw": "[method] /cdn-cgi/trace HTTP/1.1[crlf]Host: [host_primary][crlf]User-Agent: [ua][crlf][crlf]"}
        }

    def build_payloads(self, bug_input, bug_type, ssh_host, ua, user_choice):
        payloads = []
        templates = self.get_raw_templates()
        
        # Logika Kategori (User choice 1-5, 6=ALL, 7=SNI Only, 8=Payload Only)
        # Jika 7 atau 8, kita pakai semua template HTTP untuk pengetesan
        active_templates = {}
        if user_choice in ['6', '8']: 
            active_templates = templates
        elif user_choice in templates:
            active_templates = {user_choice: templates[user_choice]}
        else:
            return [] # Untuk SNI Only (7), tidak butuh payload text

        # Logika Host Pair (Mix IP/Domain/SSH)
        host_pairs = [] 
        if bug_type == "IP_ADDRESS":
            host_pairs.append((ssh_host, ssh_host, "Host:SSH"))
        else: 
            host_pairs.append((ssh_host, ssh_host, "Host:SSH"))
            host_pairs.append((bug_input, bug_input, "Host:BUG"))
            host_pairs.append((bug_input, ssh_host, "Host:MIX(Bug+SSH)"))

        for t_id, t_data in active_templates.items():
            for m in self.methods:
                for h_prim, h_sec, h_label in host_pairs:
                    if "Single" in t_data['name'] and h_prim != h_sec: continue
                    
                    raw = t_data['raw'].replace("[method]", m).replace("[crlf]", "\r\n") \
                          .replace("[host_primary]", h_prim).replace("[host_secondary]", h_sec) \
                          .replace("[ua]", ua)
                    
                    payloads.append({
                        "cat": t_data['name'],
                        "disp": f"[{m}] {h_label}",
                        "body": raw
                    })
        return payloads

# --- 4. ENGINE: SNI ONLY ---
def check_sni(target_ip, sni_host):
    """
    Hanya cek handshake SSL dengan SNI tertentu.
    Tanpa kirim payload HTTP.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    res = {"st": "FAIL", "msg": "Timeout", "col": Col.FAIL}
    
    try:
        sock.connect((target_ip, 443))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        # INTI LOGIC: Wrap socket dengan server_hostname = SNI Host
        sock = ctx.wrap_socket(sock, server_hostname=sni_host)
        
        # Jika sampai sini tanpa error, berarti Handshake Sukses
        # Kita kirim sedikit data dummy untuk memancing respon server
        sock.sendall(f"GET / HTTP/1.1\r\nHost: {sni_host}\r\n\r\n".encode())
        data = sock.recv(1024)
        
        res["st"] = "HIT"
        res["col"] = Col.GREEN
        res["msg"] = "Handshake OK (SSL Connected)"
        
    except ssl.SSLError:
        res["msg"] = "SSL Error (Wrong SNI?)"
    except Exception as e:
        res["msg"] = "Connection Refused"
    finally:
        sock.close()
    return res

# --- 5. ENGINE: SOCKET SCANNER (PAYLOAD) ---
def scan_socket(target_ip, port, ssl_mode, payload_data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2.0)
    
    res = {"st": "FAIL", "resp": "", "col": Col.FAIL, "info": payload_data['disp'], "cat": payload_data['cat']}
    
    try:
        sock.connect((target_ip, port))
        
        if ssl_mode:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # SNI menggunakan target_ip (jika bug=domain) atau skip jika bug=ip
            # Payload text sudah membawa Host header yang benar
            sock = ctx.wrap_socket(sock, server_hostname=target_ip)
            
        sock.sendall(payload_data['body'].encode())
        resp = sock.recv(4096).decode('utf-8', errors='ignore')
        
        if not resp:
            res["resp"] = "Empty"; return res
            
        head = resp.split('\n')[0].strip()
        res["resp"] = head
        
        if any(x in head for x in ["200", "101", "Switching", "301", "302", "Found", "400"]):
            res["st"] = "HIT"
            res["col"] = Col.GREEN if "200" in head or "101" in head else Col.YELLOW
            
    except: res["resp"] = "Err"
    finally: sock.close()
    return res

# --- 6. CONTROLLER ---
def run_scan_controller(account, bug_input, provider_code, type_code):
    # 1. Resolve IP
    target_ip, bug_type = get_socket_target(bug_input)
    if not target_ip: print(f"Fatal Error: {bug_input}"); return

    # 2. Prepare Resources
    ua_mgr = UserAgentManager()
    pay_gen = PayloadGenerator()
    ua = ua_mgr.generate(provider_code)['ua']
    
    clear_screen()
    print(f"{Col.HEADER}=== BUG SCANNER V10 (COMPLETE) ==={Col.ENDC}")
    print(f"Target Proxy : {Col.BOLD}{target_ip}{Col.ENDC} ({bug_type})")
    
    # --- LOGIKA EKSEKUSI BERDASARKAN PILIHAN ---
    
    # >>> MODE SNI ONLY (Atau ALL)
    if type_code == '7' or type_code == '6':
        print(f"\n{Col.BLUE}### MODE: SNI HANDSHAKE ONLY (443) ###{Col.ENDC}")
        sni_targets = []
        if bug_type == "DOMAIN":
            sni_targets.append(bug_input) # Cek Bug Domain
        sni_targets.append(account['host']) # Cek SSH Domain (Mix)
        
        for sni in sni_targets:
            r = check_sni(target_ip, sni)
            print(f"SNI Host: {sni:<25} -> {r['col']}{r['msg']}{Col.ENDC}")

    # >>> MODE PAYLOAD ONLY (Atau ALL)
    if type_code == '8' or type_code == '6':
        print(f"\n{Col.BLUE}### MODE: PAYLOAD ONLY (PORT 80 - NO SSL) ###{Col.ENDC}")
        # Generate payload khusus untuk Port 80
        payloads = pay_gen.build_payloads(bug_input, bug_type, account['host'], ua, '8')
        
        # Kelompokkan per kategori biar rapi
        cats = sorted(list(set([p['cat'] for p in payloads])))
        for c in cats:
            print(f"{Col.YELLOW}--- {c} ---{Col.ENDC}")
            batch = [p for p in payloads if p['cat'] == c]
            with ThreadPoolExecutor(max_workers=MAX_THREADS) as exe:
                futures = {exe.submit(scan_socket, target_ip, 80, False, p): p for p in batch}
                for f in as_completed(futures):
                    r = f.result()
                    if r['st'] != "FAIL":
                        print(f"[{r['col']}{r['st']}{Col.ENDC}] {r['info']:<35} -> {r['col']}{r['resp']}{Col.ENDC}")

    # >>> MODE SSL/TLS PAYLOAD (Jika user pilih specific payload atau ALL, tapi bukan khusus Payload Only)
    if type_code not in ['7', '8']: 
        print(f"\n{Col.BLUE}### MODE: SSL/TLS PAYLOAD (PORT 443) ###{Col.ENDC}")
        payloads = pay_gen.build_payloads(bug_input, bug_type, account['host'], ua, type_code)
        
        cats = sorted(list(set([p['cat'] for p in payloads])))
        for c in cats:
            print(f"{Col.YELLOW}--- {c} ---{Col.ENDC}")
            batch = [p for p in payloads if p['cat'] == c]
            with ThreadPoolExecutor(max_workers=MAX_THREADS) as exe:
                futures = {exe.submit(scan_socket, target_ip, 443, True, p): p for p in batch}
                for f in as_completed(futures):
                    r = f.result()
                    if r['st'] != "FAIL":
                        print(f"[{r['col']}{r['st']}{Col.ENDC}] {r['info']:<35} -> {r['col']}{r['resp']}{Col.ENDC}")

# --- MAIN LOOP ---
def load_db():
    try: 
        with open(SSH_FILE) as f: return json.load(f)
    except: return []

def save_db(d):
    with open(SSH_FILE, 'w') as f: json.dump(d, f, indent=4)

def main():
    while True:
        clear_screen()
        print(f"{Col.HEADER}########################################")
        print("   PYTHON BUG SCANNER V10 (COMPLETE)    ")
        print("########################################{Col.ENDC}")
        print("1. Start Scanner")
        print("2. Add SSH Account")
        print("3. Delete SSH Account")
        print("4. Exit")
        
        o = input("\n>> ")
        if o == '1':
            db = load_db()
            if not db: print("No Account!"); time.sleep(1); continue
            
            print(f"\n{Col.CYAN}[1] Select SSH (Untuk Mixing Host){Col.ENDC}")
            for i,v in enumerate(db): print(f"{i+1}. {v['host']}")
            try: acc = db[int(input("No: "))-1]
            except: continue
            
            print(f"\n{Col.CYAN}[2] Input Bug (IP / Domain){Col.ENDC}")
            bg = input("Host: ")
            
            print(f"\n{Col.CYAN}[3] Select Method{Col.ENDC}")
            print("1. Normal Payload")
            print("2. WebSocket Payload")
            print("3. WS Double Host")
            print("4. Enhanced Split")
            print("5. CF Trace")
            print("-" * 20)
            print(f"{Col.BOLD}6. SCAN ALL (Termasuk SNI & Payload Only){Col.ENDC}")
            print(f"{Col.GREEN}7. SNI ONLY (Handshake Check){Col.ENDC}")
            print(f"{Col.GREEN}8. PAYLOAD ONLY (HTTP Port 80){Col.ENDC}")
            
            ty = input("Type: ")
            pv = input("\nProvider (1.Tsel 2.XL 3.Isat 4.Uni): ")
            
            run_scan_controller(acc, bg, pv, ty)
            input("\nDone. Press Enter...")
            
        elif o == '2':
            h=input("Host: ");p=input("Port: ");u=input("User: ");pw=input("Pass: ")
            d=load_db();d.append({"host":h,"port":p,"username":u,"password":pw})
            save_db(d);print("Saved.")
        elif o == '3':
            d=load_db()
            for i,x in enumerate(d): print(f"{i+1}. {x['host']}")
            try: d.pop(int(input("Del: "))-1);save_db(d)
            except:pass
        elif o == '4': sys.exit()

if __name__ == "__main__":
    main()