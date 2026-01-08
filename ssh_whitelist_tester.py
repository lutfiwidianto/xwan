#!/usr/bin/env python3
"""
SSH Whitelist Bypass Tester
Untuk menguji kerentanan bug domain/whitelist provider (seperti XL dengan kuota iflix)
Author: Security Tester
Version: 2.2 - Fixed EXTRA_HEADERS Scope Issue
"""

import json
import socket
import ssl
import time
import datetime
from pathlib import Path
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# ========== KONFIGURASI ==========
DEFAULT_TIMEOUT = 8
QUICK_TIMEOUT = 3
SNI_TIMEOUT = 3
PAYLOAD_ONLY_TIMEOUT = 3
SPLIT_DELAY = 0.3

OUTPUT_FILE = "Result_ssh_whitelist.txt"
ACCOUNTS_FILE = Path(r"c:\xwan\ssh_accounts.json")

# Port yang akan di-test untuk SSH
SSH_PORTS = [22, 80, 443]

# HTTP Methods
METHODS = ["GET", "POST", "PATCH", "PUT", "HEAD", "OPTIONS", "CONNECT"]

# Path yang akan di-test
PATHS = ["/", "/ws", "/websocket", "/wss", "/proxy", "/connect", "/api", "/stream", "/video"]
WS_PATHS = {"/ws", "/websocket", "/wss"}

# Port yang akan di-scan
PORTS = [80, 443, 8080, 8880, 2082, 2083, 8443, 2052, 2053]
TLS_PORTS = {443, 8443, 2053, 2083}

# Enable split payload
ENABLE_SPLIT = True

# Default headers
DEFAULT_EXTRA_HEADERS = [
    ("X-Online-Host", "{host}"),
    ("X-Forward-Host", "{host}"),
    ("X-Host", "{host}"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("CF-Connecting-IP", "127.0.0.1"),
    ("X-Original-Host", "www.iflix.com"),
    ("Forwarded", "for=127.0.0.1;host=www.iflix.com;proto=https"),
    ("Via", "1.1 iflix.com"),
]

# ========== FUNGSI UTILITAS ==========
def parse_host_port(line):
    """Parse host:port dari string"""
    line = line.strip()
    if not line:
        return None, None
    if ":" in line:
        host, port_str = line.rsplit(":", 1)
        if port_str.isdigit():
            return host.strip(), int(port_str)
    return line, None


def payload_to_http_custom(raw_payload):
    """Convert payload untuk display"""
    return raw_payload.replace("\r\n", "[crlf]")


def format_host_header(host, port):
    """Format Host header"""
    if host is None:
        return ""
    return f"{host}:{port}" if port else host


def header_combinations(headers):
    """Generate semua kombinasi header"""
    combos = [[]]
    for header in headers:
        combos += [c + [header] for c in combos]
    return combos


def format_extra_headers(extra_headers, host_only):
    """Format extra headers"""
    lines = []
    for header_name, value_tmpl in extra_headers:
        value = value_tmpl.format(host=host_only)
        lines.append(f"{header_name}: {value}")
    return lines


def expand_payload(raw_payload, name):
    """Generate payload variants (normal dan split)"""
    variants = []
    display = payload_to_http_custom(raw_payload)
    variants.append((name, raw_payload, display, None))
    
    if ENABLE_SPLIT:
        split_at = len(raw_payload) // 2
        display_split = payload_to_http_custom(raw_payload[:split_at]) + "[split]" + payload_to_http_custom(raw_payload[split_at:])
        variants.append((f"{name}_SPLIT", raw_payload, display_split, split_at))
    
    return variants


def build_payload_variants(host_header, host_only, ssh_host, ssh_port, extra_headers, whitelist_domain=None):
    """Build semua variant payload"""
    payloads = []
    extra_lines = format_extra_headers(extra_headers, host_only)
    
    # Gunakan whitelist domain jika ada, jika tidak gunakan host_header biasa
    effective_host = whitelist_domain if whitelist_domain else host_header
    
    for method in METHODS:
        if method == "CONNECT":
            lines = [
                f"CONNECT {ssh_host}:{ssh_port} HTTP/1.1",
                f"Host: {effective_host}",
                "Connection: Keep-Alive",
            ]
            lines.extend(extra_lines)
            raw = "\r\n".join(lines) + "\r\n\r\n"
            
            suffix = "_WHITELIST" if whitelist_domain else ""
            payloads.extend(expand_payload(raw, f"CONNECT_SSH{suffix}"))
            continue
        
        for path in PATHS:
            lines = [
                f"{method} {path} HTTP/1.1",
                f"Host: {effective_host}",
                "Connection: Keep-Alive",
            ]
            if path in WS_PATHS:
                lines.append("Upgrade: websocket")
            lines.extend(extra_lines)
            raw = "\r\n".join(lines) + "\r\n\r\n"
            
            name_path = path.strip("/") or "root"
            suffix = "_WHITELIST" if whitelist_domain else ""
            payloads.extend(expand_payload(raw, f"{method}_{name_path}{suffix}"))
    
    return payloads


def open_socket(proxy_host, proxy_port, use_tls, sni_host, timeout):
    """Buka socket connection"""
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    if use_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(sock, server_hostname=sni_host or proxy_host)
    sock.settimeout(timeout)
    return sock


def check_sni(proxy_host, sni_host, timeout):
    """Cek SNI compatibility"""
    sock = None
    try:
        sock = open_socket(proxy_host, 443, True, sni_host, timeout)
        sock.sendall(f"GET / HTTP/1.1\r\nHost: {sni_host}\r\n\r\n".encode())
        data = sock.recv(1024)
        return b"HTTP/" in data
    except Exception:
        return False
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def try_http_payload(proxy_host, proxy_port, use_tls, sni_host, raw_payload, split_at, timeout):
    """Coba payload HTTP saja"""
    sock = None
    try:
        sock = open_socket(proxy_host, proxy_port, use_tls, sni_host, timeout)
        if split_at:
            sock.sendall(raw_payload[:split_at].encode())
            time.sleep(SPLIT_DELAY)
            sock.sendall(raw_payload[split_at:].encode())
        else:
            sock.sendall(raw_payload.encode())
        time.sleep(1)
        response = sock.recv(4096)
        return response
    except Exception:
        return b""
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def status_line_from_response(response):
    """Extract status line dari response"""
    if not response:
        return ""
    return response.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore")


def is_http_hit(status_line):
    """Cek apakah HTTP response valid"""
    if not status_line:
        return False
    if "HTTP/" not in status_line:
        return False
    for code in ("200", "101", "301", "302", "400", "403", "500"):
        if code in status_line:
            return True
    return False


def try_payload(proxy_host, proxy_port, use_tls, sni_host, raw_payload, split_at, ssh_host, ssh_port, username, password, timeout):
    """Coba payload lengkap dengan SSH auth"""
    sock = None
    try:
        sock = open_socket(proxy_host, proxy_port, use_tls, sni_host, timeout)
        if split_at:
            sock.sendall(raw_payload[:split_at].encode())
            time.sleep(SPLIT_DELAY)
            sock.sendall(raw_payload[split_at:].encode())
        else:
            sock.sendall(raw_payload.encode())
        time.sleep(1)
        auth = f"CONNECT {username}:{password}@{ssh_host}:{ssh_port}\r\n\r\n"
        sock.sendall(auth.encode())
        time.sleep(2)
        response = sock.recv(4096)
        return b"SSH-2.0" in response
    except Exception:
        return False
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def generate_ssh_config(payload_display, proxy_host, proxy_port, whitelist_domain, ssh_host, ssh_port, username, password):
    """Generate konfigurasi SSH untuk koneksi berhasil"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    config = f"""
# ===========================================
# Konfigurasi SSH Whitelist Bypass
# Generated: {timestamp}
# ===========================================
# Domain Whitelist: {whitelist_domain}
# Proxy Server: {proxy_host}:{proxy_port}
# SSH Server: {ssh_host}:{ssh_port}
# ===========================================

Host ssh-whitelist-{timestamp}
    HostName {ssh_host}
    Port {ssh_port}
    User {username}
    ServerAliveInterval 60
    ServerAliveCountMax 3
    TCPKeepAlive yes
    
    # Method 1: Menggunakan corkscrew (jika tersedia)
    # ProxyCommand corkscrew {proxy_host} {proxy_port} {whitelist_domain} {ssh_port}
    
    # Method 2: Menggunakan nc/ncat (Netcat)
    ProxyCommand ncat --proxy {proxy_host}:{proxy_port} --proxy-type http %h %p
    
    # Method 3: Menggunakan OpenSSH built-in (OpenSSH 7.3+)
    # ProxyCommand ssh -W %h:%p proxy-user@{proxy_host} -p {proxy_port}
    
    # Payload yang berhasil:
    # {payload_display}
    
    # Cara pakai:
    # ssh -F ssh_config_{timestamp}.txt ssh-whitelist-{timestamp}
    # Atau
    # ssh -o "ProxyCommand=ncat --proxy {proxy_host}:{proxy_port} --proxy-type http %h %p" {username}@{ssh_host} -p {ssh_port}

# ===========================================
# Quick Command (copy-paste):
# ssh -o "ProxyCommand=ncat --proxy {proxy_host}:{proxy_port} --proxy-type http --proxy-auth {username}:{password} %h %p" {username}@{ssh_host} -p {ssh_port}
# ===========================================
"""
    
    config_file = f"ssh_config_{timestamp}.txt"
    with open(config_file, "w", encoding="utf-8") as f:
        f.write(config)
    
    print(f"{Fore.GREEN}[✓] Konfigurasi SSH disimpan di: {config_file}{Style.RESET_ALL}")
    return config_file


def write_result(payload_display, proxy_host, proxy_port, whitelist_domain, ssh_host, ssh_port, username, password, ssl_value):
    """Tulis hasil ke file"""
    lines = [
        "=" * 50,
        f"SSH WHITELIST BYPASS RESULT",
        f"Waktu: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 50,
        f"[PAYLOAD] {payload_display}",
        "-" * 50,
        f"[PROXY] {proxy_host}:{proxy_port}",
        f"[WHITELIST DOMAIN] {whitelist_domain}",
        f"[SSL/SNI] {ssl_value}",
        "-" * 50,
        f"[SSH SERVER] {ssh_host}:{ssh_port}",
        f"[USERNAME] {username}",
        f"[PASSWORD] {password}",
        "-" * 50,
        "",
    ]
    
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write("\n".join(lines))
    
    # Generate config SSH
    config_file = generate_ssh_config(payload_display, proxy_host, proxy_port, whitelist_domain, ssh_host, ssh_port, username, password)
    
    # Tambahkan info config file ke output
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write(f"[CONFIG FILE] {config_file}\n")
        f.write("=" * 50 + "\n\n")
    
    print(f"{Fore.GREEN}[✓] Hasil tersimpan di: {OUTPUT_FILE}{Style.RESET_ALL}")


def unique_list(values):
    """Remove duplicates dari list"""
    seen = set()
    result = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def load_accounts():
    """Load akun SSH dari file"""
    if not ACCOUNTS_FILE.exists():
        return []
    try:
        return json.loads(ACCOUNTS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def save_accounts(accounts):
    """Simpan akun SSH ke file"""
    ACCOUNTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    ACCOUNTS_FILE.write_text(json.dumps(accounts, indent=2), encoding="utf-8")


def select_account():
    """Pilih atau tambah akun SSH"""
    accounts = load_accounts()
    
    while True:
        print(f"\n{Fore.CYAN}[*] SSH Accounts Management{Style.RESET_ALL}")
        print("-" * 40)
        
        for idx, acc in enumerate(accounts, 1):
            print(f"[{idx}] {acc['host']}:{acc.get('port', 22)} | {acc['username']}")
        
        print(f"[{len(accounts) + 1}] Tambah akun baru")
        print(f"[{len(accounts) + 2}] Edit akun")
        print(f"[{len(accounts) + 3}] Hapus akun")
        print(f"[{len(accounts) + 4}] Input manual (tidak disimpan)")
        print(f"[{len(accounts) + 5}] Keluar")
        
        choice = input(f"\n{Fore.YELLOW}[?] Pilih menu (1-5): {Style.RESET_ALL}").strip()
        
        if not choice.isdigit():
            print(f"{Fore.RED}[!] Input harus angka{Style.RESET_ALL}")
            continue
        
        choice_num = int(choice)
        
        # Pilih akun yang ada
        if 1 <= choice_num <= len(accounts):
            return accounts[choice_num - 1]
        
        # Tambah akun baru
        elif choice_num == len(accounts) + 1:
            print(f"\n{Fore.CYAN}[*] Tambah Akun Baru{Style.RESET_ALL}")
            host = input("[*] Host SSH : ").strip()
            port = input("[*] Port SSH [22]: ").strip()
            username = input("[*] Username : ").strip()
            password = input("[*] Password : ").strip()
            
            if not host or not username:
                print(f"{Fore.RED}[!] Host dan Username wajib diisi{Style.RESET_ALL}")
                continue
            
            new_acc = {
                "host": host,
                "port": int(port) if port.isdigit() else 22,
                "username": username,
                "password": password
            }
            
            accounts.append(new_acc)
            save_accounts(accounts)
            print(f"{Fore.GREEN}[✓] Akun berhasil disimpan{Style.RESET_ALL}")
            return new_acc
        
        # Edit akun
        elif choice_num == len(accounts) + 2:
            if not accounts:
                print(f"{Fore.RED}[!] Tidak ada akun untuk diedit{Style.RESET_ALL}")
                continue
            
            idx = input("[*] Nomor akun yang akan diedit: ").strip()
            if not idx.isdigit() or not (1 <= int(idx) <= len(accounts)):
                print(f"{Fore.RED}[!] Pilihan tidak valid{Style.RESET_ALL}")
                continue
            
            acc = accounts[int(idx) - 1]
            print(f"\n{Fore.CYAN}[*] Edit Akun: {acc['host']}{Style.RESET_ALL}")
            
            host = input(f"[*] Host SSH [{acc['host']}]: ").strip() or acc["host"]
            port = input(f"[*] Port SSH [{acc.get('port', 22)}]: ").strip()
            username = input(f"[*] Username [{acc['username']}]: ").strip() or acc["username"]
            password = input("[*] Password [tekan enter untuk tetap]: ").strip() or acc["password"]
            
            accounts[int(idx) - 1] = {
                "host": host,
                "port": int(port) if port.isdigit() else acc.get("port", 22),
                "username": username,
                "password": password
            }
            
            save_accounts(accounts)
            print(f"{Fore.GREEN}[✓] Akun berhasil diperbarui{Style.RESET_ALL}")
            continue
        
        # Hapus akun
        elif choice_num == len(accounts) + 3:
            if not accounts:
                print(f"{Fore.RED}[!] Tidak ada akun untuk dihapus{Style.RESET_ALL}")
                continue
            
            idx = input("[*] Nomor akun yang akan dihapus: ").strip()
            if not idx.isdigit() or not (1 <= int(idx) <= len(accounts)):
                print(f"{Fore.RED}[!] Pilihan tidak valid{Style.RESET_ALL}")
                continue
            
            removed = accounts.pop(int(idx) - 1)
            save_accounts(accounts)
            print(f"{Fore.GREEN}[✓] Akun dihapus: {removed['host']}{Style.RESET_ALL}")
            continue
        
        # Input manual
        elif choice_num == len(accounts) + 4:
            print(f"\n{Fore.CYAN}[*] Input Manual Akun SSH{Style.RESET_ALL}")
            host = input("[*] Host SSH : ").strip()
            port = input("[*] Port SSH [22]: ").strip()
            username = input("[*] Username : ").strip()
            password = input("[*] Password : ").strip()
            
            if not host or not username:
                print(f"{Fore.RED}[!] Host dan Username wajib diisi{Style.RESET_ALL}")
                continue
            
            return {
                "host": host,
                "port": int(port) if port.isdigit() else 22,
                "username": username,
                "password": password
            }
        
        # Keluar
        elif choice_num == len(accounts) + 5:
            print(f"{Fore.YELLOW}[!] Keluar dari program{Style.RESET_ALL}")
            exit(0)
        
        else:
            print(f"{Fore.RED}[!] Pilihan tidak valid{Style.RESET_ALL}")


def get_domain_input():
    """Dapatkan input domain dari user"""
    print(f"\n{Fore.CYAN}[*] Pilihan Input Domain Whitelist{Style.RESET_ALL}")
    print("1. Single domain (input manual)")
    print("2. Multiple domains (dari file)")
    print("3. Gunakan default iflix domains")
    
    choice = input(f"\n{Fore.YELLOW}[?] Pilih metode input (1-3): {Style.RESET_ALL}").strip()
    
    domains = []
    
    if choice == "1":
        # Single domain input
        domain = input("[*] Masukkan domain whitelist (contoh: www.iflix.com): ").strip()
        if domain:
            domains.append(domain)
            print(f"{Fore.GREEN}[✓] Domain ditambahkan: {domain}{Style.RESET_ALL}")
    
    elif choice == "2":
        # Multiple domains dari file
        file_path = input("[*] Path ke file domain (contoh: iflix.txt): ").strip()
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    domain = line.strip()
                    if domain and not domain.startswith('#'):
                        domains.append(domain)
            
            print(f"{Fore.GREEN}[✓] Loaded {len(domains)} domains from {file_path}{Style.RESET_ALL}")
            
            # Tampilkan preview
            print(f"\n{Fore.YELLOW}[*] Preview domains (max 10):{Style.RESET_ALL}")
            for i, domain in enumerate(domains[:10], 1):
                print(f"  {i}. {domain}")
            if len(domains) > 10:
                print(f"  ... dan {len(domains) - 10} domain lainnya")
        
        except FileNotFoundError:
            print(f"{Fore.RED}[!] File {file_path} tidak ditemukan{Style.RESET_ALL}")
            return get_domain_input()
        except Exception as e:
            print(f"{Fore.RED}[!] Error membaca file: {e}{Style.RESET_ALL}")
            return get_domain_input()
    
    elif choice == "3":
        # Default iflix domains
        domains = [
            "www.iflix.com",
            "iflix.com",
            "api.iflix.com",
            "cdn.iflix.com",
            "stream.iflix.com",
            "web.iflix.com",
            "m.iflix.com",
            "app.iflix.com"
        ]
        print(f"{Fore.GREEN}[✓] Menggunakan {len(domains)} domain iflix default{Style.RESET_ALL}")
    
    else:
        print(f"{Fore.RED}[!] Pilihan tidak valid{Style.RESET_ALL}")
        return get_domain_input()
    
    # Tambahkan www prefix jika belum ada
    final_domains = []
    for domain in domains:
        final_domains.append(domain)
        if not domain.startswith("www.") and "." in domain:
            final_domains.append(f"www.{domain}")
    
    return unique_list(final_domains)


def get_extra_headers():
    """Dapatkan extra headers berdasarkan domain"""
    print(f"\n{Fore.CYAN}[*] Konfigurasi Header Manipulation{Style.RESET_ALL}")
    print("1. Gunakan header default")
    print("2. Custom headers")
    
    choice = input(f"\n{Fore.YELLOW}[?] Pilih (1-2): {Style.RESET_ALL}").strip()
    
    if choice == "1":
        return DEFAULT_EXTRA_HEADERS
    elif choice == "2":
        headers = []
        print(f"\n{Fore.YELLOW}[*] Format: HeaderName: HeaderValue{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Gunakan {{host}} untuk placeholder domain{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Kosongkan line untuk selesai{Style.RESET_ALL}")
        
        while True:
            header_input = input("Header: ").strip()
            if not header_input:
                break
            
            if ":" in header_input:
                header_name, header_value = header_input.split(":", 1)
                headers.append((header_name.strip(), header_value.strip()))
            else:
                print(f"{Fore.RED}[!] Format salah, gunakan HeaderName: HeaderValue{Style.RESET_ALL}")
        
        if not headers:
            print(f"{Fore.YELLOW}[!] Menggunakan header default{Style.RESET_ALL}")
            return DEFAULT_EXTRA_HEADERS
        
        return headers
    else:
        print(f"{Fore.YELLOW}[!] Menggunakan header default{Style.RESET_ALL}")
        return DEFAULT_EXTRA_HEADERS


def quick_check(proxy_host, port_candidates, ssh_host, ssh_port, username, password, whitelist_domain=None):
    """Quick check untuk proxy"""
    quick_payloads = [
        ("GET_WS", "GET /ws HTTP/1.1\r\nHost: {host}\r\nConnection: Keep-Alive\r\nUpgrade: websocket\r\n\r\n"),
        ("CONNECT_SSH", "CONNECT {ssh_host}:{ssh_port} HTTP/1.1\r\nHost: {host}\r\nConnection: Keep-Alive\r\n\r\n"),
        ("GET_ROOT", "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: Keep-Alive\r\n\r\n"),
    ]
    
    for port in port_candidates:
        use_tls = port in TLS_PORTS
        sni_candidates = [ssh_host, proxy_host, whitelist_domain] if whitelist_domain else [ssh_host, proxy_host]
        sni_candidates = unique_list([s for s in sni_candidates if s])
        
        for sni_host in sni_candidates:
            for name, template in quick_payloads:
                host_to_use = whitelist_domain if whitelist_domain else proxy_host
                host_header = format_host_header(host_to_use, port)
                
                raw_payload = template.format(
                    host=host_header,
                    ssh_host=ssh_host,
                    ssh_port=ssh_port
                )
                
                ok = try_payload(
                    proxy_host,
                    port,
                    use_tls,
                    sni_host,
                    raw_payload,
                    None,
                    ssh_host,
                    ssh_port,
                    username,
                    password,
                    QUICK_TIMEOUT,
                )
                
                if ok:
                    return True
    
    return False


def resolve_domains(domains):
    """Resolve domain ke IP addresses"""
    resolved = {}
    
    # Coba import dnspython, jika tidak ada, skip resolving
    try:
        import dns.resolver
        
        for domain in domains:
            try:
                answers = dns.resolver.resolve(domain, 'A')
                ips = [str(rdata) for rdata in answers]
                resolved[domain] = ips
                print(f"{Fore.GREEN}[✓] {domain} -> {', '.join(ips)}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Tidak bisa resolve {domain}: {e}{Style.RESET_ALL}")
                resolved[domain] = []
    except ImportError:
        print(f"{Fore.YELLOW}[!] Module dnspython tidak tersedia, skip DNS resolving{Style.RESET_ALL}")
        for domain in domains:
            resolved[domain] = []
    
    return resolved


def ssh_whitelist_test():
    """Main function"""
    print(f"\n{Fore.CYAN}=" * 60)
    print(f"SSH WHITELIST BYPASS TESTER")
    print(f"Version 2.2 - Multi Domain Support")
    print("=" * 60 + f"{Style.RESET_ALL}\n")
    
    # Pilih akun SSH
    account = select_account()
    ssh_host = account["host"]
    ssh_port = account.get("port", 22)
    username = account["username"]
    password = account["password"]
    
    print(f"\n{Fore.GREEN}[✓] Akun SSH dipilih:{Style.RESET_ALL}")
    print(f"  Host: {ssh_host}:{ssh_port}")
    print(f"  User: {username}")
    
    # Input domain whitelist
    whitelist_domains = get_domain_input()
    if not whitelist_domains:
        print(f"{Fore.RED}[!] Tidak ada domain yang diinput{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.GREEN}[✓] Domains untuk testing:{Style.RESET_ALL}")
    for i, domain in enumerate(whitelist_domains, 1):
        print(f"  {i}. {domain}")
    
    # Resolve domain ke IP (optional)
    print(f"\n{Fore.CYAN}[*] Resolving domains...{Style.RESET_ALL}")
    resolved_ips = resolve_domains(whitelist_domains)
    
    # Input proxy list
    proxy_file = input(f"\n{Fore.YELLOW}[?] File list proxy/webserver (txt): {Style.RESET_ALL}").strip()
    try:
        with open(proxy_file, 'r', encoding='utf-8') as f:
            proxies = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}[!] File {proxy_file} tidak ditemukan!{Style.RESET_ALL}")
        return
    except Exception as e:
        print(f"{Fore.RED}[!] Error membaca file: {e}{Style.RESET_ALL}")
        return
    
    print(f"{Fore.GREEN}[✓] Loaded {len(proxies)} proxies{Style.RESET_ALL}")
    
    # Pilih mode testing
    print(f"\n{Fore.CYAN}[*] Mode Testing{Style.RESET_ALL}")
    print("1. Normal (test semua domain)")
    print("2. Quick (test hanya domain pertama)")
    print("3. Custom (pilih domain tertentu)")
    
    mode_choice = input(f"\n{Fore.YELLOW}[?] Pilih mode (1-3): {Style.RESET_ALL}").strip() or "1"
    
    # Filter domain berdasarkan mode
    if mode_choice == "2":
        # Quick mode - hanya domain pertama
        test_domains = whitelist_domains[:1]
        print(f"{Fore.YELLOW}[*] Quick mode - testing hanya: {test_domains[0]}{Style.RESET_ALL}")
    elif mode_choice == "3":
        # Custom mode - pilih domain
        print(f"\n{Fore.YELLOW}[*] Pilih domain untuk testing:{Style.RESET_ALL}")
        for i, domain in enumerate(whitelist_domains, 1):
            print(f"  {i}. {domain}")
        
        selections = input("[?] Pilih nomor (contoh: 1,3,5 atau 'all'): ").strip()
        
        if selections.lower() == "all":
            test_domains = whitelist_domains
        else:
            test_domains = []
            for sel in selections.split(','):
                sel = sel.strip()
                if sel.isdigit() and 1 <= int(sel) <= len(whitelist_domains):
                    test_domains.append(whitelist_domains[int(sel) - 1])
            
            if not test_domains:
                print(f"{Fore.RED}[!] Tidak ada domain yang dipilih{Style.RESET_ALL}")
                return
    else:
        # Normal mode - semua domain
        test_domains = whitelist_domains
    
    # Konfigurasi header
    extra_headers = get_extra_headers()
    header_combos = header_combinations(extra_headers)
    
    # Counter
    success_count = 0
    total_tests = len(proxies) * len(test_domains)
    current_test = 0
    
    print(f"\n{Fore.CYAN}[*] Memulai testing...{Style.RESET_ALL}")
    print(f"[*] Total tests: {total_tests} (proxies: {len(proxies)}, domains: {len(test_domains)})")
    print(f"[*] Output file: {OUTPUT_FILE}")
    print("-" * 60)
    
    # Main testing loop
    for proxy_line in proxies:
        proxy_host, proxy_port = parse_host_port(proxy_line)
        if not proxy_host:
            continue
        
        # Port candidates
        port_candidates = [proxy_port] if proxy_port else PORTS
        
        for whitelist_domain in test_domains:
            current_test += 1
            print(f"\n{Fore.CYAN}[{current_test}/{total_tests}] Testing: {proxy_host} → {whitelist_domain}{Style.RESET_ALL}")
            
            # Quick check dulu
            print(f"  {Fore.YELLOW}[*] Quick check...{Style.RESET_ALL}")
            quick_ok = quick_check(proxy_host, port_candidates[:2], ssh_host, ssh_port, username, password, whitelist_domain)
            
            if not quick_ok:
                print(f"  {Fore.RED}[✗] Quick check failed, skipping{Style.RESET_ALL}")
                continue
            
            print(f"  {Fore.GREEN}[✓] Quick check passed{Style.RESET_ALL}")
            
            # Full testing
            success_for_combo = False
            
            for port in port_candidates:
                use_tls = port in TLS_PORTS
                sni_candidates = [whitelist_domain, ssh_host, proxy_host]
                sni_candidates = unique_list([s for s in sni_candidates if s])
                
                for sni_host in sni_candidates:
                    tls_label = f"TLS SNI={sni_host}" if use_tls else "HTTP"
                    print(f"  {Fore.YELLOW}[*] Testing {proxy_host}:{port} ({tls_label}){Style.RESET_ALL}")
                    
                    # Build payload variants
                    host_header = format_host_header(whitelist_domain, port)
                    
                    for extra_headers_combo in header_combos:
                        payloads = build_payload_variants(
                            host_header, whitelist_domain, ssh_host, ssh_port,
                            extra_headers_combo, whitelist_domain
                        )
                        
                        for name, raw_payload, display_payload, split_at in payloads:
                            ok = try_payload(
                                proxy_host, port, use_tls, sni_host,
                                raw_payload, split_at, ssh_host, ssh_port,
                                username, password, DEFAULT_TIMEOUT
                            )
                            
                            if ok:
                                ssl_value = sni_host if use_tls else "HTTP"
                                write_result(
                                    display_payload, proxy_host, port,
                                    whitelist_domain, ssh_host, ssh_port,
                                    username, password, ssl_value
                                )
                                
                                print(f"  {Fore.GREEN}[✓] SUCCESS! {name}{Style.RESET_ALL}")
                                success_count += 1
                                success_for_combo = True
                                break
                        
                        if success_for_combo:
                            break
                    
                    if success_for_combo:
                        break
                
                if success_for_combo:
                    break
            
            if not success_for_combo:
                print(f"  {Fore.RED}[✗] No working payload found{Style.RESET_ALL}")
    
    # Summary
    print(f"\n{Fore.CYAN}" + "=" * 60)
    print(f"TESTING COMPLETED")
    print("=" * 60 + f"{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[✓] Total berhasil: {success_count}/{total_tests}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[✓] Hasil detail: {OUTPUT_FILE}{Style.RESET_ALL}")
    
    if success_count > 0:
        print(f"\n{Fore.YELLOW}[*] Konfigurasi SSH telah di-generate:")
        print(f"[*] Lihat file ssh_config_*.txt untuk konfigurasi lengkap")
        print(f"[*] Gunakan perintah: ssh -F ssh_config_*.txt <hostname>{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}[*] Program selesai{Style.RESET_ALL}")


def main():
    """Entry point"""
    try:
        ssh_whitelist_test()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Program dihentikan oleh user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()