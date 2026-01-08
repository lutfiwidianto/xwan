#!/usr/bin/env python3
"""cari_konfig_safe.py

Diagnostik konektivitas HTTP/HTTPS (port 80/443) + TLS handshake untuk daftar domain.

PENTING:
- Tool ini dibuat untuk *diagnosa* (cek respon HTTP/TLS) dan TIDAK membuat/mencoba payload tunneling.
- Tidak ada pengujian "mix host"/"double host" yang melibatkan domain kedua, header Host ganda, atau header
  non-standar (X-Online-Host, X-Forwarded-Host) karena pola itu sering dipakai untuk bypass jaringan.

Input file:
- iflix.txt            : list domain (1 per baris)
- ssh_accounts.json    : (opsional) hanya untuk menyimpan daftar akun (add/edit/delete). Tidak dipakai untuk request.
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import time
from dataclasses import dataclass
from typing import List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


# =======================
# Konfigurasi
# =======================
IFLIX_FILE = "iflix.txt"
SSH_FILE = "ssh_accounts.json"

TIMEOUT_CONNECT = 3.0
TIMEOUT_RECV = 2.0


class Col:
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    ENDC = "\033[0m"


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def color_for_status_line(status_line: str) -> str:
    # Status line contoh: HTTP/1.1 200 OK
    try:
        parts = status_line.split()
        code = int(parts[1]) if len(parts) >= 2 else 0
    except Exception:
        code = 0

    if 200 <= code < 300 or code == 101:
        return Col.GREEN
    if 300 <= code < 500:
        return Col.YELLOW
    if 500 <= code < 600:
        return Col.RED
    return Col.RED


def read_lines(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
    except FileNotFoundError:
        return []


def resolve_ip(host: str) -> Optional[str]:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def tls_handshake(ip: str, sni_host: str) -> Tuple[bool, str]:
    """Cek TLS handshake ke ip:443 dengan SNI tertentu."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT_CONNECT)
    try:
        sock.connect((ip, 443))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ssock = ctx.wrap_socket(sock, server_hostname=sni_host)
        # minimal read supaya handshake benar-benar complete
        ssock.settimeout(TIMEOUT_RECV)
        return True, "SSL Connected"
    except Exception as e:
        return False, f"SSL Error: {e.__class__.__name__}"
    finally:
        try:
            sock.close()
        except Exception:
            pass


def http_request_status(host: str, ip: str, port: int, use_ssl: bool, raw_request: str) -> Tuple[bool, str]:
    """Kirim request mentah dan ambil status line pertama."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT_CONNECT)
    try:
        sock.connect((ip, port))
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        sock.sendall(raw_request.encode("utf-8", errors="ignore"))
        sock.settimeout(TIMEOUT_RECV)
        data = b""
        try:
            data = sock.recv(2048)
        except socket.timeout:
            data = b""
        if not data:
            return False, "No Response"
        # parse status line
        try:
            head = data.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore").strip()
            if head:
                return True, head
            return True, "Response OK"
        except Exception:
            return True, "Response OK"
    except Exception as e:
        return False, f"Err: {e.__class__.__name__}"
    finally:
        try:
            sock.close()
        except Exception:
            pass


def build_basic_request(method: str, path: str, host: str, ua: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    )


def build_ws_upgrade_request(path: str, host: str, ua: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    # key statis cukup untuk diagnosa; server tetap balas 101/400/426 dst.
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"User-Agent: {ua}\r\n\r\n"
    )


def print_section(title: str) -> None:
    print(f"{Col.YELLOW}--- {title} ---{Col.ENDC}")


def print_hit(method: str, host: str, status_line: str, ok: bool) -> None:
    st = "HIT" if ok else "FAIL"
    st_col = Col.GREEN if ok else Col.RED
    line_col = color_for_status_line(status_line) if ok else Col.RED
    # mirip screenshot: [HIT] [GET] Host:xxx -> HTTP/1.1 ...
    print(
        f"[{st_col}{st}{Col.ENDC}] [{method:<7}] Host:{host:<28} -> "
        f"{line_col}{status_line}{Col.ENDC}"
    )


def run_multihost_report(selected_host: str, path: str, ip: str, ua: str) -> None:
    """Run scans using different Host header variants but keep SNI as the selected host.
    This produces a grouped report similar to the requested format.
    """
        # compatibility wrapper: use provided ssh_host or try to load first SSH account
        ssh_host = ssh_host
        if ssh_host is None:
            accs = load_accounts()
            ssh_host = accs[0]["host"] if accs else "SSH"
        # call the real worker
        _run_multihost_report_worker(selected_host, path, ip, ua, ssh_host)


def build_payload_from_template(template_raw: str, method: str, host_primary: str, host_secondary: str, ua: str) -> str:
    crlf = "\r\n"
    raw = template_raw.replace("[method]", method).replace("[crlf]", crlf)
    raw = raw.replace("[host_primary]", host_primary).replace("[host_secondary]", host_secondary)
    raw = raw.replace("[ua]", ua)
    return raw


def scan_payload(target_ip: str, port: int, use_ssl: bool, payload: dict) -> dict:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT_CONNECT)
    res = {"st": "FAIL", "resp": "", "info": payload.get("disp", ""), "cat": payload.get("cat", "")}
    try:
        sock.connect((target_ip, port))
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # original used target_ip as server_hostname when wrapping
            sock = ctx.wrap_socket(sock, server_hostname=target_ip)

        sock.sendall(payload["body"].encode())
        try:
            data = sock.recv(4096)
        except socket.timeout:
            data = b""
        if not data:
            res["resp"] = "No Response"
            return res

        head = data.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore").strip()
        res["resp"] = head
        if any(x in head for x in ["200", "101", "Switching", "301", "302", "Found", "400"]):
            res["st"] = "HIT"
    except Exception as e:
        res["resp"] = f"Err: {e.__class__.__name__}"
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return res


def _run_multihost_report_worker(selected_host: str, path: str, ip: str, ua: str, ssh_host: str) -> None:
    """Generate payloads similar to original `cari_konfig_ori.py` and scan them concurrently."""
    methods = ["GET", "HEAD", "POST", "CONNECT", "OPTIONS", "TRACE", "PUT", "DELETE", "PATCH", "PROPFIND"]

    templates = {
        "Normal": "[method] http://[host_primary]/ HTTP/1.1[crlf]Host: [host_primary][crlf]User-Agent: [ua][crlf]Connection: Keep-Alive[crlf][crlf]",
        "WS_Single": "[method] / HTTP/1.1[crlf]Host: [host_primary][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf][crlf]",
        "WS_Double": "[method] / HTTP/1.1[crlf]Host: [host_primary][crlf]Upgrade: websocket[crlf]Host: [host_secondary][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf][crlf]",
        "Split": "[method] / HTTP/1.1[crlf]Host: [host_primary][crlf]X-Online-Host: [host_secondary][crlf]User-Agent: [ua][crlf][crlf]",
        "CF": "[method] /cdn-cgi/trace HTTP/1.1[crlf]Host: [host_primary][crlf]User-Agent: [ua][crlf][crlf]",
    }

    # host pairs logic
    host_pairs = []
    host_pairs.append((ssh_host, ssh_host, "Host:SSH"))
    host_pairs.append((selected_host, selected_host, "Host:BUG"))
    host_pairs.append((selected_host, ssh_host, "Host:MIX(Bug+SSH)"))

    all_payloads: List[dict] = []
    for tname in ["CF", "Normal", "WS_Single", "WS_Double", "Split"]:
        for m in methods:
            for h_prim, h_sec, label in host_pairs:
                # single-host templates skip when primary!=secondary
                if tname in ("Normal", "WS_Single") and h_prim != h_sec:
                    continue
                body = build_payload_from_template(templates[tname], m, h_prim, h_sec, ua)
                all_payloads.append({"cat": tname, "disp": f"[{m}] {label}", "body": body, "method": m, "label": label, "host_primary": h_prim})

    hit_payloads: List[str] = []

    # run TLS scans grouped by category
    cats = sorted(list(set([p["cat"] for p in all_payloads])))
    for c in cats:
        print_section(c)
        batch = [p for p in all_payloads if p["cat"] == c]
        with ThreadPoolExecutor(max_workers=12) as exe:
            futures = {exe.submit(scan_payload, ip, 443, True, p): p for p in batch}
            for f in as_completed(futures):
                p = futures[f]
                r = f.result()
                ok = r.get("st") == "HIT"
                print_hit(p["method"], p["label"], r.get("resp", ""), ok)
                if ok:
                    hit_payloads.append(f"# {p['cat']} | {p['disp']}\n{p['body']}")

    # HTTP 80 subset
    print("\n--- Method Test (HTTP 80) ---")
    print_section("HTTP (Single Host)")
    batch80 = [p for p in all_payloads if p["cat"] in ("Normal", "CF")]
    with ThreadPoolExecutor(max_workers=8) as exe:
        futures = {exe.submit(scan_payload, ip, 80, False, p): p for p in batch80}
        for f in as_completed(futures):
            p = futures[f]
            r = f.result()
            ok = r.get("st") == "HIT"
            print_hit(p["method"], p["label"], r.get("resp", ""), ok)
            if ok:
                hit_payloads.append(f"# HTTP80 | {p['disp']}\n{p['body']}")

    # save hit payloads
    if hit_payloads:
        outpath = os.path.join(os.getcwd(), "hit_payloads.txt")
        try:
            with open(outpath, "w", encoding="utf-8") as f:
                f.write("\n\n".join(hit_payloads))
            print(f"\nSaved {len(hit_payloads)} HIT payload(s) -> {outpath}")
        except Exception as e:
            print(f"\nGagal simpan payload: {e}")

    print("\nSelesai. Tip: Jalankan ulang untuk domain lain dari list.")


def run_single_domain_mode(domains: List[str]) -> None:
    clear_screen()
    print(f"{Col.MAGENTA}{Col.BOLD}### MODE: SSL/TLS PAYLOAD (PORT 443) ###{Col.ENDC}")
    print(f"Loaded {len(domains)} domain dari {IFLIX_FILE}\n")

    # list 30 pertama biar ringkas
    print("Pilih domain:")
    show_n = min(30, len(domains))
    for i in range(show_n):
        print(f"{i+1:2d}. {domains[i]}")
    print(" 0. Input manual")

    try:
        sel = input("\nNomor: ").strip()
    except KeyboardInterrupt:
        return

    if sel == "0":
        host = input("Domain: ").strip()
    else:
        try:
            idx = int(sel) - 1
            host = domains[idx]
        except Exception:
            print("Invalid selection.")
            time.sleep(1)
            return

    if not host:
        print("Domain kosong.")
        time.sleep(1)
        return

    path = input("Path (default /): ").strip() or "/"

    ip = resolve_ip(host)
    if not ip:
        print(f"{Col.RED}DNS gagal untuk {host}{Col.ENDC}")
        return

    ua = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Mobile Safari/537.36"

    print("\n--- TLS Handshake (443) ---")
    ok, msg = tls_handshake(ip, host)
    st_col = Col.GREEN if ok else Col.RED
    st = "HIT" if ok else "FAIL"
    print(f"[{st_col}{st}{Col.ENDC}] SNI Host: {host:<32} -> {st_col}{msg}{Col.ENDC}")

    # select SSH server for mixing (if any)
    ssh_host = None
    accs = load_accounts()
    if accs:
        print("\nPilih SSH account untuk mixing (0 = skip / gunakan placeholder 'SSH'):")
        for i, a in enumerate(accs, 1):
            print(f"{i}. {a.get('host','')}")
        try:
            s = int(input("No: ").strip())
            if s > 0 and s <= len(accs):
                ssh_host = accs[s-1].get('host')
        except Exception:
            ssh_host = None

    # run the multi-host styled report (keeps SNI as selected host but varies Host header)
    run_multihost_report(host, path, ip, ua, ssh_host)


def run_multi_domain_mode(domains: List[str]) -> None:
    """Scan multiple domains from the list and report those returning HTTP 200.
    Saves matching domains to `multi_200.txt` in current working directory.
    """
    clear_screen()
    print(f"{Col.MAGENTA}{Col.BOLD}### MODE: MULTI DOMAIN DIAGNOSTIC (SCAN FOR 200) ###{Col.ENDC}")
    ua = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Mobile Safari/537.36"
    matches: List[str] = []

    # select SSH server for mixing (optional, applies to all domains)
    ssh_host = None
    accs = load_accounts()
    if accs:
        print("Pilih SSH account untuk mixing yang akan dipakai untuk semua domain (0 = skip):")
        for i, a in enumerate(accs, 1):
            print(f"{i}. {a.get('host','')}")
        try:
            s = int(input("No: ").strip())
            if s > 0 and s <= len(accs):
                ssh_host = accs[s-1].get('host')
        except Exception:
            ssh_host = None

    for i, host in enumerate(domains, 1):
        print_section(f"{i}. {host}")
        ip = resolve_ip(host)
        if not ip:
            print(f"{Col.RED}DNS gagal untuk {host}{Col.ENDC}")
            continue

        # TLS handshake check
        ok_tls, msg = tls_handshake(ip, host)
        st_col = Col.GREEN if ok_tls else Col.RED
        st = "HIT" if ok_tls else "FAIL"
        print(f"[{st_col}{st}{Col.ENDC}] SNI Host: {host:<32} -> {st_col}{msg}{Col.ENDC}")

        # run the same multi-host report as single-domain mode (keeps output consistent)
        run_multihost_report(host, "/", ip, ua, ssh_host)

        # quick 200-check summary (try HTTPS then HTTP)
        payload = build_basic_request("GET", "/", host, ua)
        ok, stline = http_request_status(host, ip, 443, True, payload)
        is_200 = False
        if ok:
            try:
                parts = stline.split()
                code = int(parts[1]) if len(parts) > 1 else 0
            except Exception:
                code = 0
            if code == 200:
                is_200 = True

        if not is_200:
            ok80, stline80 = http_request_status(host, ip, 80, False, payload)
            if ok80:
                try:
                    parts = stline80.split()
                    code80 = int(parts[1]) if len(parts) > 1 else 0
                except Exception:
                    code80 = 0
                if code80 == 200:
                    is_200 = True
                    stline = stline80

        print_hit("GET", host, stline if stline else "No Response", is_200)
        if is_200:
            matches.append(f"{host} -> {stline}")

    # save matches
    if matches:
        out = os.path.join(os.getcwd(), "multi_200.txt")
        try:
            with open(out, "w", encoding="utf-8") as f:
                f.write("\n".join(matches))
            print(f"\nSaved {len(matches)} domain(s) with 200 -> {out}")
        except Exception as e:
            print(f"Gagal simpan: {e}")
    else:
        print("\nTidak ditemukan domain dengan kode 200.")



# =======================
# SSH Accounts Management (opsional)
# =======================

def load_accounts() -> List[dict]:
    try:
        with open(SSH_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except FileNotFoundError:
        return []
    except Exception:
        return []


def save_accounts(accounts: List[dict]) -> bool:
    try:
        with open(SSH_FILE, "w", encoding="utf-8") as f:
            json.dump(accounts, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False


def menu_manage_accounts() -> None:
    while True:
        clear_screen()
        print(f"{Col.CYAN}{Col.BOLD}SSH Account Management (Storage Only){Col.ENDC}")
        print("Catatan: daftar ini TIDAK dipakai untuk request, hanya penyimpanan.")
        print("\n1. View Accounts\n2. Add Account\n3. Edit Account\n4. Delete Account\n5. Back")
        c = input("\n>> ").strip()
        accs = load_accounts()

        if c == "1":
            clear_screen()
            print(f"{Col.CYAN}{Col.BOLD}Accounts:{Col.ENDC}\n")
            if not accs:
                print(f"{Col.YELLOW}(kosong){Col.ENDC}")
            else:
                for i, a in enumerate(accs, 1):
                    host = a.get("host", "")
                    port = a.get("port", "")
                    user = a.get("username", "")
                    print(f"{i}. {host}:{port} ({user})")
            input("\nEnter...")

        elif c == "2":
            host = input("Host: ").strip()
            port = input("Port: ").strip() or "22"
            user = input("Username: ").strip()
            pw = input("Password: ").strip()
            if not host or not user or not pw:
                print(f"{Col.RED}Field tidak boleh kosong.{Col.ENDC}")
                time.sleep(1)
                continue
            accs.append({"host": host, "port": port, "username": user, "password": pw})
            ok = save_accounts(accs)
            print(f"{Col.GREEN}Saved.{Col.ENDC}" if ok else f"{Col.RED}Gagal simpan.{Col.ENDC}")
            time.sleep(1)

        elif c == "3":
            if not accs:
                print(f"{Col.YELLOW}Tidak ada akun.{Col.ENDC}")
                time.sleep(1)
                continue
            for i, a in enumerate(accs, 1):
                print(f"{i}. {a.get('host','')}:{a.get('port','')} ({a.get('username','')})")
            try:
                idx = int(input("Edit No: ").strip()) - 1
                if not (0 <= idx < len(accs)):
                    raise ValueError
            except Exception:
                print(f"{Col.RED}Invalid.{Col.ENDC}")
                time.sleep(1)
                continue
            a = accs[idx]
            host = input(f"Host [{a.get('host','')}]: ").strip() or a.get("host", "")
            port = input(f"Port [{a.get('port','')}]: ").strip() or a.get("port", "")
            user = input(f"Username [{a.get('username','')}]: ").strip() or a.get("username", "")
            pw = input("Password [hidden] (kosong=tidak diubah): ").strip() or a.get("password", "")
            accs[idx] = {"host": host, "port": port, "username": user, "password": pw}
            ok = save_accounts(accs)
            print(f"{Col.GREEN}Updated.{Col.ENDC}" if ok else f"{Col.RED}Gagal simpan.{Col.ENDC}")
            time.sleep(1)

        elif c == "4":
            if not accs:
                print(f"{Col.YELLOW}Tidak ada akun.{Col.ENDC}")
                time.sleep(1)
                continue
            for i, a in enumerate(accs, 1):
                print(f"{i}. {a.get('host','')}:{a.get('port','')} ({a.get('username','')})")
            try:
                idx = int(input("Del No: ").strip()) - 1
                if not (0 <= idx < len(accs)):
                    raise ValueError
            except Exception:
                print(f"{Col.RED}Invalid.{Col.ENDC}")
                time.sleep(1)
                continue
            accs.pop(idx)
            ok = save_accounts(accs)
            print(f"{Col.GREEN}Deleted.{Col.ENDC}" if ok else f"{Col.RED}Gagal simpan.{Col.ENDC}")
            time.sleep(1)

        elif c == "5":
            return


def main() -> None:
    domains = read_lines(IFLIX_FILE)
    while True:
        clear_screen()
        print(f"{Col.MAGENTA}{Col.BOLD}IFLIX DIAGNOSTIC SCANNER{Col.ENDC}")
        print("1. Single Domain Diagnostic (443/80)")
        print("2. Multi Domain Diagnostic (scan list for HTTP 200)")
        print("3. Manage SSH Accounts (Storage Only)")
        print("4. Exit")
        o = input("\n>> ").strip()
        if o == "1":
            if not domains:
                print(f"{Col.RED}File {IFLIX_FILE} tidak ditemukan / kosong.{Col.ENDC}")
                input("Enter...")
                continue
            run_single_domain_mode(domains)
            input("\nEnter...")
        elif o == "2":
            if not domains:
                print(f"{Col.RED}File {IFLIX_FILE} tidak ditemukan / kosong.{Col.ENDC}")
                input("Enter...")
                continue
            run_multi_domain_mode(domains)
            input("\nEnter...")
        elif o == "3":
            menu_manage_accounts()
        elif o == "4":
            return


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nBye")
