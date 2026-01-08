#!/usr/bin/env python3
import json
import socket
import ssl
import time
from pathlib import Path

from colorama import Fore, Style

DEFAULT_TIMEOUT = 8
QUICK_TIMEOUT = 3
OUTPUT_FILE = "Result_sshws.txt"
ACCOUNTS_FILE = Path(r"c:\xwan\ssh_accounts.json")

SSH_PORTS = [22, 80, 443]

METHODS = ["GET", "POST", "PATCH", "PUT", "HEAD", "OPTIONS", "CONNECT"]
PATHS = ["/", "/ws", "/websocket", "/wss", "/proxy", "/connect"]
WS_PATHS = {"/ws", "/websocket", "/wss"}
PORTS = [80, 443, 8080, 8880, 2082, 2083, 8443, 2052, 2053]
TLS_PORTS = {443, 8443, 2053, 2083}
ENABLE_SPLIT = True
SPLIT_DELAY = 0.3

EXTRA_HEADERS = [
    ("X-Online-Host", "{host}"),
    ("X-Forward-Host", "{host}"),
    ("X-Host", "{host}"),
    ("X-Forwarded-For", "127.0.0.1"),
]


def _parse_host_port(line):
    line = line.strip()
    if not line:
        return None, None
    if ":" in line:
        host, port_str = line.rsplit(":", 1)
        if port_str.isdigit():
            return host.strip(), int(port_str)
    return line, None


def _payload_to_http_custom(raw_payload):
    return raw_payload.replace("\r\n", "[crlf]")


def _format_host_header(host, port):
    if host is None:
        return ""
    return f"{host}:{port}" if port else host


def _header_combinations(headers):
    combos = [[]]
    for header in headers:
        combos += [c + [header] for c in combos]
    return combos


def _format_extra_headers(extra_headers, host_only):
    lines = []
    for header_name, value_tmpl in extra_headers:
        value = value_tmpl.format(host=host_only)
        lines.append(f"{header_name}: {value}")
    return lines


def _expand_payload(raw_payload, name):
    variants = []
    display = _payload_to_http_custom(raw_payload)
    variants.append((name, raw_payload, display, None))
    if ENABLE_SPLIT:
        split_at = len(raw_payload) // 2
        display_split = _payload_to_http_custom(raw_payload[:split_at]) + "[split]" + _payload_to_http_custom(raw_payload[split_at:])
        variants.append((f"{name}_SPLIT", raw_payload, display_split, split_at))
    return variants


def _build_payload_variants(host_header, host_only, ssh_host, ssh_port, extra_headers):
    payloads = []
    extra_lines = _format_extra_headers(extra_headers, host_only)

    for method in METHODS:
        if method == "CONNECT":
            lines = [
                f"CONNECT {ssh_host}:{ssh_port} HTTP/1.1",
                f"Host: {host_header}",
                "Connection: Keep-Alive",
            ]
            lines.extend(extra_lines)
            raw = "\r\n".join(lines) + "\r\n\r\n"
            payloads.extend(_expand_payload(raw, "CONNECT_SSH"))
            continue

        for path in PATHS:
            lines = [
                f"{method} {path} HTTP/1.1",
                f"Host: {host_header}",
                "Connection: Keep-Alive",
            ]
            if path in WS_PATHS:
                lines.append("Upgrade: websocket")
            lines.extend(extra_lines)
            raw = "\r\n".join(lines) + "\r\n\r\n"
            name_path = path.strip("/") or "root"
            payloads.extend(_expand_payload(raw, f"{method}_{name_path}"))

    return payloads


def _open_socket(proxy_host, proxy_port, use_tls, sni_host, timeout):
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    if use_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(sock, server_hostname=sni_host or proxy_host)
    sock.settimeout(timeout)
    return sock


def _try_payload(proxy_host, proxy_port, use_tls, sni_host, raw_payload, split_at, ssh_host, ssh_port, username, password, timeout):
    sock = None
    try:
        sock = _open_socket(proxy_host, proxy_port, use_tls, sni_host, timeout)
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


def _write_result(payload_display, proxy_host, proxy_port, ssh_host, ssh_port, username, password, ssl_value):
    lines = [
        "HTTP CUSTOM UNLOCKER",
        "--------------------------------",
        f"[PAYLOAD] {payload_display}",
        "--------------------------------",
        f"[PROXY] {proxy_host}:{proxy_port}",
        "--------------------------------",
        f"[SSH] {ssh_host}:{ssh_port}@{username}:{password}",
        "--------------------------------",
        f"[SSL] {ssl_value}",
        "--------------------------------",
        "",
    ]
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write("\n".join(lines))


def _unique_list(values):
    seen = set()
    result = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _load_accounts():
    if not ACCOUNTS_FILE.exists():
        return []
    try:
        return json.loads(ACCOUNTS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def _save_accounts(accounts):
    ACCOUNTS_FILE.write_text(json.dumps(accounts, indent=2), encoding="utf-8")


def _select_account():
    accounts = _load_accounts()
    while True:
        print(f"{Fore.CYAN}[*] SSH Accounts{Style.RESET_ALL}")
        for idx, acc in enumerate(accounts, 1):
            print(f"[{idx}] {acc['host']} | {acc['username']}")
        print(f"[{len(accounts) + 1}] Tambah akun baru")
        print(f"[{len(accounts) + 2}] Edit akun")
        print(f"[{len(accounts) + 3}] Hapus akun")
        print(f"[{len(accounts) + 4}] Lanjut tanpa simpan")

        choice = input("[*] Pilih: ").strip()
        if not choice.isdigit():
            print(f"{Fore.RED}[!] Pilihan tidak valid{Style.RESET_ALL}")
            continue

        choice_num = int(choice)
        if 1 <= choice_num <= len(accounts):
            return accounts[choice_num - 1]

        if choice_num == len(accounts) + 1:
            host = input("[*] Host SSH : ").strip()
            username = input("[*] Username : ").strip()
            password = input("[*] Password : ").strip()
            if not host or not username:
                print(f"{Fore.RED}[!] Host/Username wajib{Style.RESET_ALL}")
                continue
            new_acc = {"host": host, "username": username, "password": password}
            accounts.append(new_acc)
            _save_accounts(accounts)
            print(f"{Fore.GREEN}[!] Akun disimpan.{Style.RESET_ALL}")
            return new_acc

        if choice_num == len(accounts) + 2:
            if not accounts:
                print(f"{Fore.RED}[!] Tidak ada akun untuk diedit{Style.RESET_ALL}")
                continue
            idx = input("[*] Pilih akun untuk edit: ").strip()
            if not idx.isdigit() or not (1 <= int(idx) <= len(accounts)):
                print(f"{Fore.RED}[!] Pilihan tidak valid{Style.RESET_ALL}")
                continue
            acc = accounts[int(idx) - 1]
            host = input(f"[*] Host SSH (enter untuk tetap): {acc['host']} ").strip() or acc["host"]
            username = input(f"[*] Username (enter untuk tetap): {acc['username']} ").strip() or acc["username"]
            password = input("[*] Password (enter untuk tetap): ").strip() or acc["password"]
            accounts[int(idx) - 1] = {"host": host, "username": username, "password": password}
            _save_accounts(accounts)
            print(f"{Fore.GREEN}[!] Akun diperbarui.{Style.RESET_ALL}")
            continue

        if choice_num == len(accounts) + 3:
            if not accounts:
                print(f"{Fore.RED}[!] Tidak ada akun untuk dihapus{Style.RESET_ALL}")
                continue
            idx = input("[*] Pilih akun untuk hapus: ").strip()
            if not idx.isdigit() or not (1 <= int(idx) <= len(accounts)):
                print(f"{Fore.RED}[!] Pilihan tidak valid{Style.RESET_ALL}")
                continue
            removed = accounts.pop(int(idx) - 1)
            _save_accounts(accounts)
            print(f"{Fore.GREEN}[!] Akun dihapus: {removed['host']}{Style.RESET_ALL}")
            continue

        if choice_num == len(accounts) + 4:
            host = input("[*] Host SSH : ").strip()
            username = input("[*] Username : ").strip()
            password = input("[*] Password : ").strip()
            return {"host": host, "username": username, "password": password}

        print(f"{Fore.RED}[!] Pilihan tidak valid{Style.RESET_ALL}")


def _quick_check(proxy_host, port_candidates, ssh_host, username, password):
    quick_payloads = [
        ("GET_WS", "GET /ws HTTP/1.1\r\nHost: {host}\r\nConnection: Keep-Alive\r\nUpgrade: websocket\r\n\r\n", None),
        ("CONNECT_SSH", "CONNECT {ssh_host}:{ssh_port} HTTP/1.1\r\nHost: {host}\r\nConnection: Keep-Alive\r\n\r\n", None),
    ]

    for port in port_candidates:
        use_tls = port in TLS_PORTS
        sni_candidates = [ssh_host, proxy_host] if use_tls else [""]
        sni_candidates = _unique_list(sni_candidates)
        header_hosts = _unique_list([proxy_host, ssh_host])

        for sni_host in sni_candidates:
            for header_host in header_hosts:
                host_header = _format_host_header(header_host, port)
                for ssh_port in SSH_PORTS:
                    for name, template, _ in quick_payloads:
                        raw_payload = template.format(host=host_header, ssh_host=ssh_host, ssh_port=ssh_port)
                        ok = _try_payload(
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


def ssh_ws_connection():
    account = _select_account()
    ssh_host = account.get("host", "").strip()
    username = account.get("username", "").strip()
    password = account.get("password", "").strip()

    if not ssh_host or not username:
        print(f"{Fore.RED}[!] Host/Username wajib{Style.RESET_ALL}")
        return

    proxy_file = input(f"{Fore.YELLOW}[*] List web/ip (txt) : {Style.RESET_ALL}").strip()
    try:
        with open(proxy_file, "r", encoding="utf-8") as f:
            proxies = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}[!] File {proxy_file} tidak ditemukan!{Style.RESET_ALL}")
        return

    success_count = 0
    header_combos = _header_combinations(EXTRA_HEADERS)

    for i, proxy_line in enumerate(proxies, 1):
        proxy_host, proxy_port = _parse_host_port(proxy_line)
        if not proxy_host:
            continue

        port_candidates = [proxy_port] if proxy_port else PORTS
        print(f"{Fore.CYAN}[{i}/{len(proxies)}] Stage 1/2 Quick Check: {proxy_host}{Style.RESET_ALL}")
        if not _quick_check(proxy_host, port_candidates, ssh_host, username, password):
            print(f"{Fore.RED}SKIP (no quick hit){Style.RESET_ALL} - {proxy_host}")
            continue

        print(f"{Fore.GREEN}[{i}/{len(proxies)}] Stage 2/2 Full Test: {proxy_host}{Style.RESET_ALL}")
        success_for_proxy = False

        for port in port_candidates:
            use_tls = port in TLS_PORTS
            sni_candidates = [ssh_host, proxy_host] if use_tls else [""]
            sni_candidates = _unique_list(sni_candidates)
            header_hosts = _unique_list([proxy_host, ssh_host])

            for sni_host in sni_candidates:
                tls_label = f"TLS SNI={sni_host}" if use_tls else "HTTP"
                print(f"{Fore.YELLOW}  Testing {proxy_host}:{port} ({tls_label}){Style.RESET_ALL}")

                for header_host in header_hosts:
                    host_header = _format_host_header(header_host, port)
                    host_only = header_host

                    for extra_headers in header_combos:
                        payloads = _build_payload_variants(host_header, host_only, ssh_host, ssh_port=SSH_PORTS[0], extra_headers=extra_headers)
                        payload_count = len(payloads) * len(SSH_PORTS)
                        progress = 0

                        for ssh_port in SSH_PORTS:
                            payloads = _build_payload_variants(host_header, host_only, ssh_host, ssh_port, extra_headers)
                            for name, raw_payload, display_payload, split_at in payloads:
                                progress += 1
                                print(f"    Payload {progress}/{payload_count} ({name})", end="\r")
                                ok = _try_payload(
                                    proxy_host,
                                    port,
                                    use_tls,
                                    sni_host,
                                    raw_payload,
                                    split_at,
                                    ssh_host,
                                    ssh_port,
                                    username,
                                    password,
                                    DEFAULT_TIMEOUT,
                                )
                                if ok:
                                    ssl_value = sni_host if use_tls else ""
                                    _write_result(display_payload, proxy_host, port, ssh_host, ssh_port, username, password, ssl_value)
                                    print(f"{Fore.GREEN}CONNECTED{Style.RESET_ALL} - {proxy_host}:{port} ({name}) SSH:{ssh_port}        ")
                                    success_count += 1
                                    success_for_proxy = True

        if not success_for_proxy:
            print(f"{Fore.RED}FAILED{Style.RESET_ALL} - {proxy_host}")

    print(f"{Fore.CYAN}[!] Selesai. Total Berhasil: {success_count}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[!] Hasil tersimpan di : {OUTPUT_FILE}{Style.RESET_ALL}")
