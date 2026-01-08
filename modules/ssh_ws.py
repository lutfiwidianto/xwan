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
PATHS = ["/", "/ws", "/websocket", "/wss", "/proxy", "/connect", "/api", "/v1", "/v2", "/index.html", "/static", "/assets"]
WS_PATHS = {"/ws", "/websocket", "/wss"}
PORTS = [80, 443, 8080, 8880, 2082, 2083, 8443, 2052, 2053]
TLS_PORTS = {443, 8443, 2053, 2083}
ENABLE_SPLIT = True
SPLIT_DELAY = 0.3
SNI_TIMEOUT = 3
PAYLOAD_ONLY_TIMEOUT = 3

EXTRA_HEADERS = [
    ("X-Online-Host", "{host}"),
    ("X-Forward-Host", "{host}"),
    ("X-Host", "{host}"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("Referer", "https://{host}/"),
    ("Origin", "https://{host}"),
    ("X-Requested-With", "XMLHttpRequest"),
    ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"),
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


def _check_sni(proxy_host, sni_host, timeout):
    sock = None
    try:
        sock = _open_socket(proxy_host, 443, True, sni_host, timeout)
        sock.sendall(f"GET / HTTP/1.1\r\nHost: {sni_host}\r\n\r\n".encode())
        data = sock.recv(4096)
        if not data or b"HTTP/" not in data:
            return ""
        status_line = data.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore")
        return status_line
    except Exception:
        return ""
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _try_http_payload(proxy_host, proxy_port, use_tls, sni_host, raw_payload, split_at, timeout):
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


def _status_line_from_response(response):
    if not response:
        return ""
    return response.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore")


def _is_http_hit(status_line):
    if not status_line:
        return False
    if "HTTP/" not in status_line:
        return False
    for code in ("200", "101", "301", "302", "400", "403", "500"):
        if code in status_line:
            return True
    return False


def _resolve_domain(host):
    if not host:
        return []
    try:
        # returns list of IPs
        return socket.gethostbyname_ex(host)[2]
    except Exception:
        return []


def _log_response(proxy_host, port, name, status_line, raw_response):
    try:
        snippet = raw_response[:2048] if raw_response else b""
        decoded = snippet.decode("utf-8", errors="replace")
    except Exception:
        decoded = repr(raw_response)
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    fname = "sshws_responses.log"
    try:
        with open(fname, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {proxy_host}:{port} {name} STATUS: {status_line}\n")
            f.write(decoded)
            f.write("\n" + "-" * 60 + "\n")
    except Exception:
        pass


def _generate_ssh_config(ssh_host, ssh_port, username, password, proxy_host, proxy_port):
    # Create a simple ssh_config file with usage hint
    safe_host = ssh_host.replace(":", "_")
    fname = f"ssh_config_{safe_host}_{int(time.time())}.txt"
    try:
        with open(fname, "w", encoding="utf-8") as f:
            f.write(f"# Generated SSH config snippet\n")
            f.write(f"Host {username}@{ssh_host}\n")
            f.write(f"  HostName {ssh_host}\n")
            f.write(f"  Port {ssh_port}\n")
            f.write(f"  User {username}\n")
            f.write(f"  # Password: {password}\n")
            f.write(f"  # Proxy (use with netcat/nc or proxycommand tools): {proxy_host}:{proxy_port}\n")
            f.write(f"\n# Example usage:\n")
            f.write(f"# ssh -o 'ProxyCommand=nc -X connect -x {proxy_host}:{proxy_port} %h %p' {username}@{ssh_host} -p {ssh_port}\n")
        print(f"{Fore.CYAN}[!] ssh_config saved: {fname}{Style.RESET_ALL}")
    except Exception:
        pass


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
        status_line = _status_line_from_response(response)
        # log response snippet for analysis
        _log_response(proxy_host, proxy_port, "TRY_PAYLOAD", status_line, response)
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
            port_display = acc.get("port", 22)
            print(f"[{idx}] {acc['host']}:{port_display} | {acc['username']}")
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
            port_in = input("[*] Port (enter=22) : ").strip()
            username = input("[*] Username : ").strip()
            password = input("[*] Password : ").strip()
            if not host or not username:
                print(f"{Fore.RED}[!] Host/Username wajib{Style.RESET_ALL}")
                continue
            port = int(port_in) if port_in.isdigit() else 22
            new_acc = {"host": host, "port": port, "username": username, "password": password}
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
            port_in = input(f"[*] Port (enter untuk tetap): {acc.get('port',22)} ").strip()
            port = int(port_in) if port_in.isdigit() else acc.get('port', 22)
            username = input(f"[*] Username (enter untuk tetap): {acc['username']} ").strip() or acc["username"]
            password = input("[*] Password (enter untuk tetap): ").strip() or acc["password"]
            accounts[int(idx) - 1] = {"host": host, "port": port, "username": username, "password": password}
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
            port_in = input("[*] Port (enter=22) : ").strip()
            username = input("[*] Username : ").strip()
            password = input("[*] Password : ").strip()
            port = int(port_in) if port_in.isdigit() else 22
            return {"host": host, "port": port, "username": username, "password": password}

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
    # Allow testing one target or a list, and optionally test all saved accounts
    accounts = _load_accounts()
    if not accounts:
        print(f"{Fore.YELLOW}[!] Tidak ada akun tersimpan. Anda akan diminta memasukkan akun sekarang.{Style.RESET_ALL}")

    test_all = input(f"{Fore.YELLOW}[*] Uji semua akun tersimpan? (y/N): {Style.RESET_ALL}").strip().lower() == "y"
    if test_all:
        if not accounts:
            print(f"{Fore.RED}[!] Tidak ada akun untuk diuji{Style.RESET_ALL}")
            return
        accounts_to_test = accounts
    else:
        acc = _select_account()
        accounts_to_test = [acc]

    # Target input: single host or list file
    target_mode = input(f"{Fore.YELLOW}[*] Target input (1=single host, 2=list file): {Style.RESET_ALL}").strip() or "2"
    if target_mode == "1":
        single = input(f"{Fore.YELLOW}[*] Host domain/ip : {Style.RESET_ALL}").strip()
        if not single:
            print(f"{Fore.RED}[!] Host tidak boleh kosong{Style.RESET_ALL}")
            return
        proxies = [single]
    else:
        proxy_file = input(f"{Fore.YELLOW}[*] List web/ip (txt) : {Style.RESET_ALL}").strip()
        try:
            with open(proxy_file, "r", encoding="utf-8") as f:
                proxies = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}[!] File {proxy_file} tidak ditemukan!{Style.RESET_ALL}")
            return

    scan_mode = input(f"{Fore.YELLOW}[*] Mode (1=Normal, 2=Scan All): {Style.RESET_ALL}").strip() or "1"
    force_full = input(f"{Fore.YELLOW}[*] Force full test even if SNI fails? (y/N): {Style.RESET_ALL}").strip().lower() == "y"
    enable_resolve = input(f"{Fore.YELLOW}[*] Enable DNS resolve step? (y/N): {Style.RESET_ALL}").strip().lower() == "y"
    # Allow user to add custom headers for this run
    custom_headers = []
    if input(f"{Fore.YELLOW}[*] Tambah custom headers per-run? (y/N): {Style.RESET_ALL}").strip().lower() == "y":
        print("[*] Masukkan header dalam format 'Name: Value'. Kosongkan untuk selesai.")
        while True:
            line = input("Header: ").strip()
            if not line:
                break
            if ":" in line:
                name, val = line.split(":", 1)
                custom_headers.append((name.strip(), val.strip()))
    runtime_extra = EXTRA_HEADERS + custom_headers
    success_count = 0
    header_combos = _header_combinations(runtime_extra)

    for i, proxy_line in enumerate(proxies, 1):
        proxy_host, proxy_port = _parse_host_port(proxy_line)
        if not proxy_host:
            continue

        # For each account, run the regular checks
        for acc in accounts_to_test:
            ssh_host = acc.get("host", "").strip()
            username = acc.get("username", "").strip()
            password = acc.get("password", "").strip()

            if not ssh_host or not username:
                print(f"{Fore.RED}[!] Host/Username wajib untuk akun {ssh_host}/{username}{Style.RESET_ALL}")
                continue

            # Optional DNS resolve step
            if enable_resolve:
                try:
                    addrs = _resolve_domain(proxy_host) if proxy_host else []
                    if addrs:
                        print(f"  Resolved {proxy_host} -> {', '.join(addrs)}")
                except Exception:
                    print(f"  {Fore.YELLOW}[!] DNS resolve gagal untuk {proxy_host}{Style.RESET_ALL}")

            if scan_mode == "2":
                sni_candidates = []
                if proxy_host and not proxy_host.replace(".", "").isdigit():
                    sni_candidates.append(proxy_host)
                if ssh_host:
                    sni_candidates.append(ssh_host)
                sni_candidates = _unique_list(sni_candidates)
                sni_hit = True
                if sni_candidates:
                    sni_hit = False
                    print(f"{Fore.CYAN}[{i}/{len(proxies)}] SNI Check (443): {proxy_host}{Style.RESET_ALL}")
                    for sni in sni_candidates:
                        ok = _check_sni(proxy_host, sni, SNI_TIMEOUT)
                        status = f"{Fore.GREEN}HIT{Style.RESET_ALL}" if ok else f"{Fore.RED}FAIL{Style.RESET_ALL}"
                        print(f"  {sni} -> {status}")
                        if ok:
                            sni_hit = True

                if not sni_hit:
                    if force_full:
                        print(f"{Fore.YELLOW}FORCE full test enabled — proceeding despite SNI FAIL{Style.RESET_ALL} - {proxy_host}")
                    else:
                        print(f"{Fore.RED}SKIP full test (SNI FAIL){Style.RESET_ALL} - {proxy_host}")
                        continue

                print(f"{Fore.CYAN}[{i}/{len(proxies)}] Payload Only (80): {proxy_host}{Style.RESET_ALL}")
                payload_port = proxy_port or 80
                header_hosts = _unique_list([proxy_host, ssh_host])
                first_status = ""
                hit_count = 0
                for header_host in header_hosts:
                    host_header = _format_host_header(header_host, payload_port)
                    host_only = header_host
                    for extra_headers in header_combos:
                        payloads = _build_payload_variants(host_header, host_only, ssh_host, ssh_port=SSH_PORTS[0], extra_headers=extra_headers)
                        for name, raw_payload, display_payload, split_at in payloads:
                            response = _try_http_payload(
                                proxy_host,
                                payload_port,
                                False,
                                None,
                                raw_payload,
                                split_at,
                                PAYLOAD_ONLY_TIMEOUT,
                            )
                            status_line = _status_line_from_response(response)
                            # Log response for analysis
                            _log_response(proxy_host, payload_port, name, status_line, response)
                            if _is_http_hit(status_line):
                                hit_count += 1
                                if not first_status:
                                    first_status = status_line

                if first_status:
                    print(f"  Payload Only -> {Fore.GREEN}{first_status}{Style.RESET_ALL}")
                else:
                    print(f"  Payload Only -> {Fore.RED}FAIL{Style.RESET_ALL}")

            port_candidates = [proxy_port] if proxy_port else PORTS
            print(f"{Fore.CYAN}[{i}/{len(proxies)}] Stage 1/2 Quick Check: {proxy_host} (account: {username}){Style.RESET_ALL}")
            if not _quick_check(proxy_host, port_candidates, ssh_host, username, password):
                print(f"{Fore.RED}SKIP (no quick hit){Style.RESET_ALL} - {proxy_host}")
                continue

            print(f"{Fore.GREEN}[{i}/{len(proxies)}] Stage 2/2 Full Test: {proxy_host} (account: {username}){Style.RESET_ALL}")
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
                                        # Log success and write result
                                        _write_result(display_payload, proxy_host, port, ssh_host, ssh_port, username, password, ssl_value)
                                        _generate_ssh_config(ssh_host, ssh_port, username, password, proxy_host, port)
                                        print(f"{Fore.GREEN}CONNECTED{Style.RESET_ALL} - {proxy_host}:{port} ({name}) SSH:{ssh_port}        ")
                                        success_count += 1
                                        success_for_proxy = True

            if not success_for_proxy:
                print(f"{Fore.RED}FAILED{Style.RESET_ALL} - {proxy_host} (account: {username})")

    print(f"{Fore.CYAN}[!] Selesai. Total Berhasil: {success_count}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[!] Hasil tersimpan di : {OUTPUT_FILE}{Style.RESET_ALL}")
