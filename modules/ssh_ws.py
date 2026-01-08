#!/usr/bin/env python3
import socket
import ssl
import time

from colorama import Fore, Style

DEFAULT_TIMEOUT = 8
OUTPUT_FILE = "Result_sshws.txt"
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


def _try_payload(proxy_host, proxy_port, use_tls, sni_host, raw_payload, split_at, ssh_host, ssh_port, username, password):
    sock = None
    try:
        sock = _open_socket(proxy_host, proxy_port, use_tls, sni_host, DEFAULT_TIMEOUT)
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


def ssh_ws_connection():
    ssh_host = input("[*] Host SSH : ").strip()
    if not ssh_host:
        print(f"{Fore.RED}[!] Host SSH kosong{Style.RESET_ALL}")
        return

    username = input("[*] Username : ").strip()
    password = input("[*] Password : ").strip()

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
        success_for_proxy = False

        for port in port_candidates:
            use_tls = port in TLS_PORTS
            sni_candidates = [ssh_host, proxy_host] if use_tls else [""]
            sni_candidates = _unique_list(sni_candidates)
            header_hosts = _unique_list([proxy_host, ssh_host])

            for sni_host in sni_candidates:
                tls_label = f"TLS SNI={sni_host}" if use_tls else "HTTP"
                print(f"{Fore.YELLOW}[{i}/{len(proxies)}] Testing {proxy_host}:{port} ({tls_label}){Style.RESET_ALL}")

                for header_host in header_hosts:
                    host_header = _format_host_header(header_host, port)
                    host_only = header_host

                    for extra_headers in header_combos:
                        for ssh_port in SSH_PORTS:
                            payloads = _build_payload_variants(host_header, host_only, ssh_host, ssh_port, extra_headers)
                            for name, raw_payload, display_payload, split_at in payloads:
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
                                )
                                if ok:
                                    ssl_value = sni_host if use_tls else ""
                                    _write_result(display_payload, proxy_host, port, ssh_host, ssh_port, username, password, ssl_value)
                                    print(f"{Fore.GREEN}CONNECTED{Style.RESET_ALL} - {proxy_host}:{port} ({name}) SSH:{ssh_port}")
                                    success_count += 1
                                    success_for_proxy = True

        if not success_for_proxy:
            print(f"{Fore.RED}FAILED{Style.RESET_ALL} - {proxy_host}")

    print(f"{Fore.CYAN}[!] Selesai. Total Berhasil: {success_count}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[!] Hasil tersimpan di : {OUTPUT_FILE}{Style.RESET_ALL}")
