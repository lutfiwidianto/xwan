#!/usr/bin/env python3
import socket
import ssl
import time
from colorama import Fore, Style

DEFAULT_TIMEOUT = 8
OUTPUT_FILE = "Result_sshws.txt"


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


def _build_payloads(ws_path, host_header, ssh_host, ssh_port):
    templates = [
        ("GET_WS", f"GET {ws_path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: Keep-Alive\r\nUpgrade: websocket\r\n\r\n"),
        ("PATCH_WS", f"PATCH {ws_path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: Keep-Alive\r\nUpgrade: websocket\r\n\r\n"),
        ("GET_HTTP", f"GET / HTTP/1.1\r\nHost: {host_header}\r\nConnection: Keep-Alive\r\n\r\n"),
        ("CONNECT_SSH", f"CONNECT {ssh_host}:{ssh_port} HTTP/1.1\r\nHost: {host_header}\r\nConnection: Keep-Alive\r\n\r\n"),
    ]
    payloads = []
    for name, raw in templates:
        payloads.append((name, raw, _payload_to_http_custom(raw)))
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


def _try_payload(proxy_host, proxy_port, use_tls, sni_host, raw_payload, ssh_host, ssh_port, username, password):
    sock = None
    try:
        sock = _open_socket(proxy_host, proxy_port, use_tls, sni_host, DEFAULT_TIMEOUT)
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


def ssh_ws_connection():
    ssh_host = input("[*] Host SSH : ").strip()
    if not ssh_host:
        print(f"{Fore.RED}[!] Host SSH kosong{Style.RESET_ALL}")
        return

    try:
        ssh_port = int(input("[*] SSH Port : ").strip())
    except ValueError:
        print(f"{Fore.RED}[!] SSH Port tidak valid{Style.RESET_ALL}")
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

    print(f"{Fore.CYAN}[1] HTTP (port 80)")
    print(f"[2] TLS/SSL (port 443)")
    print(f"[3] AUTO (80 lalu 443){Style.RESET_ALL}")
    mode = input(f"{Fore.YELLOW}[*] Pilih mode (1/2/3) : {Style.RESET_ALL}").strip()
    if mode not in {"1", "2", "3"}:
        print(f"{Fore.RED}[!] Mode tidak valid{Style.RESET_ALL}")
        return

    sni_host = ""
    if mode in {"2", "3"}:
        sni_host = input(f"{Fore.YELLOW}[*] SNI (kosong = host SSH) : {Style.RESET_ALL}").strip()
        if not sni_host:
            sni_host = ssh_host

    ws_path = input(f"{Fore.YELLOW}[*] WS Path (default /ws) : {Style.RESET_ALL}").strip()
    if not ws_path:
        ws_path = "/ws"

    success_count = 0
    for i, proxy_line in enumerate(proxies, 1):
        proxy_host, proxy_port = _parse_host_port(proxy_line)
        if not proxy_host:
            continue

        port_candidates = []
        if proxy_port:
            port_candidates = [proxy_port]
        else:
            if mode == "1":
                port_candidates = [80]
            elif mode == "2":
                port_candidates = [443]
            elif mode == "3":
                port_candidates = [80, 443]

        found = False
        for port in port_candidates:
            use_tls = mode == "2" or (mode == "3" and port == 443)
            header_hosts = [proxy_host]
            if sni_host and sni_host != proxy_host:
                header_hosts.append(sni_host)

            print(f"{Fore.YELLOW}[{i}/{len(proxies)}] Testing {proxy_host}:{port} ({'TLS' if use_tls else 'HTTP'}){Style.RESET_ALL}")

            for header_host in header_hosts:
                host_header = _format_host_header(header_host, port)
                payloads = _build_payloads(ws_path, host_header, ssh_host, ssh_port)
                for name, raw_payload, display_payload in payloads:
                    ok = _try_payload(proxy_host, port, use_tls, sni_host, raw_payload, ssh_host, ssh_port, username, password)
                    if ok:
                        ssl_value = sni_host if use_tls else ""
                        _write_result(display_payload, proxy_host, port, ssh_host, ssh_port, username, password, ssl_value)
                        print(f"{Fore.GREEN}CONNECTED{Style.RESET_ALL} - {proxy_host}:{port} ({name})")
                        success_count += 1
                        found = True
                        break
                if found:
                    break
            if found:
                break

        if not found:
            print(f"{Fore.RED}FAILED{Style.RESET_ALL} - {proxy_host}")

    print(f"{Fore.CYAN}[!] Selesai. Total Berhasil: {success_count}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[!] Hasil tersimpan di : {OUTPUT_FILE}{Style.RESET_ALL}")
