#!/usr/bin/env python3
import json
import urllib.parse
import base64
from colorama import Fore, Style

def parse_vmess_trojan_url(url):
    if url.startswith('trojan://'):
        return parse_trojan_url(url)
    elif url.startswith('vmess://'):
        return parse_vmess_url(url)
    elif url.startswith('vless://'):
        return parse_vless_url(url)
    else:
        raise ValueError(f"{Fore.RED}Protocol tidak didukung: {url}{Style.RESET_ALL}")

def parse_trojan_url(url):
    parsed = urllib.parse.urlparse(url)
    password = parsed.username or parsed.netloc.split('@')[0]
    server_info = parsed.netloc.split('@')[1] if '@' in parsed.netloc else parsed.netloc
    address = server_info.split(':')[0]
    port = int(server_info.split(':')[1]) if ':' in server_info else 443
    
    query_params = urllib.parse.parse_qs(parsed.query)
    
    security = "tls"
    if 'security' in query_params:
        security = query_params['security'][0]
    elif port == 80 or 'allowInsecure' in query_params:
        security = "none"
    
    config = {
        "protocol": "trojan",
        "address": address,
        "port": port,
        "password": password,
        "security": security,
        "network": query_params.get('type', ['tcp'])[0],
        "path": query_params.get('path', ['/'])[0],
        "host": query_params.get('host', [address])[0],
        "sni": query_params.get('sni', query_params.get('host', [address])[0])[0],
        "fp": query_params.get('fp', ['chrome'])[0],
        "alpn": query_params.get('alpn', ['h2,http/1.1'])[0].split(',')[0]
    }
    
    return config

def parse_vmess_url(url):
    encoded_data = url[8:]
    padding = 4 - len(encoded_data) % 4
    if padding != 4:
        encoded_data += '=' * padding
    decoded_data = base64.b64decode(encoded_data).decode('utf-8')
    vmess_config = json.loads(decoded_data)
    
    security = "none"
    if vmess_config.get('tls') == 'tls':
        security = "tls"
    
    config = {
        "protocol": "vmess",
        "address": vmess_config['add'],
        "port": int(vmess_config['port']),
        "id": vmess_config['id'],
        "security": security,
        "network": vmess_config.get('net', 'tcp'),
        "path": vmess_config.get('path', '/'),
        "host": vmess_config.get('host', vmess_config['add']),
        "sni": vmess_config.get('sni', vmess_config.get('host', vmess_config['add'])),
        "fp": vmess_config.get('fp', 'chrome'),
        "type": vmess_config.get('type', 'none')
    }
    
    return config

def parse_vless_url(url):
    parsed = urllib.parse.urlparse(url)
    uuid = parsed.username
    server_info = parsed.netloc.split('@')[1] if '@' in parsed.netloc else parsed.netloc
    address = server_info.split(':')[0]
    port = int(server_info.split(':')[1]) if ':' in server_info else 443
    
    query_params = urllib.parse.parse_qs(parsed.query)
    
    security = query_params.get('security', ['none'])[0]
    if security == 'none' and (port == 80 or 'encryption' in query_params):
        security = "none"
    
    config = {
        "protocol": "vless",
        "address": address,
        "port": port,
        "id": uuid,
        "security": security,
        "network": query_params.get('type', ['tcp'])[0],
        "path": query_params.get('path', ['/'])[0],
        "host": query_params.get('host', [address])[0],
        "sni": query_params.get('sni', query_params.get('host', [address])[0])[0],
        "fp": query_params.get('fp', ['chrome'])[0],
        "flow": query_params.get('flow', [''])[0]
    }
    
    return config