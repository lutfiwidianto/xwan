#!/usr/bin/env python3
import json

def create_onering_config_vmess(server_config, target_ip):
    sni_host = f"onering:{server_config['sni']}:{target_ip}"
    
    config = {
        "inbounds": [{
            "port": 10808,
            "protocol": "socks",
            "listen": "127.0.0.1",
            "settings": {
                "auth": "noauth",
                "udp": True,
                "ip": "127.0.0.1"
            }
        }],
        "outbounds": [{
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": target_ip,
                    "port": int(server_config['port']),
                    "users": [{
                        "id": server_config['id'],
                        "alterId": int(server_config.get('aid', 0) or server_config.get('alterId', 0))
                    }]
                }]
            },
            "streamSettings": {
                "network": server_config.get('network', 'ws'),
                "security": server_config.get('security', 'tls'),
                "tlsSettings": {
                    "allowInsecure": True,
                    "serverName": sni_host
                },
                "wsSettings": {
                    "path": server_config.get('path', '/'),
                    "headers": {"Host": server_config['sni']}
                }
            }
        }]
    }
    return config

def create_onering_config_trojan(server_config, target_ip):
    sni_host = f"onering:{server_config['sni']}:{target_ip}"
    
    config = {
        "inbounds": [{
            "port": 10808,
            "protocol": "socks",
            "listen": "127.0.0.1",
            "settings": {
                "auth": "noauth",
                "udp": True,
                "ip": "127.0.0.1"
            }
        }],
        "outbounds": [{
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": target_ip,
                    "port": int(server_config['port']),
                    "password": server_config['password']
                }]
            },
            "streamSettings": {
                "network": server_config.get('network', 'ws'),
                "security": server_config.get('security', 'tls'),
                "tlsSettings": {
                    "allowInsecure": True,
                    "serverName": sni_host
                },
                "wsSettings": {
                    "path": server_config.get('path', '/'),
                    "headers": {"Host": server_config['sni']}
                }
            }
        }]
    }
    return config

def create_onering_config_vless(server_config, target_ip):
    sni_host = f"onering:{server_config['sni']}:{target_ip}"
    
    config = {
        "inbounds": [{
            "port": 10808,
            "protocol": "socks",
            "listen": "127.0.0.1",
            "settings": {
                "auth": "noauth",
                "udp": True,
                "ip": "127.0.0.1"
            }
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": target_ip,
                    "port": int(server_config['port']),
                    "users": [{
                        "id": server_config['id'],
                        "flow": server_config.get('flow', ''),
                        "encryption": "none"
                    }]
                }]
            },
            "streamSettings": {
                "network": server_config.get('network', 'ws'),
                "security": server_config.get('security', 'tls'),
                "tlsSettings": {
                    "allowInsecure": True,
                    "serverName": sni_host
                },
                "wsSettings": {
                    "path": server_config.get('path', '/'),
                    "headers": {"Host": server_config['sni']}
                }
            }
        }]
    }
    return config

def create_onering_config(server_config, target_ip):
    protocol = server_config['protocol']
    
    if protocol == 'vmess':
        return create_onering_config_vmess(server_config, target_ip)
    elif protocol == 'trojan':
        return create_onering_config_trojan(server_config, target_ip)
    elif protocol == 'vless':
        return create_onering_config_vless(server_config, target_ip)
    else:
        raise ValueError(f"Protocol {protocol} tidak didukung untuk onering")