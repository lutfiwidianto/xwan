#!/usr/bin/env python3

def create_xray_config(server_config, target_address=None, sni_address=None):
    if target_address:
        actual_address = target_address
    else:
        actual_address = server_config['address']
    
    if sni_address:
        sni_host = sni_address
    else:
        sni_host = server_config['sni']
    
    base_config = {
        "inbounds": [{
            "port": 10808,
            "protocol": "socks",
            "listen": "127.0.0.1",
            "settings": {"auth": "noauth", "udp": True}
        }]
    }
    
    stream_settings = {
        "network": server_config['network']
    }
    
    if server_config['security'] == 'tls':
        stream_settings["security"] = "tls"
        stream_settings["tlsSettings"] = {
            "serverName": sni_host,
            "allowInsecure": True,
            "fingerprint": server_config['fp']
        }
        if server_config.get('alpn'):
            stream_settings["tlsSettings"]["alpn"] = [server_config['alpn']]
    else:
        stream_settings["security"] = "none"
    
    if server_config['network'] == 'ws':
        stream_settings["wsSettings"] = {
            "path": server_config['path'],
            "headers": {"Host": server_config['host']}
        }
    
    if server_config['protocol'] == 'trojan':
        base_config["outbounds"] = [{
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": actual_address,
                    "port": server_config['port'],
                    "password": server_config['password']
                }]
            },
            "streamSettings": stream_settings
        }]
    
    elif server_config['protocol'] == 'vmess':
        base_config["outbounds"] = [{
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": actual_address,
                    "port": server_config['port'],
                    "users": [{
                        "id": server_config['id'],
                        "security": server_config.get('security', 'auto')
                    }]
                }]
            },
            "streamSettings": stream_settings
        }]
    
    elif server_config['protocol'] == 'vless':
        base_config["outbounds"] = [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": actual_address,
                    "port": server_config['port'],
                    "users": [{
                        "id": server_config['id'],
                        "flow": server_config.get('flow', ''),
                        "encryption": "none"
                    }]
                }]
            },
            "streamSettings": stream_settings
        }]
    
    return base_config

def create_xray_config_wildcard(server_config, target_address):
    actual_address = target_address
    
    sni_host = f"{target_address}.{server_config['sni']}"
    
    base_config = {
        "inbounds": [{
            "port": 10808,
            "protocol": "socks",
            "listen": "127.0.0.1",
            "settings": {"auth": "noauth", "udp": True}
        }]
    }
    
    stream_settings = {
        "network": server_config['network']
    }
    
    if server_config['security'] == 'tls':
        stream_settings["security"] = "tls"
        stream_settings["tlsSettings"] = {
            "serverName": sni_host,  
            "allowInsecure": True,
            "fingerprint": server_config['fp']
        }
        if server_config.get('alpn'):
            stream_settings["tlsSettings"]["alpn"] = [server_config['alpn']]
    else:
        stream_settings["security"] = "none"
    
    if server_config['network'] == 'ws':
        stream_settings["wsSettings"] = {
            "path": server_config['path'],
            "headers": {"Host": sni_host}
        }
    
    if server_config['protocol'] == 'trojan':
        base_config["outbounds"] = [{
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": actual_address,
                    "port": server_config['port'],
                    "password": server_config['password']
                }]
            },
            "streamSettings": stream_settings
        }]
    
    elif server_config['protocol'] == 'vmess':
        base_config["outbounds"] = [{
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": actual_address,
                    "port": server_config['port'],
                    "users": [{
                        "id": server_config['id'],
                        "security": server_config.get('security', 'auto')
                    }]
                }]
            },
            "streamSettings": stream_settings
        }]
    
    elif server_config['protocol'] == 'vless':
        base_config["outbounds"] = [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": actual_address,
                    "port": server_config['port'],
                    "users": [{
                        "id": server_config['id'],
                        "flow": server_config.get('flow', ''),
                        "encryption": "none"
                    }]
                }]
            },
            "streamSettings": stream_settings
        }]
    
    return base_config