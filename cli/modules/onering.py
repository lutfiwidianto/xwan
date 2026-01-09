#!/usr/bin/env python3
import os
import json
from colorama import Fore, Style
from .onering_config import create_onering_config
from .onering_test import test_onering_connection

def test_onering(target_ip, server_config):
    try:
        config = create_onering_config(server_config, target_ip)
        
        config_name = f"onering-{target_ip.replace('.', '-')}.json"
        config_file = f"test-{config_name}"
        
        with open(config_file, "w") as f:
            json.dump(config, f, indent=2)
        
        success, connected_ip = test_onering_connection(config_file)
        
        try:
            os.remove(config_file)
        except:
            pass
        
        return success, connected_ip
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error testing onering {target_ip}: {e}{Style.RESET_ALL}")
        return False, None