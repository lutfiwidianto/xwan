#!/usr/bin/env python3
import json
import subprocess
import time
import os
from pathlib import Path
from colorama import Fore, Style

ROOT_DIR = Path(__file__).resolve().parents[2]
BIN_DIR = ROOT_DIR / "bin" / "onering"
XRAY_PATH = "/data/data/com.termux/files/usr/bin/xray.linux.arm64.64bit"
XRAY_PATH2 = "/data/data/com.termux/files/usr/bin/xray.linux.amd64.64bit"
BIN_ARM = BIN_DIR / "xray.linux.arm64.64bit"
BIN_AMD = BIN_DIR / "xray.linux.amd64.64bit"


def test_onering_connection(config_file):
    try:
        if not (BIN_ARM.exists() or BIN_AMD.exists() or os.path.exists(XRAY_PATH) or os.path.exists(XRAY_PATH2)):
            print(f"{Fore.RED}[!] Xray onering tidak ditemukan{Style.RESET_ALL}")
            return False, None
        
        xray_executable = None
        if BIN_ARM.exists():
            xray_executable = str(BIN_ARM)
        elif BIN_AMD.exists():
            xray_executable = str(BIN_AMD)
        elif os.path.exists(XRAY_PATH):
            xray_executable = XRAY_PATH
        elif os.path.exists(XRAY_PATH2):
            xray_executable = XRAY_PATH2
        
        proc = subprocess.Popen(
            [xray_executable, "run", "-config", config_file],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(3)
        
        connected_ip = None
        try:
            result = subprocess.run(
                ["curl", "-s", "--socks5", "127.0.0.1:10808",
                 "--max-time", "5", "https://api.ipify.org"],
                capture_output=True, text=True, timeout=8
            )
            
            if result.returncode == 0 and result.stdout.strip():
                connected_ip = result.stdout.strip()
                success = True
            else:
                success = False
                
        except subprocess.TimeoutExpired:
            success = False
        except Exception as e:
            success = False
        
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except:
            try:
                proc.kill()
                proc.wait(timeout=1)
            except:
                pass
        
        return success, connected_ip
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error test onering: {e}{Style.RESET_ALL}")
        return False, None
