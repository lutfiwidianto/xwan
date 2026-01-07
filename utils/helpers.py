#!/usr/bin/env python3
import subprocess
import time
from colorama import Fore, Style

def kill_xray_processes():
    """Menghentikan semua proses Xray yang sedang berjalan agar port tidak bentrok."""
    subprocess.run(["pkill", "-9", "-f", "xray"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["pkill", "-9", "xray"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

def show_banner():
    """Menampilkan banner utama aplikasi XWan."""
    banner = f"""
__   ___    _             
\ \ / / |  | |            
 \ V /| |  | | __ _ _ __  
 /   \| |/\| |/ _` | '_ \ 
/ /^\ \  /\  / (_| | | | |
\/   \/\/  \/ \__,_|_| |_|
{Fore.YELLOW}Xray v25.12.8{Style.RESET_ALL}  {Fore.GREEN}v.3.0(new){Style.RESET_ALL}

Github : github.com/wannazid
Blog : www.malastech.my.id

{Fore.YELLOW}> Pastikan Akun VPN Stabil!
> Gunakan SSH dan Xray agar hasil lebih pasti!{Style.RESET_ALL}                         
"""
    return banner

def show_menu():
    """Menampilkan daftar metode scanning yang tersedia."""
    print("\t")
    print(f"{Fore.YELLOW}[*] Pilih metode:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[1] (Xray) Address{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[2] (Xray) Wildcard{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[3] (Xray) SNI{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[4] (Xray) Onering{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[5] SSH WEBSOCKET{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[6] Subdomain Scanner (Perlu Internet){Style.RESET_ALL}")
    print(f"{Fore.CYAN}[7] Reverse IP Address (Perlu Internet){Style.RESET_ALL}")
    print(f"{Fore.CYAN}[8] Keyword Domain Search (Custom Save){Style.RESET_ALL}")
    # Tambahan menu baru untuk fitur Auto Scan All Modes
    print(f"{Fore.GREEN}[9] (Xray) Auto Check All Modes (1,2,3,4){Style.RESET_ALL}")
