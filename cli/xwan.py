#!/usr/bin/env python3
#xwan v.3.0 modded with Auto-All-Mode
import os
import sys
from pathlib import Path
from colorama import Fore, Style, init

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "cli"))

from modules import parse, config, test_xray, ssh_ws, subdomain, onering, revip
from utils import helpers
from core import check
from modules import keyword_search

init()
os.system("clear")

def main():
    print(helpers.show_banner())
    check.check_core()
    
    # Menampilkan menu manual (dari helpers)
    helpers.show_menu()
    # Menambahkan opsi menu tambahan secara visual di sini
    
    choice = input(f"{Fore.YELLOW}[*] Pilih metode (1-9): {Style.RESET_ALL}").strip()
    
    # Handle fitur selain scanning Xray
    if choice == "5":
        ssh_ws.ssh_ws_connection()
        return
    if choice == "6":
        subdomain.Subdomain()
        return
    if choice == "7":
        revip.reverse_ip()
        return
    if choice == "8":
        keyword_search.search_by_keyword()
        return
    
    # Definisi mode untuk labeling
    modes = {
        "1": "Address",
        "2": "Wildcard", 
        "3": "SNI",
        "4": "Onering",
        "9": "Auto All Modes"
    }
    
    if choice not in modes:
        print(f"{Fore.RED}[!] Pilihan tidak valid{Style.RESET_ALL}")
        return
    
    print(f"{Fore.CYAN}[!] Mode: {modes[choice]}{Style.RESET_ALL}")
    
    url = input(f"{Fore.YELLOW}[*] URL akun (vmess/trojan/vless): {Style.RESET_ALL}").strip()
    if not url:
        print(f"{Fore.RED}[!] URL diperlukan{Style.RESET_ALL}")
        return
    
    try:
        # Parsing URL akun VPN
        account = parse.parse_vmess_trojan_url(url)
        print(f"{Fore.GREEN}[+] Account : {account['protocol']} {account['address']}:{account['port']}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        return
    
    list_file = input(f"{Fore.YELLOW}[*] List IP/domain (txt): {Style.RESET_ALL}").strip()
    list_path = Path(list_file)
    if list_file and not list_path.exists():
        candidate = ROOT_DIR / "data" / list_file
        if candidate.exists():
            list_path = candidate
    if not list_path.exists():
        print(f"{Fore.RED}[!] File tidak ditemukan{Style.RESET_ALL}")
        return
    
    targets = test_xray.load_addresses_from_file(str(list_path))
    if not targets: return

    print(f"\n{Fore.CYAN}[!] Starting scan ({len(targets)} targets) :{Style.RESET_ALL}")
    
    success_count = 0
    for i, target in enumerate(targets, 1):
        print(f"\n{Fore.YELLOW}[{i}/{len(targets)}] Testing Target: {target}{Style.RESET_ALL}")
        
        # Logika utama: Jika pilih 9, tes semua mode. Jika tidak, tes mode yang dipilih saja.
        active_modes = ["1", "2", "3", "4"] if choice == "9" else [choice]

        for m in active_modes:
            mode_name = modes[m]
            print(f"  [>] Testing {mode_name}... ", end="", flush=True)
            
            # Membersihkan proses xray sebelumnya agar port tidak bentrok
            helpers.kill_xray_processes()
            result = False

            try:
                if m == "4":  # Onering
                    result, _ = onering.test_onering(target, account)
                elif m == "2":  # Wildcard
                    result = test_xray.test_wildcard_address(target, account)
                elif m == "3":  # SNI
                    result = test_xray.test_address(None, account, target)
                elif m == "1":  # Address
                    result = test_xray.test_address(target, account)
                
                if result:
                    print(f"{Fore.GREEN}CONNECTED ✅{Style.RESET_ALL}")
                    success_count += 1
                    output_path = ROOT_DIR / "output" / "Result.txt"
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(output_path, "a") as f:
                        f.write(f"Domain: {target} | Mode: {mode_name} | Account: {account['address']}\n")
                else:
                    print(f"{Fore.RED}FAILED ❌{Style.RESET_ALL}")
            except:
                print(f"{Fore.RED}ERROR ⚠️{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}[!] Scan Selesai. Total Berhasil: {success_count}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[!] Result tersimpan di: {ROOT_DIR / 'output' / 'Result.txt'}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
