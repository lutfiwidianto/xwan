#!/usr/bin/env python3
import requests
import random
import socket
import os
from bs4 import BeautifulSoup
from colorama import Fore, Style

def user_agent():
    try:
        with open("user-agents.txt", "r") as f:
            ua = f.read().splitlines()
        return random.choice(ua)
    except:
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def search_by_keyword():
    print(f"{Fore.GREEN}--- SMART SCANNER: SAFE & PRIORITY ---{Style.RESET_ALL}")
    keyword = input(f"{Fore.YELLOW}[*] Masukkan Keyword/Domain Utama : {Style.RESET_ALL}").strip()
    if not keyword: return

    file_name = input(f"{Fore.YELLOW}[*] Nama file simpan : {Style.RESET_ALL}").strip() or "final_results.txt"
    if not file_name.endswith(".txt"): file_name += ".txt"

    # Inisialisasi penghitung untuk laporan akhir
    count_keyword = 0
    count_subdomain = 0
    all_results = set()

    # TAHAP 1: PENGUMPULAN & PENYELAMATAN DATA (ANTI-LOSS)
    print(f"\n{Fore.CYAN}[*] Tahap 1: Mengambil data (Auto-Save Aktif)...{Style.RESET_ALL}")
    
    # Memisahkan URL untuk pelaporan yang lebih akurat
    targets = [
        {'url': f"https://rapiddns.io/s/{keyword}?full=1&down=0", 'label': 'KEYWORD'},
    ]
    if "." in keyword:
        targets.append({'url': f"https://rapiddns.io/subdomain/{keyword}?full=1&down=0", 'label': 'SUBDOMAIN'})

    with open(file_name, 'w') as f:
        for target in targets:
            try:
                headers = {'User-Agent': user_agent()}
                r = requests.get(target['url'], headers=headers, timeout=15).text
                soup = BeautifulSoup(r, 'html.parser')
                tbody = soup.find('tbody')
                if tbody:
                    for row in tbody.find_all('tr'):
                        cells = row.find_all('td')
                        if cells:
                            domain = cells[0].text.strip().rstrip('.')
                            if domain not in all_results:
                                f.write(domain + '\n')
                                f.flush()
                                print(f"{Fore.WHITE}[FOUND] {domain}{Style.RESET_ALL}")
                                all_results.add(domain)
                                # Hitung berdasarkan label sumber
                                if target['label'] == 'KEYWORD':
                                    count_keyword += 1
                                else:
                                    count_subdomain += 1
            except Exception as e:
                print(f"{Fore.RED}[!] Koneksi terganggu di {target['label']}: {e}{Style.RESET_ALL}")
                break

    if not all_results:
        print(f"{Fore.RED}[!] Tidak ada data ditemukan.{Style.RESET_ALL}")
        return

    # TAHAP 2: PENYUSUNAN ULANG BERDASARKAN PRIORITAS
    print(f"\n{Fore.CYAN}[*] Tahap 2: Menganalisis & Menyusun Prioritas...{Style.RESET_ALL}")
    
    ref_ip = get_ip(keyword)
    ref_base = ".".join(ref_ip.split(".")[:2]) if ref_ip else None
    
    top_priority = []
    mid_priority = []
    low_priority = []

    for domain in all_results:
        target_ip = get_ip(domain)
        if target_ip and ref_base and target_ip.startswith(ref_base):
            print(f"{Fore.GREEN}[HOT-MATCH] {domain}{Style.RESET_ALL}")
            top_priority.append(domain)
        elif keyword in domain and "." in keyword:
            mid_priority.append(domain)
        else:
            low_priority.append(domain)

    # Mengurutkan dan menggabungkan
    top_priority.sort(); mid_priority.sort(); low_priority.sort()
    final_list = top_priority + mid_priority + low_priority

    # TAHAP 3: MENULIS ULANG FILE DENGAN URUTAN PRIORITAS
    with open(file_name, 'w') as f:
        for dom in final_list:
            f.write(dom + '\n')

    # --- LAPORAN AKHIR (REPORT) ---
    print(f"\n{Fore.GREEN}================ REPORT AKHIR ================{Style.RESET_ALL}")
    print(f"[*] Total Domain dari Keyword   : {count_keyword}")
    print(f"[*] Total dari Subdomain Search : {count_subdomain}")
    print(f"[*] Total Unik Ditemukan        : {len(all_results)}")
    print(f"----------------------------------------------")
    print(f"[*] Prioritas 1 (HOT Match IP)  : {len(top_priority)}")
    print(f"[*] Prioritas 2 (Subdomain)     : {len(mid_priority)}")
    print(f"[*] Prioritas 3 (Others)        : {len(low_priority)}")
    print(f"{Fore.GREEN}=============================================={Style.RESET_ALL}")
    print(f"[!] File '{file_name}' siap digunakan.")