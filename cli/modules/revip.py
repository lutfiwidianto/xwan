import requests, random
from pathlib import Path
from bs4 import BeautifulSoup
from colorama import Fore, Style

def user_agent():
    data_file = Path(__file__).resolve().parents[2] / "data" / "user-agents.txt"
    try:
        ua = open(data_file, "r").read().splitlines()
        return random.choice(ua)
    except:
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

def reverse_ip():
    input_ip = input(f"{Fore.YELLOW}[*] IP Address : {Style.RESET_ALL}")
    output_path = Path(__file__).resolve().parents[2] / "data" / "rev_ip.txt"
    try:
        page = 0
        domains_found = False
        
        while True:
            page += 1
            url = f"https://www.rapiddns.io/s/{input_ip}?page={page}"
            Agents = {'User-Agent': user_agent()}
            req = requests.get(url, headers=Agents)
            req.raise_for_status()
            
            bs = BeautifulSoup(req.text, "html.parser")
            tbody = bs.find("tbody")
            
            if tbody:
                tr = tbody.find_all("tr")
                if not tr:
                    break
                    
                for row in tr:
                    cell = row.find_all("td")
                    if cell:
                        dom_cell = cell[0]
                        dom_txt = dom_cell.text.strip()
                        if dom_txt:
                            print(f"[*] from {Fore.YELLOW}{input_ip}{Style.RESET_ALL} get {Fore.YELLOW}{dom_txt}{Style.RESET_ALL}")
                            output_path.parent.mkdir(parents=True, exist_ok=True)
                            with open(output_path, "a") as f:
                                f.write(dom_txt + "\n")
                            domains_found = True
            else:
                if page == 1:
                    print(f"[*] IP tidak ditemukan, ganti IP lain!")
                break
        
        if domains_found:
            print(f"[!] Selesai! Hasil disimpan di {Fore.GREEN}{output_path}{Style.RESET_ALL}")
        else:
            print(f"[!] Tidak ada domain ditemukan untuk IP {input_ip}")
            
    except requests.exceptions.RequestException as e:
        print(f"[!] Error koneksi: {e}")
    except Exception as e:
        print(f"[!] Error: {e}")
