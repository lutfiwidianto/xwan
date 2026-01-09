import os
from pathlib import Path
from colorama import Fore, Style

def check_core():
    root_dir = Path(__file__).resolve().parents[2]
    onering_arm = root_dir / "bin" / "onering" / "xray.linux.arm64.64bit"
    onering_amd = root_dir / "bin" / "onering" / "xray.linux.amd64.64bit"
    termux_arm = "/data/data/com.termux/files/usr/bin/xray.linux.arm64.64bit"
    termux_amd = "/data/data/com.termux/files/usr/bin/xray.linux.amd64.64bit"

    if onering_arm.exists() or onering_amd.exists() or os.path.exists(termux_arm) or os.path.exists(termux_amd):
        print(f"{Fore.GREEN}> ONERING?o.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}> ONERINGdYY?{Style.RESET_ALL}")

    xray_normal = root_dir / "bin" / "xray"
    termux_xray = "/data/data/com.termux/files/usr/bin/xray"
    if xray_normal.exists() or os.path.exists(termux_xray):
        print(f"{Fore.GREEN}> XRAY?o.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}> XRAYdYY?{Style.RESET_ALL}")
