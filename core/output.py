import json
from pathlib import Path
from colorama import Fore, Style
from .config import Config


def banner():
    print(f"{Fore.CYAN}")
    print(" A3terRecon - OSINT Reconnaissance Framework")
    print(" by joaov1t (Et3rn4l) - recon is endless")
    print(f"{Style.RESET_ALL}")


def section(title):
    print(f"\n{Fore.GREEN}[+] {title}{Fore.RESET}")
    print(f"{Fore.GREEN}{'=' * 60}{Fore.RESET}")


def info(label, value):
    print(f"  {Fore.CYAN}[{label}]{Fore.RESET} {value}")


def critical(label, value):
    print(f"  {Fore.RED}[{label}] {Fore.RED}{value}{Fore.RESET}")


def found(label, value):
    print(f"  {Fore.GREEN}[{label}] {value}{Fore.RESET}")


def warn(msg):
    print(f"  {Fore.YELLOW}[!] {msg}{Fore.RESET}")


def error(msg):
    print(f"  {Fore.RED}[-] {msg}{Fore.RESET}")


def save_report(data: dict, filename: str):
    """Save findings as JSON report."""
    Config.REPORT_DIR.mkdir(parents=True, exist_ok=True)
    path = Config.REPORT_DIR / filename
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"\n{Fore.GREEN}[+] Report saved to {path}{Fore.RESET}")
