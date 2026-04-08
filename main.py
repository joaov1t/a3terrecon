#!/usr/bin/env python3
"""
A3terRecon — OSINT Reconnaissance Framework
by joaov1t (Et3rn4l) — recon is endless.
"""
import argparse
import sys
from colorama import init, Fore, Style

init(autoreset=True)

from core.output import banner, section, warn
from modules.webpage import WebpageAnalyzer
from modules.subdomain import SubdomainFinder
from modules.email import EmailFinder
from modules.infra import InfraScanner
from modules.breach import BreachChecker


MODULES = {
    "webpage": {"desc": "Web page analyzer (F12 automatizado)", "class": WebpageAnalyzer, "method": "analyze"},
    "subdomain": {"desc": "Subdomain enumeration", "class": SubdomainFinder, "method": "enumerate"},
    "email": {"desc": "Email enumeration", "class": EmailFinder, "method": "enumerate"},
    "infra": {"desc": "Infrastructure recon (IP, geo, SSL, Shodan)", "class": InfraScanner, "method": "scan"},
    "breach": {"desc": "Breach & credential leak checker", "class": BreachChecker, "method": "check"},
    "all": {"desc": "Run all modules on target"},
}


def print_list_modules():
    print(f"\n{Fore.CYAN}Available modules:{Fore.RESET}")
    print(f"{'=' * 60}")
    for name, mod in MODULES.items():
        print(f"  {Fore.GREEN}{name:<12}{Fore.RESET} {mod['desc']}")
    print()


def run_module(name, target):
    if name == "all":
        for mod_name in ["subdomain", "email", "webpage", "infra", "breach"]:
            try:
                run_module(mod_name, target)
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Skipping {mod_name}...{Fore.RESET}")
        return

    mod = MODULES[name]
    try:
        scanner = mod["class"]()
        getattr(scanner, mod["method"])(target)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Interrupted by user.{Fore.RESET}")
    except Exception as e:
        print(f"\n{Fore.RED}[-] Error in {name}: {e}{Fore.RESET}")


def main():
    banner()

    parser = argparse.ArgumentParser(
        description=f"A3terRecon {Style.DIM}— OSINT Reconnaissance Framework{Style.RESET_ALL}",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-t", "--target", help="Target URL, domain, or email")
    parser.add_argument("-m", "--module", default="all",
                        help=f"Module to run (default: all)\nAvailable: {', '.join(MODULES.keys())}")
    parser.add_argument("-l", "--list", action="store_true", help="List available modules")
    parser.add_argument("-p", "--proxy", help="HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("-d", "--delay", type=float, default=0,
                        help="Delay between requests in seconds (default: 0)")

    args = parser.parse_args()

    if args.list:
        print_list_modules()
        sys.exit(0)

    if not args.target:
        print(f"\n{Fore.RED}[-] No target specified. Use -t <target>{Fore.RESET}")
        print_list_modules()
        sys.exit(1)

    # Apply CLI options to config
    from core.config import Config
    if args.proxy:
        Config.PROXY = args.proxy
    if args.delay:
        Config.DELAY = args.delay

    # Validate module
    if args.module not in MODULES:
        print(f"{Fore.RED}[-] Unknown module: {args.module}{Fore.RESET}")
        print_list_modules()
        sys.exit(1)

    # Run
    print(f"{Style.DIM}[+] Target: {args.target}{Style.RESET_ALL}")
    print(f"{Style.DIM}[+] Module: {args.module}{Style.RESET_ALL}\n")

    try:
        run_module(args.module, args.target)
        print(f"\n{Fore.GREEN}[+] A3terRecon complete. Reports saved to reports/{Fore.RESET}")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Interrupted. Partial reports may exist in reports/{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
