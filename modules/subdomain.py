"""
Subdomain Enumerator — discovers subdomains via multiple sources.
Passive OSINT only (no brute force by default).
"""
import json
import re
import time
import dns.resolver
from urllib.parse import urlparse
from colorama import Fore
from core.http import HTTPClient
from core.output import section, info, found, warn, error, save_report
from core.config import Config


class SubdomainFinder:
    def __init__(self):
        self.http = HTTPClient()
        self.subdomains = set()

    def enumerate(self, domain):
        """Run all subdomain enumeration techniques."""
        self.domain = domain.strip().lower()
        # Remove protocol if present
        if "://" in self.domain:
            self.domain = urlparse(f"https://{self.domain}").netloc

        self.findings = {"domain": self.domain}

        section(f"Enumerating subdomains for {self.domain}")

        self._crtsh()
        self._dns_dumpster()
        self._google_dorks()
        self._dns_resolve()

        self._display_results()
        self._save_report()
        return sorted(self.subdomains)

    # --- crt.sh (certificate transparency) ---
    def _crtsh(self):
        info("Source", "crt.sh (Certificate Transparency)")
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            resp = self.http.get(url, timeout=Config.TIMEOUT + 5)
            if resp and resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(self.domain) and sub != self.domain:
                            self.subdomains.add(sub)
                found("crt.sh", f"Found {len(self.subdomains)} subdomain(s) so far")
        except Exception as e:
            warn(f"crt.sh failed: {e}")

    # --- DNS Dumpster (html) ---
    def _dns_dumpster(self):
        info("Source", "DNS enumeration")
        # Common subdomains wordlist
        common = [
            "www", "mail", "smtp", "ftp", "ns1", "ns2", "mx1", "mx2",
            "webmail", "dev", "staging", "test", "api", "blog", "shop",
            "admin", "login", "cpanel", "webdisk", "autodiscover",
            "remote", "server", "mail2", "backup", "portal", "app",
            "cdn", "img", "static", "media", "video", "db",
            "vpn", "intranet", "wiki", "forum", "cloud", "owa",
            "git", "jenkins", "docker", "dashboard", "monitor",
        ]
        found_wordlist = False
        for sub in common:
            candidate = f"{sub}.{self.domain}"
            try:
                answers = dns.resolver.resolve(candidate, "A")
                if answers:
                    self.subdomains.add(candidate)
                    found_wordlist = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                pass
            except Exception:
                pass

        if found_wordlist:
            found("DNS", f"Resolved common subdomains (total: {len(self.subdomains)})")
        else:
            info("DNS", "No additional common subdomains resolved")

    # --- Google Dorks (basic) ---
    def _google_dorks(self):
        info("Source", "Search engine dorks (basic site: query)")
        try:
            # Just construct the dork URL for manual use
            dork_url = f"https://www.google.com/search?q=site:{self.domain}+-www"
            warn(f"Manual dork: {dork_url}")
            self.findings["google_dork"] = dork_url
        except Exception:
            pass

    # --- DNS Record Resolution ---
    def _dns_resolve(self):
        section("DNS Records")
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        dns_info = {}

        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, rtype)
                values = [str(rdata) for rdata in answers]
                dns_info[rtype] = values
                found(rtype, values[0] if len(values) == 1 else f"{len(values)} records")
                if len(values) > 1:
                    for v in values[:5]:
                        print(f"    {Fore.CYAN}> {v}{Fore.RESET}")
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                error(f"{self.domain} does not exist")
                return
            except Exception:
                pass

        self.findings["dns_records"] = dns_info

    # --- Display ---
    def _display_results(self):
        section("Subdomains Found")
        if self.subdomains:
            for sub in sorted(self.subdomains):
                print(f"  {Fore.GREEN}> {sub}{Fore.RESET}")
            found("Total", f"{len(self.subdomains)} subdomain(s)")
        else:
            warn("No subdomains found")

        self.findings["subdomains"] = sorted(self.subdomains)

    def _save_report(self):
        filename = f"subdomains_{self.domain.replace('.', '_')}.json"
        save_report(self.findings, filename)
