"""
Email Enumerator — finds emails associated with a domain.
"""
import re
from urllib.parse import urlparse
from colorama import Fore
from core.http import HTTPClient
from core.output import section, info, found, warn, error, save_report


class EmailFinder:
    def __init__(self):
        self.http = HTTPClient()
        self.emails = set()

    def enumerate(self, domain):
        self.domain = domain.strip().lower()
        if "://" in self.domain:
            self.domain = urlparse(f"https://{self.domain}").netloc

        self.findings = {"domain": self.domain}

        section(f"Searching emails for {self.domain}")

        self._web_search()
        self._page_crawl()
        self._whois_check()
        self._display_results()
        self._save_report()
        return sorted(self.emails)

    # --- Search engine pages for email patterns ---
    def _web_search(self):
        """Extract emails from public pages related to the domain."""
        for proto in ["https", "http"]:
            try:
                url = f"{proto}://{self.domain}"
                resp = self.http.get(url)
                if resp:
                    self._extract_from_text(resp.text)
            except Exception:
                pass

    def _page_crawl(self):
        """Crawl common pages that might contain emails."""
        paths = [
            "/about", "/contact", "/team", "/impressum",
            "/privacy", "/terms", "/sitemap.xml",
        ]
        for path in paths:
            try:
                url = f"https://{self.domain}{path}"
                resp = self.http.get(url)
                if resp and resp.status_code == 200:
                    self._extract_from_text(resp.text)
            except Exception:
                pass

    def _whois_check(self):
        """Check WHOIS for admin email."""
        info("WHOIS", "Skipped — requires python-whois, results may be unreliable")
        # WHOIS parsing is unreliable in automation; skip for now

    def _extract_from_text(self, text):
        """Extract email addresses from HTML/text."""
        # Pattern for emails in source
        pattern = r'[a-zA-Z0-9._%+-]+@' + re.escape(self.domain)
        found_emails = re.findall(pattern, text)
        for email in found_emails:
            # Clean up HTML artifacts
            email = email.lstrip(".").rstrip(">")
            if email and "@" in email:
                self.emails.add(email.lower())

        # Also look for mailto: links
        mailto = re.findall(r'href\s*=\s*["\']mailto:([^"\'>]+)', text, re.IGNORECASE)
        for m in mailto:
            clean = m.split("?")[0].lower()
            if clean:
                self.emails.add(clean)

    def _display_results(self):
        section("Email Addresses Found")
        if self.emails:
            for email in sorted(self.emails):
                print(f"  {Fore.GREEN}> {email}{Fore.RESET}")
            found("Total", f"{len(self.emails)} email(s)")
        else:
            warn("No emails found")

        self.findings["emails"] = sorted(self.emails)

    def _save_report(self):
        filename = f"emails_{self.domain.replace('.', '_')}.json"
        save_report(self.findings, filename)
