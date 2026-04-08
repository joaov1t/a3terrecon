"""
Breach Checker — checks for leaked credentials and exposed data.
Uses public resources and API integrations.
"""
from urllib.parse import urlparse
from colorama import Fore
from core.http import HTTPClient
from core.output import section, info, found, warn, error, save_report


class BreachChecker:
    def __init__(self):
        self.http = HTTPClient()
        self.findings = {}

    def check(self, target):
        """Check for breaches affecting the target domain or email."""
        self.target = target.strip().lower()
        is_email = "@" in self.target

        if is_email:
            self.findings = {"email": self.target}
            section(f"Checking breaches for {self.target}")
        else:
            domain = target
            if "://" in target:
                domain = urlparse(f"https://{target}").netloc
            self.findings = {"domain": domain}
            section(f"Checking breaches for domain {domain}")

        self._haveibeenpwned()
        self._github_leaks()
        self._pastebin_search()
        self._save_report()
        return self.findings

    def _haveibeenpwned(self):
        """Check Have I Been Pwned (requires API key for v3)."""
        section("Have I Been Pwned")
        warn("HIBP requires a paid API key")
        warn("Visit: https://haveibeenpwned.com/API/Key")
        self.findings["hibp"] = "Requires API key"

    def _github_leaks(self):
        """Search GitHub for domain-related leaks."""
        section("GitHub Search for Domain Leaks")

        from core.http import HTTPClient
        import re

        keywords = [
            "password", "secret", "token", "api_key",
            "database", "credentials", "login",
            "config", "env", ".env",
        ]

        for kw in keywords:
            search_url = (
                f"https://api.github.com/search/code?q="
                f"{self.target}+{kw}+in:file&per_page=5"
            )
            import os
            github_token = os.getenv("GITHUB_TOKEN", "")
            if github_token:
                headers = {"Authorization": f"token {github_token}"}
            else:
                headers = {}

            try:
                resp = self.http.get(search_url, headers=headers)
                if resp and resp.status_code == 200:
                    data = resp.json()
                    total = data.get("total_count", 0)
                    if total > 0:
                        warn(f"Found {total} result(s) for '{kw}' containing {self.target}")
                        for item in data.get("items", [])[:3]:
                            found("Repo", item["repository"]["full_name"])
                            info("File", item["path"])
                            info("URL", item["html_url"])
                    else:
                        found(kw, "No leaks found")
                elif resp and resp.status_code == 403:
                    warn(f"Rate limited on '{kw}' (add GITHUB_TOKEN env var)")
            except Exception as e:
                pass

        self.findings["github_leaks"] = "Results depend on GITHUB_TOKEN"

    def _pastebin_search(self):
        """Search Pastebin for domain mentions."""
        section("Pastebin Search")

        search_url = f"https://psbdmp.ws/api/v3/search/{self.target}"
        try:
            resp = self.http.get(search_url)
            if resp and resp.status_code == 200:
                data = resp.json()
                results = data.get("data", [])
                if results:
                    warn(f"Found {len(results)} paste(s) mentioning {self.target}")
                    for r in results[:5]:
                        found("Paste", r.get("id", "N/A"))
                else:
                    found("Clean", "No pastes found")
        except Exception:
            warn("Pastebin search failed — may require manual check")

        self.findings["pastebin"] = "Check manually on pbdmp.ws"

    def _save_report(self):
        target_name = self.target.replace(".", "_").replace("@", "_")
        filename = f"breach_{target_name}.json"
        save_report(self.findings, filename)
