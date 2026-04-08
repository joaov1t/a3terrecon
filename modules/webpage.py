"""
Webpage Analyzer — o "F12 automatizado" do A3terRecon.
Analyzes a target page's source code like a manual F12 inspection.
"""
import re
import json
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup, Comment
from colorama import Fore
from core.http import HTTPClient
from core.output import section, info, critical, found, warn, save_report
from core.config import Config

# Patterns for secrets / interesting strings in source
SECRET_PATTERNS = {
    "API Key (generic)": r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
    "AWS Access Key": r'(?i)(AKIA[0-9A-Z]{16})',
    "AWS Secret Key": r'(?i)(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])',
    "JWT Token": r'(?i)(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}[\w.-]*?)',
    "Private Key": r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
    "Password in JS": r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{3,}["\']',
    "Bearer Token": r'(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*',
    "GitHub Token": r'(?i)ghp_[A-Za-z0-9_]{36}',
    "Slack Token": r'(?i)xox[baprs]-[0-9a-zA-Z-]+',
    "Google API Key": r'(?i)AIza[0-9A-Za-z\\-_]{35}',
    "Email Address": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "IP Address": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
    "Internal URL/Endpoint": r'(?i)(?:href|src|action|url|endpoint)\s*[:=]\s*["\']([/][^\s"\']+|[\w.-]+/\S*)["\']',
}


class WebpageAnalyzer:
    def __init__(self):
        self.http = HTTPClient()

    def analyze(self, url):
        """Full analysis of a webpage — like automated F12."""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        self.url = url
        self.domain = urlparse(url).netloc
        self.findings = {"target": url, "domain": self.domain}

        section(f"Analyzing {url}")

        self._fetch_page()
        if not self.response:
            warn("Could not fetch page. Aborting.")
            return

        self._parse_html()
        self._show_response_headers()
        self._show_technology()
        self._show_comments()
        self._show_links()
        self._show_forms()
        self._show_meta_tags()
        self._show_scripts()
        self._show_secrets()
        self._save_json_report()

    def _fetch_page(self):
        info("Fetching", self.url)
        self.response = self.http.get(self.url)
        if self.response:
            found("Status", f"{self.response.status_code}")
            found("Content-Type", self.response.headers.get("Content-Type", "N/A"))
            found("Server", self.response.headers.get("Server", "N/A"))

    def _parse_html(self):
        self.soup = BeautifulSoup(self.response.text, "html.parser")
        self.title = self.soup.title.string.strip() if self.soup.title else "N/A"
        found("Title", self.title)

    # --- HTTP Response Headers ---
    def _show_response_headers(self):
        section("Response Headers")
        security_headers = {
            "Content-Security-Policy": "CSP header",
            "X-Frame-Options": "Clickjacking protection",
            "X-Content-Type-Options": "MIME sniffing protection",
            "Strict-Transport-Security": "HSTS",
            "X-XSS-Protection": "XSS filter",
            "Referrer-Policy": "Referrer control",
            "Permissions-Policy": "Browser features control",
        }
        for header, desc in self.response.headers.items():
            info(header, desc)

        missing = [h for h in security_headers if h not in self.response.headers]
        if missing:
            section("Missing Security Headers")
            for h in missing:
                critical("MISSING", f"{security_headers[h]} ({h})")
        else:
            found("All", "security headers present")

        self.findings["headers"] = dict(self.response.headers)
        self.findings["missing_security_headers"] = missing

    # --- Cookies ---
    def _show_cookies(self):
        section("Cookies")
        if self.response.cookies:
            for cookie in self.response.cookies:
                flags = []
                if cookie.secure:
                    flags.append("Secure")
                if "httponly" in (cookie._rest or {}).get("HttpOnly", "").lower():
                    flags.append("HttpOnly")
                if "samesite" in (cookie._rest or {}).get("SameSite", "").lower():
                    flags.append("SameSite")

                flag_str = f" ({', '.join(flags)})" if flags else " (⚠ No security flags)"
                warn_flag = "⚠ " if not flags else ""
                print(f"  {Fore.CYAN}{warn_flag}{cookie.name}{Fore.RESET}: {cookie.value[:50]}...{flag_str}")
        else:
            info("Cookies", "None")

    # --- Technology Detection ---
    def _show_technology(self):
        section("Detected Technologies")
        techs = []
        html = self.response.text.lower()

        indicators = {
            "WordPress": ("wp-content", "wp-includes", "/xmlrpc.php"),
            "React": ("react", "_next/static", "webpackJsonp"),
            "Angular": ("ng-", "ng-app", "__angular"),
            "Vue.js": ("vue", "__vue_devtools", "data-v-"),
            "jQuery": ("jquery", "jQuery(", "$.ajax"),
            "Bootstrap": ("bootstrap", "bs-", ".bootstrap"),
            "Laravel": ("laravel_session", "XSRF-TOKEN"),
            "Django": ("csrftoken", "django"),
            "PHP": ("phpsessid", ".php", "x-powered-by"),
            "Node.js": ("node", "express", "connect.sid"),
            "Ruby on Rails": ("rails", "csrf-param", "authenticity_token"),
            "Cloudflare": ("cloudflare", "cf-", "__cf"),
            "Google Tag Manager": ("googletagmanager", "gtm.js"),
            "Google Analytics": ("google-analytics", "ga=", "gtag"),
            "Nginx": ("nginx",),
            "Apache": ("apache",),
        }

        # Check HTML content
        for tech, keywords in indicators.items():
            if any(kw in html or kw in self.response.headers.get("Server", "").lower()
                   for kw in keywords):
                techs.append(tech)
                found(tech, "Detected")

        if not techs:
            warn("No specific technologies identified")

        self.findings["technologies"] = techs

    # --- Comments ---
    def _show_comments(self):
        section("Hidden HTML Comments (like F12 > Elements > Comments)")
        comments = self.soup.find_all(string=lambda text: isinstance(text, Comment))
        interesting = []
        for c in comments:
            txt = str(c).strip()
            if txt:
                interesting.append(txt)
                print(f"  {Fore.MAGENTA}<!--{Fore.RESET}{Fore.YELLOW} {txt}{Fore.MAGENTA} -->{Fore.RESET}")

        if not interesting:
            info("Comments", "None found")
        else:
            warn(f"Found {len(interesting)} comment(s) — check for dev notes, credentials, or TODOs")

        self.findings["comments"] = interesting

    # --- Links ---
    def _show_links(self):
        section("Links & Endpoints")
        internal = set()
        external = set()
        suspicious = set()

        for tag in self.soup.find_all(["a", "link", "img", "script"], href=True):
            href = tag.get("href", "")
            if not href or href.startswith(("#", "javascript:", "mailto:")):
                continue
            full = urljoin(self.url, href)
            if self.domain in full:
                internal.add(full)
            else:
                external.add(full)

            # Suspicious patterns
            susp_words = ["admin", "login", "config", "backup", "db", "test",
                         "dev", "staging", "api", "debug", "console", "shell",
                         "upload", "phpinfo", "wp-", ".env"]
            if any(s in href.lower() for s in susp_words):
                suspicious.add(full)

        for tag in self.soup.find_all(href=True):
            href = tag.get("href", "")
            if href and not href.startswith(("#", "javascript:")):
                full = urljoin(self.url, href)
                internal.add(full) if self.domain in full else external.add(full)

        found("Internal links", f"{len(internal)}")
        found("External links", f"{len(external)}")

        if suspicious:
            section("Suspicious / Interesting Endpoints")
            for s in sorted(suspicious):
                critical("INTERESTING", s)
            self.findings["suspicious_endpoints"] = sorted(suspicious)

        self.findings["internal_links"] = sorted(internal)
        self.findings["external_links"] = sorted(external)

    # --- Forms ---
    def _show_forms(self):
        section("Forms (like F12 > Inspect > <form>)")
        forms = self.soup.find_all("form")
        if not forms:
            info("Forms", "None found")
            return

        for i, form in enumerate(forms, 1):
            method = form.get("method", "GET").upper()
            action = form.get("action", "")
            full_action = urljoin(self.url, action) if action else self.url

            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inp_type = inp.get("type", "text")
                inp_name = inp.get("name", "")
                inp_value = inp.get("value", "")
                is_hidden = "hidden" in (inp.get("class", []) or [inp_type])
                inputs.append({
                    "type": inp_type,
                    "name": inp_name,
                    "value": inp_value[:30] if inp_value else "",
                    "hidden": is_hidden,
                })

            details = f"{method} > {full_action} ({len(inputs)} inputs)"
            info(f"Form {i}", details)

            hidden_inputs = [inp for inp in inputs if inp.get("hidden") or inp["type"] == "hidden"]
            if hidden_inputs:
                warn("Hidden inputs found:")
                for h in hidden_inputs:
                    print(f"    {Fore.RED}{h['name']}{Fore.RESET} = {h['value']}")

            if method == "POST":
                warn(f"Form {i} uses POST — potential injection target")
            if "password" in [inp["type"] for inp in inputs]:
                warn(f"Form {i} has a password field — check for HTTPS")

            self.findings.setdefault("forms", []).append({
                "method": method,
                "action": full_action,
                "inputs": inputs,
            })

    # --- Meta Tags ---
    def _show_meta_tags(self):
        section("Meta Tags")
        for meta in self.soup.find_all("meta"):
            name = meta.get("name") or meta.get("property") or ""
            content = meta.get("content", "")
            if name and content:
                info(name, content)

    # --- JavaScript Analysis ---
    def _show_scripts(self):
        section("JavaScript Files")
        scripts = set()
        inline_scripts = []

        # External scripts
        for tag in self.soup.find_all("script", src=True):
            src = tag["src"]
            full = urljoin(self.url, src)
            scripts.add(full)
            found("External", src)

        # Inline scripts — search for interesting patterns
        for tag in self.soup.find_all("script"):
            if tag.string:
                inline_scripts.append(tag.string)

        found("Inline scripts", f"{len(inline_scripts)}")
        self.findings["external_scripts"] = sorted(scripts)

        # Analyze JS content for secrets/endpoints
        if inline_scripts:
            section("Interesting JS Patterns (inline)")
            js_content = "\n".join(inline_scripts)
            self._scan_js_content(js_content)

        # Fetch and analyze external JS files (limited to first 5)
        if scripts:
            section("Fetching External JS for Analysis")
            for src in sorted(list(scripts)[:5]):
                print(f"  {Fore.CYAN}[JS] {src}{Fore.RESET}")
                try:
                    resp = self.http.get(src, timeout=Config.TIMEOUT)
                    if resp and resp.status_code == 200:
                        self._scan_js_content(resp.text, src)
                except Exception:
                    pass

    def _scan_js_content(self, content, source="inline"):
        """Scan JS content for interesting patterns."""
        js_findings = []

        # API endpoints in JS
        api_patterns = re.findall(
            r'(?:(?:get|post|put|delete|fetch|axios)\s*\(\s*["\']|url\s*:\s*["\']|endpoint\s*[:=]\s*["\']|fetch\s*\(\s*["\'])'
            r'([^"\']{3,})["\']',
            content, re.IGNORECASE
        )
        for api in api_patterns:
            js_findings.append(f"API endpoint: {api}")
            found("API endpoint", api)

        # Check secret patterns
        for name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            for match in matches[:3]:  # limit display
                js_findings.append(f"{name}: {match[:50]}")
                critical(name, match[:50])

        if not js_findings:
            info("JS", "No interesting patterns found")

        self.findings.setdefault("js_findings", []).append({
            "source": source,
            "findings": js_findings,
        })

    # --- Secrets & Sensitive Data ---
    def _show_secrets(self):
        section("Secrets & Sensitive Data in Source")
        total_findings = 0

        for name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, self.response.text)
            if matches:
                for match in matches[:5]:  # limit display
                    total_findings += 1
                    critical(name, str(match)[:60])

        if total_findings == 0:
            found("Clean", "No obvious secrets found in page source")
        else:
            warn(f"Found {total_findings} potential secret(s) — verify manually")

        self.findings["total_secret_indicators"] = total_findings

    # --- Robots.txt & Sitemap ---
    def _check_robots(self):
        section("robots.txt Analysis")
        robots_url = f"{self.url.rsplit('/', 1)[0]}/robots.txt"
        resp = self.http.get(robots_url)
        if resp and resp.status_code == 200:
            found("Status", "robots.txt found")
            disallowed = []
            for line in resp.text.splitlines():
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        disallowed.append(path)
                        found("Disallow", path)

            if disallowed:
                warn(f"{len(disallowed)} disallowed path(s) — interesting for fuzzing")
            self.findings["robots_disallowed"] = disallowed
        else:
            warn("robots.txt not found")

    def _save_json_report(self):
        filename = f"webpage_{self.domain.replace('.', '_')}.json"
        save_report(self.findings, filename)
