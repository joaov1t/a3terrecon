"""
Infrastructure — IP info, ASN, geo, SSL cert, and Shodan integration.
"""
import json
from ipaddress import ip_address
from urllib.parse import urlparse
from colorama import Fore
from core.http import HTTPClient
from core.output import section, info, found, warn, error, save_report
from core.config import Config


class InfraScanner:
    def __init__(self):
        self.http = HTTPClient()
        self.findings = {}

    def scan(self, target):
        """Full infrastructure recon on a target."""
        self.target = target.strip().lower()
        if "://" in self.target:
            self.domain = urlparse(self.target).netloc
        else:
            self.domain = self.target
            self.target = "https://" + self.target

        self.findings = {"target": self.target, "domain": self.domain}

        section(f"Infrastructure Recon: {self.domain}")

        self._ip_lookup()
        self._geoip()
        self._shodan()
        self._ssl_check()
        self._save_report()
        return self.findings

    def _ip_lookup(self):
        section("IP Resolution")
        try:
            ips = __import__("socket").getaddrinfo(self.domain, None)
            unique_ips = set()
            for ip_info in ips:
                ip = ip_info[4][0]
                unique_ips.add(ip)
                self.findings.setdefault("ips", []).append(ip)
                found("Resolved", ip)
        except Exception as e:
            error(f"Could not resolve: {e}")

    def _geoip(self):
        section("GeoIP Info")
        for ip_raw in self.findings.get("ips", []):
            try:
                ip = str(ip_address(ip_raw))
                url = f"http://ip-api.com/json/{ip}"
                resp = self.http.get(url)
                if resp:
                    geo = resp.json()
                    if geo.get("status") == "success":
                        info("Country", f"{geo['country']} ({geo['countryCode']})")
                        info("Region", geo.get("regionName", "N/A"))
                        info("City", geo.get("city", "N/A"))
                        info("ISP", geo.get("isp", "N/A"))
                        info("ASN", geo.get("as", "N/A"))
                        found("Timezone", geo.get("timezone", "N/A"))
                        self.findings.setdefault("geoip", []).append(geo)
                    else:
                        warn(f"GeoIP failed for {ip}")
            except Exception:
                pass

    def _shodan(self):
        if not Config.SHODAN_API_KEY:
            warn("Shodan: No API key set (set SHODAN_API_KEY env var)")
            self.findings["shodan"] = "No API key"
            return

        section("Shodan Results")
        try:
            for ip_raw in self.findings.get("ips", []):
                ip = str(ip_address(ip_raw))
                url = f"https://api.shodan.io/shodan/host/{ip}?key={Config.SHODAN_API_KEY}"
                resp = self.http.get(url)
                if resp and resp.status_code == 200:
                    data = resp.json()
                    found("Ports", f"{data.get('ports', [])}")
                    found("Org", data.get("org", "N/A"))
                    for vuln in data.get("vulns", [])[:5]:
                        critical("CVE", vuln)
                    self.findings["shodan"] = data
                else:
                    warn(f"Shodan query failed for {ip}")
        except Exception as e:
            error(f"Shodan error: {e}")

    def _ssl_check(self):
        section("SSL/TLS Info")
        try:
            import ssl
            import socket
            ctx = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    subject = dict(x[0] for x in cert.get("subject", ()))

                    info("Issuer", issuer.get("organizationName", "N/A"))
                    info("Domain", subject.get("commonName", "N/A"))
                    info("Not Before", cert.get("notBefore", "N/A"))
                    info("Not After", cert.get("notAfter", "N/A"))

                    self.findings["ssl"] = {
                        "issuer": issuer,
                        "subject": subject,
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                    }
        except Exception as e:
            warn(f"SSL check failed: {e}")

    def _save_report(self):
        filename = f"infra_{self.domain.replace('.', '_')}.json"
        save_report(self.findings, filename)
