import time
import requests
from colorama import Fore
from .config import Config


class HTTPClient:
    """Reusable HTTP engine with retry, proxy, and rate-limit support."""

    def __init__(self):
        session = requests.Session()
        session.headers.update({"User-Agent": Config.USER_AGENT})
        if Config.get_proxy_dict():
            session.proxies.update(Config.get_proxy_dict())
        self.session = session

    def get(self, url, **kwargs):
        kwargs.setdefault("timeout", Config.TIMEOUT)
        for attempt in range(Config.MAX_RETRIES):
            try:
                time.sleep(Config.DELAY)
                r = self.session.get(url, **kwargs)
                return r
            except requests.RequestException as e:
                print(f"{Fore.YELLOW}[!] Retry {attempt + 1}/{Config.MAX_RETRIES} for {url}: {e}{Fore.RESET}")
        return None

    def post(self, url, **kwargs):
        kwargs.setdefault("timeout", Config.TIMEOUT)
        for attempt in range(Config.MAX_RETRIES):
            try:
                time.sleep(Config.DELAY)
                r = self.session.post(url, **kwargs)
                return r
            except requests.RequestException as e:
                print(f"{Fore.YELLOW}[!] Retry {attempt + 1}/{Config.MAX_RETRIES} for {url}: {e}{Fore.RESET}")
        return None
