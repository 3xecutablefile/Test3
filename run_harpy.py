from harpy_ai_otp import HarpyAIOTP
from colorama import Fore, Style, init
import requests
import socket
from urllib.parse import urlparse
import threading
import time
import os
import logging
from typing import Optional, Dict, Any

# Configure logging for the main script
logging.basicConfig(level=logging.INFO, format='[🦅 HARPY] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

init(autoreset=True)  # Auto-reset colors after print

class ProxyMonitor:
    """
    Monitors the reachability of a given proxy URL in a background thread.
    If the proxy goes down, it can either cause the application to abort (force mode)
    or signal a fallback to direct connection.
    """
    def __init__(self, proxy_url: str, force: bool = False, check_interval: int = 5):
        """
        Initializes the ProxyMonitor.

        Args:
            proxy_url (str): The URL of the proxy to monitor.
            force (bool): If True, aborts the application if the proxy goes down.
                          If False, signals a fallback to direct connection.
            check_interval (int): How often (in seconds) to check the proxy status.
        """
        self.proxy_url = proxy_url
        self.force = force
        self.check_interval = check_interval
        self.running = True
        self.alive = proxy_alive(proxy_url) # Initial check
        logger.info(f"ProxyMonitor initialized for {proxy_url}. Force mode: {force}.")

    def start(self):
        """Starts the background monitoring thread."""
        thread = threading.Thread(target=self._monitor, daemon=True)
        thread.start()
        logger.info("ProxyMonitor thread started.")

    def _monitor(self):
        """The main monitoring loop that runs in a separate thread."""
        while self.running:
            if not proxy_alive(self.proxy_url):
                self.alive = False
                if self.force:
                    logger.critical(f"Proxy {self.proxy_url} went down. Aborting (force mode).")
                    os._exit(1)  # Hard stop as requested by user
                else:
                    logger.warning(f"Proxy {self.proxy_url} went down. Switching to direct connection.")
                break # Stop monitoring once proxy is down
            time.sleep(self.check_interval)

    def stop(self):
        """Stops the background monitoring thread."""
        self.running = False
        logger.info("ProxyMonitor thread stopped.")

def proxy_alive(proxy_url: str) -> bool:
    """Check if a proxy (Burp/ZAP) is reachable by attempting a socket connection."""
    try:
        parsed = urlparse(proxy_url)
        host, port = parsed.hostname, parsed.port
        if not host or not port:
            logger.error(f"Invalid proxy URL format: {proxy_url}")
            return False
        with socket.create_connection((host, port), timeout=2):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logger.debug(f"Proxy {proxy_url} not reachable: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error checking proxy {proxy_url} reachability: {e}")
        return False

def detect_proxy_type(proxy_url: str) -> str:
    """
    Attempts to detect if the proxy is Burp Suite or OWASP ZAP by probing known endpoints/headers.
    Returns 'Burp Suite', 'OWASP ZAP', 'Unknown Proxy', or 'Unreachable'.
    """
    try:
        # Probe with a harmless URL, disabling SSL verification for local proxy probes
        r = requests.get("http://example.com", proxies={"http": proxy_url, "https": proxy_url}, timeout=3, verify=False)
        
        # Burp detection: Check for 'Server: Burp' header or 'Burp Suite' in response text
        if "Burp Suite" in r.text or "burp" in r.headers.get("Server", "").lower():
            return "Burp Suite"

        # ZAP detection: Try to hit the ZAP API endpoint
        # Ensure the URL is correctly formed for the API endpoint
        parsed_proxy_url = urlparse(proxy_url)
        zap_api_url = f"{parsed_proxy_url.scheme}://{parsed_proxy_url.netloc}/JSON/core/view/version/"
        try:
            zap_r = requests.get(zap_api_url, proxies={"http": proxy_url, "https": proxy_url}, timeout=2, verify=False)
            if zap_r.status_code == 200 and "version" in zap_r.json():
                return "OWASP ZAP"
        except (requests.exceptions.RequestException, ValueError): # ValueError for json() parse errors
            pass # ZAP probe failed, continue

        return "Unknown Proxy"
    except requests.exceptions.ProxyError:
        logger.debug(f"Proxy {proxy_url} returned ProxyError during type detection.")
        return "Unreachable"
    except requests.exceptions.RequestException as e:
        logger.debug(f"RequestException during proxy type detection for {proxy_url}: {e}")
        return "Unreachable"
    except Exception as e:
        logger.error(f"Unexpected error during proxy type detection for {proxy_url}: {e}")
        return "Unreachable"

def banner():
    """Prints the HarpyOTP ASCII art banner."""
    print(Fore.CYAN + r'''

d88888b db    db d8888b.  .o88b. db    db d888888b  .d8b.  d8888b. db      d88888b d88888b d888888b db      d88888b 
88'     `8b  d8' VP  `8D d8P  Y8 88    88 `~~88~~' d8' `8b 88  `8D 88      88'     88'       `88'   88      88'     
88ooooo  `8bd8'    oooY' 8P      88    88    88    88ooo88 88oooY' 88      88ooooo 88ooo      88    88      88ooooo 
88~~~~~  .dPYb.    ~~~b. 8b      88    88    88    88~~~88 88~~~b. 88      88~~~~~ 88~~~      88    88      88~~~~~
88.     .8P  Y8. db   8D Y8b  d8 88b  88    88    88   88 88   8D 88booo. 88.     88        .88.   88booo. 88.     
Y88888P YP    YP Y8888P'  `Y88P' ~Y8888P'    YP    YP   YP Y8888P' Y88888P Y88888P YP      Y888888P Y88888P Y88888P 

                🦅 ''' + Fore.YELLOW +