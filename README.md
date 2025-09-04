# HarpyOTP: AI-Driven OTP Exploitation Suite 🦅

HarpyOTP is an advanced, interactive command-line tool designed for security researchers and penetration testers to identify and exploit vulnerabilities in One-Time Password (OTP) authentication mechanisms. Leveraging AI-driven analysis and robust proxy handling, HarpyOTP provides a professional-grade platform for OTP security assessments.

## ✨ Features

-   **Interactive CLI:** User-friendly, menu-driven interface with styled output using `colorama`.
-   **AI-Driven Attack:** Utilizes a Random Forest Classifier to learn from OTP verification responses and predict the likelihood of success, enabling intelligent brute-force attacks.
-   **Adaptive Brute-Force:** A fallback sequential brute-force mode for simpler scenarios or when AI training data is limited.
-   **Login Chaining:** Seamlessly integrates a login step (username/password) to obtain an authenticated session before proceeding with OTP attacks, crucial for multi-factor authentication (MFA) bypass testing.
-   **Intelligent Proxy Handling:**
    -   Supports routing traffic through Burp Suite or OWASP ZAP.
    -   Automatically detects if the specified proxy is alive and identifies its type (Burp/ZAP).
    -   **Fallback Mode:** Gracefully switches to a direct connection if the proxy becomes unreachable during an attack (default).
    -   **Force Mode:** Aborts the attack immediately if the proxy is not reachable or goes down mid-run, ensuring all traffic is intercepted.
-   **Real-time Proxy Monitoring:** A background thread continuously monitors the proxy's status, providing real-time awareness and dynamic adaptation.
-   **Configurable Endpoints:** Prompts for target base URL, login path, and OTP verification path, making it adaptable to various web applications.
-   **Timing Analysis Visualization:** Generates plots to visualize response times, helping to identify potential timing side-channel vulnerabilities.

## 🚀 Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/3xecutablefile/Test3.git
    cd Test3
    ```

2.  **Install dependencies:**
    It's highly recommended to use a Python virtual environment.
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: .\venv\Scripts\activate
    pip install -r requirements.txt
    ```

## 💡 Usage

To launch HarpyOTP, simply run the `run_harpy.py` script:

```bash
python3 run_harpy.py
```

The tool will guide you through the process with interactive prompts:

1.  **Target Base URL:** The root URL of the web application (e.g., `https://example.com`).
2.  **Login Path (Optional):** The path to the login endpoint (e.g., `/login`). Provide this if you want HarpyOTP to handle the initial login.
3.  **OTP Verification Path:** The path to the OTP verification endpoint (e.g., `/auth/verify-otp`).
4.  **Target User ID:** The identifier for the user whose OTP you are testing (e.g., `wiener`, `victim@example.com`).
5.  **Target Password (Optional):** The password for the user ID, if you provided a login path and want to use the login chaining feature.
6.  **Burp/ZAP Proxy (Optional):** The URL of your proxy (e.g., `http://127.0.0.1:8080`).
7.  **Force Proxy? (y/N):** Choose whether to abort if the proxy is unreachable or goes down.

After initial setup, you'll be presented with the main menu:

```
╔════════════════════════════════════════╗
║        Choose an Attack Mode           ║
╠════════════════════════════════════════╣
║  1) Fingerprint OTP system             ║
║  2) Adaptive brute-force               ║
║  3) AI-driven attack                   ║
║  4) Exit                               ║
╚════════════════════════════════════════╝
```

Select an option to begin your assessment.

### Attack Modes Explained

-   **Fingerprint OTP system:** Sends a small set of random OTPs to the target to gather initial response data. This data is used to train the AI model.
-   **Adaptive brute-force:** A traditional sequential brute-force attack. Useful as a fallback or for systems with weak rate-limiting.
-   **AI-driven attack:** Leverages the trained AI model to prioritize OTP guesses based on predicted success likelihood, potentially speeding up the discovery of valid OTPs, especially in the presence of timing side-channels.


## 🛣️ Future Enhancements

-   Full `curses`-based TUI for a more dynamic and responsive user interface.
-   Support for different OTP payload formats (e.g., form-urlencoded, XML).
-   More advanced AI features and attack strategies.
-   Integration of other OTP attack types (e.g., replay, race conditions, harvesting).
