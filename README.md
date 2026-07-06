# 🛡️ CryptKey
**Advanced Deterministic Password Synthesis**

CryptKey is a next-generation, zero-storage credential management tool. Traditional password managers store sensitive data in centralized, encrypted vaults—creating a massive single point of failure if the provider is breached. CryptKey abandons the "vault" model entirely. Instead, it acts as a **deterministic synthesizer**, calculating high-entropy passwords on the fly based on standard cryptographic algorithms. 

Because passwords are mathematically generated rather than stored, they cannot be leaked, stolen from a database, or intercepted during a cloud sync. 

## ✨ Key Features

*   **Zero-Storage Cryptography:** Passwords are generated locally on demand and disappear the moment the application closes.
*   **Key Versioning (Rotation):** Easily rotate a compromised password by incrementing the "Version" number, generating a brand-new key without having to change your Master Password.
*   **k-Anonymity Breach Checking:** Integrates with the *Have I Been Pwned* API. Hashes the generated key locally and only transmits the first 5 characters over the network to check for compromises, ensuring absolute privacy.
*   **Zero-Knowledge Analytics:** A local dashboard tracks metadata (secured sites, average length, expiry warnings) via `localStorage` without ever touching the plaintext keys.
*   **Advanced UI/UX:** Features a responsive, futuristic glassmorphism interface, real-time password strength analysis (calculating true entropy in bits), and visual hacker-reveal animations.

## 🧠 Security Architecture

CryptKey is built with a defense-in-depth approach to protect against brute-force, dictionary, and web-based attacks.

*   **Key Derivation Function:** Uses **PBKDF2-HMAC-SHA256** with 310,000 iterations to derive a secure deterministic seed, intentionally slowing down processing to thwart GPU-based brute-force attacks.
*   **Cryptographic PRNG:** The resulting hash acts as a strict seed for a Pseudo-Random Number Generator, guaranteeing high entropy and enforcing character variety (uppercase, lowercase, numbers, symbols).
*   **Strict Security Headers:** The Flask backend is hardened with strict `Content-Security-Policy` (CSP) headers to mitigate Cross-Site Scripting (XSS), alongside `X-Frame-Options` and `Strict-Transport-Security` (HSTS).
*   **Input Normalization:** Automatically sanitizes and standardizes domains (e.g., converting `GitHub.com` to `github.com`) before synthesis to prevent accidental lockouts.

## 🛠️ Tech Stack

*   **Backend:** Python 3, Flask, `hashlib`
*   **Frontend:** HTML5, CSS3, Vanilla JavaScript
*   **APIs:** Have I Been Pwned (k-Anonymity model)

## Prerequisites
Ensure you have Python 3.8+ and Git installed on your machine.


## 🚀 Installation & Usage

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Abhijeet-Mishra22/CryptKey.git
   cd CryptKey

2. **Install dependencies:**
   ```bash
   pip install Flask

3. **Run the cryptographic server:**
   ```bash
   app.py

4. **Access the application:**
   Open your preferred web browser and navigate to the local development server:
    ```bash
    http://localhost:5000

   


   

   
