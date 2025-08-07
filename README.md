# WordPressDominator

⚠️ **Warning:** Use this tool only on systems you own or have explicit permission to test. Unauthorized use is illegal and unethical.

## What is WordPressDominator?

WordPressDominator is a Python-based framework designed to simulate a multi-stage attack on WordPress websites for educational and authorized penetration testing purposes. It automates:

- CSRF (Cross-Site Request Forgery) attack to create a new administrator user by exploiting missing security nonces.
- Credential stuffing/brute-force attack to find valid login credentials from a wordlist.
- Backdoor implantation by injecting malicious PHP code into a theme file using the WordPress theme editor.

## How It Works

1. **CSRF Attack:**  
   Generates an HTML file that, when executed, attempts to create a new admin account on the target site by sending a crafted POST request.

2. **Brute-Force Attack:**  
   Uses a provided credentials list to try login attempts concurrently. It detects successful logins by checking for admin/dashboard indicators in the response.

3. **Backdoor Implantation:**  
   After successful login, it accesses the theme editor page to extract a required nonce and then injects a base64-encoded PHP backdoor into a theme file (e.g., `404.php`).

## Usage Instructions

- Ensure Python 3.x and required libraries (`requests`, `beautifulsoup4`) are installed.  
- Run the script and enter the WordPress login URL when prompted.  
- Provide a credentials file (`creds.txt`) with username:password pairs or use the default sample list created automatically.  
- Review the generated CSRF HTML file (`csrf_admin_create.html`) and deliver it manually to the target (e.g., via social engineering).  
- The script attempts brute force and backdoor injection automatically after this.

## Important Notes

- This tool is for **educational and authorized testing only**. Using it without permission is illegal and unethical.  
- The success of each step depends on the target's security posture. Many WordPress sites have protections against these attacks.  
- Manual intervention is required to deliver the CSRF payload.  
- Backdoor implantation requires theme editor access, which may be disabled or restricted on many sites.

## Disclaimer

The author and distributor of this tool take no responsibility for misuse. Always have explicit authorization before testing any system.

---

*Stay ethical and use your skills responsibly.*
