import tkinter as tk
from tkinter import ttk, messagebox
import requests
import json
import csv
import re
import logging
import threading
from datetime import datetime
from github import Github, GithubException
from ratelimit import limits, sleep_and_retry
import queue
import time
import os
import subprocess

# Add this at the top for additional logging
token_logger = logging.getLogger('TokenUsage')
token_handler = logging.FileHandler('token_usage.log')
token_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
token_logger.addHandler(token_handler)
token_logger.setLevel(logging.INFO)

def get_github_instance(self):
    """Return a Github instance from the pool in a round-robin fashion and log token usage."""
    if not self.github_instances:
        raise Exception("No GitHub tokens available")

    instance = self.github_instances[self.token_index]
    token_logger.info(f"Using token index: {self.token_index}")

    # Log remaining requests and rate limit reset
    try:
        rate_limit = instance.get_rate_limit().core
        remaining = rate_limit.remaining
        reset_time = rate_limit.reset.strftime('%Y-%m-%d %H:%M:%S')
        token_logger.info(f"Token index {self.token_index}: {remaining} requests remaining, resets at {reset_time}")
    except Exception as e:
        token_logger.warning(f"Error retrieving rate limit info for token index {self.token_index}: {str(e)}")

    self.token_index = (self.token_index + 1) % len(self.github_instances)
    return instance

@sleep_and_retry
@limits(calls=30, period=60)
def search_repositories(self):
    findings = []
    query = "discord.com/api/webhooks"
    attempts = 0
    max_attempts = len(self.github_instances)
    code_results = None

    while attempts < max_attempts:
        instance = self.get_github_instance()
        try:
            rate = instance.get_rate_limit().core
            if rate.remaining < 5:
                wait_time = (rate.reset - datetime.now()).total_seconds() + 5
                self.thread_safe_log(f"Token {self.token_index} approaching rate limit. Waiting {int(wait_time)} seconds...\n", "yellow")
                token_logger.info(f"Token {self.token_index} rate limit reached. Waiting {wait_time} seconds.")
                time.sleep(wait_time)

            code_results = instance.search_code(query)
            break
        except GithubException as ge:
            if ge.status == 403:
                attempts += 1
                self.thread_safe_log(f"Token {self.token_index} rate limited during search_code, switching token...\n", "yellow")
                token_logger.warning(f"Token {self.token_index} rate limited. Switching tokens.")
            else:
                self.thread_safe_log(f"GitHub error during search_code: {str(ge)}\n", "yellow")
                token_logger.error(f"GitHub error with token {self.token_index}: {str(ge)}")
                return findings
        except Exception as e:
            self.thread_safe_log(f"Error during search_code: {str(e)}\n", "yellow")
            token_logger.error(f"Unexpected error with token {self.token_index}: {str(e)}")
            return findings

    if code_results is None:
        self.thread_safe_log("All tokens appear to be rate limited during search_code.\n", "yellow")
        token_logger.error("All tokens rate limited during search_code.")
        return findings

    self.thread_safe_log(f"Found approximately {code_results.totalCount} code results. Starting scan...\n", "black")
    for repo_file in code_results:
        if self.stop_event.is_set():
            self.thread_safe_log("Scan stopped by user.\n", "yellow")
            return findings

        try:
            content = repo_file.decoded_content.decode('utf-8', errors='ignore')
            current_pattern = self.regex_entry.get().strip() or self.webhook_pattern
            matches = re.finditer(current_pattern, content)

            for match in matches:
                if self.stop_event.is_set():
                    self.thread_safe_log("Scan stopped by user.\n", "yellow")
                    return findings

                webhook_url = match.group()
                validation_status = self.validate_webhook(webhook_url)
                finding = {
                    'repository': repo_file.repository.full_name,
                    'file_path': repo_file.path,
                    'webhook_url': webhook_url,
                    'discovered_at': datetime.now().isoformat(),
                    'validation_status': validation_status
                }
                findings.append(finding)
                color = "green" if validation_status == "Valid" else "red" if validation_status == "Invalid" else "yellow"
                self.thread_safe_log(f"Found webhook ({validation_status}) in {finding['repository']}/{finding['file_path']}\n", color)
        except Exception as e:
            self.thread_safe_log(f"Error processing file {repo_file.path}: {str(e)}\n", "yellow")
            token_logger.error(f"Error processing file {repo_file.path} in {repo_file.repository.full_name}: {str(e)}")

    return findings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='discord_webhook_scanner.log',
    filemode='a'
)

class DiscordWebhookScanner:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Discord Webhook Scanner")
        self.window.geometry("900x700")

        # Default regex pattern for Discord webhooks (editable by user)
        self.webhook_pattern = r'https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_-]+'

        # Thread control event for stopping scan and a thread-safe log queue
        self.stop_event = threading.Event()
        self.log_queue = queue.Queue()

        # Token pool: list of Github instances and a pointer for round-robin selection
        self.github_instances = []
        self.token_index = 0

        # To store findings for preview and post-scan actions
        self.findings = []
        self.last_saved_file = None

        self.setup_gui()
        self.process_log_queue()  # Start polling the log queue

    def setup_gui(self):
        # Top frame for GitHub token and regex configuration
        config_frame = ttk.LabelFrame(self.window, text="Configuration", padding=10)
        config_frame.pack(fill="x", padx=10, pady=5)

        # GitHub Token(s) input: multiple tokens can be separated by comma or newline.
        ttk.Label(config_frame, text="GitHub Token(s):").grid(row=0, column=0, sticky="w")
        self.token_entry = ttk.Entry(config_frame, width=50, show="*")
        self.token_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        ttk.Label(config_frame, text="(Separate multiple tokens with commas or newlines)").grid(row=0, column=2, sticky="w")

        # Regex Pattern (editable)
        ttk.Label(config_frame, text="Webhook Regex Pattern:").grid(row=1, column=0, sticky="w")
        self.regex_entry = ttk.Entry(config_frame, width=50)
        self.regex_entry.insert(0, self.webhook_pattern)
        self.regex_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # Output format selection frame
        output_frame = ttk.LabelFrame(self.window, text="Output Configuration", padding=10)
        output_frame.pack(fill="x", padx=10, pady=5)
        self.output_format = tk.StringVar(value="json")
        ttk.Radiobutton(output_frame, text="JSON", variable=self.output_format, value="json").pack(side="left", padx=5)
        ttk.Radiobutton(output_frame, text="CSV", variable=self.output_format, value="csv").pack(side="left", padx=5)

        # Status frame with progress bar and status label
        status_frame = ttk.Frame(self.window)
        status_frame.pack(fill="x", padx=10, pady=5)
        self.progress_bar = ttk.Progressbar(status_frame, orient="horizontal", mode="indeterminate")
        self.progress_bar.pack(fill="x", expand=True, side="left", padx=5)
        self.status_label = ttk.Label(status_frame, text="Idle")
        self.status_label.pack(side="left", padx=5)

        # Progress log frame
        self.progress_frame = ttk.LabelFrame(self.window, text="Progress", padding=10)
        self.progress_frame.pack(fill="both", expand=True, padx=10, pady=5)
        self.progress_text = tk.Text(self.progress_frame, height=20)
        self.progress_text.pack(fill="both", expand=True)

        # Control buttons
        button_frame = ttk.Frame(self.window)
        button_frame.pack(fill="x", padx=10, pady=5)
        ttk.Button(button_frame, text="Start Scan", command=self.start_scan_thread).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Preview Results", command=self.preview_results).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Clear Logs", command=self.clear_logs).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Open Results File", command=self.open_results_file).pack(side="right", padx=5)
        ttk.Button(button_frame, text="Exit", command=self.window.quit).pack(side="right", padx=5)

    def clear_logs(self):
        self.progress_text.delete(1.0, tk.END)

    def process_log_queue(self):
        try:
            while True:
                message, color = self.log_queue.get_nowait()
                self._append_text(message, color)
        except queue.Empty:
            pass
        self.window.after(100, self.process_log_queue)

    def thread_safe_log(self, log_text, color="black"):
        """Put log message in queue for thread-safe GUI update and log to file."""
        self.log_queue.put((log_text, color))
        logging.info(log_text)

    def _append_text(self, text, color):
        self.progress_text.insert(tk.END, text)
        # Set tag configurations for colors
        self.progress_text.tag_add(color, "end-1c linestart", "end")
        self.progress_text.tag_configure("green", foreground="green")
        self.progress_text.tag_configure("red", foreground="red")
        self.progress_text.tag_configure("yellow", foreground="orange")
        self.progress_text.tag_configure("black", foreground="black")
        self.progress_text.see(tk.END)

    def get_github_instance(self):
        """Return a Github instance from the pool in a round-robin fashion."""
        if not self.github_instances:
            raise Exception("No GitHub tokens available")
        instance = self.github_instances[self.token_index]
        self.token_index = (self.token_index + 1) % len(self.github_instances)
        return instance

    @sleep_and_retry
    @limits(calls=30, period=60)  # Rate limiting for the search function calls
    def search_repositories(self):
        """Search GitHub repositories for code containing Discord webhook URLs."""
        findings = []
        query = "discord.com/api/webhooks"

        # Try to get a Github instance to call search_code. If one is rate limited, rotate.
        attempts = 0
        max_attempts = len(self.github_instances) if self.github_instances else 1
        code_results = None

        while attempts < max_attempts:
            instance = self.get_github_instance()
            try:
                # Check dynamic rate limit status for this instance
                core_rate = instance.get_rate_limit().core
                if core_rate.remaining < 5:
                    wait_time = (core_rate.reset - datetime.now()).total_seconds() + 5
                    self.thread_safe_log(f"Token approaching rate limit. Waiting {int(wait_time)} seconds...\n", "yellow")
                    time.sleep(wait_time)
                code_results = instance.search_code(query)
                break
            except GithubException as ge:
                if ge.status == 403:
                    attempts += 1
                    self.thread_safe_log("Token rate limited during search_code, switching token...\n", "yellow")
                else:
                    self.thread_safe_log(f"GitHub error during search_code: {str(ge)}\n", "yellow")
                    return findings
            except Exception as e:
                self.thread_safe_log(f"Error during search_code: {str(e)}\n", "yellow")
                return findings

        if code_results is None:
            self.thread_safe_log("All tokens appear to be rate limited during search_code.\n", "yellow")
            return findings

        total_count = code_results.totalCount
        self.thread_safe_log(f"Found approximately {total_count} code results. Starting scan...\n", "black")

        for repo_file in code_results:
            if self.stop_event.is_set():
                self.thread_safe_log("Scan stopped by user.\n", "yellow")
                return findings

            try:
                content = None
                try:
                    content = repo_file.decoded_content.decode('utf-8', errors='ignore')
                except Exception:
                    if hasattr(repo_file, 'text'):
                        content = repo_file.text
                    else:
                        continue

                # Update regex pattern from user input
                current_pattern = self.regex_entry.get().strip() or self.webhook_pattern
                matches = re.finditer(current_pattern, content)

                for match in matches:
                    if self.stop_event.is_set():
                        self.thread_safe_log("Scan stopped by user.\n", "yellow")
                        return findings
                    webhook_url = match.group()
                    validation_status = self.validate_webhook(webhook_url)
                    finding = {
                        'repository': repo_file.repository.full_name,
                        'file_path': repo_file.path,
                        'webhook_url': webhook_url,
                        'discovered_at': datetime.now().isoformat(),
                        'validation_status': validation_status
                    }
                    findings.append(finding)
                    color = "green" if validation_status == "Valid" else "red" if validation_status == "Invalid" else "yellow"
                    self.thread_safe_log(f"Found webhook ({validation_status}) in {finding['repository']}/{finding['file_path']}\n", color)
            except Exception as e:
                error_msg = f"Error processing file {repo_file.path} in {repo_file.repository.full_name}: {str(e)}\n"
                logging.exception(error_msg)
                self.thread_safe_log(error_msg, "yellow")
        return findings

    def validate_webhook(self, webhook_url):
        """Check if the webhook URL returns a valid response with exponential backoff."""
        backoff = 1
        max_backoff = 16
        while True:
            try:
                response = requests.get(webhook_url, timeout=10)
                if response.status_code == 200:
                    return "Valid"
                elif response.status_code in [401, 404]:
                    return "Invalid"
                else:
                    return f"Unknown ({response.status_code})"
            except Exception as e:
                logging.exception(f"Error validating webhook: {webhook_url}")
                if backoff > max_backoff:
                    return "Error"
                time.sleep(backoff)
                backoff *= 2

    def save_results(self, findings):
        """Save only the valid webhooks to a file in the selected format."""
        valid_findings = [f for f in findings if f['validation_status'] == "Valid"]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = ""
        try:
            if self.output_format.get() == "json":
                filename = f"webhook_findings_{timestamp}.json"
                with open(filename, 'w') as f:
                    json.dump(valid_findings, f, indent=4)
            else:
                filename = f"webhook_findings_{timestamp}.csv"
                with open(filename, 'w', newline='') as f:
                    fieldnames = ['repository', 'file_path', 'webhook_url', 'discovered_at', 'validation_status']
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    for finding in valid_findings:
                        writer.writerow(finding)
            self.thread_safe_log(f"Results saved to {filename} (only valid webhooks).\n", "green")
            self.last_saved_file = os.path.abspath(filename)
        except Exception as e:
            logging.exception("Error saving results")
            self.window.after(0, lambda: messagebox.showerror("Error", f"Could not save results: {str(e)}"))
            self.last_saved_file = None

    def preview_results(self):
        """Preview valid webhook findings in a separate window."""
        valid_findings = [f for f in self.findings if f['validation_status'] == "Valid"]
        if not valid_findings:
            messagebox.showinfo("Preview Results", "No valid webhook findings to preview.")
            return

        preview_window = tk.Toplevel(self.window)
        preview_window.title("Preview Valid Webhooks")
        preview_text = tk.Text(preview_window, wrap="none")
        preview_text.pack(fill="both", expand=True)
        for finding in valid_findings:
            preview_text.insert(tk.END, f"Repository: {finding['repository']}\n")
            preview_text.insert(tk.END, f"File: {finding['file_path']}\n")
            preview_text.insert(tk.END, f"Webhook: {finding['webhook_url']}\n")
            preview_text.insert(tk.END, f"Status: {finding['validation_status']}\n")
            preview_text.insert(tk.END, "-"*50 + "\n")

    def open_results_file(self):
        """Open the last saved results file if available."""
        if self.last_saved_file and os.path.exists(self.last_saved_file):
            try:
                if os.name == 'nt':  # Windows
                    os.startfile(self.last_saved_file)
                elif os.name == 'posix':
                    subprocess.Popen(['xdg-open', self.last_saved_file])
                else:
                    messagebox.showinfo("Open File", f"File saved at: {self.last_saved_file}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not open the file: {str(e)}")
        else:
            messagebox.showinfo("Open File", "No results file available.")

    def scan(self):
        """Main scanning function: authenticates with GitHub, searches for webhooks, and saves the results."""
        raw_tokens = self.token_entry.get().strip()
        if not raw_tokens:
            self.window.after(0, lambda: messagebox.showerror("Error", "Please enter at least one GitHub token"))
            return

        # Split tokens by comma or newline and create a pool of Github instances
        tokens = [t.strip() for t in re.split('[,\n]+', raw_tokens) if t.strip()]
        if not tokens:
            self.window.after(0, lambda: messagebox.showerror("Error", "No valid tokens provided"))
            return

        self.github_instances = [Github(token, timeout=30) for token in tokens]
        self.token_index = 0

        # For authentication feedback, try getting the login from the first token
        try:
            user = self.github_instances[0].get_user().login
            self.thread_safe_log(f"Authenticated as {user} (using token pool with {len(self.github_instances)} token(s)).\n", "black")
        except Exception as e:
            self.thread_safe_log(f"Error authenticating with provided token(s): {str(e)}\n", "yellow")
            self.window.after(0, lambda: messagebox.showerror("Error", f"Authentication failed: {str(e)}"))
            return

        self.stop_event.clear()
        self.status_label.config(text="Scanning...")
        self.progress_bar.start(10)
        self.thread_safe_log("Starting scan...\n", "black")
        # Clear previous logs if desired
        self.window.after(0, lambda: self.progress_text.delete(1.0, tk.END))
        try:
            findings = self.search_repositories()
            self.findings = findings  # store for previewing later
            self.save_results(findings)
            total_valid = len([f for f in findings if f['validation_status'] == 'Valid'])
            self.thread_safe_log(f"\nScan complete. Found {len(findings)} webhooks (Valid: {total_valid}).\n", "black")
        except GithubException as ge:
            logging.exception("GitHub exception during scan")
            self.window.after(0, lambda: messagebox.showerror("Error", f"GitHub error: {str(ge)}"))
        except Exception as e:
            logging.exception("Error during scan")
            self.window.after(0, lambda: messagebox.showerror("Error", f"An error occurred: {str(e)}"))
        finally:
            self.progress_bar.stop()
            self.status_label.config(text="Idle")

    def start_scan_thread(self):
        threading.Thread(target=self.scan, daemon=True).start()

    def stop_scan(self):
        self.stop_event.set()
        self.thread_safe_log("Stop signal sent. Waiting for scan to terminate...\n", "yellow")

    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    scanner = DiscordWebhookScanner()
    scanner.run()
