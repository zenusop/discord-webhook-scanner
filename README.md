# discord-webhook-scanner


A Python-based tool for scanning public GitHub repositories for exposed Discord webhooks. Uses GitHub's API to search for code containing Discord webhook URLs and validates them by making HTTP requests. The tool supports token rotation for authentication, rate limiting, and provides detailed logging of actions, including token usage and rate limit resets.
Features:

    Token Rotation: Automatically rotates through multiple GitHub tokens to avoid rate limits.
    Webhook Detection: Detects Discord webhook URLs in public GitHub repositories.
    Webhook Validation: Validates the detected webhooks by making HTTP requests.
    Logging: Detailed logging of scanning process, token usage, and rate limit resets.
    Customizable Regex: Supports custom regex patterns for Discord webhook URL detection.
    Output Options: Results can be saved as JSON or CSV files for further review.
    User-friendly GUI: Built using tkinter for a simple, easy-to-use interface.

Features That Will Be Added:

    Scan Pastebin: Future support for scanning Pastebin for exposed Discord webhooks.
    Scan Other Code Hosting Sites: Add support for scanning other public code hosting sites such as GitLab, Bitbucket, etc.
    Advanced Webhook Validation: Improve webhook validation with additional checks (e.g., ensure the webhook is actively used).
    Enhanced Logging: More detailed and configurable logging options, including log levels and output destinations.
    Scheduled Scans: Ability to schedule regular scans for continuous monitoring of public repositories and websites.

Installation:

    Clone the repository:

git clone https://github.com/yourusername/discord-webhook-scanner.git

Install the required dependencies:

pip install -r requirements.txt

Run the tool:

    python discord_webhook_scanner.py

Usage:

    Add your GitHub tokens to the configuration window.
    Customize the regex pattern for webhook detection.
    Start scanning GitHub repositories for exposed webhooks.
    View logs and preview the results directly within the application.

Requirements:

    Python 3.7+
    Required libraries: requests, github, ratelimit, tkinter, logging, csv, json, re, time, queue, and threading.

Contributing:

Feel free to open issues or contribute to the project. Pull requests are welcome!
