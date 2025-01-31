# InboxInspector

## Synopsis

InboxInspector is a Python-based email analysis tool designed to inspect `.eml` and `.msg` email files for potential threats, such as phishing attempts, spoofed senders, and malicious links. It extracts and evaluates key email components, including sender information, DNS records (SPF, DKIM, DMARC), URLs, and IP addresses.

## Features

- Extracts sender email and domain information
- Checks SPF, DKIM, and DMARC records for email authentication
- Performs WHOIS lookups on sender domains
- Extracts URLs from the email body
- Identifies IP addresses from email headers
- Evaluates the legitimacy of the email
- Provides the option to save analysis results in a `.txt` file

## Why It's Useful

InboxInspector helps users, security analysts, and IT professionals quickly assess the legitimacy of an email. It aids in identifying phishing attempts, spam, and other malicious email-based threats.

## How to Use

1. **Install Dependencies**  
   Ensure you have Python installed, then install required packages:
   ```bash
   pip install -r requirements.txt
   ```
2. **Run the Application**
   Execute the script in your terminal or command prompt:
   ```bash
   python inboxInspector.py
   ```
3. **Analyze an Email File**

- The program will prompt you to select a .eml or .msg file.
- It will extract and analyze key email components.
- You will be given an option to save the results in a .txt file.

4. **Interpreting the Results**

- The script will display extracted email data and security checks.
- If potential issues are detected, a warning will be provided.

## Requirements

See requirements.txt for the necessary dependencies.

## License

This project is licensed under the MIT License.
