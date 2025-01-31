import re
import tkinter as tk
from tkinter import filedialog
import email
import email.policy
import email.parser
import dns.resolver
import whois
import sys
import socket
import os


def display_help():
    print("\nHow to Use Inbox Inspector:")
    print("1. Select an .eml or .msg email file for scanning.")
    print("2. The app will analyze the sender's email, domain, and headers.")
    print("3. Look for key indicators of fraud:")
    print("   - Mismatched sender domain and return path.")
    print("   - SPF, DKIM, or DMARC failures.")
    print("   - Suspicious URLs in the email body.")
    print("   - Unknown or suspicious WHOIS domain information.")
    print("\nIf you suspect fraud, do NOT click on links or download attachments!")

# Function to extract domain from email address


def extract_domain(email_address):
    if not email_address:
        return None
    domain = email_address.split('@')[-1].strip().strip('>')
    return domain if domain else None

# Function to check DNS records (SPF, DKIM, DMARC) using Google's 8.8.8.8 DNS


def check_dns_record(domain, record_type, selector=None):
    if not domain:
        return None
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8"]
        resolver.cache = None

        if record_type == "SPF":
            query = domain
        elif record_type == "DKIM" and selector:
            query = f"{selector}._domainkey.{domain}"
        elif record_type == "DMARC":
            query = f"_dmarc.{domain}"
        else:
            return None

        answers = resolver.resolve(query, "TXT")
        return [rdata.to_text() for rdata in answers]
    except Exception as e:
        return None

# Function to perform a WHOIS lookup


def get_whois_info(domain):
    if not domain:
        return None
    try:
        return whois.whois(domain)
    except Exception:
        return None

# Function to extract DKIM selector from headers


def extract_dkim_selector(email_headers):
    match = re.search(r's=(\S+);\s*d=(\S+);', email_headers)
    return match.group(1) if match else "default"

# Function to extract URLs from email body


def extract_urls(text):
    return re.findall(r'(https?://\S+)', text) if text else []

# Function to extract IPs from email headers


def extract_ips(email_headers):
    return re.findall(r'\d+\.\d+\.\d+\.\d+', email_headers) if email_headers else []

# Function to select a file


def select_file():
    root = tk.Tk()
    root.withdraw()
    root.lift()
    root.attributes('-topmost', True)
    return filedialog.askopenfilename(title="Select an EML or MSG file", filetypes=[("Email files", "*.eml;*.msg")])

# Function to extract text from email payload


def get_email_body(msg):
    if msg.is_multipart():
        return "\n".join(part.get_payload(decode=True).decode(errors='ignore') for part in msg.walk() if part.get_content_type() == "text/plain")
    return msg.get_payload(decode=True).decode(errors='ignore') if msg.get_payload() else ""

# Function to evaluate email legitimacy


def evaluate_email_legitimacy(sender_domain, spf, dkim, dmarc, urls):
    issues = []
    if not sender_domain:
        issues.append("Missing sender domain.")
    if not spf:
        issues.append("SPF record missing or invalid.")
    if not dkim:
        issues.append("DKIM record missing or invalid.")
    if not dmarc:
        issues.append("DMARC record missing or invalid.")
    if urls:
        issues.append("Suspicious URLs found in the email body.")

    return "This email appears legitimate." if not issues else f"Potential issues detected: {'; '.join(issues)}. Proceed with caution."


# Function to save output to a file
def save_output(output_text):
    while True:
        save_option = input(
            "\nWould you like to save the results? (C: Current Directory, N: New Directory, X: Do Not Save): \n").strip().lower()
        if save_option == 'c':
            file_path = os.path.join(os.getcwd(), "email_analysis_results.txt")
        elif save_option == 'n':
            root = tk.Tk()
            root.withdraw()
            root.lift()
            root.attributes('-topmost', True)
            directory = filedialog.askdirectory(
                title="\nSelect Directory to Save Results")
            if not directory:
                print("\nNo directory selected. Try again.")
                continue
            file_path = os.path.join(directory, "email_analysis_results.txt")
        elif save_option == 'x':
            print("\nResults not saved.")
            return
        else:
            print("\nInvalid option. Please enter C, N, or X.")
            continue

        with open(file_path, "w", encoding="utf-8") as file:
            file.write(output_text)
        print(f"\nResults saved to {file_path}")
        break


def analyze_email(file_path):
    try:
        with open(file_path, "rb") as f:
            msg = email.message_from_binary_file(
                f, policy=email.policy.default)
    except Exception as e:
        print(f"Error reading email file: {e}", file=sys.stderr)
        return

    sender_email = msg.get("From")
    sender_domain = extract_domain(sender_email)
    received_ips = extract_ips(msg.as_string())
    email_body = get_email_body(msg)
    urls = extract_urls(email_body)

    dkim_selector = extract_dkim_selector(msg.as_string())
    spf = check_dns_record(sender_domain, "SPF")
    dkim = check_dns_record(sender_domain, "DKIM", dkim_selector)
    dmarc = check_dns_record(sender_domain, "DMARC")
    whois_info = get_whois_info(sender_domain)

    output_text = (
        f"Sender Email: {sender_email}\n"
        f"Sender Domain: {sender_domain}\n\n"
        f"SPF Record: {spf}\n"
        f"DKIM Record: {dkim}\n"
        f"DMARC Record: {dmarc}\n\n"
        f"WHOIS Info: {whois_info}\n\n"
        f"Extracted URLs: {urls}\n"
        f"Extracted IPs from Headers: {received_ips}\n\n"
        f"Email Legitimacy Verdict: {evaluate_email_legitimacy(
            sender_domain, spf, dkim, dmarc, urls)}"
    )

    print(output_text)
    save_output(output_text)


if __name__ == "__main__":
    while True:
        user_response = input(
            "\nPlease select a .eml or .msg file for scanning. Are you ready? (Y/N or H for Help): ").strip().lower()
        if user_response == 'y':
            email_file = select_file()
            if email_file:
                analyze_email(email_file)
            else:
                print("No file selected.")
            break
        elif user_response == 'h':
            display_help()
        elif user_response == 'n':
            print("No problem, get your files together and try again.")
            break
        else:
            print("Invalid option. Please enter Y, N or H.")
