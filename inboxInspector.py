import re
import tkinter as tk
from colorama import Fore, Style
from tkinter import filedialog
import email
import email.policy
import dns.resolver
import whois
import sys
import os


def display_banner():
    """
    Display an ASCII art banner for InboxInspector.
    """
    ascii_banner = r"""
 +-++-++-++-++-++-++-++-++-++-++-++-++-++-+
 |I||n||b||o||x||I||n||s||p||e||c||t||o||r|
 +-++-++-++-++-++-++-++-++-++-++-++-++-++-+
 ***KEEPINGSCAMMERSBROKEANDBROKENHEARTED***                                                                                                                                   
    """
    print(ascii_banner)


def display_help():
    """Display usage instructions to the user."""
    print("\nHow to Use:")
    print("1. Download email and save locally as .eml or .msg")
    print("2. Select file for scanning.")
    print("3. The app will analyze the sender's email, domain, and headers.")
    print("4. Look for key indicators of fraud:")
    print("   - Mismatched sender domain and return path.")
    print("   - SPF, DKIM, or DMARC failures.")
    print("   - Suspicious URLs in the email body.")
    print("   - Unknown or suspicious WHOIS domain information.")
    print("\nIf you suspect fraud, do NOT click on links or download attachments!")


def extract_domain(email_address):
    """
    Extract the domain part from an email address.
    Returns None if the email_address is empty or improperly formatted.
    """
    if not email_address:
        return None
    domain = email_address.split('@')[-1].strip().strip('>')
    return domain if domain else None


def check_dns_record(domain, record_type, selector=None):
    """
    Check DNS records for SPF, DKIM, or DMARC using Google's 8.8.8.8 DNS.
    Returns a list of TXT record strings or None on error.
    """
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
    except Exception:
        return None


def get_whois_info(domain):
    """
    Perform a WHOIS lookup on the given domain.
    Returns the WHOIS data or None on error.
    """
    if not domain:
        return None
    try:
        return whois.whois(domain)
    except Exception:
        return None


def extract_dkim_selector(email_headers):
    """
    Extract the DKIM selector from the email headers.
    Returns the selector if found; otherwise, returns "default".
    """
    match = re.search(r's=(\S+);\s*d=(\S+);', email_headers)
    return match.group(1) if match else "default"


def extract_urls(text):
    """
    Extract URLs from a text block.
    Returns a list of URLs.
    """
    return re.findall(r'(https?://\S+)', text) if text else []


def extract_ips(email_headers):
    """
    Extract IP addresses from the email headers.
    Returns a list of IP addresses.
    """
    return re.findall(r'\d+\.\d+\.\d+\.\d+', email_headers) if email_headers else []


def select_file():
    """
    Open a file selection dialog for .eml or .msg files.
    Returns the selected file path.
    """
    root = tk.Tk()
    root.withdraw()
    root.lift()
    root.attributes('-topmost', True)
    return filedialog.askopenfilename(title="Select an EML or MSG file", filetypes=[("Email files", "*.eml;*.msg")])


def get_email_body(msg):
    """
    Extract the plain text body from an email message.
    Handles both multipart and singlepart messages.
    """
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    parts.append(payload.decode(errors='ignore'))
        return "\n".join(parts)
    else:
        payload = msg.get_payload(decode=True)
        return payload.decode(errors='ignore') if payload else ""


def evaluate_email_legitimacy(sender_domain, spf, dkim, dmarc, urls):
    """
    Evaluate the legitimacy of an email based on various checks.
    Returns a verdict string.
    """
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


def save_output(output_text):
    """
    Prompt the user to save the output and write the analysis results to a file if requested.
    """
    while True:
        save_option = input(
            "\nWould you like to save the results? (C: Current Directory, N: New Directory, X: Do Not Save): \n"
        ).strip().lower()
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

        try:
            with open(file_path, "w", encoding="utf-8") as file:
                file.write(output_text)
            print(f"\nResults saved to {file_path}")
        except Exception as e:
            print(f"Error saving file: {e}", file=sys.stderr)
        break


def analyze_email(file_path):
    """
    Analyze the selected email file and print/save the analysis results.
    """
    try:
        with open(file_path, "rb") as f:
            msg = email.message_from_binary_file(
                f, policy=email.policy.default)
    except Exception as e:
        print(f"Error reading email file: {e}", file=sys.stderr)
        return

    sender_email = msg.get("From")
    sender_domain = extract_domain(sender_email)

    # Convert the message to a string once for header analysis
    raw_email = msg.as_string()

    received_ips = extract_ips(raw_email)
    email_body = get_email_body(msg)
    urls = extract_urls(email_body)
    dkim_selector = extract_dkim_selector(raw_email)

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


def main():
    """
    Main loop for user interaction.
    """
    print(Fore.RED)
    display_banner()

    while True:
        print(Fore.WHITE, end="")

        user_response = input(
            "\nPlease select a .eml or .msg file for scanning. Are you ready? (Y/N or H for Help): "
        ).strip().lower()
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
            print("Invalid option. Please enter Y, N, or H.")


if __name__ == "__main__":
    main()
