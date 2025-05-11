import requests
import whois
import ssl
import socket
from urllib.parse import urlparse

# Function to check if a URL uses HTTPS (SSL certificate)
def has_ssl(url):
    try:
        # Check if the site is using HTTPS
        parsed_url = urlparse(url)
        if parsed_url.scheme == "https":
            return True
        return False
    except Exception as e:
        return False

# Function to perform a basic WHOIS lookup to check domain age/reputation
def whois_info(url):
    try:
        domain = whois.whois(url)
        creation_date = domain.creation_date
        # Basic check: If domain is too new, it may be suspicious
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        return creation_date
    except Exception as e:
        return None

# Function to check if the website's domain contains any suspicious keywords
def is_suspicious_domain(url):
    suspicious_keywords = ['login', 'account', 'secure', 'paypal', 'bank']
    domain = urlparse(url).hostname
    for keyword in suspicious_keywords:
        if keyword in domain:
            return True
    return False

# Function to analyze a website for phishing
def analyze_website(url):
    print(f"Analyzing website: {url}")
    
    # Check SSL/TLS certificate (HTTPS)
    if not has_ssl(url):
        print("Warning: The website does not use HTTPS.")

    # Check WHOIS information (domain age)
    creation_date = whois_info(url)
    if creation_date:
        age = (socket.gethostbyname(urlparse(url).hostname) - creation_date).days
        if age < 30:
            print("Warning: The website domain is very new (less than 30 days). This could be suspicious.")
    else:
        print("Warning: Unable to retrieve WHOIS information.")
    
    # Check for suspicious domain patterns
    if is_suspicious_domain(url):
        print("Warning: The website domain contains suspicious keywords.")
    
    # Perform HTTP request to detect phishing (e.g., check if the page has malicious content or redirects)
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print("Website seems accessible and operational.")
        else:
            print(f"Warning: The website returned status code {response.status_code}.")
    except requests.exceptions.RequestException as e:
        print(f"Error while accessing the website: {e}")

# Example usage
if __name__ == "__main__":
    website_to_check = "http://example-phishing.com"
    analyze_website(website_to_check)
