import requests
from bs4 import BeautifulSoup
import urllib.parse

# Function to check SQL Injection vulnerability
def check_sql_injection(url):
    payloads = ["' OR '1'='1", '" OR "1"="1"', "' OR 1=1 --"]
    for payload in payloads:
        test_url = f"{url}{payload}"
        response = requests.get(test_url)
        if "error" in response.text.lower() or "syntax" in response.text.lower():
            print(f"Potential SQL Injection vulnerability found at {test_url}")

# Function to check XSS vulnerability
def check_xss(url):
    payload = "<script>alert('XSS')</script>"
    test_url = f"{url}{payload}"
    response = requests.get(test_url)
    if payload in response.text:
        print(f"Potential XSS vulnerability found at {test_url}")

# Function to check for Directory Traversal
def check_directory_traversal(url):
    payload = "../../../../etc/passwd"
    test_url = f"{url}{payload}"
    response = requests.get(test_url)
    if "root" in response.text:  # Check for existence of a user in passwd file
        print(f"Potential Directory Traversal vulnerability found at {test_url}")

# Function to check for missing HTTP security headers
def check_security_headers(url):
    response = requests.get(url)
    headers = response.headers

    missing_headers = []
    if "Strict-Transport-Security" not in headers:
        missing_headers.append("Strict-Transport-Security")
    if "X-Content-Type-Options" not in headers:
        missing_headers.append("X-Content-Type-Options")
    if "X-Frame-Options" not in headers:
        missing_headers.append("X-Frame-Options")

    if missing_headers:
        print(f"Missing security headers: {', '.join(missing_headers)}")

# Function to find all forms on the page and check for vulnerabilities
def scan_forms(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")

    forms = soup.find_all("form")
    for form in forms:
        action = form.get("action")
        method = form.get("method")
        print(f"Found form with action: {action}, method: {method}")

        # Test SQL injection on form inputs
        for input_tag in form.find_all("input"):
            input_name = input_tag.get("name")
            if input_name:
                test_payload = "' OR '1'='1"
                test_data = {input_name: test_payload}
                if method.lower() == "post":
                    response = requests.post(url, data=test_data)
                else:
                    response = requests.get(url, params=test_data)
                if "error" in response.text.lower() or "syntax" in response.text.lower():
                    print(f"Potential SQL Injection vulnerability in form with action: {action}")
                
                # Test XSS on form inputs
                xss_payload = "<script>alert('XSS')</script>"
                test_data[input_name] = xss_payload
                if method.lower() == "post":
                    response = requests.post(url, data=test_data)
                else:
                    response = requests.get(url, params=test_data)
                if xss_payload in response.text:
                    print(f"Potential XSS vulnerability in form with action: {action}")

# Main function to run the scanner
def run_scanner(target_url):
    print(f"Running security scanner on {target_url}...\n")
    
    # Check for SQL Injection vulnerability
    check_sql_injection(target_url)

    # Check for XSS vulnerability
    check_xss(target_url)

    # Check for Directory Traversal vulnerability
    check_directory_traversal(target_url)

    # Check for missing security headers
    check_security_headers(target_url)

    # Scan all forms on the page
    scan_forms(target_url)

# Example usage
if __name__ == "__main__":
    target = "http://example.com"  # Change to the URL you want to scan
    run_scanner(target)

