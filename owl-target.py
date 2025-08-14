#!/usr/bin/env python3
import sys
import requests
import socket
import whois
from bs4 import BeautifulSoup
import re
import ssl
import datetime

common_subdomains = [
    "www", "mail", "dev", "vpn", "admin", "test", "portal", "shop", "blog", "api"
]

def get_domain_from_query(query):
    if '.' in query:
        return query.lower()
    headers = {'User-Agent': 'Mozilla/5.0'}
    url = f"https://html.duckduckgo.com/html?q={query}"
    resp = requests.get(url, headers=headers)
    soup = BeautifulSoup(resp.text, "html.parser")
    links = soup.find_all("a", href=True)
    for link in links:
        href = link['href']
        match = re.search(r"https?://([\w\.-]+)", href)
        if match:
            return match.group(1)
    return None

def check_domain_status(domain):
    try:
        ip = socket.gethostbyname(domain)
        ssl_status = "Invalid"
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    not_after = cert.get('notAfter')
                    expire_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    if expire_date > datetime.datetime.utcnow():
                        ssl_status = "Valid"
                    else:
                        ssl_status = "Expired"
        except Exception:
            ssl_status = "Invalid"

        cdn = "Unknown"
        try:
            hostname = socket.gethostbyaddr(ip)[0].lower()
            cdn_providers = ["cloudflare", "akamai", "fastly", "amazonaws", "stackpath"]
            for provider in cdn_providers:
                if provider in hostname:
                    cdn = provider.capitalize()
                    break
        except Exception:
            cdn = "Unknown"

        return True, ssl_status, cdn
    except Exception:
        return False, "N/A", "N/A"

def get_related_links(domain):
    try:
        r = requests.get(f"https://{domain}", timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        links = soup.find_all("a", href=True)
        out = set()
        for l in links:
            href = l['href']
            if href.startswith("http") and domain in href:
                out.add(href.split('?')[0])
            elif href.startswith("/"):
                out.add(f"https://{domain}{href.split('?')[0]}")
        return list(out)[:10]
    except Exception:
        return []

def get_whois(domain):
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if isinstance(created, datetime.datetime):
            created = created.strftime("%Y-%m-%d %H:%M:%S")
        else:
            created = str(created)
        return {
            "Registrar": w.registrar,
            "Country": w.country,
            "Created": created
        }
    except Exception:
        return {}

def scan_subdomains(domain):
    found = []
    for sub in common_subdomains:
        full_domain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(full_domain)
            found.append(full_domain)
        except Exception:
            continue
    return found

def main():
    if len(sys.argv) != 2:
        print("Usage: owl-target <company_or_domain>")
        sys.exit(1)

    query = sys.argv[1]
    domain = get_domain_from_query(query)
    if not domain:
        print("Could not find domain.")
        sys.exit(1)

    print(f"Found domain: {domain}")

    online, ssl_status, cdn = check_domain_status(domain)
    print(f"Status: {'Online' if online else 'Offline'} | SSL: {ssl_status} | CDN: {cdn}")

    links = get_related_links(domain)
    if links:
        print("Related Links:")
        for l in links:
            print(f" - {l}")

    whois_data = get_whois(domain)
    if whois_data:
        print("WHOIS:")
        for k, v in whois_data.items():
            print(f" {k}: {v}")

    subdomains = scan_subdomains(domain)
    if subdomains:
        print("Subdomains found:")
        for sd in subdomains:
            print(f" - {sd}")

if __name__ == "__main__":
    main()
