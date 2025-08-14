# 🦉 owl-target

**owl-target** is a Python-based reconnaissance tool that collects intelligence about a company or domain.  
It performs passive scanning, WHOIS lookups, subdomain checking, related link extraction, and SSL/CDN fingerprinting.

Created by **KHALED.S.HADDAD**  
🌐 [https://khaledhaddad.tech](https://khaledhaddad.tech)

---

## 🎯 Features

- 🔍 Detects the **main domain** from a company name or domain query
- 🌐 Checks if the domain is **online**, with **SSL certificate** status and **CDN detection**
- 🌎 Extracts **internal and related links** from the homepage
- 📜 Performs **WHOIS** lookup (creation date, registrar, country)
- 🏗️ Scans for **common subdomains** (`www`, `dev`, `api`, etc.)

---

## 🛠️ Requirements

- Python 3.x
- Required libraries:

```bash
pip install requests beautifulsoup4 python-whois

