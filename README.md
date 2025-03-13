Subfind3r - Subdomain Discovery Tool

Subfind3r is a powerful and lightweight subdomain enumeration tool that uses crt.sh for passive subdomain discovery and supports DNS resolution and brute-force wordlist scanning for active enumeration. This tool helps penetration testers and security researchers identify subdomains efficiently.

🚀 Features

✅ Fetches subdomains from crt.sh (Certificate Transparency logs)✅ Resolves DNS records to get IP addresses✅ Supports brute-force subdomain discovery using wordlists✅ Saves results in JSON format for later analysis✅ Uses Rich CLI for better visual output
🛠 Installation

1️⃣ Clone the Repository
 git clone https://github.com/youwerejailed/subfind3r.git
 cd subfind3r


 
 2️⃣ Install Dependencies
 pip install -r requirements.txt


 
 ⚡ Usage
Basic Subdomain Enumeration
python subfind3r.py -d example.com

With DNS Resolution (Filter Active Subdomains)
python subfind3r.py -d example.com --resolve


With Brute-Force Wordlist Scan
python subfind3r.py -d example.com --brute -w wordlist.txt

Save Output to File
python subfind3r.py -d example.com -o output.json




🔗 Connect


👤 Author: youwerejailed

GitHub: github.com/youwerejailed/subfind3r

