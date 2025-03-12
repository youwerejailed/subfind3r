import requests
import re
import json
import socket
import time
from rich.console import Console
from rich.table import Table

# Constants
USER_AGENT = "Mozilla/5.0"
RETRIES = 5
TIMEOUT = 10
SLEEP_DURATION = 10
CONSOLE = Console()

def get_subdomains_from_crtsh(domain):
    """
    Fetch subdomains for a given domain from crt.sh.
    
    Args:
        domain (str): The domain to search for subdomains.
    
    Returns:
        list: A sorted list of valid subdomains.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {"User-Agent": USER_AGENT}
    
    for attempt in range(RETRIES):
        try:
            response = requests.get(url, headers=headers, timeout=TIMEOUT)
            if response.status_code == 200:
                subdomains = set()
                for entry in response.json():
                    found = re.findall(r'[\w.-]+\.' + re.escape(domain), entry["name_value"])
                    subdomains.update(found)
                
                valid_subdomains = [sub.strip().lower() for sub in subdomains if re.match(r'^[a-zA-Z0-9.-]+$', sub.strip()) and 1 < len(sub.strip()) < 255]
                return sorted(valid_subdomains)
            else:
                CONSOLE.print(f"[red][-] HTTP Error: {response.status_code}[/red]")
        except requests.exceptions.RequestException as e:
            CONSOLE.print(f"[yellow][*] crt.sh connection error! Retrying ({attempt+1}/{RETRIES})...[/yellow]")
            CONSOLE.print(f"[yellow][*] Error details: {e}[/yellow]")
            time.sleep(SLEEP_DURATION)  # Wait before retrying
    
    CONSOLE.print("[red][-] Unable to reach crt.sh, trying alternative sources...[/red]")
    return []

def get_subdomains_from_threatcrowd(domain):
    """
    Fetch subdomains for a given domain from ThreatCrowd.
    
    Args:
        domain (str): The domain to search for subdomains.
    
    Returns:
        list: A sorted list of valid subdomains.
    """
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    try:
        response = requests.get(url, timeout=TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            subdomains = data.get("subdomains", [])
            valid_subdomains = [sub.strip().lower() for sub in subdomains if re.match(r'^[a-zA-Z0-9.-]+$', sub.strip()) and 1 < len(sub.strip()) < 255]
            return sorted(valid_subdomains)
        else:
            CONSOLE.print(f"[red][-] HTTP Error: {response.status_code}[/red]")
    except requests.exceptions.RequestException as e:
        CONSOLE.print(f"[yellow][*] ThreatCrowd connection error: {e}[/yellow]")
    
    return []

def get_subdomains_from_virustotal(domain):
    """
    Fetch subdomains for a given domain from VirusTotal.
    
    Args:
        domain (str): The domain to search for subdomains.
    
    Returns:
        list: A sorted list of valid subdomains.
    """
    api_key = "ef258e0024db3411bddf5f2dfdadd917236a2786ec91df4e004ee2a24ffaa79f"  # Replace with your VirusTotal API key
    url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={domain}"
    try:
        response = requests.get(url, timeout=TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            subdomains = data.get("subdomains", [])
            valid_subdomains = [sub.strip().lower() for sub in subdomains if re.match(r'^[a-zA-Z0-9.-]+$', sub.strip()) and 1 < len(sub.strip()) < 255]
            return sorted(valid_subdomains)
        else:
            CONSOLE.print(f"[red][-] HTTP Error: {response.status_code}[/red]")
    except requests.exceptions.RequestException as e:
        CONSOLE.print(f"[yellow][*] VirusTotal connection error: {e}[/yellow]")
    
    return []

def resolve_dns(subdomain):
    """
    Resolve the IP address of a given subdomain.
    
    Args:
        subdomain (str): The subdomain to resolve.
    
    Returns:
        str or None: The IP address if resolved, otherwise None.
    """
    try:
        ip = socket.gethostbyname(subdomain)
        return ip
    except (socket.gaierror, UnicodeError):
        return None

def brute_force_subdomains(domain, wordlist_file):
    """
    Perform brute-force subdomain discovery using a wordlist.
    
    Args:
        domain (str): The domain to search for subdomains.
        wordlist_file (str): The path to the wordlist file.
    
    Returns:
        list: A list of valid subdomains.
    """
    try:
        with open(wordlist_file, "r", encoding="utf-8") as f:
            words = [line.strip() for line in f if line.strip()]
        
        brute_subdomains = [f"{word}.{domain}" for word in words]
        valid_subdomains = [sub for sub in brute_subdomains if re.match(r'^[a-zA-Z0-9.-]+$', sub) and len(sub) < 255]
        return valid_subdomains
    except Exception as e:
        CONSOLE.print(f"[red][-] Wordlist loading error: {e}[/red]")
        return []

if __name__ == "__main__":
    domain = input("Enter domain: ").strip().lower()
    wordlist_path = input("Enter wordlist file path (optional, press Enter to skip): ").strip()
    
    subdomains = get_subdomains_from_crtsh(domain)
    
    if not subdomains:
        subdomains = get_subdomains_from_threatcrowd(domain)
    
    if not subdomains:
        subdomains = get_subdomains_from_virustotal(domain)
    
    if wordlist_path:
        CONSOLE.print("[yellow][*] Brute-forcing additional subdomains...[/yellow]")
        brute_subdomains = brute_force_subdomains(domain, wordlist_path)
        subdomains.extend(brute_subdomains)
        subdomains = sorted(set(subdomains))  # Remove duplicates
    
    if subdomains:
        table = Table(title=f"Discovered and Resolved Subdomains ({domain})")
        table.add_column("Subdomain", style="cyan")
        table.add_column("IP Address", style="green")
        
        resolved_subdomains = {}
        for sub in subdomains:
            ip = resolve_dns(sub)
            if ip:
                resolved_subdomains[sub] = ip
                table.add_row(sub, ip)
        
        CONSOLE.print(table)
        
        # Save results
        output_file = f"{domain}_resolved_subdomains.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(resolved_subdomains, f, indent=4)
        CONSOLE.print(f"[green][+] {len(resolved_subdomains)} active subdomains saved: {output_file}[/green]")
    else:
        CONSOLE.print("[yellow][-] No subdomains found.[/yellow]")
