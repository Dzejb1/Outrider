import shutil
import sys
import ipaddress

def check_dependencies():
    """Checks if all required command-line tools are installed."""
    print("[+] Checking for required tools...")
    required_tools = ["nmap", "nikto", "gobuster", "subfinder", "wafw00f", "nuclei"]
    missing_tools = []
    for tool in required_tools:
        if not shutil.which(tool):
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"[!] Error: The following required tools are not installed or not in your PATH: {', '.join(missing_tools)}")
        print("[!] Please install them and try again.")
        sys.exit(1)
    print("[+] All required tools found.")

def is_ip_address(address):
    """
    Checks if the given string is a valid IP address.
    """
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False
