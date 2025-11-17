import asyncio
import os

async def run_nmap(target, full_scan=False, quiet=False):
    """
    Runs an nmap scan on the given target and saves the output to an XML file.
    """
    if not quiet:
        if full_scan:
            print(f"[+] Performing full Nmap scan on {target} (all ports, default scripts)...")
        else:
            print(f"[+] Performing standard Nmap scan on {target} (service version detection)...")
    
    nmap_command = ["nmap", "-sV", "-oX", "nmap_results.xml", target, "--stats-every", "10s"]
    if full_scan:
        nmap_command = ["nmap", "-p-", "-sC", "-oX", "nmap_results.xml", target, "--stats-every", "10s"]

    process = await asyncio.create_subprocess_exec(*nmap_command, stdout=asyncio.subprocess.PIPE, stderr=None)
    stdout, stderr = await process.communicate()

    if process.returncode == 0:
        if not quiet:
            print("[+] Nmap scan completed. Results saved to nmap_results.xml")
        return "nmap_results.xml"
    else:
        if not quiet:
            print(f"[!] Error running nmap: {stderr.decode() if stderr else ''}")
        return None

async def run_subfinder(target, quiet=False):
    """
    Runs subfinder to discover subdomains for the given target domain.
    """
    if not quiet:
        print(f"[+] Running subfinder on {target}...")
    subfinder_command = ["subfinder", "-d", target, "-silent"]
    process = await asyncio.create_subprocess_exec(*subfinder_command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await process.communicate()

    if process.returncode == 0:
        subdomains = stdout.decode().strip().split("\n")
        subdomains = [s for s in subdomains if s]
        if not quiet:
            print(f"[+] Subfinder found {len(subdomains)} subdomains.")
        return subdomains
    else:
        if not quiet:
            print(f"[!] Error running subfinder: {stderr.decode()}")
        return []

async def run_nikto(target, port, quiet=False, tuning_options=None):
    """
    Runs a nikto scan on the given target and port.
    """
    if not quiet:
        print(f"[+] Running nikto scan on {target}:{port}...")
    protocol = "https" if port == "443" else "http"
    nikto_command = ["nikto", "-h", f"{protocol}://{target}:{port}"]
    if tuning_options:
        nikto_command.extend(["-Tuning", tuning_options])
    process = await asyncio.create_subprocess_exec(*nikto_command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await process.communicate()

    if process.returncode == 0:
        if not quiet:
            print(f"[+] Nikto scan completed for port {port}.")
        return stdout.decode()
    else:
        if not quiet:
            print(f"[!] Error running nikto on port {port}: {stderr.decode()}")
        return None

async def run_gobuster(target, port, wordlist, quiet=False, delay=None):
    """
    Runs a gobuster scan for directories on the given target and port.
    """
    if not quiet:
        print(f"[+] Running gobuster scan on {target}:{port}...")
    if not os.path.exists(wordlist):
        if not quiet:
            print(f"[!] Error: Gobuster wordlist not found at {wordlist}")
            print("[!] Please update the GOBUSTER_WORDLIST path in your config.ini.")
        return None

    protocol = "https" if port == "443" else "http"
    gobuster_command = ["gobuster", "dir", "-u", f"{protocol}://{target}:{port}", "-w", wordlist, "-t", "10"]
    if delay:
        gobuster_command.extend(["--delay", delay])
    process = await asyncio.create_subprocess_exec(*gobuster_command, stdout=asyncio.subprocess.PIPE, stderr=None)
    stdout, stderr = await process.communicate()

    if process.returncode == 0:
        if not quiet:
            print(f"[+] Gobuster scan completed for port {port}.")
        return stdout.decode()
    else:
        if not quiet:
            print(f"[!] Gobuster finished with a non-standard exit code on port {port}. This might be expected.")
        return stdout.decode()

async def run_wafw00f(target, quiet=False):
    """
    Runs wafw00f to detect a Web Application Firewall.
    """
    if not quiet:
        print(f"[+] Checking for WAF on {target}...")
    # We check common web ports. wafw00f is clever enough to figure out http/https.
    # The '-a' flag tells it to not stop after the first finding.
    wafw00f_command = ["wafw00f", "-a", target]
    process = await asyncio.create_subprocess_exec(*wafw00f_command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await process.communicate()

    if process.returncode in [0, 1]: # wafw00f exits with 1 if no WAF is found, which is a valid result
        if not quiet:
            print("[+] WAF check completed.")
        return stdout.decode()
    else:
        if not quiet:
            print(f"[!] Error running wafw00f: {stderr.decode()}")
        return None

async def run_nuclei_takeover(targets, quiet=False):
    """
    Runs nuclei to check for subdomain takeover vulnerabilities.
    """
    if not targets:
        return None

    if not quiet:
        print(f"[+] Running nuclei takeover scan on {len(targets)} subdomains...")
    
    # Create a temporary file with targets
    temp_target_file = "temp_nuclei_targets.txt"
    with open(temp_target_file, "w") as f:
        for target in targets:
            f.write(f"{target}\n")

    # Use -itags for better template filtering. The 'takeover' tag is common.
    nuclei_command = ["nuclei", "-l", temp_target_file, "-itags", "takeover", "-json"]
    
    process = await asyncio.create_subprocess_exec(*nuclei_command, stdout=asyncio.subprocess.PIPE, stderr=None)
    stdout, stderr = await process.communicate()

    # Clean up the temporary file
    os.remove(temp_target_file)

    if process.returncode == 0:
        if not quiet:
            print("[+] Nuclei takeover scan completed.")
        return stdout.decode()
    else:
        if not quiet:
            # stderr might contain info about no templates found, which is not a critical error.
            print(f"[!] Nuclei finished with a non-zero exit code. Stderr: {stderr.decode() if stderr else ''}")
        # Still return stdout as it might contain partial results
        return stdout.decode()

async def run_nuclei_web_scan(target_url, quiet=False):
    """
    Runs nuclei with a broad set of web vulnerability templates against a single URL.
    """
    if not quiet:
        print(f"[+] Running deep web vulnerability scan with nuclei on {target_url}...")
    # Using common template categories for web vulnerabilities
    # -t cves/ - for known CVEs
    # -t default-logins/ - for default credentials
    # -t exposed-panels/ - for exposed admin panels
    # -t misconfiguration/ - for common misconfigurations
    # -t vulnerabilities/ - for general web vulnerabilities (XSS, SQLi, etc.)
    nuclei_command = ["nuclei", "-u", target_url, 
                      "-t", "cves/", "-t", "default-logins/", 
                      "-t", "exposed-panels/", "-t", "misconfiguration/", 
                      "-t", "vulnerabilities/", 
                      "-json"]
    
    process = await asyncio.create_subprocess_exec(*nuclei_command, stdout=asyncio.subprocess.PIPE, stderr=None)
    stdout, stderr = await process.communicate()

    if process.returncode == 0:
        if not quiet:
            print(f"[+] Nuclei deep web scan completed for {target_url}.")
        return stdout.decode()
    else:
        if not quiet:
            print(f"[!] Nuclei deep web scan finished with a non-zero exit code for {target_url}. Stderr: {stderr.decode() if stderr else ''}")
        return stdout.decode()
