import xml.etree.ElementTree as ET
import re
import json

def parse_nmap_results(xml_file):
    """
    Parses the nmap XML output to find open ports, services, and NSE script results.
    """
    print(f"[+] Parsing nmap results from {xml_file}...")
    open_ports = []
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for port in root.findall(".//port"):
            if port.find("state").get("state") == "open":
                portid = port.get("portid")
                service = port.find("service")
                service_name = service.get("name") if service is not None else "unknown"
                
                port_details = {"port": portid, "service": service_name, "scripts": []}
                
                # Extract script outputs
                for script in port.findall('script'):
                    script_id = script.get("id", "")
                    script_output = script.get("output", "")
                    if script_id and script_output:
                        port_details["scripts"].append({"id": script_id, "output": script_output.strip()})
                
                open_ports.append(port_details)

        print(f"[+] Found {len(open_ports)} open ports.")
        return open_ports
    except ET.ParseError as e:
        print(f"[!] Error parsing XML file: {e}")
        return []
    except FileNotFoundError:
        print(f"[!] Error: {xml_file} not found.")
        return []

def parse_gobuster_results(gobuster_output):
    """
    Parses the raw string output from Gobuster to extract found paths and status codes.
    """
    if not gobuster_output:
        return []

    SENSITIVE_PATHS = {
        # High Severity - Exposed credentials, source code, sensitive configs
        ".git": "High",
        ".env": "High",
        ".aws": "High",
        "credentials": "High",
        "htpasswd": "High",
        "id_rsa": "Critical",
        # Medium Severity - Potentially sensitive directories or files
        "admin": "Medium",
        "dashboard": "Medium",
        "login": "Medium",
        "config": "Medium",
        "backup": "Medium",
        "private": "Medium",
        "database": "Medium",
        # Low Severity - Informational or less critical files
        ".bak": "Low",
        ".old": "Low",
        "~": "Low",
        "test": "Low",
        "dev": "Low",
    }
    
    findings = []
    pattern = re.compile(r"^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d{3})\)")
    
    for line in gobuster_output.strip().split('\n'):
        match = pattern.match(line.strip())
        if match:
            finding = match.groupdict()
            finding["severity"] = "Informational" # Default severity

            for path_keyword, severity in SENSITIVE_PATHS.items():
                if path_keyword in finding["path"].lower():
                    finding["severity"] = severity
                    break # Stop at the first (most specific) match
            
            findings.append(finding)
            
    return findings

def parse_nikto_results(nikto_output):
    """
    Parses the raw string output from Nikto to extract interesting findings.
    """
    if not nikto_output:
        return []
        
    findings = []
    # Extracts lines starting with '+' which typically denote findings.
    for line in nikto_output.strip().split('\n'):
        if line.startswith('+'):
            # Clean up the line by removing the leading '+' and extra whitespace
            finding_text = line[1:].strip()
            if finding_text:
                findings.append(finding_text)
                
    return findings

def parse_wafw00f(wafw00f_output):
    """
    Parses the raw string output from wafw00f to extract the WAF name.
    """
    if not wafw00f_output:
        return "Unable to determine."

    # Regex to find a line like: [+] The site https://... is behind Generic WAF (Unknown). 
    match = re.search(r"is behind\s+(?P<waf_name>.*)\s+WAF", wafw00f_output)
    if match:
        return match.group("waf_name").strip()
    
    if "No WAF detected" in wafw00f_output:
        return "Not Detected"
        
    return "Unable to determine."

def parse_nuclei_jsonl(nuclei_output):
    """
    Parses the JSONL output from Nuclei to extract takeover findings.
    """
    if not nuclei_output:
        return []

    findings = []
    for line in nuclei_output.strip().split('\n'):
        try:
            result = json.loads(line)
            finding = {
                "host": result.get("host", "N/A"),
                "finding_name": result.get("info", {}).get("name", "N/A"),
                "severity": result.get("info", {}).get("severity", "N/A"),
                "description": result.get("info", {}).get("description", "N/A"),
            }
            findings.append(finding)
        except json.JSONDecodeError:
            # Ignore lines that are not valid JSON
            continue
    return findings
