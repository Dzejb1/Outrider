# Automated Reconnaissance Tool

This project is a Python-based tool that automates a wide range of reconnaissance tasks for penetration testing. It streamlines the process of gathering information about a target, running various scans, and generating comprehensive reports in multiple formats.

## Features

-   **Target Input**: Accepts a domain or IP address as a target.
-   **Subdomain Enumeration**: Uses `subfinder` to discover subdomains.
-   **Port Scanning**: Performs `nmap` scans to identify open ports, services, and versions. Includes options for both standard and full scans.
-   **Web Scanning**:
    -   **Directory & File Brute-forcing**: Uses `gobuster` to find common directories and files.
    -   **Web Server Vulnerability Scanning**: Runs `nikto` to check for web server vulnerabilities.
    -   **WAF Detection**: Employs `wafw00f` to detect Web Application Firewalls.
-   **Advanced Vulnerability Scanning**:
    -   **Subdomain Takeover**: Uses `nuclei` to check for vulnerabilities related to subdomain takeovers.
    -   **Deep Web Vulnerability Scanning**: Leverages `nuclei` for in-depth web vulnerability analysis (optional).
-   **State Management**: Saves the scan progress and results, allowing you to resume scans or avoid re-running completed ones.
-   **Flexible Reporting**: Generates reports in multiple formats:
    -   **HTML**: A detailed, easy-to-read report with tables and styling.
    -   **JSON**: A machine-readable format for easy integration with other tools.
    -   **CSV**: For easy data manipulation and analysis in spreadsheets.
    -   **Markdown**: A clean, simple report format.
-   **Customization**:
    -   Skip specific scans.
    -   Override wordlists for `gobuster`.
    -   Adjust `nikto` tuning options.
    -   Set a delay for `gobuster` requests.

## Setup

1.  **Install Python**: Ensure you have Python 3.6+ installed.

2.  **Install External Tools**: This script relies on several external tools. You must install them and ensure they are in your system's PATH.
    -   **Nmap**: [https://nmap.org/download.html](https://nmap.org/download.html)
    -   **Nikto**: [https://cirt.net/Nikto2](https://cirt.net/Nikto2)
    -   **Gobuster**: [https://github.com/OJ/gobuster](https://github.com/OJ/gobuster)
    -   **Subfinder**: [https://github.com/projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder)
    -   **Wafw00f**: [https://github.com/EnableSecurity/wafw00f](https://github.com/EnableSecurity/wafw00f)
    -   **Nuclei**: [https://github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)

3.  **Clone the Project**:
    ```bash
    git clone https://github.com/Dzejb1/Outrider.git

    ```

4.  **Install Python Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```



## Configuration

The `config.ini` file allows you to configure the tool's behavior:

```ini
[DEFAULT]
# Ports considered as web ports for running web-related scans
WEB_PORTS = 80,443,8080,8443

[PATHS]
# Path to the wordlist for Gobuster
GOBUSTER_WORDLIST = /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

## Usage

Run the script from your terminal with the required target argument.

```bash
python main.py <target> [options]
```

**Example:**

```bash
python main.py example.com --format html,json --deep-web-scan
```

### Options

| Argument | Description | Default |
|---|---|---|
| `target` | The target domain or IP address. | (Required) |
| `--output-dir` | Directory to save reports. | `.` |
| `--format` | Comma-separated list of report formats (html,json,csv,md). | `html,json` |
| `--skip-scans` | Comma-separated list of scans to skip (e.g., `subfinder,nikto`). | `""` |
| `--wordlist` | Override the `gobuster` wordlist path from `config.ini`. | |
| `--full-scan` | Perform a full Nmap scan (all ports, default scripts). | `False` |
| `--deep-web-scan` | Perform a deep web vulnerability scan using Nuclei. | `False` |
| `--force-rescan` | Ignore saved state and re-run all scans. | `False` |
| `--nikto-tuning` | Nikto tuning options (e.g., `'x 123'`). | |
| `--gobuster-delay`| Delay between Gobuster requests (e.g., `'500ms'`). | |

## Reporting

The tool can generate reports in four different formats:

-   **HTML**: A visually appealing and detailed report, ideal for manual review.
-   **JSON**: A structured format that can be easily parsed by other scripts or imported into databases.
-   **CSV**: A set of comma-separated files, useful for analyzing data in spreadsheets.
-   **Markdown**: A simple and clean report that can be easily shared and version-controlled.

Reports are saved in the specified output directory, with filenames based on the target's name.