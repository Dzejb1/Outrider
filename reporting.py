import json
import html
import os
import csv

def save_json_report(target, subdomains, waf_info, takeover_findings, web_vulnerabilities, open_ports, nikto_results, gobuster_results, output_dir="."):
    """
    Organizes all findings into a dictionary and saves it to a JSON file.
    """
    print("\n[+] Generating JSON report...")
    
    report_data = {
        "target": target,
        "waf_info": waf_info,
        "subdomains": subdomains,
        "takeover_findings": takeover_findings,
        "web_vulnerabilities": web_vulnerabilities,
        "scan_results": {
            "host": target,
            "open_ports": open_ports,
            "nikto": nikto_results,
            "gobuster": gobuster_results,
        }
    }

    report_filename_json = os.path.join(output_dir, f"{target.replace('.', '_')}_report.json")
    try:
        with open(report_filename_json, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)
        print(f"[+] JSON report successfully saved to {report_filename_json}")
    except IOError as e:
        print(f"[!] Error saving JSON report: {e}")

def save_html_report(target, subdomains, waf_info, takeover_findings, web_vulnerabilities, open_ports, nikto_results, gobuster_results, output_dir="."):
    """
    Organizes all findings into an HTML report and saves it to a file.
    """
    print("[+] Generating HTML report...")

    def e(s):
        if s is None: return ""
        return html.escape(str(s))

    def generate_nmap_table(results):
        if not results:
            return "<div class='empty-state'><p>No open ports found.</p></div>"
        
        table_rows = ""
        for r in results:
            table_rows += f"<tr><td>{e(r['port'])}</td><td>{e(r['service'])}</td></tr>"
            if r.get("scripts"):
                script_rows = ""
                for script in r["scripts"]:
                    script_rows += f"<tr><td>{e(script['id'])}</td><td><pre>{e(script['output'])}</pre></td></tr>"
                table_rows += f'''
                    <tr class="script-row">
                        <td colspan="2">
                            <div class="nested-table-container">
                                <h4>NSE Script Results</h4>
                                <table>
                                    <tr><th>Script Name</th><th>Output</th></tr>
                                    {script_rows}
                                </table>
                            </div>
                        </td>
                    </tr>
                '''
        return f"<table><tr><th>Port</th><th>Service</th></tr>{table_rows}</table>"

    def generate_gobuster_table(results):
        if not results:
            return "<div class='empty-state'><p>No directories or files found.</p></div>"
        rows = ""
        for r in results:
            severity = r.get("severity", "Informational")
            rows += f'''<tr>
                <td>{e(r['path'])}</td>
                <td>{e(r['status'])}</td>
                <td class="severity-{severity.lower()}">{e(severity)}</td>
            </tr>'''
        return f"<table><tr><th>Path</th><th>Status</th><th>Severity</th></tr>{rows}</table>"

    def generate_nikto_table(results):
        if not results:
            return "<div class='empty-state'><p>No significant findings from Nikto.</p></div>"
        rows = "".join(f"<tr><td>{e(r)}</td></tr>" for r in results)
        return f"<table><tr><th>Finding</th></tr>{rows}</table>"

    def generate_takeover_table(results):
        if not results:
            return "<div class='empty-state'><p>No potential subdomain takeovers found.</p></div>"
        rows = ""
        for r in results:
            severity = r.get("severity", "N/A")
            rows += f'''<tr>
                <td>{e(r['host'])}</td>
                <td>{e(r['finding_name'])}</td>
                <td class="severity-{severity.lower()}">{e(severity)}</td>
            </tr>'''
        return f"<table><tr><th>Subdomain</th><th>Finding</th><th>Severity</th></tr>{rows}</table>"

    def generate_web_vulnerabilities_table(results):
        if not results:
            return "<div class='empty-state'><p>No web vulnerabilities found.</p></div>"
        rows = ""
        for r in results:
            severity = r.get("severity", "N/A")
            rows += f'''<tr>
                <td>{e(r['host'])}</td>
                <td>{e(r['finding_name'])}</td>
                <td class="severity-{severity.lower()}">{e(severity)}</td>
                <td>{e(r['description'])}</td>
            </tr>'''
        return f"<table><tr><th>Host</th><th>Finding</th><th>Severity</th><th>Description</th></tr>{rows}</table>"

    gobuster_sections = "".join(f'''
        <div class="port-section">
            <h2>Gobuster Scan on Port {e(port)}</h2>
            {generate_gobuster_table(results)}
        </div>
    ''' for port, results in gobuster_results.items())

    nikto_sections = "".join(f'''
        <div class="port-section">
            <h2>Nikto Scan on Port {e(port)}</h2>
            {generate_nikto_table(results)}
        </div>
    ''' for port, results in nikto_results.items())

    waf_section = f'''<h2>WAF Detection</h2><div class="port-section"><p>{e(waf_info)}</p></div>''' if waf_info else ""
    takeover_section = f'''<h2>Subdomain Takeover Scan</h2>{generate_takeover_table(takeover_findings)}''' if takeover_findings else ""
    web_vulnerabilities_section = f'''<h2>Web Vulnerabilities (Nuclei)</h2>{generate_web_vulnerabilities_table(web_vulnerabilities)}''' if web_vulnerabilities else ""
    nmap_section = f'''<h2>Nmap Scan Results</h2>{generate_nmap_table(open_ports)}'''

    html_content = f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reconnaissance Report for {e(target)}</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 0; padding: 0; background-color: #f8f9fa; color: #212529; }}
            .container {{ width: 80%; max-width: 1200px; margin: 20px auto; background-color: #ffffff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.05); }}
            h1, h2, h4 {{ color: #343a40; }}
            h1, h2 {{ border-bottom: 2px solid #dee2e6; padding-bottom: 10px; }}
            h1 {{ font-size: 2.5em; text-align: center; }}
            h2 {{ font-size: 1.75em; margin-top: 40px; }}
            h4 {{ margin-top: 0; border-bottom: 1px solid #e9ecef; padding-bottom: 5px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ border: 1px solid #dee2e6; padding: 12px; text-align: left; word-break: break-all; }}
            th {{ background-color: #e9ecef; font-weight: 600; }}
            pre {{ background-color: #f8f9fa; padding: 10px; border: 1px solid #dee2e6; white-space: pre-wrap; word-wrap: break-word; font-family: "Courier New", Courier, monospace; border-radius: 4px; margin: 0; }}
            .subdomain-list {{ list-style-type: none; padding-left: 0; }}
            .subdomain-list li {{ background-color: #f8f9fa; padding: 8px; border-radius: 4px; margin-bottom: 5px; }}
            .port-section {{ background-color: #fff; border: 1px solid #dee2e6; border-radius: 8px; padding: 20px; margin-top: 20px; }}
            .empty-state {{ text-align: center; color: #6c757d; padding: 20px; }}
            .script-row > td {{ background-color: #f8f9fa; padding: 0; }}
            .nested-table-container {{ padding: 15px; }}
            .nested-table-container table th {{ background-color: #e9ecef; }}
            .severity-critical {{ background-color: #dc3545; color: white; font-weight: bold; }}
            .severity-high {{ background-color: #fd7e14; color: white; }}
            .severity-medium {{ background-color: #ffc107; color: #343a40; }}
            .severity-low {{ background-color: #0dcaf0; }}
            .severity-informational {{ background-color: #f8f9fa; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Reconnaissance Report for <strong>{e(target)}</strong></h1>

            {f"<h2>Subdomains</h2><ul class='subdomain-list'>{''.join(f'<li>{e(s)}</li>' for s in subdomains)}</ul>" if subdomains else "<h2>Subdomains</h2><div class='empty-state'><p>No subdomains found.</p></div>"}

            {takeover_section}

            {web_vulnerabilities_section}

            {waf_section}

            {nmap_section}

            {nikto_sections}
            {gobuster_sections}

        </div>
    </body>
    </html>
    '''

    report_filename_html = os.path.join(output_dir, f"{target.replace('.', '_')}_report.html")
    try:
        with open(report_filename_html, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"[+] HTML report successfully saved to {report_filename_html}")
    except IOError as err:
        print(f"[!] Error saving HTML report: {err}")

def save_csv_report(target, subdomains, waf_info, takeover_findings, web_vulnerabilities, open_ports, nikto_results, gobuster_results, output_dir="."):
    """
    Organizes all findings into a set of CSV files.
    """
    print("\n[+] Generating CSV reports...")
    base_filename = os.path.join(output_dir, f"{target.replace('.', '_')}")

    def write_csv(filename, headers, rows):
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                writer.writerows(rows)
            print(f"[+] CSV report successfully saved to {filename}")
        except IOError as e:
            print(f"[!] Error saving CSV report {filename}: {e}")

    # Nmap ports report
    if open_ports:
        write_csv(f"{base_filename}_ports.csv", ["Port", "Service"], [[p['port'], p['service']] for p in open_ports])

    # Takeover report
    if takeover_findings:
        write_csv(f"{base_filename}_takeovers.csv", ["Host", "Finding", "Severity"], [[f['host'], f['finding_name'], f['severity']] for f in takeover_findings])

    # Web Vulnerabilities report
    if web_vulnerabilities:
        write_csv(f"{base_filename}_web_vulnerabilities.csv", ["Host", "Finding", "Severity", "Description"], 
                  [[f['host'], f['finding_name'], f['severity'], f['description']] for f in web_vulnerabilities])

    # Gobuster report
    gobuster_rows = []
    for port, results in gobuster_results.items():
        for r in results:
            gobuster_rows.append([port, r.get('path'), r.get('status'), r.get('severity', 'Informational')])
    if gobuster_rows:
        write_csv(f"{base_filename}_gobuster.csv", ["Port", "Path", "Status", "Severity"], gobuster_rows)

def save_md_report(target, subdomains, waf_info, takeover_findings, web_vulnerabilities, open_ports, nikto_results, gobuster_results, output_dir="."):
    """
    Organizes all findings into a Markdown report.
    """
    print("\n[+] Generating Markdown report...")
    md_content = f"# Reconnaissance Report for {target}\n\n"

    if subdomains:
        md_content += "## Subdomains\n"
        for s in subdomains:
            md_content += f"- {s}\n"
        md_content += "\n"

    if takeover_findings:
        md_content += "## Subdomain Takeover Scan\n"
        md_content += "| Subdomain | Finding | Severity |\n"
        md_content += "|---|---|---|\n"
        for f in takeover_findings:
            md_content += f"| {f['host']} | {f['finding_name']} | {f['severity']} |\n"
        md_content += "\n"

    if web_vulnerabilities:
        md_content += "## Web Vulnerabilities (Nuclei)\n"
        md_content += "| Host | Finding | Severity | Description |\n"
        md_content += "|---|---|---|---|\n"
        for f in web_vulnerabilities:
            md_content += f"| {f['host']} | {f['finding_name']} | {f['severity']} | {f['description']} |\n"
        md_content += "\n"

    if waf_info:
        md_content += f"## WAF Detection\n- {waf_info}\n\n"

    if open_ports:
        md_content += "## Nmap Scan Results\n"
        md_content += "| Port | Service |\n"
        md_content += "|---|---|\n"
        for p in open_ports:
            md_content += f"| {p['port']} | {p['service']} |\n"
            if p.get('scripts'):
                md_content += "| | **NSE Scripts** |\n"
                md_content += "| | --- |\n"
                for s in p['scripts']:
                    md_content += f"| | **{s['id']}**: ```{s['output']}``` |\n"
        md_content += "\n"

    for port, results in gobuster_results.items():
        if results:
            md_content += f"## Gobuster Scan on Port {port}\n"
            md_content += "| Path | Status | Severity |\n"
            md_content += "|---|---|---|\n"
            for r in results:
                md_content += f"| {r.get('path')} | {r.get('status')} | {r.get('severity', 'Informational')} |\n"
            md_content += "\n"

    for port, results in nikto_results.items():
        if results:
            md_content += f"## Nikto Scan on Port {port}\n"
            for r in results:
                md_content += f"- {r}\n"
            md_content += "\n"

    report_filename_md = os.path.join(output_dir, f"{target.replace('.', '_')}_report.md")
    try:
        with open(report_filename_md, "w", encoding="utf-8") as f:
            f.write(md_content)
        print(f"[+] Markdown report successfully saved to {report_filename_md}")
    except IOError as e:
        print(f"[!] Error saving Markdown report: {e}")
