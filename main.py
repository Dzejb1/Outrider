import argparse
import asyncio
import os
import configparser

from utils import check_dependencies, is_ip_address
from scanners import run_nmap, run_subfinder, run_nikto, run_gobuster, run_wafw00f, run_nuclei_takeover, run_nuclei_web_scan
from parsers import parse_nmap_results, parse_gobuster_results, parse_nikto_results, parse_wafw00f, parse_nuclei_jsonl
from reporting import save_json_report, save_html_report, save_csv_report, save_md_report
from state_manager import load_state, save_state

async def main():
    check_dependencies()
    # --- Configuration Loading ---
    config = configparser.ConfigParser()
    config.read('config.ini')
    
    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(description="Automated reconnaissance script for penetration testing.", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("target", help="The target domain or IP address.")
    parser.add_argument("--output-dir", default=".", help="Directory to save reports.")
    parser.add_argument("--format", default="html,json", help="Comma-separated list of report formats (html,json,csv,md).")
    parser.add_argument("--skip-scans", default="", help="Comma-separated list of scans to skip (e.g., subfinder,nikto,gobuster,waf,takeover,nuclei-web).")
    parser.add_argument("--wordlist", help="Override the gobuster wordlist path from config.ini.")
    parser.add_argument("--full-scan", action="store_true", help="Perform a full Nmap scan (all ports, default scripts).")
    parser.add_argument("--deep-web-scan", action="store_true", help="Perform a deep web vulnerability scan using Nuclei.")
    parser.add_argument("--force-rescan", action="store_true", help="Ignore saved state and re-run all scans.")
    parser.add_argument("--nikto-tuning", help="Nikto tuning options (e.g., 'x 123').")
    parser.add_argument("--gobuster-delay", help="Delay between Gobuster requests (e.g., '500ms').")
    args = parser.parse_args()
    
    target = args.target
    output_dir = args.output_dir
    skipped_scans = {s.strip() for s in args.skip_scans.split(',') if s.strip()}
    report_formats = {f.strip() for f in args.format.split(',') if f.strip()}
    full_scan = args.full_scan
    deep_web_scan = args.deep_web_scan

    # --- Get Config Values ---
    try:
        web_ports = config.get('DEFAULT', 'WEB_PORTS').split(',')
        gobuster_wordlist = args.wordlist if args.wordlist else config.get('PATHS', 'GOBUSTER_WORDLIST')
    except (configparser.NoSectionError, configparser.NoOptionError) as e:
        print(f"[!] Error reading config.ini: {e}")
        print("[!] Please ensure 'config.ini' exists and has the correct format.")
        return

    # --- Create output directory ---
    os.makedirs(output_dir, exist_ok=True)

    # --- State Management ---
    current_state = {} if args.force_rescan else load_state(target, output_dir)
    if current_state is None:
        current_state = {}

    # --- Initialize result variables from state or defaults ---
    subdomains = current_state.get('subdomains', [])
    takeover_findings = current_state.get('takeover_findings', [])
    web_vulnerabilities = current_state.get('web_vulnerabilities', [])
    waf_info = current_state.get('waf_info', None)
    open_ports = current_state.get('open_ports', [])
    nikto_results = current_state.get('nikto_results', {})
    gobuster_results = current_state.get('gobuster_results', {})

    # --- Scan Progress Tracking ---
    scans_to_run = [
        'subfinder', 'nmap', 'takeover', 'waf', 'nikto', 'gobuster', 'nuclei-web'
    ]
    scans_to_run = [s for s in scans_to_run if s not in skipped_scans]
    total_scans = len(scans_to_run)
    scan_counter = 0

    def print_progress(scan_name):
        nonlocal scan_counter
        scan_counter += 1
        print(f"[{scan_counter}/{total_scans}] Running {scan_name} scan...")

    # --- Execute Scans ---
    if 'subfinder' in scans_to_run and not subdomains:
        print_progress('subfinder')
        if not is_ip_address(target):
            subdomains = await run_subfinder(target, quiet=True)
            current_state['subdomains'] = subdomains
            save_state(target, output_dir, current_state)
        else:
            print("[+] Target is an IP address, skipping subdomain enumeration.")
    elif 'subfinder' not in skipped_scans:
        print("[-] Skipping subfinder scan (already done or skipped by user).")

    if 'takeover' in scans_to_run and subdomains and not takeover_findings:
        print_progress('takeover')
        raw_nuclei_output = await run_nuclei_takeover(subdomains, quiet=True)
        if raw_nuclei_output:
            takeover_findings = parse_nuclei_jsonl(raw_nuclei_output)
            current_state['takeover_findings'] = takeover_findings
            save_state(target, output_dir, current_state)
    elif 'takeover' not in skipped_scans:
        print("[-] Skipping takeover scan (no subdomains, already done, or skipped by user).")

    if 'nmap' in scans_to_run and not open_ports:
        print_progress('nmap')
        nmap_output_file = await run_nmap(target, full_scan=full_scan, quiet=True)
        if nmap_output_file:
            open_ports = parse_nmap_results(nmap_output_file)
            current_state['open_ports'] = open_ports
            save_state(target, output_dir, current_state)
    elif 'nmap' not in skipped_scans:
        print("[-] Skipping nmap scan (already done or skipped by user).")

    web_port_infos = [p for p in open_ports if p["port"] in web_ports]
    
    if web_port_infos:
        if 'waf' in scans_to_run and not waf_info:
            print_progress('waf')
            raw_waf_output = await run_wafw00f(target, quiet=True)
            if raw_waf_output:
                waf_info = parse_wafw00f(raw_waf_output)
                current_state['waf_info'] = waf_info
                save_state(target, output_dir, current_state)
        elif 'waf' not in skipped_scans:
            print("[-] Skipping WAF detection (already done or skipped by user).")

        if deep_web_scan and 'nuclei-web' in scans_to_run and not web_vulnerabilities:
            print_progress('nuclei-web')
            nuclei_web_tasks = []
            for p in web_port_infos:
                protocol = "https" if p["port"] == "443" else "http"
                target_url = f"{protocol}://{target}:{p["port"]}"
                nuclei_web_tasks.append(run_nuclei_web_scan(target_url, quiet=True))
            
            raw_web_vulnerabilities_outputs = await asyncio.gather(*nuclei_web_tasks)
            for output in raw_web_vulnerabilities_outputs:
                if output:
                    web_vulnerabilities.extend(parse_nuclei_jsonl(output))
            current_state['web_vulnerabilities'] = web_vulnerabilities
            save_state(target, output_dir, current_state)
        elif 'nuclei-web' not in skipped_scans:
            print("[-] Skipping deep web vulnerability scan (already done or skipped by user).")

        # Check if we need to run any web scans
        run_web_scans = ('nikto' in scans_to_run and not nikto_results) or \
                        ('gobuster' in scans_to_run and not gobuster_results)

        if run_web_scans:
            if 'nikto' in scans_to_run:
                print_progress('nikto')
            nikto_tasks = [run_nikto(target, p["port"], quiet=True, tuning_options=args.nikto_tuning) for p in web_port_infos if 'nikto' in scans_to_run]
            
            if 'gobuster' in scans_to_run:
                print_progress('gobuster')
            gobuster_tasks = [run_gobuster(target, p["port"], gobuster_wordlist, quiet=True, delay=args.gobuster_delay) for p in web_port_infos if 'gobuster' in scans_to_run]
            
            nikto_results_list = await asyncio.gather(*nikto_tasks)
            gobuster_results_list = await asyncio.gather(*gobuster_tasks)

            for i, port_info in enumerate(web_port_infos):
                if 'nikto' in scans_to_run and nikto_results_list and i < len(nikto_results_list) and nikto_results_list[i]:
                    nikto_results[port_info["port"]] = parse_nikto_results(nikto_results_list[i])
                if 'gobuster' in scans_to_run and gobuster_results_list and i < len(gobuster_results_list) and gobuster_results_list[i]:
                    gobuster_results[port_info["port"]] = parse_gobuster_results(gobuster_results_list[i])
            
            if 'nikto' in scans_to_run:
                current_state['nikto_results'] = nikto_results
            if 'gobuster' in scans_to_run:
                current_state['gobuster_results'] = gobuster_results
            if run_web_scans:
                save_state(target, output_dir, current_state)
        else:
            print("[-] Skipping web scans (already done or skipped by user).")

    # --- Generate Reports ---
    print("\n[+] All scans complete. Generating final reports...")
    all_results = (target, subdomains, waf_info, takeover_findings, web_vulnerabilities, open_ports, nikto_results, gobuster_results, output_dir)
    if 'json' in report_formats:
        save_json_report(*all_results)
    if 'html' in report_formats:
        save_html_report(*all_results)
    if 'csv' in report_formats:
        save_csv_report(*all_results)
    if 'md' in report_formats:
        save_md_report(*all_results)

    # --- Clean up ---
    if os.path.exists("nmap_results.xml"):
        os.remove("nmap_results.xml")
        print("[+] Cleaned up nmap_results.xml")

if __name__ == "__main__":
    asyncio.run(main())
