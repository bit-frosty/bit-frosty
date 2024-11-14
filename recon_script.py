#!/usr/bin/env python3
import os
import subprocess
import requests
import json
import argparse
import shutil
import threading
import csv

# Define color codes for output
reset = "\033[0m"
yellow = "\033[1;33m"
green = "\033[0;32m"
cyan = "\033[0;36m"
red = "\033[0;31m"

# Define file names for various outputs
output_dir = "Automation-script-output"
os.makedirs(output_dir, exist_ok=True)
os.makedirs(f"{output_dir}/Subdomains", exist_ok=True)
os.makedirs(f"{output_dir}/Cloudsnidomains", exist_ok=True)
os.makedirs(f"{output_dir}/Resolvers", exist_ok=True)
os.makedirs(f"{output_dir}/Wordlists", exist_ok=True)

sni_domains = f"{output_dir}/Cloudsnidomains/sni_domains.txt"
file0 = f"{output_dir}/Subdomains/merged_subdomains.txt"
file1 = f"{output_dir}/final_subdomains.txt"
file2 = f"{output_dir}/httpx_output_live_with_status_code.txt"
file3 = f"{output_dir}/active_subdomains.txt"
file4 = f"{output_dir}/dnsx_ip_address.txt"
file5 = f"{output_dir}/ip_address.txt"
file6 = f"{output_dir}/cdncheck_output.txt"
file7 = f"{output_dir}/cdncheck_sanitize.txt"
file8 = f"{output_dir}/ssl_out.txt"
file9 = f"{output_dir}/ssl_out_sanitize.txt"
file10 = f"{output_dir}/ssl_final.txt"
file11 = f"{output_dir}/certcheck_combined_output.txt"
file12 = f"{output_dir}/certcheck_final.txt"
file13 = f"{output_dir}/inactive_subdomains.txt"
file14 = f"{output_dir}/katana_output.txt"
file15 = f"{output_dir}/waybackurls_output.txt"
inactive_old = f"{output_dir}/inactive_subdomains_old.txt"
output_sheet1_csv = f"{output_dir}/output_sheet1.csv"
output_sheet2_csv = f"{output_dir}/output_sheet2.csv"
output_sheet3_csv = f"{output_dir}/output_sheet3.csv"
output_sheet4_csv = f"{output_dir}/output_sheet4.csv"
output_sheet5_csv = f"{output_dir}/output_sheet5.csv"

# Initialize domain variable
domain = "highradius.com"
subdomains_file = ""

def check_required_tools():
    """Check if all required tools are installed."""
    required_tools = [
        "assetfinder", "subfinder", "waybackurls", "findomain", "sublist3r",
        "amass", "gau", "curl", "jq", "httpx", "dnsx", "cdncheck",
        "certcheck", "katana", "nuclei"]
    print(f"{yellow}[*] Checking if required tools are installed...{reset}")
    missing_tools = []
    for tool in required_tools:
        if not shutil.which(tool):
            missing_tools.append(tool)
            print(f"{red}[!] {tool} is not installed{reset}")
        else:
            print(f"{green}[+] {tool} is installed{reset}")
    
    if missing_tools:
        raise Exception(f"Missing required tools: {', '.join(missing_tools)}")

def run_command(command):
    """Run a shell command safely."""
    try:
        result = subprocess.run(command, shell=True, executable='/bin/bash', check=True, capture_output=True, text=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"{red}[!] Command failed: {e.cmd}{reset}")
        print(f"{red}[!] Error output: {e.stderr}{reset}")
        raise

def run_command_thread(command):
    """Run a shell command in a separate thread."""
    thread = threading.Thread(target=run_command, args=(command,))
    thread.start()
    return thread

def enumerate_subdomains(domain, output_dir):
    print(f"[*] Enumerating subdomains for domain: {domain}")

    commands = [
        # f"curl -s 'https://crt.sh/?q=%25.{domain}&output=json' | jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u > '{output_dir}/Subdomains/crtsh-1_subdomains.txt'",
        #f"curl -s 'http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=txt&fl=original&collapse=urlkey&page=' | grep -oE 'https?://([^/]+)/?' | awk -F/ '{{print $3}}' >> '{output_dir}/Subdomains/wayback_machine_subdomains.txt' 2>/dev/null",
        #f"curl -s 'https://www.abuseipdb.com/whois/{domain}' -H 'user-agent: firefox' -b 'abuseipdb_session=' | grep -E '<li>\\w.*</li>' | sed -E 's/<\\/li>//g' | sed -e 's/<li>//g' | sed -e 's/$/.{domain}/' >> '{output_dir}/Subdomains/abuseipdb_subdomains.txt' 2>/dev/null",
        # f"curl -s 'https://www.abuseipdb.com/whois/{domain}' -H 'user-agent: firefox' -b 'abuseipdb_session=' | grep -E '<li>\\w.*</li>' | sed -E 's/<\\/li>//g' | sed -e 's/<li>//g' | sed -e 's/$/.{domain}/' >> '{output_dir}/Subdomains/abuseipdb_subdomains.txt' 2>/dev/null",
        #f"assetfinder -subs-only {domain} > {output_dir}/Subdomains/assetfinder_subdomains.txt",
        #f"subfinder -d {domain} -silent -all -o {output_dir}/Subdomains/subfinder_subdomains.txt",
        #f"echo {domain} | waybackurls | grep -oE 'https?://([^/]+)/?' | awk -F/ '{{print $3}}' >> {output_dir}/Subdomains/waybackurls_subdomains.txt 2>/dev/null",
       #  f"findomain -t {domain} -u {output_dir}/Subdomains/findomain_subdomains.txt > /dev/null 2>&1",
        f"sublist3r -d {domain} -o {output_dir}/Subdomains/sublister_subdomains.txt > /dev/null 2>&1",
        # f"crt {domain} > {output_dir}/Subdomains/crtsh-2_subdomains.txt",
        # Uncomment the following lines if needed
        #f"gau {domain} | grep -oE '[a-zA-Z0-9.-]+\\.{domain}' >> {output_dir}/Subdomains/gau_subdomains.txt 2>/dev/null",
        # f"cat {output_dir}/Subdomains/*.txt > {file0}",
        # f"github-subdomains -d {domain} -e -t $gitT | grep -oE 'b\\w+\\.highradius\\.com\\b' > {output_dir}/Subdomains/github_subdomains.txt",
        # f"gitlab-subdomains -d {domain} -e -t $gitL > {output_dir}/Subdomains/gitlab_subdomains.txt",
        # f"python3 /root/tools/as3nt/as3nt/core.py -t {domain} -so -o {output_dir}/Subdomains/as3nt_subdomains.txt > /dev/null 2>&1",
        # f"amass enum -d {domain} -active -brute -w {output_dir}/Wordlists/subdomains.txt | awk '$2 == 'FQDN' {{print $1}}; {{print $6}}' | grep {domain} > {output_dir}/Subdomains/amass_active_subdomains.txt",
        # f"amass enum -d {domain} | awk '$2 == 'FQDN' {{print $1}}; {{print $6}}' | grep {domain} > {output_dir}/Subdomains/amass_passive_subdomains.txt",
        # f"shuffledns -d {domain} -silent -r {output_dir}/Resolvers/resolvers.txt -w {output_dir}/Wordlists/subdomains.txt > {output_dir}/Subdomains/shufflends_subdomains.txt",
        # f"puredns bruteforce {output_dir}/Seclists/Discovery/DNS/subdomains-top1million-5000.txt {domain} -r {output_dir}/Resolvers/resolvers.txt -w {output_dir}/Subdomains/puredns_subdomains-5000.txt > /dev/null 2>&1",
        # f"puredns bruteforce {output_dir}/Seclists/Discovery/DNS/subdomains-top1million-20000.txt {domain} -r {output_dir}/Resolvers/resolvers.txt -w {output_dir}/Subdomains/puredns_subdomains-20000.txt > /dev/null 2>&1",
        # f"puredns bruteforce {output_dir}/Seclists/Discovery/DNS/subdomains-top1million-110000.txt {domain} -r {output_dir}/Resolvers/resolvers.txt -w {output_dir}/Subdomains/puredns_subdomains-110000.txt > /dev/null 2>&1",
        # f"puredns bruteforce {output_dir}/Wordlists/n0kovo_subdomains/n0kovo_subdomains_tiny.txt {domain} -r {output_dir}/Resolvers/resolvers.txt -w {output_dir}/Subdomains/puredns_subdomains-tiny.txt > /dev/null 2>&1",
        # f"puredns bruteforce {output_dir}/Wordlists/n0kovo_subdomains/n0kovo_subdomains_small.txt {domain} -r {output_dir}/Resolvers/resolvers.txt -w {output_dir}/Subdomains/puredns_subdomains-small.txt > /dev/null 2>&1",
        # f"puredns bruteforce {output_dir}/Wordlists/n0kovo_subdomains/n0kovo_subdomains_large.txt {domain} -r {output_dir}/Resolvers/resolvers.txt -w {output_dir}/Subdomains/puredns_subdomains-large.txt > /dev/null 2>&1",
        # f"puredns bruteforce {output_dir}/Wordlists/n0kovo_subdomains/n0kovo_subdomains_huge.txt {domain} -r {output_dir}/Resolvers/resolvers.txt -w {output_dir}/Subdomains/puredns_subdomains-huge.txt > /dev/null 2>&1"
    ]

    threads = [run_command_thread(command) for command in commands]

    for thread in threads:
        thread.join()

#remove duplicates from url
def duplicut(input_dir):
    unique_entries = set()
    output_file = os.path.join(output_dir,"Subdomains","merged_subdomains.txt")
    for input_file in os.listdir(input_dir):
        if input_file.endswith(".txt"):
            file_path = os.path.join(input_dir, input_file)
            with open(file_path, 'r') as file:
                for line in file:
                    unique_entries.add(line.strip())
    with open(output_file, 'w') as file:
        for entry in sorted(unique_entries):
            file.write(entry + '\n')
    print(f"{cyan}[*] Removed Duplicates from '{file_path}'{reset}")

def update_subdomains():
    print(f"{yellow}[*] Finding Active subdomains {reset}")

    if os.path.exists(file0) and os.path.getsize(file0) > 0:
        run_command(f"httpx -l {file0} -status-code --no-color -o {file2}")
    else:
        print(f"{red}[!] {file0} does not exist or is empty{reset}")
        return

    #returning only domains to modified_subdomains.txt
    run_command(rf"sed -e 's/^http:\/\///' -e 's/^https:\/\///' {file2} | awk '{{print $1}}' > {file3}")

    if os.path.getsize(file3) == 0:
        print(f"{green}[*] No active subdomains found.{reset}")
        alternative_process()
        exit(0)
    
    def find_ip_addresses():
        run_command(f"dnsx -silent -l {file3} -resp --no-color -a -o {file4}")

    def find_cdn_details():
        run_command(f"cdncheck -i {file3} -resp --no-color -o {file6}")

    def find_ssl_details():
        run_command(f"sslscan --targets={file3} --no-cipher-details --no-ciphersuites --no-compression --no-fallback --no-groups --no-heartbleed --no-renegotiation --no-check-certificate --no-colour > {file8}")

    ip_thread = threading.Thread(target=find_ip_addresses)
    cdn_thread = threading.Thread(target=find_cdn_details)
    ssl_thread = threading.Thread(target=find_ssl_details)

    ip_thread.start()
    cdn_thread.start()
    ssl_thread.start()

    print(f"{yellow}[*] Finding IP Addresses {reset}")
    ip_thread.join()
    print(f"{yellow}[*] Finding CDN Details {reset}")
    cdn_thread.join()
    print(f"{yellow}[*] Finding SSL Details {reset}")
    ssl_thread.join()

# Add a case for empty files here
    run_command(rf"grep -o '[0-9]\{{1,3\}}\.[0-9]\{{1,3\}}\.[0-9]\{{1,3\}}\.[0-9]\{{1,3\}}' {file4} > {file5}")
    run_command(rf"sed -e 's/\\x1B\\[[0-9;]*[JKmsu]//g' -e 's/\\(.*\\) \\[\\(.*\\)\\]/\\1 \\2/' {file6} | awk '{{print $1, $3}}' > {file7}")
    #This command is not cleaning the ssl_out.txt      --Need Fix
    run_command(rf"sed -e 's/\\x1B\\[[0-9;]*[JKmsu]//g' {file8} > {file9}")

    output_ssl = ""
    with open(file9, "r") as ssl_file:
        for line in ssl_file:
            if "Testing SSL server" in line:
                domain = line.split()[3]
                output_ssl += domain
            elif "SSLv2" in line:
                ssl_status_2 = line.split()[1]
                output_ssl += f" {ssl_status_2}"
            elif "SSLv3" in line:
                ssl_status_3 = line.split()[1]
                output_ssl += f" {ssl_status_3}"
            elif "TLSv1.0" in line:
                tls_status_1 = line.split()[1]
                output_ssl += f" {tls_status_1}"
            elif "TLSv1.1" in line:
                tls_status_2 = line.split()[1]
                output_ssl += f" {tls_status_2}"
            elif "TLSv1.2" in line:
                tls_status_3 = line.split()[1]
                output_ssl += f" {tls_status_3}"
            elif "TLSv1.3" in line:
                tls_status_4 = line.split()[1]
                output_ssl += f" {tls_status_4}\n"

    with open(file10, "w") as ssl_output_file:
        ssl_output_file.write(output_ssl)

    print(f"{yellow}[*] Finding Certificate Details {reset}")
    with open(file3, "r") as subdomains_file:
        for domain in subdomains_file:
            if domain.strip():
                run_command(f"certcheck -u '{domain.strip()}' >> {file11}")

    run_command(f"jq -r 'to_entries[] | \"\\(.key) \\\"\\(.value.issued_date)\\\" \\\"\\(.value.expiration_date)\\\" \\(.value.valid)\"' {file11} > {file12}")

    if not os.path.exists(output_sheet1_csv):
        with open(output_sheet1_csv, "w") as csv_file:
            csv_file.write("Domain,Status Code,IP Address,CDN,SSLv2,SSLv3,TLSv1.0,TLSv1.1,TLSv1.2,TLSv1.3,Crt Issue Date,Crt Expiration Date,Valid Status\n")

# Code is fine till here
# Examine each of the grep commands to find why its not able to catch status code.  --Need Fix
    with open(file3, "r") as subdomains_file, open(output_sheet1_csv, "a") as csv_file:
        for domain in subdomains_file:
            domain = domain.strip()
            if domain:
                status_code = subprocess.run(f"grep -E '^{domain} ' {file2} | awk '{{print $2}}'", shell=True, capture_output=True, text=True).stdout.strip()
                ips = subprocess.run(f"grep -E '{domain} \\[.*\\]' {file4} | awk -F'[][]' '{{print $2}}'", shell=True, capture_output=True, text=True).stdout.strip()
                cdn = subprocess.run(f"grep -E '^{domain} ' {file7} | awk '{{print $2}}'", shell=True, capture_output=True, text=True).stdout.strip()
                ssl_2 = subprocess.run(f"grep -E '^{domain} ' {file10} | awk '{{print $2}}'", shell=True, capture_output=True, text=True).stdout.strip()
                ssl_3 = subprocess.run(f"grep -E '^{domain} ' {file10} | awk '{{print $3}}'", shell=True, capture_output=True, text=True).stdout.strip()
                tls_1 = subprocess.run(f"grep -E '^{domain} ' {file10} | awk '{{print $4}}'", shell=True, capture_output=True, text=True).stdout.strip()
                tls_2 = subprocess.run(f"grep -E '^{domain} ' {file10} | awk '{{print $5}}'", shell=True, capture_output=True, text=True).stdout.strip()
                tls_3 = subprocess.run(f"grep -E '^{domain} ' {file10} | awk '{{print $6}}'", shell=True, capture_output=True, text=True).stdout.strip()
                tls_4 = subprocess.run(f"grep -E '^{domain} ' {file10} | awk '{{print $7}}'", shell=True, capture_output=True, text=True).stdout.strip()
                
                crt_info = get_certificate_info(domain)
                crt_1 = crt_info["issued_date"]
                crt_2 = crt_info["expiration_date"]
                crt_3 = crt_info["valid"]
                
                if status_code:
                    if ips:
                        formatted_ips = ips.replace(" ", "\n")
                        csv_file.write(f"\"{domain}\",\"{status_code}\",\"{formatted_ips}\",\"{cdn}\",\"{ssl_2}\",\"{ssl_3}\",\"{tls_1}\",\"{tls_2}\",\"{tls_3}\",\"{tls_4}\",\"{crt_1}\",\"{crt_2}\",\"{crt_3}\"\n")
                else:
                    print(f"IPs not found for domain: {domain}")
            else:
                print(f"Status code not found for domain: {domain}")
                
    print(f"{yellow}[*] Extracting Inactive subdomains {reset}")
    run_command(f"comm -23 <(sort {file1}) <(sort {file3}) > {file13}")

    with open(output_sheet2_csv, "w") as csv_file:
        csv_file.write("Inactive Subdomains\n")
        with open(file13, "r") as inactive_file:
            for line in inactive_file:
                csv_file.write(f"\"{line.strip()}\"\n")

    print(f"{green}[*] Script execution completed. {reset}")
    print(f"{green}[*] Output written to {output_sheet1_csv} and {output_sheet2_csv} {reset}")


# Function to extract certificate data from certcheck_final.txt
def get_certificate_info(domain):
    crt_info = {"issued_date": "", "expiration_date": "", "valid": ""}
    
    crt_line = subprocess.run(f"grep -E '^{domain} ' {file12} | awk -F'\"' '{{print $2, $4, $5}}'", shell=True, capture_output=True, text=True).stdout.strip()
    
    if crt_line:
        parts = crt_line.split()
        if len(parts) >= 5:
            crt_info["issued_date"] = parts[0] + " " + parts[1]  # Date and Time for issued date
            crt_info["expiration_date"] = parts[2] + " " + parts[3]  # Expiration date with possible time
            crt_info["valid"] = parts[4]  # Valid status

    return crt_info

def find_urls_using_katana():
    with open(output_sheet3_csv, "w") as csv_file:
        csv_file.write("URLs\n")
        print(f"{cyan}[*] Finding URLs for domain: {domain} {reset} find_urls_using_katana")
        katana_thread = run_command_thread(f"katana -u https://{domain} -nc -silent -o {file14}")
        wayback_thread = run_command_thread(f"waybackurls {domain} > {file15}")
        katana_thread.join()
        wayback_thread.join()
        with open(file14, "r") as katana_file, open(file15, "r") as wayback_file:
            csv_file.write(katana_file.read())
            csv_file.write(wayback_file.read())

def find_parameters_using_paramspider():
    print(f"{cyan}[*] Finding URLs for domain: {domain} {reset} find_parameters_using_paramspider")
    paramspider_thread = run_command_thread(f"paramspider -d {domain} >> {output_sheet4_csv}")
    paramspider_thread.join()

def vulnerability_scan_using_nuclei():
    print(f"{cyan}[*] Finding URLs for domain: {domain} {reset} vulnerability_scan_using_nuclei")
    nuclei_thread = run_command_thread(f"nuclei -u https://{domain} -o {output_sheet5_csv}")
    nuclei_thread.join()

def alternative_process():
    print(f"{yellow}[*] Proceeding to find URLs using Katana/waybackurls.{reset}")
    katana_thread = threading.Thread(target=find_urls_using_katana)
    paramspider_thread = threading.Thread(target=find_parameters_using_paramspider)
    nuclei_thread = threading.Thread(target=vulnerability_scan_using_nuclei)

    katana_thread.start()
    paramspider_thread.start()
    nuclei_thread.start()

    katana_thread.join()
    paramspider_thread.join()
    nuclei_thread.join()

def send_notification_to_google_chat(message):
    """Send notification to Google Chat."""
    webhook_url = "https://chat.googleapis.com/v1/spaces/AAAAWTWD8vk/messages?key=AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI&token=gbjM3lTFrRLPrTgvhm5LkZ_CB8sGrACSiYPhM6To6iY"
    headers = {"Content-Type": "application/json; charset=UTF-8"}
    data = json.dumps({"text": message})
    try:
        response = requests.post(webhook_url, headers=headers, data=data)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"{red}[!] Failed to send notification: {e}{reset}")

# Write the CSV header if it does not exist
def write_csv_header():
    if not os.path.exists(output_sheet1_csv):
        with open(output_sheet1_csv, "w", newline="") as csv_file:
            csv_writer = csv.writer(csv_file)
            csv_writer.writerow([
                "Domain", "Status Code", "IP Address", "CDN", "SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"
            ])

def write_to_csv():

    write_csv_header()

    with open(file3, "r") as subdomains_file, open(output_sheet1_csv, "a", newline="") as csv_file:
        csv_writer = csv.writer(csv_file)
        
        for domain in subdomains_file:
            domain = domain.strip()
            if domain:
                status_code = subprocess.run(f"grep -E 'http://{domain} ' {file2} | awk -F'[][]' '{{print $2}}'", shell=True, capture_output=True, text=True).stdout.strip()
                ips = subprocess.run(f"grep -E '^{domain} ' {file4} | awk '{{print $3}}'", shell=True, capture_output=True, text=True).stdout.strip()
                cdn = subprocess.run(f"grep -E '^{domain} ' {file7} | awk '{{print $2}}'", shell=True, capture_output=True, text=True).stdout.strip()
                ssl_2 = subprocess.run(f"grep -E '^{domain} ' {file10} | awk '{{print $2}}'", shell=True, capture_output=True, text=True).stdout.strip()
                ssl_3 = subprocess.run(f"grep -E '^{domain} ' {file10} | awk '{{print $3}}'", shell=True, capture_output=True, text=True).stdout.strip()
                tls_1 = subprocess.run(f"grep -E '^{domain} ' {file10} | awk '{{print $4}}'", shell=True, capture_output=True, text=True).stdout.strip()
                tls_2 = subprocess.run(f"grep -E '^{domain} ' {file10} | awk '{{print $5}}'", shell=True, capture_output=True, text=True).stdout.strip()
                tls_3 = subprocess.run(f"grep -E '^{domain} ' {file10} | awk '{{print $6}}'", shell=True, capture_output=True, text=True).stdout.strip()
                tls_4 = subprocess.run(f"grep -E '^{domain} ' {file10} | awk '{{print $7}}'", shell=True, capture_output=True, text=True).stdout.strip()

                # CRT
                crt_info = get_certificate_info(domain)
                crt_1 = crt_info["issued_date"]
                crt_2 = crt_info["expiration_date"]
                crt_3 = crt_info["valid"]

                # Clean the output before writing to CSV
                status_code = status_code.strip()
                ips = ips.strip().replace('\n', ', ')
                cdn = cdn.strip()
                ssl_2 = ssl_2.strip()
                ssl_3 = ssl_3.strip()
                tls_1 = tls_1.strip()
                tls_2 = tls_2.strip()
                tls_3 = tls_3.strip()
                tls_4 = tls_4.strip()

                # Print the extracted data for debugging
                # print(f"Domain: {domain}, Status Code: {status_code}, IP: {ips}, CDN: {cdn}, SSLv2: {ssl_2}, SSLv3: {ssl_3}, TLSv1.0: {tls_1}, TLSv1.1: {tls_2}, TLSv1.2: {tls_3}, TLSv1.3: {tls_4}")

                # Write the domain and extracted information to the CSV file
                csv_writer.writerow([
                    domain, status_code, ips, cdn, ssl_2, ssl_3, tls_1, tls_2, tls_3, tls_4,crt_1,crt_2,crt_3
                ])

    print(f"{green}[*] Data written to '{output_sheet1_csv}'{reset}")

def run_recon():
    """Main recon function."""
    try:
        print(f"{yellow}[*] Starting reconnaissance...{reset}")
        
        # Import all your existing recon functions here
        check_required_tools()
        enumerate_subdomains(domain, output_dir)
        duplicut(f"{output_dir}/Subdomains")
        update_subdomains()
        write_to_csv()
        alternative_process()
        send_notification_to_google_chat("FINISHEDDDDDDD by anuj")
        
        print(f"{green}[+] Reconnaissance completed successfully{reset}")
        
    except Exception as e:
        print(f"{red}[!] Error during reconnaissance: {e}{reset}")
        send_notification_to_google_chat(f"Error during reconnaissance: {str(e)}")
        return False
    
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HRC Recon Script")
    parser.add_argument("-d", "--domain", help="Target domain", default="highradius.com")
    args = parser.parse_args()
    
    run_recon()
