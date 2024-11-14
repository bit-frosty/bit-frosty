#!/usr/bin/env python3
import os
import sys
import shutil
import subprocess
import zipfile
from recon_script import run_recon

# Define color codes for output
RESET = "\033[0m"
YELLOW = "\033[1;33m"
GREEN = "\033[0;32m"
CYAN = "\033[0;36m"
RED = "\033[0;31m"
BLUE = "\033[0;34m"
MAGENTA = "\033[0;35m"

# Define directories
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = "Automation-script-output"
TOOLS_DIR = "/usr/local/bin"

class ReconTools:
    def __init__(self):
        self.setup_directories()
        
    def setup_directories(self):
        """Create necessary directories if they don't exist"""
        directories = [
            OUTPUT_DIR,
            f"{OUTPUT_DIR}/Subdomains",
            f"{OUTPUT_DIR}/Cloudsnidomains",
            f"{OUTPUT_DIR}/Resolvers",
            f"{OUTPUT_DIR}/Wordlists"
        ]
        for directory in directories:
            os.makedirs(directory, exist_ok=True)

    def print_banner(self):
        """Print script banner"""
        banner = """
╭──────────────────────────────────────────────────────────────╮
│  █░█ █▀█ █▀▀   ▄▀█ █░█ ▀█▀ █▀█ █▀▄▀█ ▄▀▄ ▀█▀ █ █▀█ █▄░█      │
│  █▀█ █▀▄ █▄▄   █▀█ █▄█ ░█░ █▄█ █░▀░█ █▀█ ░█░ █ █▄█ █░▀█      │
│                                                              │
│                     Version 1.0                              │
│              Developed by Security Team                      │
╰──────────────────────────────────────────────────────────────╯
        """
        print(f"{CYAN}{banner}{RESET}")

    def print_menu(self):
        """Print main menu options"""
        menu = f"""
{BLUE}╭───── Main Menu ─────╮{RESET}
{YELLOW}1{RESET}. Update Script (git pull)
{YELLOW}2{RESET}. Install/Update Tools
{YELLOW}3{RESET}. Download Wordlists and Resolvers
{YELLOW}4{RESET}. Run Recon Script
{YELLOW}5{RESET}. Exit
{BLUE}╰────────────────────╯{RESET}

Choose an option: """
        return input(menu)

    def update_script(self):
        """Update the script using git pull"""
        try:
            print(f"{YELLOW}[*] Updating script...{RESET}")
            result = subprocess.run(["git", "pull"], check=True, capture_output=True, text=True)
            print(f"{GREEN}[+] Script updated successfully!{RESET}")
            print(result.stdout)
        except subprocess.CalledProcessError as e:
            print(f"{RED}[!] Error updating script: {e}{RESET}")
        except FileNotFoundError:
            print(f"{RED}[!] Git not found. Please install git first.{RESET}")

    def extract_tools(self):
        """Extract tools from zip files and install them"""
        try:
            print(f"{YELLOW}[*] Installing tools...{RESET}")
            
            # Check if zip files exist
            tool_zips = ["tools1.zip", "tools2.zip"]
            for zip_file in tool_zips:
                if not os.path.exists(zip_file):
                    print(f"{RED}[!] {zip_file} not found{RESET}")
                    continue
                
                print(f"{YELLOW}[*] Extracting {zip_file}...{RESET}")
                with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                    # Extract to temporary directory
                    temp_dir = f"temp_{zip_file.replace('.zip', '')}"
                    zip_ref.extractall(temp_dir)
                    
                    # Copy executable files to /usr/local/bin
                    for root, _, files in os.walk(temp_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            dest_path = os.path.join(TOOLS_DIR, file)
                            try:
                                subprocess.run(['sudo', 'cp', file_path, dest_path], check=True)
                                subprocess.run(['sudo', 'chmod', '755', dest_path], check=True)
                                print(f"{GREEN}[+] Installed: {file}{RESET}")
                            except subprocess.CalledProcessError as e:
                                raise e
                            
                    # Clean up temporary directory
                    shutil.rmtree(temp_dir)

            print(f"{YELLOW}[*] Installing dependencies from requirements.txt...{RESET}")
            subprocess.run(["pip3", "install", "-r", "requirements.txt"], check=True)
            print(f"{GREEN}[+] Dependencies installed successfully{RESET}")

            # Install Sublist3r
            try:
                print(f"{YELLOW}[*] Installing Sublist3r...{RESET}")
                subprocess.run(["git", "clone", "https://github.com/aboul3la/Sublist3r.git"], check=True)
                os.chdir("Sublist3r")
                subprocess.run(["pip", "install", "."], check=True)
                os.chdir("..")
                shutil.rmtree("Sublist3r")
                print(f"{GREEN}[+] Sublist3r installed successfully{RESET}")
            except subprocess.CalledProcessError as e:
                raise e
            except Exception as e:
                print(f"{RED}[!] Unexpected error during Sublist3r installation: {e}{RESET}")

            # Install CertCheck
            try:
                print(f"{YELLOW}[*] Installing CertCheck...{RESET}")
                subprocess.run(["git", "clone", "https://github.com/h4r5h1t/CertCheck.git"], check=True)
                os.chdir("CertCheck")
                subprocess.run(["pip", "install", "."], check=True)
                os.chdir("..")
                shutil.rmtree("CertCheck")
                print(f"{GREEN}[+] CertCheck installed successfully{RESET}")
            except subprocess.CalledProcessError as e:
                raise e
            except Exception as e:
                print(f"{RED}[!] Unexpected error during CertCheck installation: {e}{RESET}")

            # Install paramspider
            try:
                print(f"{YELLOW}[*] Installing paramspider...{RESET}")
                subprocess.run(["git", "clone", "https://github.com/devanshbatham/paramspider"], check=True)
                os.chdir("paramspider")
                subprocess.run(["pip", "install", "."], check=True)
                os.chdir("..")
                shutil.rmtree("paramspider")
                print(f"{GREEN}[+] paramspider installed successfully{RESET}")
            except subprocess.CalledProcessError as e:
                raise e
            except Exception as e:
                print(f"{RED}[!] Unexpected error during paramspider installation: {e}{RESET}")

            print(f"{GREEN}[+] Tools installation completed{RESET}")
        except Exception as e:
            print(f"{RED}[!] Error installing tools: {e}{RESET}")

    def download_resources(self):
        """Download wordlists, resolvers, and additional resources"""
        try:
            print(f"{YELLOW}[*] Downloading resources...{RESET}")

            # Download resolvers
            resolver_url = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
            resolver_path = f"{OUTPUT_DIR}/Resolvers/resolvers.txt"
            print(f"{YELLOW}[*] Downloading resolvers...{RESET}")
            subprocess.run(["wget", resolver_url, "-q", "-O", resolver_path], check=True)

            # Download basic wordlist
            wordlist_url = "https://raw.githubusercontent.com/trickest/wordlists/main/inventory/subdomains.txt"
            wordlist_path = f"{OUTPUT_DIR}/Wordlists/subdomains.txt"
            print(f"{YELLOW}[*] Downloading wordlist...{RESET}")
            subprocess.run(["wget", wordlist_url, "-q", "-O", wordlist_path], check=True)

            # Download n0kovo_subdomains wordlists
            n0kovo_url = "https://github.com/n0kovo/n0kovo_subdomains/archive/refs/heads/main.zip"
            n0kovo_zip_path = f"{OUTPUT_DIR}/Wordlists/n0kovo_main.zip"
            n0kovo_dir = f"{OUTPUT_DIR}/Wordlists/n0kovo_subdomains"
            print(f"{YELLOW}[*] Downloading n0kovo_subdomains wordlists...{RESET}")
            subprocess.run(["wget", "-c", n0kovo_url, "-q", "-O", n0kovo_zip_path], check=True)

            # Extract n0kovo_subdomains
            with zipfile.ZipFile(n0kovo_zip_path, 'r') as zip_ref:
                zip_ref.extractall(f"{OUTPUT_DIR}/Wordlists")
            os.rename(f"{OUTPUT_DIR}/Wordlists/n0kovo_subdomains-main", n0kovo_dir)
            os.remove(n0kovo_zip_path)
            print(f"{CYAN}n0kovo_subdomains wordlists downloaded and extracted successfully{RESET}")

            # Download SecLists
            seclists_url = "https://github.com/danielmiessler/SecLists/archive/master.zip"
            seclists_zip_path = f"{OUTPUT_DIR}/Seclists.zip"
            seclists_dir = f"{OUTPUT_DIR}/Seclists"
            print(f"{YELLOW}[*] Downloading SecLists...{RESET}")
            subprocess.run(["wget", "-c", seclists_url, "-q", "-O", seclists_zip_path], check=True)

            # Extract SecLists
            with zipfile.ZipFile(seclists_zip_path, 'r') as zip_ref:
                zip_ref.extractall(OUTPUT_DIR)
            os.rename(f"{OUTPUT_DIR}/SecLists-master", seclists_dir)
            os.remove(seclists_zip_path)
            print(f"{CYAN}SecLists downloaded and extracted successfully{RESET}")

            print(f"{GREEN}[+] All resources downloaded successfully{RESET}")

        except subprocess.CalledProcessError as e:
            print(f"{RED}[!] Error downloading resources: {e}{RESET}")
        except Exception as e:
            print(f"{RED}[!] Unexpected error: {e}{RESET}")


def main():
    tools = ReconTools()
    tools.print_banner()
    
    while True:
        choice = tools.print_menu()
        
        if choice == "1":
            tools.update_script()
        elif choice == "2":
            tools.extract_tools()
        elif choice == "3":
            tools.download_resources()
        elif choice == "4":
            run_recon()  # This calls the recon script from the imported module
        elif choice == "5":
            print(f"{GREEN}[*] Exiting...{RESET}")
            sys.exit(0)
        else:
            print(f"{RED}[!] Invalid option. Please try again.{RESET}")
        
        input(f"\n{YELLOW}Press Enter to continue...{RESET}")

if __name__ == "__main__":
    main()