#!/bin/bash

##################################################
# Author: ckalnarayan
# Script: subdomain-enumeration.sh
# Description: A Bash script to enumerate subdomains using various enumeration tools.
##################################################

# Set up color codes for output
reset="\033[0m"
yellow="\033[1;33m"
green="\033[0;32m"
cyan="\033[0;36m"
red="\033[0;31m"

    figlet "HRC Automation"

# Function to print usage information
print_usage() {
    echo "Usage: $0 [-d domain] [-l subdomains_file]"
    echo "Options:"
    echo "  -d domain             Specify the domain to enumerate subdomains (default: highradius.com)"
    echo "  -l subdomains_file    Specify a file containing a list of subdomains"
    echo "  -h                    Display this help message"
    exit 1
}

#Tokens 
#statically allocated tokens/variables should be changed according to the user's private tokens
# gitT : github access token
gitT=""
# gitL : gitlab access token
gitL=""
# virustotal scan API Key
knockpyvirusapi=""

# Define file names for various outputs
output_dir="Automation-script-output"
mkdir -p "$output_dir"
mkdir -p "$output_dir/Subdomains"
mkdir -p "$output_dir/Cloudsnidomains"
mkdir -p "$output_dir/Resolvers"
mkdir -p "$output_dir/Wordlists"
sni_domains="$output_dir/Cloudsnidomains/sni_domains.txt"
file0="$output_dir/Subdomains/all_subdomains.txt"
file1="$output_dir/final_subdomains.txt"
file2="$output_dir/httpx_output_live_with_status_code.txt"
file3="$output_dir/modified_subdomains.txt"
file4="$output_dir/dnsx_ip_address.txt"
file5="$output_dir/ip_address.txt"
file6="$output_dir/cdncheck_output.txt"
file7="$output_dir/cdncheck_sanitize.txt"
file8="$output_dir/ssl_out.txt"
file9="$output_dir/ssl_out_sanitize.txt"
file10="$output_dir/ssl_final.txt"
file11="$output_dir/certcheck_combined_output.txt"
file12="$output_dir/certcheck_final.txt"
file13="$output_dir/inactive_subdomains.txt"
file14="$output_dir/katana_output.txt"
file15="$output_dir/waybackurls_output.txt"
inactive_old="$output_dir/inactive_subdomains_old.txt"
output_sheet1_csv="$output_dir/output_sheet1.csv"
output_sheet2_csv="$output_dir/output_sheet2.csv"
output_sheet3_csv="$output_dir/output_sheet3.csv"
output_sheet4_csv="$output_dir/output_sheet4.csv"
output_sheet5_csv="$output_dir/output_sheet5.csv"

# Initialize domain variable
domain="highradius.com"
subdomains_file=""

# check if required tools are installed
required_tools=("assetfinder" "subfinder" "waybackurls" "findomain" "sublister" "amass" "gau" "curl" "jq" "duplicut" "httpx" "dnsx" "cdncheck" "sslscan" "certcheck" "katana" "nuclei")
for tool in "${required_tools[@]}"; do
    if ! command -v "$tool" > /dev/null 2>&1; then
        echo -e "${red}[!] Error: $tool is not installed. Please install it before running the script.${reset}"
        exit 1
    fi
done

#First implement amass & subfinder config && Wordlist
#if [ ! -f $HOME/.config/subfinder/provider-config.yaml ]
#then
    #echo "${BLINK}${RED}Error: Subfinder provider-config.yaml files not found${RESET}"
    #exit 1
#elif [ ! -f $HOME/.config/amass/config.yaml ] || [ ! -f $HOME/.config/amass/datasources.yaml ]
#then
    #echo "${BLINK}${RED}Error: Amass config.yaml and datasources.yaml files not found${RESET}"
    #exit 1
#elif [ ! -f $HOME/.config/notify/provider-config.yaml ]
#then
    #echo "${BLINK}${RED}Error: Notify provider-config.yaml files not found${RESET}"
    #exit 1
#fi

resolver_download(){
    # Set the URL of the file to download
    echo -e "${yellow}[*] Downloading resolvers files${reset}"
    resolverurl="https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
    cd $output_dir/Resolvers
    wget $resolverurl -q -P "$output_dir/Resolvers" -O resolvers.txt -N
    cd ../../
    echo -e "${cyan}Resolvers OK${reset}"
    if [ $? -ne 0 ] ## checks whether the wget is done successfully or not!
    then
        echo -e "${red}wget '${resolverurl}' failed !!! \nSet manually please${reset}"
        exit 1
    fi
}
#resolver_download

wordlists_download(){
    # Set the URL of the file to download
    echo -e "${yellow}[*] Downloading wordlists files${reset}"
    wordlistsurl="https://raw.githubusercontent.com/trickest/wordlists/main/inventory/subdomains.txt"
    cd "$output_dir/Wordlists"
    wget $wordlistsurl -q -P "$output_dir/Wordlists" -N -O subdomains.txt
    cd ../../
    echo -e "${cyan}Wordlist Ok${reset}"
    if [ $? -ne 0 ] ## checks whether the wget is done successfully or not!
    then
        echo "${red}wget '${wordlistsurl}' failed !!!${reset}"
        exit 1
    fi    

}
#wordlists_download

n0kovo_subdomains_wordlists_download(){
    # Set the URL of the file to download
    echo -e "${yellow}[*] Downloading seclists files${reset}"
    wordlistsurl="https://github.com/n0kovo/n0kovo_subdomains/archive/refs/heads/main.zip" 
    cd "$output_dir/Wordlists"
    wget -c $wordlistsurl 
    unzip main.zip 
    mv n0kovo_subdomains-main n0kovo_subdomains
    rm -rf main.zip
    cd ../../
    echo -e "${cyan}Wordlists Ok${reset}"
    if [ $? -ne 0 ] ## checks whether the wget is done successfully or not!
    then
        echo "${red}wget '${wordlistsurl}' failed !!!${reset}"
        exit 1
    fi    

}
#n0kovo_subdomains_wordlists_download

seclists_download(){
    # Set the URL of the file to download
    echo -e "${yellow}[*] Downloading seclists files${reset}"
    wordlistsurl="https://github.com/danielmiessler/SecLists/archive/master.zip"
    cd "$output_dir/"
    wget -c $wordlistsurl
    unzip master.zip
    mv SecLists-master Seclists
    rm -rf master.zip
    cd ../
    echo -e "${cyan}Seclists Ok${reset}"
    if [ $? -ne 0 ] ## checks whether the wget is done successfully or not!
    then
        echo "${red}wget '${wordlistsurl}' failed !!!${reset}"
        exit 1
    fi    

}
#seclists_download

#Function to Download Necessary files
downloading_necessary_files() {
    echo -e "${yellow}[*] Downloading Cloudsnidomains necessary files${reset}"

    echo -e "${yellow}[*] Downloading google ips sni files"
    wget "https://kaeferjaeger.gay/sni-ip-ranges/google/ipv4_merged_sni.txt" -q -N -O "$output_dir/Cloudsnidomains/google_ips.txt"
    #echo -e "${yellow}[*] Downloading amazon ips snifiles"
    #wget "https://kaeferjaeger.gay/sni-ip-ranges/amazon/ipv4_merged_sni.txt" -q -N -O "$output_dir/Cloudsnidomains/amazon_ips.txt" 
    #echo -e "${yellow}[*] Downloading digital ocean ips sni files"
    #wget "https://kaeferjaeger.gay/sni-ip-ranges/digitalocean/ipv4_merged_sni.txt" -q -N -O "$output_dir/Cloudsnidomains/digitalocean_ips.txt"
    #echo -e "${yellow}[*] Downloading microsoft ips sni files"
    #wget "https://kaeferjaeger.gay/sni-ip-ranges/microsoft/ipv4_merged_sni.txt" -q -N -O "$output_dir/Cloudsnidomains/microsoft_ips.txt"
    #echo -e "${yellow}[*] Downloading oracle ips sni files"
    #wget "https://kaeferjaeger.gay/sni-ip-ranges/oracle/ipv4_merged_sni.txt" -q -N -O "$output_dir/Cloudsnidomains/oracle_ips.txt"

    cat "$output_dir/Cloudsnidomains/google_ips.txt" "$output_dir/Cloudsnidomains/amazon_ips.txt" "$output_dir/Cloudsnidomains/digitalocean_ips.txt" "$output_dir/Cloudsnidomains/microsoft_ips.txt" "$output_dir/Cloudsnidomains/oracle_ips.txt" | grep "$(echo "$domain" | awk -F'.' '{print $1}')" | grep -oE '\[(.*?)\]' | sed 's/[][]//g' | sed 's/\s\+/\n/g' | grep -v '^*' | uniq >> "$sni_domains"
}
#downloading_necessary_files


        echo -e "${yellow}[*] Enumerating subdomains for domain: $domain ${reset}"   

#        curl -s "https://crt.sh/?q=%.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > "$output_dir/Subdomains/crtsh-1_subdomains.txt"
    
#        curl -s "http://web.archive.org/cdx/search/cdx?url=*.$domain&output=txt&fl=original&collapse=urlkey&page=" | grep -oE "https?://([^/]+)/?"  | awk -F/ '{print $3}' >> "$output_dir/Subdomains/wayback_machine_subdomains.txt" 2>/dev/null
        
#        curl -s "https://www.abuseipdb.com/whois/$domain" -H "user-agent: firefox" -b "abuseipdb_session=" | grep -E '<li>\w.*</li>' | sed -E 's/<\/?li>//g' | sed -e "s/$/.$domain/" >> "$output_dir/Subdomains/abuseipdb_subdomains.txt" 2>/dev/null

#        AssetFinder="assetfinder -subs-only $domain > $output_dir/Subdomains/assetfinder_subdomains.txt"

#        SubFinder="subfinder -d $domain -silent -all -o $output_dir/Subdomains/subfinder_subdomains.txt"

        #WaybackUrls="echo $domain | waybackurls | grep -oE \'\https?://([^/]+)/?\'\  | awk -F/ '{print $3}' >> $output_dir/Subdomains/waybackurls_subdomains.txt 2>/dev/null"

        #Findomain="findomain -t $domain -u $output_dir/Subdomains/findomain_subdomains.txt > /dev/null 2>&1"

        #Sublister="sublister -d $domain -o $output_dir/Subdomains/sublister_subdomains.txt > /dev/null 2>&1"

        #Gau="gau $domain | grep -oE '[a-zA-Z0-9.-]+\.$domain' >> $output_dir/Subdomains/gau_subdomains.txt 2>/dev/null"
        
        #Crtsh="crtsh -d $domain -r > $output_dir/Subdomains/crtsh-2_subdomains.txt"

        #GithubSubdomains="github-subdomains -d $domain -e -t $gitT | grep -oE 'b\w+\.highradius\.com\b' > $output_dir/Subdomains/github_subdomains.txt"

        #GithlabSubdomains="gitlab-subdomains -d $domain -e -t $gitL > $output_dir/Subdomains/gitlab_subdomains.txt"

        #As3nt="python3 /root/tools/as3nt/as3nt/core.py -t $domain -so -o $output_dir/Subdomains/as3nt_subdomains.txt > /dev/null 2>&1"

        #AmassActive="amass enum -d $domain -active -brute -w $output_dir/Wordlists/subdomains.txt | awk '$2 == '(FQDN)' {print $1}; {print $6}' | grep $domain > $output_dir/Subdomains/amass_active_subdomains.txt"

        #AmassPassive="amass enum -d $domain | awk '$2 == '(FQDN)' {print $1}; {print $6}' | grep $domain > $output_dir/Subdomains/amass_passive_subdomains.txt"

        #ShuffleDns="shuffledns -d $domain -r $output_dir/Resolvers/resolvers.txt -w $output_dir/Wordlists/subdomains.txt > $output_dir/Subdomains/shufflends_subdomains.txt"

        #Puredns="puredns bruteforce $output_dir/Seclists/Discovery/DNS/subdomains-top1million-5000.txt $domain -r $output_dir/Resolvers/resolvers.txt -w $output_dir/Subdomains/puredns_subdomains-5000.txt > /dev/null 2>&1"
        #Puredns="puredns bruteforce $output_dir/Seclists/Discovery/DNS/subdomains-top1million-20000.txt $domain -r $output_dir/Resolvers/resolvers.txt -w $output_dir/Subdomains/puredns_subdomains-20000.txt > /dev/null 2>&1"
        #Puredns="puredns bruteforce $output_dir/Seclists/Discovery/DNS/subdomains-top1million-110000.txt $domain -r $output_dir/Resolvers/resolvers.txt -w $output_dir/Subdomains/puredns_subdomains-110000.txt > /dev/null 2>&1"
        #Puredns="puredns bruteforce $output_dir/Wordlists/n0kovo_subdomains/n0kovo_subdomains_tiny.txt $domain -r $output_dir/Resolvers/resolvers.txt -w $output_dir/Subdomains/puredns_subdomains-tiny.txt > /dev/null 2>&1"
        #Puredns="puredns bruteforce $output_dir/Wordlists/n0kovo_subdomains/n0kovo_subdomains_small.txt $domain -r $output_dir/Resolvers/resolvers.txt -w $output_dir/Subdomains/puredns_subdomains-small.txt > /dev/null 2>&1"
        #Puredns="puredns bruteforce $output_dir/Wordlists/n0kovo_subdomains/n0kovo_subdomains_large.txt $domain -r $output_dir/Resolvers/resolvers.txt -w $output_dir/Subdomains/puredns_subdomains-large.txt > /dev/null 2>&1"
        #Puredns="puredns bruteforce $output_dir/Wordlists/n0kovo_subdomains/n0kovo_subdomains_huge.txt $domain -r $output_dir/Resolvers/resolvers.txt -w $output_dir/Subdomains/puredns_subdomains-huge.txt > /dev/null 2>&1"

# Function to execute commands in parallel using screen
execute_in_screen() {
    echo "Starting screen session: $1"
    screen -dmS "$1" bash -c "$2; exit"
    if [ $? -ne 0 ]; then
        echo "Failed to start screen session: $1"
        exit 1
    fi
}

# Function to wait for all screen sessions to complete
wait_for_screens() {
    echo "${RED}Waiting for processes to complete...${RESET}"
    while true; do 
        screencount=$(screen -ls | grep -oP '^\s*\K\d+(?=[.])' | wc -l)
        if [ "$screencount" -eq 0 ]; then
            break
        fi
        sleep 1
    done
    echo -e "${GREEN}Scan Completed${RESET}"
}
# Debugging function to check environment variables
check_env_vars() {
    echo "a_opt_bool: $a_opt_bool"
    echo "p_opt_bool: $p_opt_bool"
}

# Set environment variables for active or passive enumeration

a_opt_bool=true
p_opt_bool=true

# Check environment variables for debugging
check_env_vars

# Active and Passive Enumeration
if [ "$a_opt_bool" == "true" ]; then 
    echo -e "${BLUE}Enumerating Domains using Active & Passive resources${RESET}"

    # Execute each command in a separate screen session
    execute_in_screen "AssetFinder_S" "$AssetFinder"
    execute_in_screen "SubFinder_S" "$SubFinder"
    execute_in_screen "WaybackUrls_S" "$WaybackUrls"
    execute_in_screen "WebArchieve_S" "$WebArchieve"
    execute_in_screen "AbuseIpDB_S" "$AbuseIpDB"
    execute_in_screen "Findomain_S" "$Findomain"
    execute_in_screen "Sublister_S" "$Sublister"
    execute_in_screen "Gau_S" "$Gau"
    execute_in_screen "Crtsh_S" "$Crtsh"
    execute_in_screen "GithubSubdomains" "$GithubSubdomains"
    execute_in_screen "GithlabSubdomains" "$GithlabSubdomains"
    execute_in_screen "As3nt" "$As3nt"
    execute_in_screen "AmassActive" "$AmassActive"
    execute_in_screen "AmassPassive" "$AmassPassive"
    execute_in_screen "ShuffleDns" "$ShuffleDns"
    execute_in_screen "Puredns" "$Puredns"

    screen -ls
        wait_for_screens

elif [ "$p_opt_bool" == "true" ]; then
    echo -e "${BLUE}Enumerating Domains using Passive resources${RESET}"
  # Execute each command in a separate screen session

    execute_in_screen "AssetFinder_S" "$AssetFinder"
    execute_in_screen "SubFinder_S" "$SubFinder"
    execute_in_screen "WaybackUrls_S" "$WaybackUrls"
    execute_in_screen "WebArchieve_S" "$WebArchieve"
    execute_in_screen "AbuseIpDB_S" "$AbuseIpDB"
    execute_in_screen "Findomain_S" "$Findomain"
    execute_in_screen "Sublister_S" "$Sublister"
    execute_in_screen "Gau_S" "$Gau"
    execute_in_screen "Crtsh_S" "$Crtsh"
    execute_in_screen "GithubSubdomains" "$GithubSubdomains"
    execute_in_screen "GithlabSubdomains" "$GithlabSubdomains"
    execute_in_screen "As3nt" "$As3nt"
    execute_in_screen "AmassActive" "$AmassActive"
    execute_in_screen "AmassPassive" "$AmassPassive"
    execute_in_screen "ShuffleDns" "$ShuffleDns"
    execute_in_screen "Puredns" "$Puredns"

    screen -ls
    wait_for_screens

else
    echo "Neither a_opt_bool nor p_opt_bool is set to true. Exiting."
    exit 1
fi
    

    # Merge all results for each domain into a single file
    cat "$output_dir/Subdomains/amass_active_subdomains.txt" "$output_dir/Subdomains/amass_passive_subdomains.txt" "$output_dir/Subdomains/shufflends_subdomains.txt" "$output_dir/Subdomains/github_subdomains.txt" "$output_dir/Subdomains/github_subdomains.txt" "$output_dir/Subdomains/as3nt_subdomains.txt" "$output_dir/Subdomains/assetfinder_subdomains.txt" "$output_dir/Subdomains/subfinder_subdomains.txt" "$output_dir/Subdomains/waybackurls_subdomains.txt" "$output_dir/Subdomains/wayback_machine_subdomains.txt" "$output_dir/Subdomains/abuseipdb_subdomains.txt" "$output_dir/Subdomains/findomain_subdomains.txt" "$output_dir/Subdomains/sublister_subdomains.txt" "$output_dir/Subdomains/gau_subdomains.txt" "$output_dir/Subdomains/crtsh-1_subdomains.txt" "$output_dir/Subdomains/crtsh-2_subdomains.txt" "$output_dir/Subdomains/puredns_subdomains-5000.txt" "$output_dir/Subdomains/puredns_subdomains-20000.txt" "$output_dir/Subdomains/puredns_subdomains-110000.txt" "$output_dir/Subdomains/puredns_subdomains-tiny.txt" "$output_dir/Subdomains/puredns_subdomains-small.txt" "$output_dir/Subdomains/puredns_subdomains-medium.txt" "$output_dir/Subdomains/puredns_subdomains-large.txt" "$output_dir/Subdomains/puredns_subdomains-huge.txt" "$output_dir/Cloudsnidomains/sni_domains.txt" > "$file0"

    # Removing duplicates
    duplicut "$file0" -o "$file1"

    echo -e "${green}[*] Subdomain enumeration complete. Results saved in '$file0'${reset}"

# Function to run alternative process
alternative_process() {
    # Search for URLs using Katana/waybackurls
    echo -e "${yellow}[*] Proceeding to find URLs using Katana/waybackurls.${reset}"
    find_urls_using_katana

    # Search for Parameters using Paramspider
    echo -e "${yellow}[*] Proceeding to find parameters using paramspider"
    find_parameters_using_paramspider

    # Perform vulnerability scan using Nuclei
    echo -e "${yellow}[*] Proceeding to Vulnerability scan using nuclei.${reset}"
    vulnerability_scan_using_nuclei
}

# Function to update subdomains
update_subdomains() {
    # Finding Active subdomains
    echo -e "${yellow}[*] Finding Active subdomains ${reset}"
    httpx -l "$file1" -silent -status-code | sed -e 's/http[s]*:\/\///' -e 's/\(.*\) \[\(.*\)\]/\1 \2/' -e 's/\x1B\[[0-9;]*[JKmsu]//g' > "$file2" 
    sed -e 's/^http:\/\///' -e  's/^https:\/\///' "$file2" | awk '{print $1}' > "$file3" 

    # Check if there are no active subdomains
    if [ ! -s "$file3" ]; then
        echo -e "${green}[*] No active subdomains found.${reset}"
        # Run alternative process
        alternative_process
        exit 0
    fi

    # Finding IP Addresses
    echo -e "${yellow}[*] Finding IP Addresses ${reset}"
    dnsx -silent -l "$file3" -resp -a -o "$file4" > /dev/null 2>&1
    cat $file4 | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' > "$file5"

    # Finding Port details
    #echo -e "${yellow}[*] Finding Port of IP Addresses ${reset}"
    #naabu -l 1.txt -Pn -p - -o 2.txt
    
    # Finding CDN Details
    echo -e "${yellow}[*] Finding CDN Details ${reset}"
    cdncheck -i "$file3" -resp -o "$file6" > /dev/null 2>&1
    sed -e 's/\x1B\[[0-9;]*[JKmsu]//g' -e 's/\(.*\) \[\(.*\)\]/\1 \2/' "$file6" | awk '{print $1, $3}' > "$file7"

    # Finding SSL Details
    echo -e "${yellow}[*] Finding SSL Details ${reset}"
    sslscan --targets="$file3" --no-cipher-details --no-ciphersuites --no-compression --no-fallback --no-groups --no-heartbleed --no-renegotiation --no-check-certificate > "$file8" 
    sed -e 's/\x1B\[[0-9;]*[JKmsu]//g' "$file8" > "$file9" 

    # Parsing SSL details
    output_ssl=""
    while read -r line; do
        if [[ $line =~ "Testing SSL server" ]]; then
            domain=$(echo "$line" | grep -oP 'Testing SSL server \K[^ ]+')
            output_ssl+="$domain"
        elif [[ $line =~ "SSLv2" ]]; then
            ssl_status_2=$(echo "$line" | grep -oP 'SSLv2\s+\K\S+')
            output_ssl+=" $ssl_status_2"
        elif [[ $line =~ "SSLv3" ]]; then
            ssl_status_3=$(echo "$line" | grep -oP 'SSLv3\s+\K\S+')
            output_ssl+=" $ssl_status_3"
        elif [[ $line =~ "TLSv1.0" ]]; then
            tls_status_1=$(echo "$line" | grep -oP 'TLSv1.0\s+\K\S+')
            output_ssl+=" $tls_status_1"
        elif [[ $line =~ "TLSv1.1" ]]; then
            tls_status_2=$(echo "$line" | grep -oP 'TLSv1.1\s+\K\S+')
            output_ssl+=" $tls_status_2"
        elif [[ $line =~ "TLSv1.2" ]]; then
            tls_status_3=$(echo "$line" | grep -oP 'TLSv1.2\s+\K\S+')
            output_ssl+=" $tls_status_3"
        elif [[ $line =~ "TLSv1.3" ]]; then
            tls_status_4=$(echo "$line" | grep -oP 'TLSv1.3\s+\K\S+')
            output_ssl+=" $tls_status_4\n"
        fi
    done < "$file9"

    echo -e "$output_ssl" >> "$file10"

    # Finding Certificate Details
    echo -e "${yellow}[*] Finding Certificate Details ${reset}"
    while IFS= read -r domain; do
        if [ -z "$domain" ]; then
            continue
        fi

        certcheck -u "$domain" >> "$file11" 
    done < "$file3"

    # Check if jq is installed
    if ! command -v jq &> /dev/null; then
        echo "jq is not installed. Please install it before running this script."
        exit 1
    fi

    # Parsing certificate details
    jq -r 'to_entries[] | "\(.key) \"\(.value.issued_date)\" \"\(.value.expiration_date)\" \(.value.valid)"' "$file11" > "$file12"


    # Print header to CSV
    if [[ ! -e "$output_sheet1_csv" ]]; then
    echo -e "Domain,Status Code,IP Address,CDN,SSLv2,SSLv3,TLSv1.0,TLSv1.1,TLSv1.2,TLSv1.3,Crt Issue Date,Crt Expiration Date,Valid Status" > "$output_sheet1_csv"
fi
    
    # Writing active subdomains to CSV
while IFS= read -r domain; do
        status_code=$(grep -E "^${domain} " "$file2" | awk '{print $2}')
        ips=$(grep -E "${domain} \[.*\]" "$file4" | awk -F'[][]' '{print $2}')
        cdn=$(grep -E "^${domain} " "$file7" | awk '{print $2}')
        ssl_2=$(grep -E "^${domain} " "$file10" | awk '{print $2}')
        ssl_3=$(grep -E "^${domain} " "$file10" | awk '{print $3}')
        tls_1=$(grep -E "^${domain} " "$file10" | awk '{print $4}')
        tls_2=$(grep -E "^${domain} " "$file10" | awk '{print $5}')
        tls_3=$(grep -E "^${domain} " "$file10" | awk '{print $6}')
        tls_4=$(grep -E "^${domain} " "$file10" | awk '{print $7}')
        crt_1=$(grep -E "^${domain} " "$file12" | awk -F'"' '{print $2}')
        crt_2=$(grep -E "^${domain} " "$file12" | awk -F'"' '{print $4}')
        crt_3=$(grep -E "^${domain} " "$file12" | awk -F'"' '{print $5}')

        if [ -n "$status_code" ]; then
            if [ -n "$ips" ]; then
                # Format IPs with newline characters
                formatted_ips=$(echo "$ips" | tr ' ' '\n')
                # Replace spaces with commas and add the block of IPs and CDN to CSV
    echo -e "\"${domain}\",\"${status_code}\",\"${formatted_ips}\",\"${cdn}\",\"${ssl_2}\",\"${ssl_3}\",\"${tls_1}\",\"${tls_2}\",\"${tls_3}\",\"${tls_2}\",\"${crt_1}\",\"${crt_2}\",\"${crt_3}\"" >> "$output_sheet1_csv"
            else
                echo "IPs not found for domain: $domain"
            fi
        else
            echo "Status code not found for domain: $domain"
        fi
    done < "$file3"

    # Extracting Inactive subdomains
    echo -e "${yellow}[*] Extracting Inactive subdomains ${reset}"

    comm -23 <(sort "$file1") <(sort "$file3") > "$file13"

    # Print header to CSV for Sheet2
    echo -e "Inactive Subdomains" > "$output_sheet2_csv"

    # Read inactive subdomains and add them to the CSV for Sheet2
    awk '{print "\"" $1 "\""}' "$file13" > "$output_sheet2_csv"

    echo -e "${green}[*] Script execution completed.  ${reset}"
    echo -e "${green}[*] Output written to $output_sheet1_csv and $output_sheet2_csv  ${reset}"
}

# Function to find URLs using Katana
find_urls_using_katana/waybackurls() {
    echo -e "${yellow}[*] No active subdomains found. Proceeding to find URLs using Katana.${reset}"

    # Print header to CSV for Sheet3
    echo -e "URLs" > "$output_sheet3_csv"

    # Check if final_subdomains.txt exists
    if [ ! -f "$file1" ]; then
        echo -e "${red}[!] Error: final_subdomains.txt not found.${reset}"
        exit 1
    fi
    
    # Iterate over each domain in final_subdomains.txt and run katana
    while IFS= read -r domain; do
        if [ -n "$domain" ]; then
            echo -e "${cyan}[*] Finding URLs for domain: $domain ${reset}"
            katana -u "$domain" --silent > "$file14"

            waybackurls "$domain" > "$file15" 

            cat "$output_dir/katana_output.txt" "$output_dir/waybackurls_output.txt" >> "$output_sheet3_csv"
        fi
    done < "$file1" 
}


# Function to find parameters using paramspider
find_parameters_using_paramspider() {
    echo -e "${yellow}[*] Proceeding to find parameters using paramspider.${reset}"

    # Check if final_subdomains.txt exists
    if [ ! -f "$file1" ]; then
        echo -e "${red}[!] Error: final_subdomains.txt not found.${reset}"
        exit 1
    fi
    
    # Iterate over each domain in final_subdomains.txt and run katana
    while IFS= read -r domain; do
        if [ -n "$domain" ]; then
            echo -e "${cyan}[*] Finding URLs for domain: $domain ${reset}"
            paramspider -d "$domain" --silent >> "$output_sheet4_csv"
        fi
    done < "$file1" 
}
# Function to find URLs using nuclei
vulnerability_scan_using_nuclei() {
    echo -e "${yellow}[*] No active subdomains found. Proceeding to Vulnerability scan using nuclei.${reset}"

    # Check if final_subdomains.txt exists
    if [ ! -f "$file1" ]; then
        echo -e "${red}[!] Error: final_subdomains.txt not found.${reset}"
        exit 1
    fi
    
    # Iterate over each domain in final_subdomains.txt and run katana
    while IFS= read -r domain; do
        if [ -n "$domain" ]; then
            echo -e "${cyan}[*] Finding URLs for domain: $domain ${reset}"
            nuclei -u "https://$domain" --silent > "$output_sheet5_csv"
        fi
    done < "$file1" 
}

# Parse command-line options
while getopts ":d:l:h" opt; do
    case $opt in
        d)
            domain="$OPTARG"
            ;;
        l)
            subdomains_file="$OPTARG"
            ;;
        h)
            print_usage
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            print_usage
            ;;
    esac
done



# Call the update_subdomains function
update_subdomains

# Call the Alternative process function
alternative_process

# Call the find_urls_using_katana/waybackurls function
find_urls_using_katana/waybackurls

# Call the find_parameters_using_paramspider function
find_parameters_using_paramspider

# Call the vulnerability_scan_using_nuclei function
vulnerability_scan_using_nuclei

# Function to send notification to Google Chat
send_notification_to_google_chat() {
    local webhook_url="https://chat.googleapis.com/v1/spaces/AAAAWTWD8vk/messages?key=AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI&token=gbjM3lTFrRLPrTgvhm5LkZ_CB8sGrACSiYPhM6To6iY"
    local message="$1"
    curl -X POST -H "Content-Type: application/json; charset=UTF-8" -d "{\"text\": \"$message\"}" "$webhook_url" > /dev/null 2>&1
}

# Function to send notification on exit
send_notification_on_exit() {
    # Construct notification message
    notification_message=$(cat <<EOF
*CDN-Cert Recon Script Output*

Check the CSV sheets for detailed information:
1. ($output_sheet1_csv)
2. ($output_sheet2_csv)
3. ($output_sheet3_csv)
4. ($output_sheet4_csv)
5. ($output_sheet5_csv)


Please review the output and take necessary actions.
EOF
    )

    # Send notification to Google Chat
    send_notification_to_google_chat "$notification_message"
}

trap 'send_notification_on_exit' EXIT INT
send_notification_on_exit
# Trap Ctrl+C and exit signals to send notification before exiting
#trap 'send_notification_on_exit' EXIT

