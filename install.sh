#!/bin/bash

# Define color codes
YELLOW='\033[1;33m'
RED='\033[1;31m'
GREEN='\033[1;32m'
NC='\033[0m' # No Color

# Create Tools folder in /dev/shm
tools_folder="/opt/Tools"
mkdir -p "$tools_folder"

# Function to get distribution information
get_distribution_info() {
    if [ -r /etc/os-release ]; then
        source /etc/os-release
        if [ -n "$PRETTY_NAME" ]; then
            echo "$PRETTY_NAME"
        else
            echo "$ID"
        fi	
    else
        echo "Unknown Distribution"
    fi
}

# Function to get architecture information
get_arch_info() {
    uname -m
}

# Get distribution and architecture information
distro_info=$(get_distribution_info)
arch_info=$(get_arch_info)

# Print distribution and architecture information
echo -e "${YELLOW}Distribution:${NC} $distro_info"
echo -e "${YELLOW}Architecture:${NC} $arch_info"

arc=$(uname -a | cut -d " " -f 3 | cut -d "-" -f 3)

# Check if the architecture is "generic" and set arc to "amd64"
if [ "$arc" == "generic" ]; then
    arc="amd64"
fi

install_package() {
    package=$1
    if command -v "$package" &>/dev/null; then
        echo -e "${YELLOW}$package is already installed.${NC}"
    else
        # Detect package manager
        if command -v apt-get &>/dev/null; then
            echo -e "${YELLOW}Installing $package...${NC}"
            sudo apt-get update
            sudo apt-get install -y "$package"
        elif command -v yum &>/dev/null; then
            echo -e "${YELLOW}Installing $package...${NC}"
            sudo yum install -y "$package"
        elif command -v dnf &>/dev/null; then
            echo -e "${YELLOW}Installing $package...${NC}"
            sudo dnf install -y "$package"
        elif command -v zypper &>/dev/null; then
            echo -e "${YELLOW}Installing $package...${NC}"
            sudo zypper install -y "$package"
        else
            echo -e "${RED}Unsupported package manager. Please install $package manually.${NC}"
            exit 1
        fi
    fi
}

install_binary() {
    url=$1
    binary_name=$2
    version=$3
    file_extension=$4
    archive_name="${binary_name}_${version}_linux_$arc.$file_extension"

    echo -e "${YELLOW}Downloading and installing $binary_name $version...${NC}"
    wget "$url" -O "$tools_folder/$archive_name"
    unzip "$tools_folder/$archive_name" -d "$tools_folder" || tar -xvf "$tools_folder/$archive_name" -C "$tools_folder"
    
    # Make the binary executable
    chmod +x "$tools_folder/$binary_name"
    
    sudo mv "$tools_folder/$binary_name" /usr/local/bin/
    rm "$tools_folder/$archive_name"
    echo -e "${GREEN}$binary_name $version installed.${NC}"
}

# List of packages to install
packages=("git" "zip" "python3" "python3-pip" "sslscan" "tar" "jq" "go" "golang-go")

# Install each package
for package in "${packages[@]}"; do
    install_package "$package"
done

# Install binaries into /dev/shm/Tools
install_binary "https://github.com/projectdiscovery/dnsx/releases/download/v1.1.6/dnsx_1.1.6_linux_$arc.zip" "dnsx" "1.1.6" "zip"
install_binary "https://github.com/projectdiscovery/cdncheck/releases/download/v1.0.9/cdncheck_1.0.9_linux_$arc.zip" "cdncheck" "1.0.9" "zip"
install_binary "https://github.com/projectdiscovery/httpx/releases/download/v1.3.7/httpx_1.3.7_linux_$arc.zip" "httpx" "1.3.7" "zip"
install_binary "https://github.com/Findomain/Findomain/releases/download/9.0.4/findomain-linux.zip" "findomain" "9.0.4" "zip"
install_binary "https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_$arc.zip" "amass" "4.2.0" "zip"
install_binary "https://github.com/jqlang/jq/releases/download/jq-1.7/jq-linux-$arc" "jq" "1.7" ""
install_binary "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_$arc.zip" "subfinder" "2.6.3" "zip"
install_binary "https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/waybackurls-linux-$arc-0.1.0.tgz" "waybackurls" "0.1.0" "tgz"
install_binary "https://github.com/tomnomnom/assetfinder/releases/download/v0.1.1/assetfinder-linux-$arc-0.1.1.tgz" "assetfinder" "0.1.1" "tgz"
install_binary "https://github.com/projectdiscovery/nuclei/releases/download/v3.1.1/nuclei_3.1.1_linux_$arc.zip" "nuclei" "3.1.1" "zip"

chmod +x "$tools_folder/amass_Linux_$arc/amass"
sudo mv "$tools_folder/amass_Linux_$arc/amass" /usr/local/bin/amass
sudo ln -s /usr/bin/python3 /usr/local/bin/python

# Clone repositories
echo -e "${YELLOW}Cloning CertCheck repository...${NC}"
git clone https://github.com/h4r5h1t/CertCheck.git "$tools_folder/CertCheck"
pip install "$tools_folder/CertCheck/."
chmod +x "$tools_folder/CertCheck/certcheck.py"
sudo ln -sfv "$tools_folder/CertCheck/certcheck.py" /usr/local/bin/certcheck

echo -e "${YELLOW}Cloning Sublist3r repository...${NC}"
git clone https://github.com/aboul3la/Sublist3r.git "$tools_folder/Sublist3r"
chmod +x "$tools_folder/Sublist3r/sublist3r.py"
pip install -r "$tools_folder/Sublist3r/requirements.txt"
sudo ln -sfv "$tools_folder/Sublist3r/sublist3r.py" /usr/local/bin/sublister

git clone https://github.com/nil0x42/duplicut "$tools_folder/duplicut"
cd "$tools_folder/duplicut/" && make
sudo mv "$tools_folder/duplicut/duplicat" /usr/local/bin/duplicut

# Install Go
echo -e "${YELLOW}Installing Go...${NC}"
wget https://go.dev/dl/go1.21.5.linux-$arc.tar.gz -O "$tools_folder/go.tar.gz"
sudo tar -C /usr/local -xzf "$tools_folder/go.tar.gz"
rm "$tools_folder/go.tar.gz"

echo -e "${GREEN}All tools successfully.${NC}"
