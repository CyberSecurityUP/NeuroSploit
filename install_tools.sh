#!/bin/bash
#
# NeuroSploit v2 - Reconnaissance Tools Installer
# Installs all required tools for advanced reconnaissance
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║        NEUROSPLOIT v2 - TOOLS INSTALLER                       ║"
echo "║        Advanced Reconnaissance Tools Setup                     ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        PKG_MANAGER="brew"
    elif [ -f /etc/debian_version ]; then
        OS="debian"
        PKG_MANAGER="apt"
    elif [ -f /etc/redhat-release ]; then
        OS="redhat"
        PKG_MANAGER="dnf"
    elif [ -f /etc/arch-release ]; then
        OS="arch"
        PKG_MANAGER="pacman"
    else
        OS="unknown"
        PKG_MANAGER="unknown"
    fi
    echo -e "${BLUE}[*] Detected OS: ${OS} (Package Manager: ${PKG_MANAGER})${NC}"
}

# Check if command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Print status
print_status() {
    if command_exists "$1"; then
        echo -e "  ${GREEN}[✓]${NC} $1 - installed"
        return 0
    else
        echo -e "  ${RED}[✗]${NC} $1 - not found"
        return 1
    fi
}

# Install Go if not present
install_go() {
    if command_exists go; then
        echo -e "${GREEN}[✓] Go is already installed${NC}"
        return 0
    fi

    echo -e "${YELLOW}[*] Installing Go...${NC}"

    if [ "$OS" == "macos" ]; then
        brew install go
    elif [ "$OS" == "debian" ]; then
        sudo apt update && sudo apt install -y golang-go
    elif [ "$OS" == "redhat" ]; then
        sudo dnf install -y golang
    elif [ "$OS" == "arch" ]; then
        sudo pacman -S --noconfirm go
    else
        # Manual installation
        GO_VERSION="1.21.5"
        wget "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
        rm "go${GO_VERSION}.linux-amd64.tar.gz"
        export PATH=$PATH:/usr/local/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
    fi

    # Set GOPATH
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
}

# Install Rust if not present
install_rust() {
    if command_exists cargo; then
        echo -e "${GREEN}[✓] Rust is already installed${NC}"
        return 0
    fi

    echo -e "${YELLOW}[*] Installing Rust...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
}

# Install Python packages
install_python_packages() {
    echo -e "${BLUE}[*] Installing Python packages...${NC}"

    pip3 install --upgrade pip 2>/dev/null || pip install --upgrade pip

    # Core packages
    pip3 install requests dnspython urllib3 2>/dev/null || pip install requests dnspython urllib3

    # Security tools
    pip3 install wafw00f 2>/dev/null || echo -e "${YELLOW}  [!] wafw00f installation failed, try: pip install wafw00f${NC}"
    pip3 install paramspider 2>/dev/null || echo -e "${YELLOW}  [!] paramspider installation failed${NC}"
}

# Install tool via Go
install_go_tool() {
    local tool_name=$1
    local repo=$2

    if command_exists "$tool_name"; then
        echo -e "  ${GREEN}[✓]${NC} $tool_name - already installed"
        return 0
    fi

    echo -e "  ${YELLOW}[~]${NC} Installing $tool_name..."
    go install "$repo@latest" 2>/dev/null

    if command_exists "$tool_name"; then
        echo -e "  ${GREEN}[✓]${NC} $tool_name - installed successfully"
    else
        echo -e "  ${RED}[✗]${NC} $tool_name - installation failed"
    fi
}

# Install tool via Cargo (Rust)
install_cargo_tool() {
    local tool_name=$1
    local crate_name=${2:-$tool_name}

    if command_exists "$tool_name"; then
        echo -e "  ${GREEN}[✓]${NC} $tool_name - already installed"
        return 0
    fi

    echo -e "  ${YELLOW}[~]${NC} Installing $tool_name..."
    cargo install "$crate_name" 2>/dev/null

    if command_exists "$tool_name"; then
        echo -e "  ${GREEN}[✓]${NC} $tool_name - installed successfully"
    else
        echo -e "  ${RED}[✗]${NC} $tool_name - installation failed"
    fi
}

# Install system packages
install_system_packages() {
    echo -e "${BLUE}[*] Installing system packages...${NC}"

    if [ "$OS" == "macos" ]; then
        brew update
        brew install nmap curl wget jq git python3 2>/dev/null || true
        brew install feroxbuster 2>/dev/null || true
        brew install nikto 2>/dev/null || true
        brew install whatweb 2>/dev/null || true

    elif [ "$OS" == "debian" ]; then
        sudo apt update
        sudo apt install -y nmap curl wget jq git python3 python3-pip dnsutils whois
        sudo apt install -y nikto whatweb 2>/dev/null || true

    elif [ "$OS" == "redhat" ]; then
        sudo dnf install -y nmap curl wget jq git python3 python3-pip bind-utils whois

    elif [ "$OS" == "arch" ]; then
        sudo pacman -Syu --noconfirm nmap curl wget jq git python python-pip dnsutils whois
        sudo pacman -S --noconfirm nikto whatweb 2>/dev/null || true
    fi
}

# Install Go-based tools
install_go_tools() {
    echo -e "\n${BLUE}[*] Installing Go-based reconnaissance tools...${NC}"

    # Ensure Go paths are set
    export GOPATH=${GOPATH:-$HOME/go}
    export PATH=$PATH:$GOPATH/bin

    # ProjectDiscovery tools
    install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx"
    install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
    install_go_tool "naabu" "github.com/projectdiscovery/naabu/v2/cmd/naabu"
    install_go_tool "katana" "github.com/projectdiscovery/katana/cmd/katana"
    install_go_tool "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx"
    install_go_tool "shuffledns" "github.com/projectdiscovery/shuffledns/cmd/shuffledns"

    # Other Go tools
    install_go_tool "amass" "github.com/owasp-amass/amass/v4/..."
    install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder"
    install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls"
    install_go_tool "gau" "github.com/lc/gau/v2/cmd/gau"
    install_go_tool "httprobe" "github.com/tomnomnom/httprobe"
    install_go_tool "ffuf" "github.com/ffuf/ffuf/v2"
    install_go_tool "gobuster" "github.com/OJ/gobuster/v3"
    install_go_tool "gospider" "github.com/jaeles-project/gospider"
    install_go_tool "hakrawler" "github.com/hakluke/hakrawler"
    install_go_tool "subjack" "github.com/haccer/subjack"
    install_go_tool "gowitness" "github.com/sensepost/gowitness"
    install_go_tool "findomain" "github.com/Findomain/Findomain"
}

# Install Rust-based tools
install_rust_tools() {
    echo -e "\n${BLUE}[*] Installing Rust-based tools...${NC}"

    source "$HOME/.cargo/env" 2>/dev/null || true

    install_cargo_tool "rustscan" "rustscan"
    install_cargo_tool "feroxbuster" "feroxbuster"
}

# Install Nuclei templates
install_nuclei_templates() {
    echo -e "\n${BLUE}[*] Updating Nuclei templates...${NC}"

    if command_exists nuclei; then
        nuclei -update-templates 2>/dev/null || echo -e "${YELLOW}  [!] Template update failed, run manually: nuclei -update-templates${NC}"
        echo -e "  ${GREEN}[✓]${NC} Nuclei templates updated"
    else
        echo -e "  ${RED}[✗]${NC} Nuclei not installed, skipping templates"
    fi
}

# Install SecLists
install_seclists() {
    echo -e "\n${BLUE}[*] Checking SecLists...${NC}"

    SECLISTS_PATH="/opt/wordlists/SecLists"

    if [ -d "$SECLISTS_PATH" ]; then
        echo -e "  ${GREEN}[✓]${NC} SecLists already installed at $SECLISTS_PATH"
        return 0
    fi

    echo -e "  ${YELLOW}[~]${NC} Installing SecLists..."
    sudo mkdir -p /opt/wordlists
    sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$SECLISTS_PATH" 2>/dev/null || {
        echo -e "  ${RED}[✗]${NC} SecLists installation failed"
        return 1
    }

    # Create symlinks for common wordlists
    sudo ln -sf "$SECLISTS_PATH/Discovery/Web-Content/common.txt" /opt/wordlists/common.txt 2>/dev/null
    sudo ln -sf "$SECLISTS_PATH/Discovery/Web-Content/raft-medium-directories.txt" /opt/wordlists/directories.txt 2>/dev/null
    sudo ln -sf "$SECLISTS_PATH/Discovery/DNS/subdomains-top1million-5000.txt" /opt/wordlists/subdomains.txt 2>/dev/null

    echo -e "  ${GREEN}[✓]${NC} SecLists installed"
}

# Install additional tools via package managers or manual
install_additional_tools() {
    echo -e "\n${BLUE}[*] Installing additional tools...${NC}"

    # wafw00f
    if ! command_exists wafw00f; then
        echo -e "  ${YELLOW}[~]${NC} Installing wafw00f..."
        pip3 install wafw00f 2>/dev/null || pip install wafw00f 2>/dev/null
    fi
    print_status "wafw00f"

    # paramspider
    if ! command_exists paramspider; then
        echo -e "  ${YELLOW}[~]${NC} Installing paramspider..."
        pip3 install paramspider 2>/dev/null || {
            git clone https://github.com/devanshbatham/ParamSpider.git /tmp/paramspider 2>/dev/null
            cd /tmp/paramspider && pip3 install . 2>/dev/null
            cd -
        }
    fi
    print_status "paramspider"

    # whatweb
    if ! command_exists whatweb; then
        if [ "$OS" == "macos" ]; then
            brew install whatweb 2>/dev/null
        elif [ "$OS" == "debian" ]; then
            sudo apt install -y whatweb 2>/dev/null
        fi
    fi
    print_status "whatweb"

    # nikto
    if ! command_exists nikto; then
        if [ "$OS" == "macos" ]; then
            brew install nikto 2>/dev/null
        elif [ "$OS" == "debian" ]; then
            sudo apt install -y nikto 2>/dev/null
        fi
    fi
    print_status "nikto"

    # sqlmap
    if ! command_exists sqlmap; then
        echo -e "  ${YELLOW}[~]${NC} Installing sqlmap..."
        if [ "$OS" == "macos" ]; then
            brew install sqlmap 2>/dev/null
        elif [ "$OS" == "debian" ]; then
            sudo apt install -y sqlmap 2>/dev/null
        else
            pip3 install sqlmap 2>/dev/null
        fi
    fi
    print_status "sqlmap"

    # eyewitness
    if ! command_exists eyewitness; then
        echo -e "  ${YELLOW}[~]${NC} Installing EyeWitness..."
        git clone https://github.com/RedSiege/EyeWitness.git /opt/EyeWitness 2>/dev/null || true
        if [ -d "/opt/EyeWitness" ]; then
            cd /opt/EyeWitness/Python/setup
            sudo ./setup.sh 2>/dev/null || true
            sudo ln -sf /opt/EyeWitness/Python/EyeWitness.py /usr/local/bin/eyewitness 2>/dev/null
            cd -
        fi
    fi
    print_status "eyewitness"

    # wpscan
    if ! command_exists wpscan; then
        echo -e "  ${YELLOW}[~]${NC} Installing wpscan..."
        if [ "$OS" == "macos" ]; then
            brew install wpscan 2>/dev/null
        else
            sudo gem install wpscan 2>/dev/null || true
        fi
    fi
    print_status "wpscan"

    # dirsearch
    if ! command_exists dirsearch; then
        echo -e "  ${YELLOW}[~]${NC} Installing dirsearch..."
        pip3 install dirsearch 2>/dev/null || {
            git clone https://github.com/maurosoria/dirsearch.git /opt/dirsearch 2>/dev/null
            sudo ln -sf /opt/dirsearch/dirsearch.py /usr/local/bin/dirsearch 2>/dev/null
        }
    fi
    print_status "dirsearch"

    # massdns (for shuffledns/puredns)
    if ! command_exists massdns; then
        echo -e "  ${YELLOW}[~]${NC} Installing massdns..."
        git clone https://github.com/blechschmidt/massdns.git /tmp/massdns 2>/dev/null
        cd /tmp/massdns && make 2>/dev/null && sudo make install 2>/dev/null
        cd -
    fi
    print_status "massdns"

    # puredns
    if ! command_exists puredns; then
        echo -e "  ${YELLOW}[~]${NC} Installing puredns..."
        go install github.com/d3mondev/puredns/v2@latest 2>/dev/null
    fi
    print_status "puredns"

    # waymore
    if ! command_exists waymore; then
        echo -e "  ${YELLOW}[~]${NC} Installing waymore..."
        pip3 install waymore 2>/dev/null || pip install waymore 2>/dev/null
    fi
    print_status "waymore"
}

# Check all tools status
check_tools_status() {
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                    TOOLS STATUS SUMMARY                        ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}\n"

    echo -e "${BLUE}[Subdomain Enumeration]${NC}"
    print_status "subfinder"
    print_status "amass"
    print_status "assetfinder"
    print_status "findomain"
    print_status "puredns"
    print_status "shuffledns"
    print_status "massdns"

    echo -e "\n${BLUE}[HTTP Probing]${NC}"
    print_status "httpx"
    print_status "httprobe"

    echo -e "\n${BLUE}[URL Collection]${NC}"
    print_status "gau"
    print_status "waybackurls"
    print_status "waymore"
    print_status "hakrawler"

    echo -e "\n${BLUE}[Web Crawling]${NC}"
    print_status "katana"
    print_status "gospider"

    echo -e "\n${BLUE}[Directory Bruteforce]${NC}"
    print_status "feroxbuster"
    print_status "gobuster"
    print_status "ffuf"
    print_status "dirsearch"

    echo -e "\n${BLUE}[Port Scanning]${NC}"
    print_status "rustscan"
    print_status "naabu"
    print_status "nmap"

    echo -e "\n${BLUE}[Vulnerability Scanning]${NC}"
    print_status "nuclei"
    print_status "nikto"
    print_status "sqlmap"
    print_status "wpscan"

    echo -e "\n${BLUE}[WAF Detection]${NC}"
    print_status "wafw00f"

    echo -e "\n${BLUE}[Parameter Discovery]${NC}"
    print_status "paramspider"

    echo -e "\n${BLUE}[Fingerprinting]${NC}"
    print_status "whatweb"

    echo -e "\n${BLUE}[Screenshot]${NC}"
    print_status "gowitness"
    print_status "eyewitness"

    echo -e "\n${BLUE}[Subdomain Takeover]${NC}"
    print_status "subjack"

    echo -e "\n${BLUE}[DNS Tools]${NC}"
    print_status "dnsx"
    print_status "dig"

    echo -e "\n${BLUE}[Utilities]${NC}"
    print_status "curl"
    print_status "wget"
    print_status "jq"
    print_status "git"

    echo -e "\n${BLUE}[Wordlists]${NC}"
    if [ -d "/opt/wordlists/SecLists" ]; then
        echo -e "  ${GREEN}[✓]${NC} SecLists - installed at /opt/wordlists/SecLists"
    else
        echo -e "  ${RED}[✗]${NC} SecLists - not found"
    fi
}

# Update PATH
update_path() {
    echo -e "\n${BLUE}[*] Updating PATH...${NC}"

    # Add Go bin to PATH
    if ! grep -q 'GOPATH' ~/.bashrc 2>/dev/null; then
        echo 'export GOPATH=$HOME/go' >> ~/.bashrc
        echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
    fi

    if ! grep -q 'GOPATH' ~/.zshrc 2>/dev/null; then
        echo 'export GOPATH=$HOME/go' >> ~/.zshrc 2>/dev/null || true
        echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.zshrc 2>/dev/null || true
    fi

    # Add Cargo bin to PATH
    if ! grep -q '.cargo/bin' ~/.bashrc 2>/dev/null; then
        echo 'export PATH=$PATH:$HOME/.cargo/bin' >> ~/.bashrc
    fi

    # Source for current session
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin:$HOME/.cargo/bin

    echo -e "  ${GREEN}[✓]${NC} PATH updated"
}

# Main installation function
main() {
    echo -e "${BLUE}[*] Starting NeuroSploit tools installation...${NC}\n"

    detect_os

    # Parse arguments
    INSTALL_ALL=false
    CHECK_ONLY=false

    while [[ "$#" -gt 0 ]]; do
        case $1 in
            --all) INSTALL_ALL=true ;;
            --check) CHECK_ONLY=true ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --all     Install all tools (full installation)"
                echo "  --check   Only check tool status, don't install"
                echo "  --help    Show this help message"
                echo ""
                exit 0
                ;;
            *) echo "Unknown parameter: $1"; exit 1 ;;
        esac
        shift
    done

    if [ "$CHECK_ONLY" = true ]; then
        check_tools_status
        exit 0
    fi

    # Installation steps
    install_system_packages
    install_go
    install_rust
    install_python_packages
    install_go_tools
    install_rust_tools
    install_additional_tools
    install_seclists
    install_nuclei_templates
    update_path

    # Final status check
    check_tools_status

    echo -e "\n${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}           INSTALLATION COMPLETE!                              ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "\n${YELLOW}[!] Please restart your terminal or run: source ~/.bashrc${NC}"
    echo -e "${YELLOW}[!] Some tools may require sudo privileges to run${NC}\n"
}

# Run main
main "$@"
