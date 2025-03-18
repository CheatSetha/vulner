#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Required tools checker
check_dependencies() {
    local required_tools=("nmap" "hydra" "searchsploit" "xmlstarlet")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            echo -e "${RED}Error: $tool is not installed.${NC}" >&2
            echo -e "${YELLOW}Please install the required tools and try again.${NC}" >&2
            exit 1
        fi
    done
}

# Validate network input
validate_network() {
    local network_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'
    if [[ ! $1 =~ $network_regex ]]; then
        echo -e "${RED}Invalid network format. Use CIDR notation (e.g., 192.168.1.0/24)${NC}" >&2
        return 1
    fi
}

# Validate scan type
validate_scan_type() {
    if [[ "$1" != "B" && "$1" != "F" ]]; then
        echo -e "${RED}Invalid scan type. Choose Basic or Full${NC}" >&2
        return 1
    fi
}


# Create default password list if needed
create_default_password_list() {
    if [ ! -f "password.lst" ]; then
        echo -e "${YELLOW}Creating default password list...${NC}"
        echo -e "password\n123456\nadmin\nroot\nletmein\nqwerty\n12345\n123456789" > password.lst
    fi
}

# Create default username list if needed
create_default_username_list() {
    if [ ! -f "username.lst" ]; then
        echo -e "${YELLOW}Creating default username list...${NC}"
        echo -e "root\nadmin\nuser\ntest\nguest" > username.lst
    fi
}

# Run Nmap scan
run_nmap() {
    local network="$1"
    local output_dir="$2"
    local scan_type="$3"
    
    echo -e "${GREEN}Starting Nmap ${scan_type} scan...${NC}"
    
    if [[ "$scan_type" == "B" ]]; then
        # check for live hosts
        nmap -sn -oG "${output_dir}/nmap_discovery" "$network"
        # defince var for store live host
        local live_hosts=$(grep -oP '\d+\.\d+\.\d+\.\d+' "${output_dir}/nmap_discovery")

        # run basic scan on live hosts
        nmap -sC -sV -oA "${output_dir}/nmap_basic" $live_hosts
        
        
    else
        # check for live hosts
        nmap -sn -oG "${output_dir}/nmap_discovery" "$network"
        # defince var for store live host
        local live_hosts=$(grep -oP '\d+\.\d+\.\d+\.\d+' "${output_dir}/nmap_discovery")

        # run full scan on live hosts
        # nmap -sC -sV -p- -oA "${output_dir}/nmap_full" $live_hosts
        nmap -sS -sU -sV --script vuln -sC -oA "${output_dir}/nmap_full" "$live_hosts"
    fi
}

# Run Hydra attacks
run_hydra() {
    local output_dir="$1"
    local username_list="$2"
    local passlist="$3"
    local xml_file="$4"
    
    echo -e "${GREEN}Starting weak credentials check...${NC}"
    
    # Parse Nmap XML output
    local services=()
    local ips=$(xmlstarlet sel -t -v "//host/address/@addr" -n "$xml_file" | sort -u)
    
    for ip in $ips; do
        local ports=$(xmlstarlet sel -t -m "//host[address/@addr='$ip']/ports/port[state/@state='open']" \
            -v "@portid" -o " " -v "service/@name" -n "$xml_file")
        
        while read -r port service; do
            case $service in
                ssh|ftp|telnet|ms-wbt-server)
                    local hydra_service="$service"
                    [[ "$service" == "ms-wbt-server" ]] && hydra_service="rdp"
                    services+=("$hydra_service $ip $port")
                    ;;
            esac
        done <<< "$ports"
    done

    # Run Hydra for each service
    for entry in "${services[@]}"; do
        read -r service ip port <<< "$entry"
        echo -e "${YELLOW}Checking $service on $ip:$port...${NC}"
        hydra -L "$username_list" -P "$passlist" "$service://$ip" -s "$port" \
            -o "${output_dir}/hydra_${service}_${ip}_${port}.txt" -t 4
    done
}

# Run vulnerability analysis
run_vulnerability_analysis() {
    local output_dir="$1"
    local xml_file="$2"
    
    echo -e "${GREEN}Starting vulnerability analysis...${NC}"
    searchsploit --nmap "$xml_file" > "${output_dir}/searchsploit.txt"
}

# Main function
main() {
    # call function to check dependencies
    check_dependencies

    echo -e "${GREEN}=== Network Security Scanner ===${NC}"
    
    # Get user input
    read -p "Enter network to scan (CIDR format): " network
    validate_network "$network" || exit 1
    
    read -p "Enter output directory name: " output_dir
    if [[ -d "$output_dir" ]]; then
        echo -e "${RED}Error: Output directory already exists${NC}" >&2
        exit 1
    fi
    
    read -p "Choose scan type ([B]asic/[F]ull): " scan_type
    validate_scan_type "$scan_type" || exit 1
    
    # Password list handling
    read -p "Use custom password list? (y/n): " use_custom
    if [[ "$use_custom" == "y" ]]; then
        read -p "Path to custom password list: " passlist
        [[ -f "$passlist" ]] || { echo -e "${RED}File not found${NC}"; exit 1; }
    else
        create_default_password_list
        passlist="password.lst"
    fi
    
    # Create output directory
    mkdir -p "$output_dir" || { echo -e "${RED}Failed to create directory${NC}"; exit 1; }
    
    # Create username list
    create_default_username_list
    local username_list="username.lst"
    
    # Run Nmap scan
    run_nmap "$network" "$output_dir" "$scan_type"
    local nmap_xml="${output_dir}/nmap_${scan_type,,}.xml"
    
    # Run Hydra attacks
    run_hydra "$output_dir" "$username_list" "$passlist" "$nmap_xml"
    
    # Run vulnerability analysis if Full scan
    if [[ "$scan_type" == "F" ]]; then
        run_vulnerability_analysis "$output_dir" "$nmap_xml"
    fi
    
    # Final output
    echo -e "\n${GREEN}=== Scan Results ==="
    echo -e "Results saved in: ${output_dir}${NC}"
    
    # Search option
    read -p "Search results? (y/n): " search
    if [[ "$search" == "y" ]]; then
        read -p "Enter search term: " term
        grep -rni "$term" "$output_dir"
    fi
    
    # Zip option
    read -p "Create ZIP archive? (y/n): " zip
    if [[ "$zip" == "y" ]]; then
        zip -r "${output_dir}.zip" "$output_dir"
        echo -e "${GREEN}ZIP archive created: ${output_dir}.zip${NC}"
    fi
}


main