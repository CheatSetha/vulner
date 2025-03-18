#!/bin/bash

# Project: VULNER
# Student: Cheat Setha
# Class Code: TCI-2409-Cambodia-III
# Lecturer: 


# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
INFO='\033[0;36m' # Cyan
NC='\033[0m' # No Color

# Banner for the project
banner() {
    cat << "EOF"
 __   __   _   _     _       _  _      ___      ___   
 \ \ / /  | | | |   | |     | \| |    | __|    | _ \  
  \ V /   | |_| |   | |__   | .` |    | _|     |   /  
  _\_/_    \___/    |____|  |_|\_|    |___|    |_|_\  
_| """"| _|"""""| _|"""""| _|"""""| _|"""""| _|"""""| 
"`-0-0-' "`-0-0-' "`-0-0-' "`-0-0-' "`-0-0-' "`-0-0-' 
EOF

    echo -e "${GREEN}VULNER - Vulnerability Scanner${NC}"
    echo -e "${YELLOW}Created by: Cheat Setha${NC}"
    echo -e "${YELLOW}Class Code: TCI-2409-Cambodia-III${NC}"
    echo -e "${YELLOW}Lecturer: Kru indiea${NC}"
}

# tools suggested by cyberium
# namp,hydra,medusa,searchsploit
#xmlstarlet use for parsing xml file
check_tools(){
    local required_tools=("nmap" "hydra" "searchsploit" "xmlstarlet")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            echo -e "${RED}Error: $tool is not installed.${NC}" >&2
            echo -e "${YELLOW}Please install the required tools and try again.${NC}" >&2
            exit 1
        fi
    done
}

#validate network input range 
validate_network_input(){
    local network_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'
    if [[ ! $1 =~ $network_regex ]]; then
        echo -e "${RED}Invalid network format. Use CIDR notation (e.g., 127.0.0..1/24)${NC}" >&2
        exit 1
    fi
    return 0
}

# get network input from user
get_network_input(){
    read -p "Enter network (CIDR. e.g: 0.0.0.0/24): " network
    validate_network_input "$network" || return 1
}

# Run Nmap scan
run_nmap(){
    local target_ip="$1"
    local scan_type="$2"
    local output_file="$3"

    echo -e "${INFO}Scanning: $target_ip...${NC}"
    
    if [[ "$scan_type" == "B" ]]; then
        nmap -T4 -sS -sU -sV --top-ports 1000 --vv "$target_ip" >> "$output_file"
    else
        nmap --vv -sS -sU -sV -O --script vuln,auth,default,brute "$target_ip" >> "$output_file"
    fi
    echo -e "${GREEN}Scan for $target_ip completed.${NC}"
}

# Check user scan type input
check_scan_type(){
    read -p "Enter scan type (B for Basic, F for Full): " scan_type 
    scan_type=$(echo "$scan_type" | tr '[:lower:]' '[:upper:]') # Convert to uppercase

    if [[ "$scan_type" != "B" && "$scan_type" != "F" ]]; then
        echo -e "${RED}Invalid scan type. Choose Basic or Full${NC}" >&2
        return 1
    fi

    case "$scan_type" in
        B)
            # scan_type="Basic"
            echo -e "${INFO}You have selected a Basic scan.${NC}"
            ;;
        F)
            # scan_type="Full"
            echo -e "${INFO}You have selected a Full scan.${NC}"
            ;;
    esac

    get_network_input
    echo -e "${INFO}Checking live hosts...${NC}"

    # Store live hosts in an array
    mapfile -t live_hosts < <(nmap -sn "$network" | grep "Nmap scan report for" | awk '{print $5}')

    if [[ ${#live_hosts[@]} -eq 0 ]]; then
        echo -e "${RED}No live hosts found!${NC}"
        return 1
    fi

    # Ask for output directory (only once per scan)
    read -p "Enter output directory: " output_dir
    if [ ! -d "$output_dir" ]; then
        mkdir -p "$output_dir"
    fi

    # Define output file (one file for all hosts)
    case "$scan_type" in
        B)
            # scan_type="Basic"
            output_file="$output_dir/nmap_basic_scan_results.txt"
            ;;
        F)
            # scan_type="Full"
            output_file="$output_dir/nmap_full_scan_results.txt"
            ;;
    esac
    # Show total live hosts
    echo -e "${INFO}Total live hosts: ${#live_hosts[@]}${NC}"
    echo -e "${INFO}Live hosts:${NC}"
    printf "%s\n" "${live_hosts[@]}"

    # Loop through each live host and scan, appending results to one file
    for host in "${live_hosts[@]}"; do
        run_nmap "$host" "$scan_type" "$output_file"
    done
    echo -e "${GREEN}All scan results saved to: $output_file${NC}"
}

# 2. weak password


banner
check_scan_type