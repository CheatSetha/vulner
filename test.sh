#!/bin/bash

# Project: VULNER
# Student: Cheat Setha
# student code: s23
# Class Code: TCI-2409-Cambodia-II
# Lecturer: Harshit Katiyar


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
    echo -e "${YELLOW}Class Code: TCI-2409-Cambodia-II${NC}"
    echo -e "${YELLOW}Lecturer: Harshit Katiyar${NC}"
}

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
    local output_dir="$3"
    local scan_protocol="$4"

    # Skip IPs ending with .1 or .254
    if [[ "$target_ip" =~ \.1$ || "$target_ip" =~ \.254$ ]]; then
        echo -e "${YELLOW}Skipping IP: $target_ip (ends with .1 or .254)${NC}"
        return
    fi

    echo -e "${INFO}[*] Start Scanning: $target_ip...${NC}"
    
    if [[ "$scan_type" == "B" ]]; then
        if [[ "$scan_protocol" == "U" ]]; then
            echo -e "${INFO}UDP scan is so slow :(${NC}"
            nmap -T4 -sS -sU -sV --top-ports 1000 --min-rate 10000 --vv "$target_ip" -oN "$output_dir/${target_ip}_nmap_basic_scan_results.txt"
        else
            nmap -T4 -sS -sV --top-ports 1000 --min-rate 10000 --vv "$target_ip" -oN "$output_dir/${target_ip}_nmap_basic_scan_results.txt"
        fi   
    else
        if [[ "$scan_protocol" == "U" ]]; then
            echo -e "${INFO}UDP scan is so slow :(${NC}"
            nmap --vv --min-rate 10000 -sS -sU -sV -O --script vuln,auth,default,brute "$target_ip" -oN "$output_dir/${target_ip}_nmap_full_scan_results.txt"
        else
            echo -e "${INFO}Glad that no UDP scan${NC}"
            nmap --vv --min-rate 10000 -sS -sV -O --script vuln,auth,default,brute "$target_ip" -oN "$output_dir/${target_ip}_nmap_full_scan_results.txt"
        fi
    fi
    echo -e "${GREEN}[*] Scan for $target_ip completed.${NC}"
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
            echo -e "${INFO}You have selected a Basic scan.${NC}"
            ;;
        F)
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
    # Show total live hosts
    echo -e "${INFO}Total live hosts: ${#live_hosts[@]}${NC}"
    echo -e "${INFO}Live hosts:${NC}"
    printf "%s\n" "${live_hosts[@]}"

    read -p "Enter output directory: " output_dir
    if [ ! -d "$output_dir" ]; then
        mkdir -p "$output_dir"
    fi

    # Check TCP or UDP scan
    echo -e "${INFO}Time to pick your poison! Do you want to scan TCP,or include UDP?${NC}"
    echo -e "${INFO}Just say 'T' for TCP, 'U' if you want to include UDP (${YELLOW}Warning: UDP is super slow!${NC})${NC}"

    read -p "Enter your choice (T for TCP, U for include UDP): " scan_protocol
    scan_protocol=$(echo "$scan_protocol" | tr '[:lower:]' '[:upper:]') # Convert to uppercase

    # Loop through each live host and scan, appending results to one file
    for host in "${live_hosts[@]}"; do
        run_nmap "$host" "$scan_type" "$output_dir" "$scan_protocol"
    done
    echo -e "${GREEN}All scan results saved to: $output_dir ${NC}"
}

# retrieve target ip that contain port off ssh, telnet, ftp, rdp
get_target_ip_with_deserved_port(){
    local output_dir="$1"
    # recursive search for port 22, 23, 21, 3389 in output directory
    # grep -E -Rn "22/tcp|23/tcp|21/tcp|3389/tcp" mino | sed 's/_nmap_basic_scan_results\.txt//g' | awk -F'[:/ ]' '{print $2":"$4}'
    grep -E -Rn "22/tcp|23/tcp|21/tcp|3389/tcp" "$output_dir"  | sed 's/_nmap_basic_scan_results\.txt//g' | awk -F'[:/ ]' '{service=""; if ($4 == "21") service="ftp"; else if ($4 == "22") service="ssh"; else if ($4 == "23") service="telnet"; else if ($4 == "3389") service="rdp"; print $2":"$4":"service}'
 > "$output_dir/target_ip_with_port.txt" #ip:port
    while read -r line; do
        target_ip_with_port+=("$line")
    done < "$output_dir/target_ip_with_port.txt"
    echo -e "${INFO}Checking Target IP with port 22, 23, 21, 3389:${NC}"
    # if target_ip_with_port is empty
    if [ ${#target_ip_with_port[@]} -eq 0 ]; then
        echo -e "${RED}No target IP found with port 22, 23, 21, 3389.${NC}"
        return 1
    fi
    # call run_hydra function
    for target_ip in "${target_ip_with_port[@]}"; do
        run_hydra "$target_ip"
    done
    

}

# hydra to check ssh, telnet, ftp, rdp weak password
run_hydra(){
    local default_passwd="/usr/share/wordlists/rockyou.txt"
    local default_user="/usr/share/wordlists/usernames.txt"
    local target_ip="$1" # ip:port:service

    # Check if target IP is empty
    if [ -z "$target_ip" ]; then
        echo -e "${RED}Error: Target IP is empty.${NC}" >&2
        return 1
    fi

    # Split target IP into IP, port, and service
    IFS=':' read -r -a target_ip_arr <<< "$target_ip"
    local ip="${target_ip_arr[0]}"
    local port="${target_ip_arr[1]}"
    local service="${target_ip_arr[2]}"

    # Check if user wants to use default password and username or custom
    read -p "Do you want to use default username and password? (Y/N): " use_default
    use_default=$(echo "$use_default" | tr '[:lower:]' '[:upper:]') # Convert to uppercase
    case "$use_default" in
        Y)
            echo -e "${INFO}Using default username and password.${NC}"
            ;;
        N)
            read -p "Enter username list file path: " username
            read -p "Enter password list file path: " password_file
            ;;
    esac

    # Run hydra
    case "$service" in
        ssh)
            if [ "$use_default" == "Y" ]; then
                hydra -L "$default_user" -P "$default_passwd" -t 4 -vV -e ns -s "$port" "$ip" ssh
            else
                hydra -L "$username" -P "$password_file" -t 4 -vV -e ns -s "$port" "$ip" ssh
            fi
            ;;
        telnet)
            if [ "$use_default" == "Y" ]; then
                hydra -L "$default_user" -P "$default_passwd" -t 4 -vV -e ns -s "$port" "$ip" telnet
            else
                hydra -L "$username" -P "$password_file" -t 4 -vV -e ns -s "$port" "$ip" telnet
            fi
            ;;
        ftp)
            if [ "$use_default" == "Y" ]; then
                hydra -L "$default_user" -P "$default_passwd" -t 4 -vV -e ns -s "$port" "$ip" ftp
            else
                hydra -L "$username" -P "$password_file" -t 4 -vV -e ns -s "$port" "$ip" ftp
            fi
            ;;
        rdp)
            if [ "$use_default" == "Y" ]; then
                hydra -L "$default_user" -P "$default_passwd" -t 4 -vV -e ns -s "$port" "$ip" rdp
            else
                hydra -L "$username" -P "$password_file" -t 4 -vV -e ns -s "$port" "$ip" rdp
            fi
            ;;
        *)
            echo -e "${RED}Error: Unsupported service ${service}.${NC}" >&2
            return 1
            ;;
    esac
}

banner
check_scan_type
get_target_ip_with_deserved_port "$output_dir"