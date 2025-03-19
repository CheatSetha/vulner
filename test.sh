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
    # warning message to rus as root
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Warning: Please run as root.${NC}" >&2
        exit 1
    fi
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
    # msg that ready to scan
    echo -e "${INFO}All required tools are installed. Ready to scan.${NC}"
    # set time out for more beutiful output
    sleep 2
    
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
    grep -E -Rn "22/tcp|23/tcp|21/tcp|3389/tcp" "$output_dir"  | sed 's/_nmap_basic_scan_results\.txt//g' | awk -F'[:/ ]' '{service=""; if ($4 == "21") service="ftp"; else if ($4 == "22") service="ssh"; else if ($4 == "23") service="telnet"; else if ($4 == "3389") service="rdp"; print $2":"$4":"service}' > "$output_dir/target_ip_with_port.txt" #ip:port
    while read -r line; do
        target_ip_with_port+=("$line")
    done < "$output_dir/target_ip_with_port.txt"
    echo -e "${INFO}Checking Target IP with port 22, 23, 21, 3389:${NC}"
    # if target_ip_with_port is empty
    if [ ${#target_ip_with_port[@]} -eq 0 ]; then
        echo -e "${RED}No target IP found with port 22, 23, 21, 3389.${NC}"
        return 1
    fi
    #msg to user about  to run hydra
    echo 
    echo
    echo -e "${INFO}Time to run Hydra against target IP with port 22, 23, 21, 3389.${NC}"
    # call run_hydra function
    for target_ip in "${target_ip_with_port[@]}"; do
        run_hydra "$target_ip" "$output_dir"
    done
    
}

# hydra to check ssh, telnet, ftp, rdp weak password
run_hydra(){
    local default_passwd="/usr/share/wordlists/rockyou.txt"  # Built-in weak password list
    local target_ip="$1"  # Expecting ip:port:service
    local output_dir="$2"  # Directory to store logs
    local log_file="$output_dir/valid_credentials.log"  # Log file for valid credentials

    echo $target_ip

    # Validate input format
    if [ -z "$target_ip" ]; then
        echo -e "${RED}Error: Target IP is empty.${NC}" >&2
        return 1
    fi

    IFS=':' read -r ip port service <<< "$target_ip"

    if [ -z "$ip" ] || [ -z "$port" ] || [ -z "$service" ]; then
        echo -e "${RED}Error: Invalid target format. Use ip:port:service.${NC}" >&2
        return 1
    fi

    # Ask for username
    read -p "Enter the username to test: " username
    if [ -z "$username" ]; then
        echo -e "${RED}Error: Username cannot be empty.${NC}" >&2
        return 1
    fi

    # Ask user for password input method
    read -p "Do you want to use the built-in weak password list? (Y/N): " use_default
    use_default=$(echo "$use_default" | tr '[:lower:]' '[:upper:]')  # Convert to uppercase

    local password_file  # Declare variable

    if [ "$use_default" = "N" ]; then
        read -p "Enter password list file path: " password_file
        if [ ! -f "$password_file" ]; then
            echo -e "${RED}Error: Password file not found.${NC}" >&2
            return 1
        fi
    else
        echo -e "${INFO}Using built-in weak password list.${NC}"
        password_file="$default_passwd"
    fi

    # Run Hydra based on service
    case "$service" in
        ssh|telnet|ftp|rdp)
            echo -e "${INFO}Running Hydra against $ip on port $port ($service)...${NC}"
            hydra -l "$username" -P "$password_file" -t 4 -vV -e ns -s "$port" "$ip" "$service" | tee >(grep -i "login:" >> "$log_file")
            ;;
        *)
            echo -e "${RED}Error: Unsupported service '${service}'.${NC}" >&2
            return 1
            ;;
    esac

    # Check if valid credentials were found and log them
    if grep -q "login:" "$log_file"; then
        echo -e "${GREEN}Valid credentials found for $service on $ip:$port. Logged to $log_file.${NC}"
    else
        echo -e "${YELLOW}No valid credentials found for $service on $ip:$port.${NC}"
    fi
}

map_vulnerabilities() {
    local output_dir="$1"
    local scan_type="$2"

    # Ensure this function only runs for Full scans
    if [[ "$scan_type" != "F" ]]; then
        echo -e "${YELLOW}Skipping vulnerability mapping as Full scan was not selected.${NC}"
        return
    fi

    echo -e "${INFO}Mapping vulnerabilities for Full scan results...${NC}"

    # Iterate through all Full scan result files
    for scan_file in "$output_dir"/*_nmap_full_scan_results.txt; do
        if [[ -f "$scan_file" ]]; then
            echo -e "${INFO}Analyzing vulnerabilities in: $scan_file${NC}"

            # Extract services and versions from the Nmap scan results
            grep -E "open|service" "$scan_file" | while read -r line; do
                echo -e "${INFO}Found service: $line${NC}"
            done

            # Use Searchsploit to map vulnerabilities
            echo -e "${INFO}Running Searchsploit for potential exploits...${NC}"
            searchsploit --nmap "$scan_file"
        else
            echo -e "${YELLOW}No Full scan results found in $output_dir.${NC}"
        fi
    done

    echo -e "${GREEN}Vulnerability mapping completed.${NC}"
}

log_results() {
    local output_dir="$1"
    local log_file="$output_dir/final_results.log"

    echo -e "${INFO}Logging results...${NC}"
    echo "===== SCAN RESULTS =====" > "$log_file"

    # Gather all scan results
    cat "$output_dir"/*_nmap_*.txt  >> "$log_file"
    echo -e "${INFO}Hydra results:" >> "$log_file"
    cat "$output_dir/valid_credentials.log" >> "$log_file"
    echo -e "${INFO}Scan results logged in $log_file${NC}"

    # Display summary of findings
    echo -e "${INFO}Summary of Findings:${NC}"
    grep -E "open|login:|VULNERABLE" "$log_file" | tee "$output_dir/summary.log"

    # Allow user to search inside results
    read -p "Do you want to search inside the results? (Y/N): " search_choice
    search_choice=$(echo "$search_choice" | tr '[:lower:]' '[:upper:]')

    if [[ "$search_choice" == "Y" ]]; then
        read -p "Enter search term: " search_term
        grep -i "$search_term" "$log_file" || echo -e "${YELLOW}No matches found.${NC}"
    fi

    # Allow user to save results in a ZIP file
    read -p "Do you want to save all results into a ZIP file? (Y/N): " zip_choice
    zip_choice=$(echo "$zip_choice" | tr '[:lower:]' '[:upper:]')

    if [[ "$zip_choice" == "Y" ]]; then
        zip -r "$output_dir/scan_results.zip" "$output_dir"
        echo -e "${GREEN}Results saved to $output_dir/scan_results.zip${NC}"
    fi
}


banner
check_tools 
check_scan_type
get_target_ip_with_deserved_port "$output_dir"
map_vulnerabilities "$output_dir" "$scan_type"
log_results "$output_dir"
