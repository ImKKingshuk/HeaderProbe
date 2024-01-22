#!/bin/bash


N='\033[0m'
R='\033[0;31m'
G='\033[0;32m'
O='\033[0;33m'
B='\033[0;34m'
Y='\033[0;38m'
C='\033[0;36m'
W='\033[0;37m'

trap 'printf "\e[1;77m \n Ctrl+C was pressed, exiting...\n\n \e[0m"; exit 0' 2


function banner() {
    echo "******************************************"
    echo "*               HeaderProbe              *"
    echo "*       Host Header Injection Tool       *"
    echo "*      ----------------------------      *"
    echo "*                        by @ImKKingshuk *"
    echo "* Github- https://github.com/ImKKingshuk *"
    echo "******************************************"
    echo
}


function check_internet() {
    echo -e "${O}[+] Checking Internet Connectivity"
    if ! ping -c 1 8.8.8.8 &>/dev/null; then
        echo "No Internet Connection"
        exit 1
    else
        echo "Internet is present"
    fi
}


function host_header_injection_check() {
    local domain
    local file
    local method
    local custom_headers
    local follow_redirects
    local timeout
    local output_file

    echo -e "${B}\n[+] Welcome to the Host Header Injection Tool!"
    read -p "Enter the target URL(s) (space-separated for multiple URLs): " domains

    IFS=' ' read -r -a domains_array <<< "$domains"

    if [[ ${#domains_array[@]} -eq 0 ]]; then
        echo -e "${R}[Error] No URLs provided. Exiting..."
        exit 1
    fi

    read -p "Choose HTTP method (default: GET): " method
    method=${method:-GET}

    read -p "Enter custom headers (comma-separated, e.g., Header1:Value1,Header2:Value2): " custom_headers

    read -p "Follow redirects? (yes/no, default: yes): " follow_redirects
    follow_redirects=${follow_redirects:-yes}

    read -p "Enter request timeout in seconds (default: 5): " timeout
    timeout=${timeout:-5}

    read -p "Enter output file name (default: output.txt): " output_file
    output_file=${output_file:-output.txt}

    echo -e "${R}\n[+] Performing Host Header Injection Check"
    sleep 2

    for domain in "${domains_array[@]}"; do
        file=$(curl -s -m "$timeout" -I -X "$method" "$domain" -H "X-Forwarded-Host: evil.com" $([[ -n "$custom_headers" ]] && echo "-H $custom_headers") $([[ "$follow_redirects" == "no" ]] && echo "-L"))
        echo -e "${Y}\nURL: $domain" >>"$output_file"
        echo "$file" >>"$output_file"

        clear
        banner
        echo -e "${B}===================${O}========================="

        if grep -qi 'X-Forwarded-Host: evil.com' <<<"$file"; then
            echo -n -e "${O}URL: $domain  [Vulnerable]\n"
            analyze_response "$file"
        else
            echo -n -e "${O}URL: $domain  [Not Vulnerable]\n"
        fi
    done

    select_output_format "$output_file"
}


function analyze_response() {
    local response="$1"
    local server_header

    server_header=$(grep -i 'Server:' <<<"$response")

    if [[ -n "$server_header" ]]; then
        echo -e "${C}Server Header: $server_header"
    fi

   
}


function select_output_format() {
    local output_file="$1"
    local format
    echo -e "${B}\n[+] Select Output Format:"
    select format in "Plain Text" "JSON" "Exit"; do
        case "$format" in
            "Plain Text")
                cat "$output_file"
                break
                ;;
            "JSON")
                generate_json_output "$output_file"
                break
                ;;
            "Exit")
                exit 0
                ;;
            *)
                echo -e "${R}[Error] Invalid selection. Please choose a valid option."
                ;;
        esac
    done
}


function generate_json_output() {
    local output_file="$1"
    local domain
    local vulnerability_status
    local server_header

    domain=$(awk '/URL:/ {print $2}' "$output_file")
    vulnerability_status=$(awk '/Vulnerable/ {print "true"} /Not Vulnerable/ {print "false"}' "$output_file")
    server_header=$(grep -i 'Server:' "$output_file" | cut -d' ' -f2-)

    cat <<EOF
{
    "URL": "$domain",
    "Vulnerability": $vulnerability_status,
    "ServerHeader": "$server_header"
}
EOF
}


check_internet
clear
banner
host_header_injection_check
