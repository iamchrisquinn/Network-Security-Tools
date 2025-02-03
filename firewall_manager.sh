#!/bin/bash

# Firewall Rule Manager v1.0
# This script manages iptables firewall rules

# Check if script is run with root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Function to validate IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to validate port number
validate_port() {
    local port=$1
    if [[ $port =~ ^[0-9]+$ ]] && [ $port -ge 1 ] && [ $port -le 65535 ]; then
        return 0
    else
        return 1
    fi
}

# Function to list all current rules
list_rules() {
    echo "Current Firewall Rules:"
    echo "----------------------"
    iptables -L -n -v
}

# Function to add a new rule
add_rule() {
    local source_ip=$1
    local dest_port=$2
    local protocol=$3

    # Validate inputs
    if ! validate_ip "$source_ip"; then
        echo "Error: Invalid IP address format"
        return 1
    fi

    if ! validate_port "$dest_port"; then
        echo "Error: Invalid port number"
        return 1
    fi

    if [[ ! "$protocol" =~ ^(tcp|udp)$ ]]; then
        echo "Error: Protocol must be tcp or udp"
        return 1
    fi

    # Add the rule
    iptables -A INPUT -p "$protocol" -s "$source_ip" --dport "$dest_port" -j ACCEPT
    echo "Rule added successfully"
}

# Function to remove a rule
remove_rule() {
    local source_ip=$1
    local dest_port=$2
    local protocol=$3

    # Validate inputs (reusing previous validation)
    if ! validate_ip "$source_ip" || ! validate_port "$dest_port" || [[ ! "$protocol" =~ ^(tcp|udp)$ ]]; then
        echo "Error: Invalid input parameters"
        return 1
    fi

    # Remove the rule
    iptables -D INPUT -p "$protocol" -s "$source_ip" --dport "$dest_port" -j ACCEPT
    echo "Rule removed successfully"
}

# Main menu
while true; do
    echo ""
    echo "Firewall Rule Manager"
    echo "1. List all rules"
    echo "2. Add new rule"
    echo "3. Remove rule"
    echo "4. Exit"
    read -p "Select an option (1-4): " choice

    case $choice in
        1)
            list_rules
            ;;
        2)
            read -p "Enter source IP address: " source_ip
            read -p "Enter destination port: " dest_port
            read -p "Enter protocol (tcp/udp): " protocol
            add_rule "$source_ip" "$dest_port" "$protocol"
            ;;
        3)
            read -p "Enter source IP address to remove: " source_ip
            read -p "Enter destination port to remove: " dest_port
            read -p "Enter protocol (tcp/udp): " protocol
            remove_rule "$source_ip" "$dest_port" "$protocol"
            ;;
        4)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option"
            ;;
    esac
done