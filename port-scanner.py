'''
Script Name: Port Scanner
By: Chris Quinn
'''
import socket
import argparse
import ipaddress
import concurrent.futures
import time
import sys

print("DISCLAIMER: Port scanning can be intrusive and impact network traffic. Do not execute this script on a target without permission.\n")

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    27017: "MongoDB"
}

def parse_input():
    """
    Parse and validate command-line arguments.
    Returns: 
        tuple: (ip, ports)
    """
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("-i", required=True, help="IP address to scan (e.g., 192.168.1.2")
    parser.add_argument("-p", default="1-1024", 
                        help="Individual or range of port numbers to scan (e.g. 23; 80,443; 1-500 ). Default: common ports (1-1024)")
    args = parser.parse_args()
    
    try:
        ip = ipaddress.ip_address(args.i)
    except ValueError:
        print(f"Invalid IP address: {args.i}")
        sys.exit(1)

    try:
        ports = validate_ports(args.p)
    except ValueError as e:
        print(e)
        sys.exit(1)

    return ip, ports

def validate_ports(target_ports):
    if "," in target_ports:
        try:
            target_ports = [int(port.strip()) for port in target_ports.split(",")]
            ports = []
            for port in target_ports:
                if 0 <= port <= 65536:
                    ports.append(port)
                else:
                    raise ValueError("Invalid port range.")
            return ports
        except ValueError:
            raise ValueError("Invalid port format.")
            
    elif "-" in target_ports:
        try:
            start_port, end_port = map(int, target_ports.split("-"))
            if 0 <= start_port <= 65536 and 0 <= end_port <= 65536:
                return list(range(start_port, end_port + 1))
            else:
                raise ValueError("Port range must be between 0-65536")
        except ValueError:
            raise ValueError("Invalid port range format")
    
    elif len(target_ports) == 1:
        try:
            port = int(target_ports.strip())
            if 0 <= port <= 65536:
                return port
            raise ValueError(f"Port {port} is not between 0-65536")
        except ValueError:
            raise ValueError("Invalid single port format")
    
    raise ValueError("Invalid port specification")
        

def scan_port(ip, port):
    try:    
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:     # Creates a socket connection. "with" automatically cleans up resources (ie closes the socket) when their context ends at end of 'with' code block
            sock.settimeout(1)                                              # Sets a timeout for the connection attempt
            result = sock.connect_ex((str(ip), port))                            # Connect to ip, port, 
            if result == 0:         # Port is open if result == 0
                return True
            else:
                return False            # Port is closed, silently returning false
    except Exception as e:
        print(f"Error scanning port {port}: {e}")
        return False            
            

def scan_ports(ip, ports):
    
    open_ports = []
    # Create thread pool with 100 worker threads
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
       
        # Create dictionary mapping Future objects to ports
        # executor.submit(scan_port, ip, port) starts a task for each port
        # The dict comprehension creates {Future: port_number} pairs
        future_to_port = {executor.submit(scan_port, ip, port): port for port in ports}
        
        # as_completed yields futures as they finish (in completion order)
        for future in concurrent.futures.as_completed(future_to_port):
            # Get the port number associated with this future
            port = future_to_port[future]
            
            try:
                # Get the result of the scan_port function
                is_open = future.result()
                if is_open:
                    print(f"Port {port} is open")
                    open_ports.append(port)
            except Exception as e:
                print(f"Port {port} generated an exception: {e}")
        return open_ports

def display_results(open_ports):
    if open_ports:
        print("\nOPEN PORTS SUMMARY:")
        for port in open_ports:
            service = COMMON_PORTS.get(port, "Unknown service")     # using dict.get() with default value to handle unknown ports
            print(f"{port:>5}  |  {service}")                        # using string formatting (:>5) to right-align port numbers for a cleaner table look
    else:
        print("No open ports detected.")

def main():
    start_time = time.time()
    ip, ports = parse_input()
    if len(ports) > 1:
        display_results(scan_ports(ip, ports))
    else:
        if scan_port(ip, ports):
            print(f"Port {ports} is open on host {ip}")
        else:
            print(f"Port {ports} is closed on host {ip}")
    
    duration = time.time() - start_time
    print(f"\nScan completed in {duration:.2f} seconds")

if__name__== "__main__":
    main()