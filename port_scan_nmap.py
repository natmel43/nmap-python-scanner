import nmap
import sys
from datetime import datetime

if __name__ == "__main__":
    # Prompt user for input
    target_input = input("Enter the IP or domain to scan: ").strip()
    
    if not target_input:
        print("Error: Target input cannot be empty.")
        sys.exit(1)
        
    # Initialize the Nmap PortScanner object
    nm = nmap.PortScanner()
    
    print("\nScanning... please wait.")
    
    try:
        # Scan the target for the top 1000 ports (1-1024)
        # '-v' enables verbose output, '-sS' runs a SYN stealth scan
        nm.scan(hosts=target_input, ports='1-1024', arguments='-v -sS')
    except Exception as e:
        print(f"An error occurred during scanning: {e}")
        sys.exit(1)
        
    print("-" * 50)
    print(f"Scan Summary for: {target_input}")
    print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50)

    # Loop through all detected hosts in the scan results
    for host in nm.all_hosts():
        # Get resolved IP (or hostname if IP was provided)
        try:
            print(f"dns resolve: {host} ({nm[host].hostname() or 'No hostname'})")
        except KeyError:
            print(f"dns resolve: {host}")
            
        print(f"Host Status: {nm[host].state()}")
        print("-" * 50)
        print(f"{'STATE':<8} {'PORT':<10} SERVICE")
        print("-" * 50)
        
        # Iterate over scanned protocols (usually just 'tcp')
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            
            # Sort the ports numerically
            for port in sorted(lport):
                state = nm[host][proto][port]['state']
                
                # Check for open ports only
                if state == 'open':
                    service = nm[host][proto][port]['name']
                    print(f"open     {port:<5}/{proto}   {service}")
                    
    print("-" * 50)
    print("Scan Complete.")
