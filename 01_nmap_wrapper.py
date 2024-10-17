# Automated HTTP Service and Directory Brute Forcing Tool
# 
# This script:
# - Performs a network scan using nmap to identify open HTTP services on specified ports.
# - Runs gobuster to brute force directories on the discovered HTTP services.
# - Parses and displays results for further analysis.

# Run the program:
# python script_name.py example.com -w /path/to/wordlist.txt -o results.json

### Imported Libraries
import argparse
import json
import re
import subprocess

### The 'run_nmap' function
def run_nmap(target):
    """Runs an nmap scan on the target and returns the result."""
    command = ['nmap', '-p-', '--open', '-sV', target]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f"Error running nmap: {result.stderr}")
        return None
    return result.stdout

### The 'parse_nmap_output' function
def parse_nmap_output(output):
    """Parses nmap output and returns a list of HTTP ports."""
    http_ports = []
    for line in output.splitlines():
        if re.search(r"http\\b", line, re.IGNORECASE):
            port_match = re.search(r"(\\d+)/tcp", line)
            if port_match:
                http_ports.append(port_match.group(1))
    return http_ports

### The 'run_gobuster' function
def run_gobuster(target, port, wordlist):
    """Runs gobuster to brute-force directories on a target HTTP service."""
    url = f"http://{target}:{port}"
    result = subprocess.run(['gobuster', 'dir', '-u', url, '-w', wordlist], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f"Error running gobuster on {url}: {result.stderr}")
        return None
    return result.stdout

### The main function
def main(target, wordlist, output_file=None):
    """Main function to run nmap, parse results, and run gobuster on HTTP ports."""
    nmap_output = run_nmap(target)
    if not nmap_output:
        print("Nmap scan failed.")
        return

    http_ports = parse_nmap_output(nmap_output)
    if not http_ports:
        print("No HTTP services found.")
        return

    results = {}
    for port in http_ports:
        print(f"Starting gobuster on {target}:{port}")
        gobuster_output = run_gobuster(target, port, wordlist)
        if gobuster_output:
            results[port] = gobuster_output

    if output_file:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"Results saved to {output_file}.")
    else:
        print("Scan results:")
        for port, output in results.items():
            print(f"Port {port}:\n{output}")

    return results

### Command-line argument parsing
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated tool for scanning HTTP services and directory brute-forcing.")
    parser.add_argument("target", help="Target IP address or domain")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to the wordlist file for Gobuster")
    parser.add_argument("-o", "--output", help="File path to save results. Leave blank to print to console.")

    args = parser.parse_args()
    main(args.target, args.wordlist, args.output)
