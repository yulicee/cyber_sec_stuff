# Security Tools Collection

This repository contains a set of Python-based security tools designed for educational purposes, ethical security testing, and network auditing. These tools should **only** be used on systems that you own or have explicit permission to test.

## Tools Included

### 1. **nmap_wrapper**
A Python wrapper for the popular Nmap tool that simplifies scanning processes. It allows you to initiate Nmap scans programmatically and easily capture results for reporting or further analysis.

### 2. **webcrawler**
A lightweight web crawler that helps gather information about websites, such as URLs, metadata, and linked resources. It can be useful for reconnaissance and initial data gathering in ethical penetration tests.

### 3. **certificate_check**
This tool analyzes SSL/TLS certificates and configurations of websites. It checks for weak ciphers, certificate expiration, HSTS headers, forward secrecy, and other security issues. The tool also supports multiple ports for scanning and exports results to CSV and text files.

---

## Installation

You can install the necessary dependencies by running the following command:

```bash
pip install -r requirements.txt
```

Make sure to have Python 3.6 or higher installed.

---

## Usage

### nmap_wrapper

A wrapper around Nmap for easier scanning.

#### Example:
```bash
python3 nmap_wrapper.py -t target_ip -p ports
```
This will scan the target IP on the specified ports using Nmap.

---

## webcrawler

A simple web crawler that recursively gathers website links and metadata.

#### Example:
```bash
python3 webcrawler.py --url https://example.com
```
This will start crawling the target URL and print out discovered links and metadata.

---

## certificate_check

A tool to audit SSL/TLS certificates and security settings on websites.

#### Example:
```bash
python3 certificate_check.py
```
You'll be prompted to enter the target website, and the tool will check the SSL/TLS certificate and related security issues. The results will be exported to CSV and text files.

---

## Ethical Usage Disclaimer

These tools are intended for **ethical** purposes such as security audits, penetration testing (with permission), and learning. **You should never use these tools on systems or networks that you do not have explicit authorization to test.**

The misuse of these tools can lead to legal consequences. By using these tools, you agree to take full responsibility for any actions resulting from their use.

---

## Contributing

Feel free to submit issues or pull requests if you have suggestions for improving these tools.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Contact

For questions or feedback, feel free to contact me via [[LinkedIn Profile](https://www.linkedin.com/in/julie-jung-ae-spars-500ba524a/)] or open an issue in the repository.


