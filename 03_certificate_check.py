import textwrap
from tabulate import tabulate
import socket
import ssl
from datetime import datetime, timedelta
import pandas as pd
import requests
import subprocess
import re

# List of common ports to check for HTTPS and SSL/TLS
COMMON_PORTS = [443, 8443, 9443, 10443, 8080, 993, 465, 995]

# Constants for weak and deprecated ciphers/protocols
WEAK_CIPHERS = ['RC4', 'DES', '3DES', 'MD5']
WEAK_TLS_VERSIONS = ['SSLv3', 'TLSv1', 'TLSv1.1']
DEPRECATED_CIPHERS = ['RSA', '3DES', 'CBC']

# Function to wrap long text for better display
def wrap_text(text, width=80):
    return "\n".join(textwrap.wrap(text, width=width))

# Check for OCSP stapling using OpenSSL (limited to port 443)
def check_ocsp_stapling(hostname, port):
    if port != 443:
        return None  # Skip OCSP stapling check if not on port 443

    try:
        result = subprocess.run(
            ['openssl', 's_client', '-connect', f'{hostname}:{port}', '-status'],
            capture_output=True,
            text=True,
            timeout=20
        )

        if "OCSP response:" in result.stdout:
            return "OCSP Stapling is enabled."
        else:
            return "OCSP Stapling is NOT enabled."
    except subprocess.TimeoutExpired:
        return "OCSP Stapling check timed out."
    except FileNotFoundError:
        return "OpenSSL command not found. Ensure OpenSSL is installed."
    except Exception as e:
        return f"Error checking OCSP Stapling: {e}"

# Check certificate revocation using OCSP
def check_revocation_status(hostname, port=443):
    try:
        result = subprocess.run(
            ['openssl', 's_client', '-connect', f'{hostname}:{port}', '-status'],
            capture_output=True,
            text=True,
            timeout=20
        )

        if "OCSP response: no response sent" in result.stdout:
            return "OCSP revocation status: No response sent by the server."
        
        ocsp_uri = re.search(r"OCSP - URI:(\S+)", result.stdout)
        if ocsp_uri:
            ocsp_url = ocsp_uri.group(1)
            print(f"OCSP URI found: {ocsp_url}")
        else:
            return "No OCSP URI found in certificate."

        ocsp_check = subprocess.run(
            ['openssl', 'ocsp', '-issuer', f'{hostname}', '-url', ocsp_url],
            capture_output=True,
            text=True,
            timeout=20
        )

        if "revoked" in ocsp_check.stdout:
            return "OCSP revocation status: Certificate is revoked."
        else:
            return "OCSP revocation status: Certificate is valid."

    except subprocess.TimeoutExpired:
        return "OCSP revocation check timed out."
    except FileNotFoundError:
        return "OpenSSL command not found. Ensure OpenSSL is installed."
    except Exception as e:
        return f"Error checking certificate revocation status: {e}"

# Check for various weaknesses in TLS configuration and certificates
def check_weaknesses(cipher, tls_version, certificate, cert_info, hostname, port):
    warnings = []
    passed_checks = []
    timed_out_checks = 0

    # TLS version check (High priority)
    if tls_version in WEAK_TLS_VERSIONS:
        warnings.append(f"Weak TLS version detected: {tls_version} (High priority)")
    else:
        passed_checks.append(f"TLS version {tls_version} is secure.")

    # Cipher suite check (High priority)
    if any(weak_cipher in cipher for weak_cipher in WEAK_CIPHERS):
        warnings.append(f"Weak cipher suite detected: {cipher} (High priority)")
    else:
        passed_checks.append(f"Cipher suite {cipher} is secure.")

    # Certificate expiration check (Critical priority)
    expiration_date = cert_info[3][1]
    if expiration_date != "Not available":
        if expiration_date < datetime.now():
            warnings.append("Certificate has expired (Critical priority).")
        elif expiration_date - timedelta(days=30) < datetime.now():
            warnings.append("Certificate is close to expiring (within 30 days) (Critical priority).")
        else:
            passed_checks.append("Certificate is valid and not expiring soon.")
    
    # Self-signed certificate check (Critical priority)
    if certificate.get('issuer') == certificate.get('subject'):
        warnings.append("Self-signed certificate detected (Critical priority).")
    else:
        passed_checks.append("Certificate is not self-signed.")

    # Additional checks
    checks = [
        check_hsts(hostname),
        check_forward_secrecy(cipher),
        check_sni(hostname, port),
        check_wildcard_certificate_usage(certificate)
    ]

    # Only run OCSP stapling and revocation checks on port 443
    if port == 443:
        ocsp_stapling_result = check_ocsp_stapling(hostname, port)
        if ocsp_stapling_result == "OCSP Stapling check timed out":
            timed_out_checks += 1
        else:
            checks.append(ocsp_stapling_result)

        revocation_status = check_revocation_status(hostname, port)
        if revocation_status == "OCSP revocation check timed out":
            timed_out_checks += 1
        else:
            checks.append(revocation_status)

    # Separate failed and passed checks, assign importance ranking
    for check in checks:
        if "NOT enabled" in check or "detected" in check:
            if "Forward Secrecy" in check or "OCSP" in check or "expired" in check:
                warnings.append(f"{check} (Critical priority)")
            elif "HSTS" in check or "Weak" in check:
                warnings.append(f"{check} (High priority)")
            elif "SNI" in check or "Wildcard" in check:
                if "Wildcard" in check and "No wildcard certificates found" in check:
                    passed_checks.append("No wildcard certificates found (Good practice).")
                else:
                    warnings.append(f"{check} (Medium priority)")
        else:
            passed_checks.append(check)

    return warnings, timed_out_checks, passed_checks

# Function to sort checks by priority
def sort_by_priority(checks):
    priority_order = {"Critical": 1, "High": 2, "Medium": 3}
    
    def extract_priority(check):
        if "Critical priority" in check:
            return priority_order["Critical"]
        elif "High priority" in check:
            return priority_order["High"]
        elif "Medium priority" in check:
            return priority_order["Medium"]
        return 4  # Default value if no priority is found

    # Sort the checks based on extracted priority
    return sorted(checks, key=extract_priority)

# Grading system with weighted importance of checks
def calculate_security_grade(warnings, total_checks, timed_out_checks):
    CRITICAL_WEIGHT = 3
    HIGH_WEIGHT = 2
    MEDIUM_WEIGHT = 1

    critical_failures = 0
    high_failures = 0
    medium_failures = 0

    for warning in warnings:
        if "Critical priority" in warning:
            critical_failures += CRITICAL_WEIGHT
        elif "High priority" in warning:
            high_failures += HIGH_WEIGHT
        elif "Medium priority" in warning:
            medium_failures += MEDIUM_WEIGHT

    total_failure_points = critical_failures + high_failures + medium_failures

    effective_checks = total_checks - timed_out_checks
    if effective_checks == 0:
        return "Unable to grade (No effective checks)", 0.0

    fail_percentage = (total_failure_points / (effective_checks * CRITICAL_WEIGHT)) * 100

    if total_failure_points == 0:
        grade = "A (Excellent security)"
    elif total_failure_points <= effective_checks * CRITICAL_WEIGHT * 0.2:
        grade = "B (Good security)"
    elif total_failure_points <= effective_checks * CRITICAL_WEIGHT * 0.4:
        grade = "C (Moderate security)"
    else:
        grade = "D (Weak security)"

    return grade, fail_percentage

# Check for HSTS header
def check_hsts(hostname):
    try:
        response = requests.get(f"https://{hostname}")
        return "HSTS is enabled." if "Strict-Transport-Security" in response.headers else "HSTS is NOT enabled."
    except requests.exceptions.RequestException as e:
        return f"Error checking HSTS: {e}"

# Check for forward secrecy (ECDHE)
def check_forward_secrecy(cipher):
    return "Forward Secrecy is enabled." if 'ECDHE' in cipher else "Forward Secrecy is NOT enabled."

# Check for Server Name Indication (SNI) configuration
def check_sni(hostname, port):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=20) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                common_name = dict(x[0] for x in cert['subject']).get('commonName', None)
                return "SNI is properly configured." if common_name == hostname else f"SNI mismatch detected: {common_name}."
    except Exception as e:
        return f"Error during SNI check: {e}"

# Check if the certificate is a wildcard certificate
def check_wildcard_certificate_usage(certificate):
    alt_names = certificate.get('subjectAltName', [])
    wildcards = [name[1] for name in alt_names if isinstance(name, tuple) and name[1].startswith('*')]
    return f"Wildcard certificate detected for: {wrap_text(', '.join(wildcards), 80)}" if wildcards else "No wildcard certificates found (Good practice)."

# Get and display the certificate information and security issues
def get_certificate_info(hostname, port):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=20) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                certificate = ssock.getpeercert()
                cipher = ssock.cipher()

        subject = dict(x[0] for x in certificate['subject'])
        issuer = dict(x[0] for x in certificate['issuer'])
        valid_from = certificate.get('notBefore', 'Not available')
        valid_to = certificate.get('notAfter', 'Not available')

        valid_from_dt = datetime.strptime(valid_from, "%b %d %H:%M:%S %Y %Z") if valid_from != 'Not available' else "Not available"
        valid_to_dt = datetime.strptime(valid_to, "%b %d %H:%M:%S %Y %Z") if valid_to != 'Not available' else "Not available"

        cert_info = [
            ["Issued to", subject.get('commonName', 'Not available')],
            ["Issued by", issuer.get('commonName', 'Not available')],
            ["Valid from", valid_from_dt],
            ["Valid until", valid_to_dt],
            ["TLS Version", cipher[1]],
            ["Cipher Suite", cipher[0]]
        ]

        warnings, timed_out_checks, passed_checks = check_weaknesses(cipher[0], cipher[1], certificate, cert_info, hostname, port)
        return cert_info, warnings, timed_out_checks, passed_checks

    except Exception as e:
        print(f"Port {port} could not be reached: {e}")
        return None, None, 0, []

# Export to CSV
def export_to_csv(cert_info, hostname):
    df = pd.DataFrame(cert_info, columns=["Field", "Value"])
    df.to_csv(f"{hostname}_certificate_info.csv", index=False)
    print(f"Exported certificate information to {hostname}_certificate_info.csv")

# Export to text file
def export_to_text(security_issues, hostname):
    with open(f"{hostname}_security_issues.txt", 'w') as f:
        f.write("Security Issues Detected:\n")
        for issue in security_issues:
            f.write(f"- {issue}\n")
    print(f"Exported security issues to {hostname}_security_issues.txt")

if __name__ == "__main__":
    website = input("Please enter the website (e.g., example.com): ")
    total_checks = 0
    total_warnings = []
    total_passed = []
    total_timeouts = 0

    for port in COMMON_PORTS:
        print(f"\nChecking port {port} for {website}...")
        cert_info, warnings, timeouts, passed_checks = get_certificate_info(website, port)
        
        if cert_info is not None:
            total_checks += len(warnings) + len(passed_checks)
            total_warnings.extend(warnings)
            total_passed.extend(passed_checks)
            total_timeouts += timeouts

            print("\nCertificate Information:")
            print(tabulate(cert_info, headers=["Field", "Value"], tablefmt="grid"))

            print("\nSecurity Issues (Sorted by Priority):")
            combined_checks = warnings + passed_checks
            sorted_checks = sort_by_priority(combined_checks)
            security_issues_table = [[wrap_text(issue)] for issue in sorted_checks]
            print(tabulate(security_issues_table, headers=["Security Issues Detected"], tablefmt="grid"))
            
            export_to_csv(cert_info, website)
            export_to_text(warnings, website)
            
            grade, fail_percentage = calculate_security_grade(total_warnings, total_checks, total_timeouts)
            print(f"\nOverall Security Grade: {grade}")
            print(f"Percentage of Failed Checks: {fail_percentage:.2f}%")
            
            break
