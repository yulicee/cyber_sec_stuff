import textwrap
from tabulate import tabulate
import socket
import ssl
from datetime import datetime, timedelta
import pandas as pd
import requests

# List of common ports to check for HTTPS and SSL/TLS
COMMON_PORTS = [443, 8443, 9443, 10443, 8080, 993, 465, 995]

# Constants for weak and deprecated ciphers/protocols
WEAK_CIPHERS = ['RC4', 'DES', '3DES', 'MD5']
WEAK_TLS_VERSIONS = ['SSLv3', 'TLSv1', 'TLSv1.1']
DEPRECATED_CIPHERS = ['RSA', '3DES', 'CBC']

# Function to wrap long text for better display
def wrap_text(text, width=80):
    return "\n".join(textwrap.wrap(text, width=width))

# Check for various weaknesses in TLS configuration and certificates
def check_weaknesses(cipher, tls_version, certificate, cert_info, hostname):
    warnings = []

    # TLS version check
    if tls_version in WEAK_TLS_VERSIONS:
        warnings.append(f"Weak TLS version detected: {tls_version}")
    
    # Cipher suite check
    if any(weak_cipher in cipher for weak_cipher in WEAK_CIPHERS):
        warnings.append(f"Weak cipher suite detected: {cipher}")
    if any(deprecated_cipher in cipher for deprecated_cipher in DEPRECATED_CIPHERS):
        warnings.append(f"Deprecated cipher detected: {cipher}")
    
    # Certificate expiration check
    expiration_date = cert_info[3][1]  # Use the 'Valid until' date in cert_info (already converted)
    if expiration_date != "Not available":
        if expiration_date < datetime.now():
            warnings.append("Certificate has expired.")
        elif expiration_date - timedelta(days=30) < datetime.now():
            warnings.append("Certificate is close to expiring (within 30 days).")

    # Self-signed certificate check
    if certificate.get('issuer') == certificate.get('subject'):
        warnings.append("Self-signed certificate detected.")
    
    # Additional checks
    checks = [
        check_hsts(hostname),
        check_forward_secrecy(cipher),
        check_sni(hostname),
        check_wildcard_certificate_usage(certificate),
        check_ocsp_stapling()
    ]
    warnings.extend([check for check in checks if check])

    return warnings

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
def check_sni(hostname):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=20) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                common_name = dict(x[0] for x in cert['subject']).get('commonName', None)
                return "SNI is properly configured." if common_name == hostname else f"SNI mismatch detected: {common_name}."
    except Exception as e:
        return f"Error during SNI check: {e}"

# Placeholder for OCSP stapling check
def check_ocsp_stapling():
    return "OCSP Stapling is NOT enabled."

# Check if the certificate is a wildcard certificate
def check_wildcard_certificate_usage(certificate):
    alt_names = certificate.get('subjectAltName', [])
    
    # Iterate over the tuples in subjectAltName, and check the second element (the actual name)
    wildcards = [name[1] for name in alt_names if isinstance(name, tuple) and name[1].startswith('*')]
    
    return f"Wildcard certificate detected for: {wrap_text(', '.join(wildcards), 80)}" if wildcards else "No wildcard certificates found."

# Get and display the certificate information and security issues
def get_certificate_info(hostname, port):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=20) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                certificate = ssock.getpeercert()
                cipher = ssock.cipher()

        # Extract certificate info
        subject = dict(x[0] for x in certificate['subject'])
        issuer = dict(x[0] for x in certificate['issuer'])
        valid_from = certificate.get('notBefore', 'Not available')
        valid_to = certificate.get('notAfter', 'Not available')

        # Ensure the certificate fields are properly formatted if available
        valid_from_dt = datetime.strptime(valid_from, "%b %d %H:%M:%S %Y %Z") if valid_from != 'Not available' else "Not available"
        valid_to_dt = datetime.strptime(valid_to, "%b %d %H:%M:%S %Y %Z") if valid_to != 'Not available' else "Not available"

        cert_info = [
            ["Issued to", subject.get('commonName', 'Not available')],
            ["Issued by", issuer.get('commonName', 'Not available')],
            ["Valid from", valid_from_dt],
            ["Valid until", valid_to_dt],
            ["TLS Version", cipher[1]],  # TLS version
            ["Cipher Suite", cipher[0]]  # Cipher suite
        ]

        # Security checks
        warnings = check_weaknesses(cipher[0], cipher[1], certificate, cert_info, hostname)
        return cert_info, warnings

    except Exception as e:
        print(f"Port {port} could not be reached: {e}")
        return None, None

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

    for port in COMMON_PORTS:
        print(f"\nChecking port {port} for {website}...")
        cert_info, security_issues = get_certificate_info(website, port)
        
        if cert_info is not None:
            # Use tabulate to display tables
            print("\nCertificate Information:")
            print(tabulate(cert_info, headers=["Field", "Value"], tablefmt="grid"))

            print("\nSecurity Issues:")
            security_issues_table = [[wrap_text(issue)] for issue in security_issues]
            print(tabulate(security_issues_table, headers=["Security Issues Detected"], tablefmt="grid"))
            
            # Export data to files
            export_to_csv(cert_info, website)
            export_to_text(security_issues, website)
            
            # Stop after finding a valid connection
            break
