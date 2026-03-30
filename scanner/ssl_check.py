# For educational and authorized testing ONLY
# ssl/tls checker - validates certificates and checks for weak configs
# checks cert validity, expiry, protocol version, weak ciphers

import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime, timezone


RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"

# ciphers that are considered weak or broken
# some of these are still out there in the wild unfortunately
WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT",
    "anon", "RC2", "IDEA",
]


class SSLChecker:
    def __init__(self):
        self.findings = []

    def get_cert_info(self, hostname, port=443):
        """connect to the server and grab the ssl certificate details"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    protocol = ssock.version()

                    # sometimes getpeercert returns empty dict when verify is off
                    # need to do a second connection with verification for full cert info
                    try:
                        ctx2 = ssl.create_default_context()
                        with socket.create_connection((hostname, port), timeout=10) as sock2:
                            with ctx2.wrap_socket(sock2, server_hostname=hostname) as ssock2:
                                cert = ssock2.getpeercert()
                    except ssl.SSLCertVerificationError:
                        # cert is invalid/self-signed, we'll report that
                        pass
                    except Exception:
                        pass

                    return {
                        "cert": cert,
                        "cipher": cipher,
                        "protocol": protocol,
                    }

        except socket.timeout:
            print(f"    {RED}[-]{RESET} Connection timed out")
            return None
        except ConnectionRefusedError:
            print(f"    {RED}[-]{RESET} Connection refused on port {port}")
            return None
        except Exception as e:
            print(f"    {RED}[-]{RESET} SSL connection failed: {str(e)}")
            return None

    def check_cert_validity(self, hostname, cert_info):
        """check if the certificate is valid and not expired"""
        cert = cert_info.get("cert", {})

        if not cert:
            self.findings.append({
                "type": "SSL/TLS",
                "severity": "HIGH",
                "url": hostname,
                "parameter": "Certificate",
                "payload": "N/A",
                "method": "N/A",
                "evidence": "Could not retrieve certificate details (self-signed or invalid?)",
                "description": "Certificate validation failed. May be self-signed or expired.",
            })
            print(f"    {RED}[!]{RESET} Certificate validation failed - possibly self-signed")
            return

        # check expiry
        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                # openssl date format
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                now = datetime.now()
                days_left = (expiry - now).days

                if days_left < 0:
                    self.findings.append({
                        "type": "SSL/TLS",
                        "severity": "CRITICAL",
                        "url": hostname,
                        "parameter": "Certificate Expiry",
                        "payload": "N/A",
                        "method": "N/A",
                        "evidence": f"Certificate expired {abs(days_left)} days ago ({not_after})",
                        "description": "SSL certificate has expired. Renew immediately.",
                    })
                    print(f"    {RED}{BOLD}[!!!] Certificate EXPIRED{RESET} ({abs(days_left)} days ago)")
                elif days_left < 30:
                    self.findings.append({
                        "type": "SSL/TLS",
                        "severity": "MEDIUM",
                        "url": hostname,
                        "parameter": "Certificate Expiry",
                        "payload": "N/A",
                        "method": "N/A",
                        "evidence": f"Certificate expires in {days_left} days ({not_after})",
                        "description": "SSL certificate expiring soon. Renew before expiry.",
                    })
                    print(f"    {YELLOW}[!]{RESET} Certificate expires in {days_left} days")
                else:
                    print(f"    {GREEN}[+]{RESET} Certificate valid for {days_left} more days")
            except ValueError:
                print(f"    {YELLOW}[!]{RESET} Could not parse cert expiry date: {not_after}")

        # check subject
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        cn = subject.get("commonName", "unknown")
        issuer_cn = issuer.get("commonName", "unknown")
        print(f"    Subject: {cn}")
        print(f"    Issuer: {issuer_cn}")

    def check_protocol(self, cert_info):
        """check if the protocol version is modern enough"""
        protocol = cert_info.get("protocol", "unknown")
        print(f"    Protocol: {protocol}")

        # tls 1.0 and 1.1 are deprecated, ssl is ancient
        if protocol in ["SSLv2", "SSLv3"]:
            self.findings.append({
                "type": "SSL/TLS",
                "severity": "CRITICAL",
                "url": "",
                "parameter": "Protocol Version",
                "payload": "N/A",
                "method": "N/A",
                "evidence": f"Using deprecated protocol: {protocol}",
                "description": f"{protocol} is deprecated and has known vulnerabilities. Upgrade to TLS 1.2+.",
            })
            print(f"    {RED}{BOLD}[!!!] Using deprecated {protocol}{RESET}")
        elif protocol == "TLSv1":
            self.findings.append({
                "type": "SSL/TLS",
                "severity": "HIGH",
                "url": "",
                "parameter": "Protocol Version",
                "payload": "N/A",
                "method": "N/A",
                "evidence": f"Using deprecated TLS 1.0",
                "description": "TLS 1.0 is deprecated. Upgrade to TLS 1.2 or higher.",
            })
            print(f"    {RED}[!]{RESET} Using deprecated TLS 1.0")
        elif protocol == "TLSv1.1":
            self.findings.append({
                "type": "SSL/TLS",
                "severity": "MEDIUM",
                "url": "",
                "parameter": "Protocol Version",
                "payload": "N/A",
                "method": "N/A",
                "evidence": f"Using deprecated TLS 1.1",
                "description": "TLS 1.1 is deprecated. Upgrade to TLS 1.2 or higher.",
            })
            print(f"    {YELLOW}[!]{RESET} Using deprecated TLS 1.1")
        else:
            print(f"    {GREEN}[+]{RESET} Protocol version is acceptable")

    def check_cipher(self, cert_info):
        """check if the cipher suite is strong enough"""
        cipher = cert_info.get("cipher", ())
        if cipher:
            cipher_name = cipher[0]
            cipher_protocol = cipher[1]
            cipher_bits = cipher[2]

            print(f"    Cipher: {cipher_name} ({cipher_bits} bits)")

            # check for weak ciphers
            for weak in WEAK_CIPHERS:
                if weak.lower() in cipher_name.lower():
                    self.findings.append({
                        "type": "SSL/TLS",
                        "severity": "HIGH",
                        "url": "",
                        "parameter": "Cipher Suite",
                        "payload": "N/A",
                        "method": "N/A",
                        "evidence": f"Weak cipher in use: {cipher_name}",
                        "description": f"Cipher suite contains weak algorithm ({weak}). Use AES-GCM or ChaCha20.",
                    })
                    print(f"    {RED}[!]{RESET} Weak cipher detected: {weak}")
                    return

            # check key length
            if cipher_bits and cipher_bits < 128:
                self.findings.append({
                    "type": "SSL/TLS",
                    "severity": "HIGH",
                    "url": "",
                    "parameter": "Cipher Strength",
                    "payload": "N/A",
                    "method": "N/A",
                    "evidence": f"Cipher key length is only {cipher_bits} bits",
                    "description": "Key length below 128 bits is considered weak. Use 256-bit AES.",
                })
                print(f"    {RED}[!]{RESET} Weak key length: {cipher_bits} bits")
            else:
                print(f"    {GREEN}[+]{RESET} Cipher strength is acceptable")

    def scan(self, target_url):
        """run all ssl/tls checks"""
        parsed = urlparse(target_url)
        hostname = parsed.netloc or parsed.path
        # strip port if present
        if ":" in hostname:
            hostname, port = hostname.rsplit(":", 1)
            port = int(port)
        else:
            port = 443

        print(f"\n{BLUE}[*] Checking SSL/TLS for {hostname}:{port}{RESET}")

        cert_info = self.get_cert_info(hostname, port)
        if not cert_info:
            self.findings.append({
                "type": "SSL/TLS",
                "severity": "HIGH",
                "url": hostname,
                "parameter": "Connection",
                "payload": "N/A",
                "method": "N/A",
                "evidence": "Could not establish SSL connection",
                "description": "SSL/TLS connection failed. Server may not support HTTPS.",
            })
            return self.findings

        self.check_cert_validity(hostname, cert_info)
        self.check_protocol(cert_info)
        self.check_cipher(cert_info)

        if self.findings:
            print(f"\n    {len(self.findings)} SSL/TLS issues found\n")
        else:
            print(f"\n    {GREEN}SSL/TLS configuration looks good!{RESET}\n")

        return self.findings
