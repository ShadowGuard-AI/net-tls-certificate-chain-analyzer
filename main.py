import socket
import ssl
import argparse
import logging
import requests
from OpenSSL import crypto
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Analyzes the TLS certificate chain of a given domain or IP address."
    )
    parser.add_argument(
        "hostname",
        help="The hostname or IP address to analyze."
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=443,
        help="The port number to connect to (default: 443)."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output (debug logging)."
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Disable SSL certificate verification.  Use with caution!"
    )
    return parser.parse_args()


def get_certificate_chain(hostname, port=443, verify=True):
    """
    Retrieves the certificate chain from the given hostname and port.

    Args:
        hostname (str): The hostname or IP address.
        port (int): The port number (default: 443).
        verify (bool): Whether to verify the certificate.

    Returns:
        list: A list of OpenSSL.crypto.X509 objects representing the certificate chain,
              or None if an error occurred.
    """
    try:
        # Create a socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)  # Set a timeout to prevent hanging

        # Wrap the socket with SSL/TLS
        context = ssl.create_default_context()
        if not verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        
        wrapped_socket = context.wrap_socket(sock, server_hostname=hostname)

        # Connect to the server
        wrapped_socket.connect((hostname, port))

        # Get the certificate chain
        cert_chain = wrapped_socket.getpeercert(binary_form=True)
        wrapped_socket.close()

        if not cert_chain:
            logging.error("No certificate chain received.")
            return None
        
        # Convert the certificate chain from binary to X509 objects
        x509_chain = []
        for cert in ssl.get_server_certificate((hostname, port), cert_chain=cert_chain).split('-----END CERTIFICATE-----\n'):
            if cert:
                x509_chain.append(crypto.load_certificate(crypto.FILETYPE_PEM, cert + '-----END CERTIFICATE-----\n'))


        return x509_chain

    except socket.gaierror as e:
        logging.error(f"Socket error: Could not resolve hostname {hostname}: {e}")
        return None
    except ssl.SSLError as e:
        logging.error(f"SSL error: {e}")
        return None
    except socket.timeout as e:
        logging.error(f"Timeout error: Connection timed out: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None


def analyze_certificate_chain(cert_chain):
    """
    Analyzes the certificate chain for validity and potential issues.

    Args:
        cert_chain (list): A list of OpenSSL.crypto.X509 objects representing the certificate chain.

    Returns:
        None
    """
    if not cert_chain:
        logging.warning("No certificate chain to analyze.")
        return

    for i, cert in enumerate(cert_chain):
        subject = cert.get_subject()
        issuer = cert.get_issuer()
        
        print(f"Certificate #{i + 1}:")
        print(f"  Subject: {subject}")
        print(f"  Issuer: {issuer}")

        # Validity check
        not_before = datetime.strptime(cert.get_notBefore().decode('utf-8'), '%Y%m%d%H%M%SZ')
        not_after = datetime.strptime(cert.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%SZ')
        now = datetime.utcnow()

        print(f"  Valid From: {not_before}")
        print(f"  Valid Until: {not_after}")

        if now < not_before:
            print("  Status: Not yet valid!")
        elif now > not_after:
            print("  Status: Expired!")
        else:
            print("  Status: Valid")

        # Check for self-signed certificates (root CA)
        if subject == issuer:
            print("  Note: Self-signed certificate (Root CA)")

        print("-" * 30)

    # Check for missing intermediates
    if len(cert_chain) > 1:
        for i in range(len(cert_chain) - 1):
            if cert_chain[i].get_issuer() != cert_chain[i+1].get_subject():
                logging.warning("Potential missing intermediate certificate!")
                break


def main():
    """
    Main function to parse arguments, retrieve the certificate chain, and analyze it.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    hostname = args.hostname
    port = args.port
    no_verify = args.no_verify

    logging.info(f"Analyzing certificate chain for {hostname}:{port} (verify={not no_verify})...")

    cert_chain = get_certificate_chain(hostname, port, verify=not no_verify)

    if cert_chain:
        analyze_certificate_chain(cert_chain)
    else:
        logging.error("Failed to retrieve certificate chain.")


if __name__ == "__main__":
    main()

# Usage Examples:
#
# 1. Analyze the certificate chain for google.com:
#    python main.py google.com
#
# 2. Analyze the certificate chain for google.com on port 8443:
#    python main.py google.com -p 8443
#
# 3. Enable verbose output:
#    python main.py google.com -v
#
# 4. Disable SSL certificate verification (use with caution!):
#    python main.py google.com --no-verify
#
# Offensive Tools Integration:
#
# This tool can be integrated into offensive security workflows to:
#
# 1. Identify weak or expired certificates that could be exploited in man-in-the-middle attacks.
# 2. Discover potential missing intermediate certificates that may cause trust issues for some clients.
# 3. Analyze the certificate chain of internal servers during a penetration test to identify misconfigurations.
# 4. Identify self-signed certificates that might indicate a lack of proper security practices.