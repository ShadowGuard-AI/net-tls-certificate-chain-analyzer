# net-tls-certificate-chain-analyzer
Analyzes the TLS certificate chain of a given domain or IP address, verifying its validity and identifying any potential issues like missing intermediates or expired certificates using pyOpenSSL. - Focused on Basic network operations

## Install
`git clone https://github.com/ShadowStrikeHQ/net-tls-certificate-chain-analyzer`

Install the requirements with `pip install -r requirements.txt`. The chain retrieval uses pyOpenSSL (the `OpenSSL` package): after the handshake, the presented chain is read with `get_peer_cert_chain`, and each certificate in it is analyzed in turn.

## Usage
`python3 main.py <hostname> [params]`

Example: `python3 main.py example.com -p 443`

## Parameters
- `hostname`: The hostname or IP address to analyze (positional, required).
- `-h, --help`: Show help message and exit
- `-p, --port`: The port number to connect to (default: 443).
- `-v, --verbose`: Enable verbose output (debug logging).
- `--no-verify`: Disable SSL certificate verification.  Use with caution!

## Exit status
The run exits with status 1 when no certificate chain could be retrieved. A run that retrieved and analyzed a chain exits with status 0.

## License
Copyright (c) ShadowStrikeHQ
