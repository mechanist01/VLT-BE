from cryptography import x509
from cryptography.hazmat.backends import default_backend
import socket
import ssl
from typing import Dict, Any
from flask import Request

class TLSAnalyzer:
    def __init__(self):
        self.context = ssl.create_default_context()
    
    def analyze_connection(self) -> Dict[str, Any]:
        try:
            host = 'www.google.com'
            with socket.create_connection((host, 443)) as sock:
                with self.context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    return {
                        'version': version,
                        'cipher_suite': {
                            'name': cipher[0],
                            'protocol': cipher[1],
                            'bits': cipher[2]
                        },
                        'cert_info': self._parse_certificate(cert)
                    }
        except Exception as e:
            print(f"Error: {str(e)}")
            return {
                'version': 'Unknown',
                'cipher_suite': {
                    'name': 'Unknown',
                    'protocol': 'Unknown',
                    'bits': 0
                },
                'cert_info': {
                    'subject': 'Not available',
                    'issuer': 'Not available',
                    'not_valid_before': 'Not available',
                    'not_valid_after': 'Not available',
                    'serial_number': 'Not available'
                }
            }
            
    def _parse_certificate(self, cert_data: bytes) -> Dict[str, Any]:
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
        return {
            'subject': str(cert.subject),
            'issuer': str(cert.issuer),
            'not_valid_before': cert.not_valid_before.isoformat(),
            'not_valid_after': cert.not_valid_after.isoformat(),
            'serial_number': cert.serial_number
        }