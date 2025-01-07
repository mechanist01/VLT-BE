from cryptography import x509
from cryptography.hazmat.backends import default_backend
import socket
import ssl
from typing import Dict, Any

class TLSAnalyzer:
    def __init__(self):
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

    def analyze_host(self, host: str) -> Dict[str, Any]:
        """
        Analyze TLS configuration of a host
        """
        try:
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
            raise Exception(f"TLS analysis failed: {str(e)}")

    def _parse_certificate(self, cert_data: bytes) -> Dict[str, Any]:
        """
        Parse certificate data
        """
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
        return {
            'subject': str(cert.subject),
            'issuer': str(cert.issuer),
            'not_valid_before': cert.not_valid_before.isoformat(),
            'not_valid_after': cert.not_valid_after.isoformat(),
            'serial_number': cert.serial_number
        }