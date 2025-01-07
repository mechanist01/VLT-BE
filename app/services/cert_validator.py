from cryptography import x509
from cryptography.hazmat.backends import default_backend
import socket
import ssl
from typing import Dict, Any, List
from datetime import datetime

class CertificateValidator:
    def __init__(self):
        self.context = ssl.create_default_context()
    
    def get_certificate_info(self, host: str) -> Dict[str, Any]:
        """Get detailed certificate information for a host"""
        try:
            with socket.create_connection((host, 443)) as sock:
                with self.context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    return self._analyze_certificate(cert)
        except Exception as e:
            raise Exception(f"Certificate validation failed: {str(e)}")
    
    def _analyze_certificate(self, cert_data: bytes) -> Dict[str, Any]:
        """Analyze certificate data and return detailed information"""
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
        
        now = datetime.utcnow()
        is_expired = cert.not_valid_after < now
        is_not_yet_valid = cert.not_valid_before > now
        
        try:
            san = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san_list = [str(name) for name in san.value]
        except x509.ExtensionNotFound:
            san_list = []
        
        return {
            'subject': {
                'common_name': self._get_common_name(cert.subject),
                'organization': self._get_organization(cert.subject),
                'organizational_unit': self._get_organizational_unit(cert.subject)
            },
            'issuer': {
                'common_name': self._get_common_name(cert.issuer),
                'organization': self._get_organization(cert.issuer)
            },
            'validity': {
                'not_before': cert.not_valid_before.isoformat(),
                'not_after': cert.not_valid_after.isoformat(),
                'is_expired': is_expired,
                'is_not_yet_valid': is_not_yet_valid
            },
            'serial_number': str(cert.serial_number),
            'version': cert.version.name,
            'subject_alternative_names': san_list
        }
    
    def _get_common_name(self, name: x509.Name) -> str:
        try:
            return name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        except IndexError:
            return None
    
    def _get_organization(self, name: x509.Name) -> str:
        try:
            return name.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value
        except IndexError:
            return None
    
    def _get_organizational_unit(self, name: x509.Name) -> str:
        try:
            return name.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
        except IndexError:
            return None