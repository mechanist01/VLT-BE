from cryptography import x509
from cryptography.hazmat.backends import default_backend
from flask import Request
from datetime import datetime
from typing import Dict, Any
import ssl

class CertificateValidator:
   def __init__(self):
       self.context = ssl.create_default_context()
   
   def get_client_certificate_info(self, request: Request) -> Dict[str, Any]:
       """Get certificate info from client request"""
       client_cert = request.environ.get('SSL_CLIENT_CERT')
       if not client_cert:
           return {'error': 'No client certificate found'}
           
       try:
           cert = x509.load_pem_x509_certificate(
               client_cert.encode(), 
               default_backend()
           )
           return self._analyze_certificate(cert, request)
       except Exception as e:
           return {'error': f"Failed to analyze client cert: {str(e)}"}

   def _analyze_certificate(self, cert: x509.Certificate, request: Request) -> Dict[str, Any]:
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
       
       tls_version = request.environ.get('SSL_PROTOCOL', 'Unknown')
       cipher = request.environ.get('SSL_CIPHER', 'Unknown')
       
       return {
           'tls_info': {
               'version': tls_version,
               'cipher_suite': cipher
           },
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