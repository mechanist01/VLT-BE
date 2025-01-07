# app/__init__.py
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import Config

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize rate limiter
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"]
    )
    
    # Register blueprints
    from app.routes import api
    app.register_blueprint(api, url_prefix='/api')
    
    return app

# app/routes.py
from flask import Blueprint, request, jsonify
from app.services.tls_analyzer import TLSAnalyzer
from app.services.cert_validator import CertificateValidator
from app.services.security_headers import SecurityHeadersChecker
from app.utils.helpers import validate_host

api = Blueprint('api', __name__)

@api.route('/analyze', methods=['POST'])
def analyze_tls():
    """
    Analyze TLS configuration of a given host
    Request body: { "host": "example.com" }
    """
    try:
        data = request.get_json()
        if not data or 'host' not in data:
            return jsonify({'error': 'Missing host parameter'}), 400
            
        host = data['host']
        if not validate_host(host):
            return jsonify({'error': 'Invalid host'}), 400
            
        analyzer = TLSAnalyzer()
        results = analyzer.analyze_host(host)
        return jsonify(results)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/certificate', methods=['POST'])
def get_certificate_info():
    """
    Get detailed certificate information
    Request body: { "host": "example.com" }
    """
    try:
        data = request.get_json()
        if not data or 'host' not in data:
            return jsonify({'error': 'Missing host parameter'}), 400
            
        host = data['host']
        if not validate_host(host):
            return jsonify({'error': 'Invalid host'}), 400
            
        validator = CertificateValidator()
        cert_info = validator.get_certificate_info(host)
        return jsonify(cert_info)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/headers', methods=['POST'])
def check_security_headers():
    """
    Analyze security headers
    Request body: { "host": "example.com" }
    """
    try:
        data = request.get_json()
        if not data or 'host' not in data:
            return jsonify({'error': 'Missing host parameter'}), 400
            
        host = data['host']
        if not validate_host(host):
            return jsonify({'error': 'Invalid host'}), 400
            
        checker = SecurityHeadersChecker()
        headers_info = checker.check_headers(host)
        return jsonify(headers_info)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# app/services/tls_analyzer.py
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import socket
import ssl
from typing import Dict, Any

class TLSAnalyzer:
    def __init__(self):
        self.context = ssl.create_default_context()
        
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

# config.py
class Config:
    SECRET_KEY = 'your-secret-key-here'  # Change this in production
    JSON_SORT_KEYS = False
    RATELIMIT_HEADERS_ENABLED = True

# run.py
from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)