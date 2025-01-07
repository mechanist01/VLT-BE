import requests
from typing import Dict, Any

class SecurityHeadersChecker:
    def __init__(self):
        self.headers_to_check = {
            'Strict-Transport-Security': self._check_hsts,
            'Content-Security-Policy': self._check_csp,
            'X-Frame-Options': self._check_xframe,
            'X-Content-Type-Options': self._check_content_type_options,
            'X-XSS-Protection': self._check_xss_protection,
            'Referrer-Policy': self._check_referrer_policy
        }
    
    def check_headers(self, host: str) -> Dict[str, Any]:
        try:
            url = f"https://{host}"
            response = requests.get(url, timeout=10)
            headers = response.headers
            
            results = {
                'headers_present': {},
                'missing_headers': [],
                'analysis': {},
                'score': 0
            }
            
            max_score = len(self.headers_to_check)
            current_score = 0
            
            for header, checker in self.headers_to_check.items():
                if header.lower() in [h.lower() for h in headers.keys()]:
                    value = headers[header]
                    results['headers_present'][header] = value
                    analysis = checker(value)
                    results['analysis'][header] = analysis
                    if analysis.get('valid', False):
                        current_score += 1
                else:
                    results['missing_headers'].append(header)
            
            results['score'] = (current_score / max_score) * 100
            return results
            
        except Exception as e:
            raise Exception(f"Security headers check failed: {str(e)}")
    
    def _check_hsts(self, value: str) -> Dict[str, Any]:
        try:
            directives = [d.strip().lower() for d in value.split(';')]
            max_age = None
            include_subdomains = False
            preload = False
            
            for directive in directives:
                if directive.startswith('max-age='):
                    max_age = int(directive.split('=')[1])
                elif directive == 'includesubdomains':
                    include_subdomains = True
                elif directive == 'preload':
                    preload = True
            
            return {
                'valid': True,
                'max_age': max_age,
                'include_subdomains': include_subdomains,
                'preload': preload,
                'recommendations': []
            }
        except Exception:
            return {'valid': False, 'error': 'Invalid HSTS header'}
    
    def _check_csp(self, value: str) -> Dict[str, Any]:
        try:
            directives = value.split(';')
            parsed_directives = {}
            
            for directive in directives:
                if directive.strip():
                    parts = directive.strip().split()
                    directive_name = parts[0]
                    directive_values = parts[1:] if len(parts) > 1 else []
                    parsed_directives[directive_name] = directive_values
            
            return {
                'valid': True,
                'directives': parsed_directives,
                'recommendations': []
            }
        except Exception:
            return {'valid': False, 'error': 'Invalid CSP header'}
    
    def _check_xframe(self, value: str) -> Dict[str, Any]:
        valid_values = ['deny', 'sameorigin']
        value_lower = value.lower()
        
        return {
            'valid': value_lower in valid_values,
            'value': value,
            'recommendations': [] if value_lower in valid_values else ['Use DENY or SAMEORIGIN']
        }
    
    def _check_content_type_options(self, value: str) -> Dict[str, Any]:
        return {
            'valid': value.lower() == 'nosniff',
            'value': value,
            'recommendations': [] if value.lower() == 'nosniff' else ['Use nosniff']
        }
    
    def _check_xss_protection(self, value: str) -> Dict[str, Any]:
        return {
            'valid': value in ['1', '1; mode=block'],
            'value': value,
            'recommendations': [] if value in ['1', '1; mode=block'] else ['Use 1; mode=block']
        }
    
    def _check_referrer_policy(self, value: str) -> Dict[str, Any]:
        valid_values = [
            'no-referrer', 'no-referrer-when-downgrade', 'origin',
            'origin-when-cross-origin', 'same-origin', 'strict-origin',
            'strict-origin-when-cross-origin', 'unsafe-url'
        ]
        
        return {
            'valid': value.lower() in valid_values,
            'value': value,
            'recommendations': [] if value.lower() in valid_values else ['Use a valid referrer policy']
        }