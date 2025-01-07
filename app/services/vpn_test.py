import socket
import dns.resolver
import requests
import json
from typing import Dict, Any, List
import subprocess
import re

class VPNTester:
    def __init__(self):
        self.dns_servers = [
            "8.8.8.8",        # Google
            "8.8.4.4",        # Google
            "1.1.1.1",        # Cloudflare
            "1.0.0.1",        # Cloudflare
            "9.9.9.9",        # Quad9
            "208.67.222.222", # OpenDNS
            "208.67.220.220"  # OpenDNS
        ]

    def run_tests(self) -> Dict[str, Any]:
        """Run all VPN leak tests"""
        return {
            "ip_info": self._get_ip_info(),
            "dns_leaks": self._check_dns_leaks(),
            "webrtc_status": self._check_webrtc_leaks()
        }

    def _get_ip_info(self) -> Dict[str, Any]:
        """Get information about the current IP address"""
        try:
            response = requests.get('https://ipapi.co/json/')
            data = response.json()
            
            return {
                "ip": data.get('ip', 'Unknown'),
                "location": f"{data.get('city', 'Unknown')}, {data.get('country_name', 'Unknown')}",
                "isp": data.get('org', 'Unknown'),
                "is_vpn": self._detect_vpn(data)
            }
        except Exception as e:
            print(f"Error getting IP info: {e}")
            return {
                "ip": "Error",
                "location": "Error",
                "isp": "Error",
                "is_vpn": False
            }

    def _detect_vpn(self, ip_data: Dict[str, Any]) -> bool:
        """Detect if the connection is likely through a VPN"""
        vpn_indicators = [
            lambda d: d.get('org', '').lower().find('vpn') != -1,
            lambda d: d.get('org', '').lower().find('proxy') != -1,
            lambda d: d.get('hosting', False),
            lambda d: d.get('privacy', {}).get('hosting', False),
            lambda d: d.get('privacy', {}).get('proxy', False),
            lambda d: d.get('privacy', {}).get('tor', False),
            lambda d: d.get('privacy', {}).get('vpn', False)
        ]
        
        return any(indicator(ip_data) for indicator in vpn_indicators)

    def _check_dns_leaks(self) -> Dict[str, Any]:
        """Check for DNS leaks"""
        detected_servers = []
        
        try:
            resolver = dns.resolver.Resolver()
            for dns_server in self.dns_servers:
                resolver.nameservers = [dns_server]
                try:
                    answers = resolver.resolve('whoami.akamai.net', 'A')
                    for answer in answers:
                        detected_servers.append(str(answer))
                except:
                    continue
            
            # Remove duplicates
            detected_servers = list(set(detected_servers))
            
            return {
                "has_leaks": len(detected_servers) > 1,
                "detected_servers": detected_servers
            }
        except Exception as e:
            print(f"Error checking DNS leaks: {e}")
            return {
                "has_leaks": False,
                "detected_servers": []
            }

    def _check_webrtc_leaks(self) -> Dict[str, Any]:
        """Check for WebRTC leaks"""
        try:
            # Get local IP
            local_ip = socket.gethostbyname(socket.gethostname())
            
            # Get public IP
            response = requests.get('https://api.ipify.org?format=json')
            public_ip = response.json()['ip']
            
            # Check if IPs are different (indicating potential leak)
            has_leak = local_ip != public_ip and not local_ip.startswith('127.')
            
            return {
                "local_ip": local_ip,
                "public_ip": public_ip,
                "has_leak": has_leak
            }
        except Exception as e:
            print(f"Error checking WebRTC leaks: {e}")
            return {
                "local_ip": "Error",
                "public_ip": "Error",
                "has_leak": False
            }

    def _get_network_interfaces(self) -> List[str]:
        """Get list of network interfaces"""
        interfaces = []
        try:
            output = subprocess.check_output(['ifconfig']).decode()
            interfaces = re.findall(r'^[a-zA-Z0-9]+:', output, re.MULTILINE)
            return [i.strip(':') for i in interfaces]
        except:
            try:
                output = subprocess.check_output(['ipconfig']).decode()
                interfaces = re.findall(r'adapter (.+):', output)
                return interfaces
            except:
                return []