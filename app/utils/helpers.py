import re
import socket
import ipaddress
from typing import Union, Dict, Any

def validate_host(host: str) -> bool:
    """
    Validate if a host string is a valid hostname or IP address
    """
    if not host:
        return False
        
    if '://' in host:
        host = host.split('://')[-1]
    
    host = host.split('/')[0]
    host = host.split('?')[0]
    
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    
    if len(host) > 255:
        return False
    
    hostname_pattern = re.compile(
        r'^[a-zA-Z0-9]'
        r'([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    )
    
    return bool(hostname_pattern.match(host))