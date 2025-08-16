"""
Network Security Module for SAYN
Coordinates network security scanning operations
"""

import asyncio
from typing import Dict, List, Any
from .port_scanner import PortScanner
from .ssl_scanner import SSLScanner

class NetworkSecurityScanner:
    """Main network security scanner that coordinates all network security checks"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.port_scanner = PortScanner(config)
        self.ssl_scanner = SSLScanner(config)
    
    async def scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run all network security scans"""
        scan_results = {
            'module': 'network_security',
            'target': target,
            'vulnerabilities': [],
            'open_ports': [],
            'services': {},
            'ssl_info': {},
            'scan_completed': False
        }
        
        try:
            port_results = await self.port_scanner.scan(target, options)
            scan_results['open_ports'] = port_results.get('open_ports', [])
            scan_results['services'] = port_results.get('services', {})
            scan_results['vulnerabilities'].extend(port_results.get('vulnerabilities', []))
            
            if 443 in scan_results['open_ports'] or 8443 in scan_results['open_ports']:
                ssl_results = await self.ssl_scanner.scan(target, options)
                scan_results['ssl_info'] = ssl_results.get('ssl_info', {})
                scan_results['vulnerabilities'].extend(ssl_results.get('vulnerabilities', []))
            
            scan_results['scan_completed'] = True
            
        except Exception as e:
            scan_results['error'] = str(e)
            
        return scan_results
