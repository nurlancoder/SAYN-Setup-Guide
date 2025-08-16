"""
Port Scanner Module for SAYN
Detects open ports and identifies running services
"""

import asyncio
import socket
from typing import Dict, List, Any, Optional
import logging
from urllib.parse import urlparse

class PortScanner:
    """Advanced port scanner with service detection"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger('SAYN.port_scanner')
        self.common_ports = self._load_common_ports()
        
    def _load_common_ports(self) -> Dict[int, str]:
        """Load common ports and their associated services"""
        return {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            1521: 'Oracle',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            27017: 'MongoDB',
            9200: 'Elasticsearch',
            11211: 'Memcached'
        }
    
    async def scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Main port scanning method"""
        self.logger.info(f"Starting port scan for {target}")
        
        scan_results = {
            'module': 'port_scanner',
            'target': target,
            'open_ports': [],
            'services': {},
            'vulnerabilities': [],
            'scan_completed': False
        }
        
        try:
            parsed_url = urlparse(target)
            host = parsed_url.hostname or parsed_url.netloc
            
            if not host:
                raise ValueError("Could not extract host from target")
            
            port_range = options.get('port_range', '1-1000')
            start_port, end_port = self._parse_port_range(port_range)
            
            open_ports = await self._scan_ports(host, start_port, end_port, options)
            scan_results['open_ports'] = open_ports
            
            services = await self._identify_services(host, open_ports)
            scan_results['services'] = services
            
            vulnerabilities = self._check_port_vulnerabilities(open_ports, services)
            scan_results['vulnerabilities'] = vulnerabilities
            
            scan_results['scan_completed'] = True
            
            self.logger.info(f"Port scan completed. Found {len(open_ports)} open ports")
            
        except Exception as e:
            self.logger.error(f"Error during port scan: {str(e)}")
            scan_results['error'] = str(e)
            
        return scan_results
    
    def _parse_port_range(self, port_range: str) -> tuple:
        """Parse port range string (e.g., '1-1000', '80,443,8080')"""
        if '-' in port_range:
            start, end = port_range.split('-')
            return int(start), int(end)
        elif ',' in port_range:
            ports = [int(p.strip()) for p in port_range.split(',')]
            return min(ports), max(ports)
        else:
            port = int(port_range)
            return port, port
    
    async def _scan_ports(self, host: str, start_port: int, end_port: int, 
                         options: Dict[str, Any]) -> List[int]:
        """Scan ports asynchronously"""
        open_ports = []
        max_concurrent = options.get('max_concurrent', 100)
        timeout = options.get('timeout', 3)
        
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def scan_port(port):
            async with semaphore:
                if await self._is_port_open(host, port, timeout):
                    return port
                return None
        
        tasks = [scan_port(port) for port in range(start_port, end_port + 1)]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, int):
                open_ports.append(result)
        
        return sorted(open_ports)
    
    async def _is_port_open(self, host: str, port: int, timeout: float) -> bool:
        """Check if a specific port is open"""
        try:
            future = asyncio.get_event_loop().run_in_executor(
                None, self._check_port_sync, host, port, timeout
            )
            return await future
        except Exception as e:
            self.logger.debug(f"Error checking port {port}: {str(e)}")
            return False
    
    def _check_port_sync(self, host: str, port: int, timeout: float) -> bool:
        """Synchronous port check"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    async def _identify_services(self, host: str, open_ports: List[int]) -> Dict[int, str]:
        """Identify services running on open ports"""
        services = {}
        
        for port in open_ports:
            if port in self.common_ports:
                services[port] = self.common_ports[port]
            else:
                service = await self._banner_grab(host, port)
                if service:
                    services[port] = service
                else:
                    services[port] = 'Unknown'
        
        return services
    
    async def _banner_grab(self, host: str, port: int) -> Optional[str]:
        """Attempt to grab service banner"""
        try:
            future = asyncio.get_event_loop().run_in_executor(
                None, self._banner_grab_sync, host, port
            )
            return await future
        except Exception:
            return None
    
    def _banner_grab_sync(self, host: str, port: int) -> Optional[str]:
        """Synchronous banner grabbing"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            probes = [
                b'\r\n',
                b'GET / HTTP/1.0\r\n\r\n',
                b'HELP\r\n',
                b'VERSION\r\n'
            ]
            
            for probe in probes:
                try:
                    sock.send(probe)
                    response = sock.recv(1024)
                    if response:
                        response_str = response.decode('utf-8', errors='ignore').lower()
                        if 'http' in response_str:
                            return 'HTTP'
                        elif 'ssh' in response_str:
                            return 'SSH'
                        elif 'ftp' in response_str:
                            return 'FTP'
                        elif 'smtp' in response_str:
                            return 'SMTP'
                        elif 'pop3' in response_str:
                            return 'POP3'
                        elif 'imap' in response_str:
                            return 'IMAP'
                        elif 'mysql' in response_str:
                            return 'MySQL'
                        elif 'postgresql' in response_str:
                            return 'PostgreSQL'
                        elif 'redis' in response_str:
                            return 'Redis'
                        elif 'mongodb' in response_str:
                            return 'MongoDB'
                except:
                    continue
            
            sock.close()
            
        except Exception:
            pass
        
        return None
    
    def _check_port_vulnerabilities(self, open_ports: List[int], 
                                   services: Dict[int, str]) -> List[Dict[str, Any]]:
        """Check for common port-based vulnerabilities"""
        vulnerabilities = []
        
        dangerous_services = {
            23: 'Telnet (unencrypted)',
            21: 'FTP (unencrypted)',
            22: 'SSH (check for weak configurations)',
            3389: 'RDP (check for weak configurations)',
            5900: 'VNC (check for weak configurations)'
        }
        
        for port, service in services.items():
            if port in dangerous_services:
                vulnerabilities.append({
                    'type': 'dangerous_service',
                    'severity': 'medium',
                    'title': f'Dangerous Service: {dangerous_services[port]}',
                    'description': f'Port {port} is running {dangerous_services[port]}. '
                                 f'This service may be vulnerable to attacks.',
                    'location': f'Port {port}',
                    'recommendation': f'Disable {dangerous_services[port]} if not needed, '
                                    f'or ensure it is properly secured.',
                    'port': port,
                    'service': service
                })
        
        db_ports = [1433, 1521, 3306, 5432, 27017, 6379, 9200, 11211]
        for port in open_ports:
            if port in db_ports:
                vulnerabilities.append({
                    'type': 'database_exposure',
                    'severity': 'high',
                    'title': f'Database Service Exposed: {services.get(port, "Unknown")}',
                    'description': f'Database service is running on port {port}. '
                                 f'This should not be directly accessible from the internet.',
                    'location': f'Port {port}',
                    'recommendation': 'Restrict database access to internal networks only. '
                                    'Use firewalls and VPNs to secure database connections.',
                    'port': port,
                    'service': services.get(port, 'Unknown')
                })
        
        web_ports = [80, 443, 8080, 8443]
        for port in open_ports:
            if port not in web_ports and services.get(port) in ['HTTP', 'HTTPS']:
                vulnerabilities.append({
                    'type': 'non_standard_web_port',
                    'severity': 'low',
                    'title': f'Web Service on Non-Standard Port: {port}',
                    'description': f'Web service is running on non-standard port {port}.',
                    'location': f'Port {port}',
                    'recommendation': 'Consider using standard ports (80/443) for web services.',
                    'port': port,
                    'service': services.get(port, 'Unknown')
                })
        
        return vulnerabilities
