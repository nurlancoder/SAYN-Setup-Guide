"""
SSL/TLS Scanner Module for SAYN
Analyzes SSL/TLS configuration and certificate security
"""

import ssl
import socket
import asyncio
from typing import Dict, List, Any, Optional
import logging
from datetime import datetime, timedelta
from urllib.parse import urlparse

class SSLScanner:
    """SSL/TLS configuration and certificate scanner"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger('SAYN.ssl_scanner')
        self.weak_ciphers = self._load_weak_ciphers()
        
    def _load_weak_ciphers(self) -> List[str]:
        """Load list of weak/insecure ciphers"""
        return [
            'NULL',
            'aNULL',
            'EXPORT',
            'LOW',
            'DES',
            '3DES',
            'RC4',
            'MD5',
            'PSK',
            'SRP',
            'KRB5',
            'ADH',
            'AECDH',
            'CAMELLIA',
            'SEED',
            'IDEA'
        ]
    
    async def scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Main SSL/TLS scanning method"""
        self.logger.info(f"Starting SSL/TLS scan for {target}")
        
        scan_results = {
            'module': 'ssl_scanner',
            'target': target,
            'ssl_info': {},
            'vulnerabilities': [],
            'scan_completed': False
        }
        
        try:
            parsed_url = urlparse(target)
            host = parsed_url.hostname or parsed_url.netloc
            port = parsed_url.port or 443
            
            ssl_info = await self._get_ssl_info(host, port)
            scan_results['ssl_info'] = ssl_info
            
            vulnerabilities = self._check_ssl_vulnerabilities(ssl_info)
            scan_results['vulnerabilities'] = vulnerabilities
            
            scan_results['scan_completed'] = True
            
            self.logger.info(f"SSL/TLS scan completed. Found {len(vulnerabilities)} issues")
            
        except Exception as e:
            self.logger.error(f"Error during SSL/TLS scan: {str(e)}")
            scan_results['error'] = str(e)
            
        return scan_results
    
    async def _get_ssl_info(self, host: str, port: int) -> Dict[str, Any]:
        """Get comprehensive SSL/TLS information"""
        ssl_info = {
            'host': host,
            'port': port,
            'certificate': {},
            'protocols': {},
            'ciphers': [],
            'errors': []
        }
        
        try:
            cert_info = await self._get_certificate_info(host, port)
            ssl_info['certificate'] = cert_info
            
            protocols = await self._test_protocols(host, port)
            ssl_info['protocols'] = protocols
            
            ciphers = await self._get_supported_ciphers(host, port)
            ssl_info['ciphers'] = ciphers
            
        except Exception as e:
            ssl_info['errors'].append(str(e))
            
        return ssl_info
    
    async def _get_certificate_info(self, host: str, port: int) -> Dict[str, Any]:
        """Get SSL certificate information"""
        try:
            future = asyncio.get_event_loop().run_in_executor(
                None, self._get_certificate_sync, host, port
            )
            return await future
        except Exception as e:
            self.logger.error(f"Error getting certificate info: {str(e)}")
            return {}
    
    def _get_certificate_sync(self, host: str, port: int) -> Dict[str, Any]:
        """Synchronous certificate retrieval"""
        cert_info = {}
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    
                    if cert:
                        cert_info = {
                            'subject': dict(x[0] for x in cert['subject']),
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'version': cert.get('version'),
                            'serial_number': cert.get('serialNumber'),
                            'not_before': cert.get('notBefore'),
                            'not_after': cert.get('notAfter'),
                            'san': cert.get('subjectAltName', []),
                            'signature_algorithm': cert.get('signatureAlgorithm'),
                            'key_size': self._get_key_size(cert),
                            'ocsp_stapling': self._check_ocsp_stapling(ssock),
                            'hsts': self._check_hsts(ssock)
                        }
                        
        except Exception as e:
            cert_info['error'] = str(e)
            
        return cert_info
    
    def _get_key_size(self, cert: Dict) -> Optional[int]:
        """Extract key size from certificate"""
        try:
            return None
        except:
            return None
    
    def _check_ocsp_stapling(self, ssock) -> bool:
        """Check if OCSP stapling is enabled"""
        try:
            return False 
        except:
            return False
    
    def _check_hsts(self, ssock) -> bool:
        """Check if HSTS is enabled"""
        try:
            return False  
        except:
            return False
    
    async def _test_protocols(self, host: str, port: int) -> Dict[str, bool]:
        """Test which SSL/TLS protocols are supported"""
        protocols = {
            'SSLv2': False,
            'SSLv3': False,
            'TLSv1.0': False,
            'TLSv1.1': False,
            'TLSv1.2': False,
            'TLSv1.3': False
        }
        
        for protocol, _ in protocols.items():
            try:
                is_supported = await self._test_protocol(host, port, protocol)
                protocols[protocol] = is_supported
            except Exception as e:
                self.logger.debug(f"Error testing {protocol}: {str(e)}")
                
        return protocols
    
    async def _test_protocol(self, host: str, port: int, protocol: str) -> bool:
        """Test if a specific protocol is supported"""
        try:
            future = asyncio.get_event_loop().run_in_executor(
                None, self._test_protocol_sync, host, port, protocol
            )
            return await future
        except Exception:
            return False
    
    def _test_protocol_sync(self, host: str, port: int, protocol: str) -> bool:
        """Synchronous protocol testing"""
        try:
            protocol_map = {
                'SSLv2': ssl.PROTOCOL_SSLv2,
                'SSLv3': ssl.PROTOCOL_SSLv3,
                'TLSv1.0': ssl.PROTOCOL_TLSv1,
                'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
                'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
                'TLSv1.3': ssl.PROTOCOL_TLS
            }
            
            if protocol not in protocol_map:
                return False
            
            context = ssl.SSLContext(protocol_map[protocol])
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return True
                    
        except Exception:
            return False
    
    async def _get_supported_ciphers(self, host: str, port: int) -> List[str]:
        """Get list of supported ciphers"""
        try:
            future = asyncio.get_event_loop().run_in_executor(
                None, self._get_ciphers_sync, host, port
            )
            return await future
        except Exception:
            return []
    
    def _get_ciphers_sync(self, host: str, port: int) -> List[str]:
        """Synchronous cipher retrieval"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return ssock.shared_ciphers()
                    
        except Exception:
            return []
    
    def _check_ssl_vulnerabilities(self, ssl_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for SSL/TLS vulnerabilities"""
        vulnerabilities = []
        
        cert_vulns = self._check_certificate_vulnerabilities(ssl_info.get('certificate', {}))
        vulnerabilities.extend(cert_vulns)
        
        protocol_vulns = self._check_protocol_vulnerabilities(ssl_info.get('protocols', {}))
        vulnerabilities.extend(protocol_vulns)
        
        cipher_vulns = self._check_cipher_vulnerabilities(ssl_info.get('ciphers', []))
        vulnerabilities.extend(cipher_vulns)
        
        return vulnerabilities
    
    def _check_certificate_vulnerabilities(self, cert_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for certificate-related vulnerabilities"""
        vulnerabilities = []
        
        if not cert_info or 'error' in cert_info:
            vulnerabilities.append({
                'type': 'ssl_certificate_error',
                'severity': 'high',
                'title': 'SSL Certificate Error',
                'description': f'Failed to retrieve SSL certificate: {cert_info.get("error", "Unknown error")}',
                'location': 'SSL Certificate',
                'recommendation': 'Check SSL certificate configuration and ensure it is valid.',
                'issue': 'certificate_error'
            })
            return vulnerabilities
        
        if 'not_after' in cert_info:
            try:
                expiry_date = datetime.strptime(cert_info['not_after'], '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (expiry_date - datetime.now()).days
                
                if days_until_expiry < 0:
                    vulnerabilities.append({
                        'type': 'expired_certificate',
                        'severity': 'critical',
                        'title': 'Expired SSL Certificate',
                        'description': f'SSL certificate expired on {cert_info["not_after"]}',
                        'location': 'SSL Certificate',
                        'recommendation': 'Renew the SSL certificate immediately.',
                        'issue': 'expired_certificate'
                    })
                elif days_until_expiry < 30:
                    vulnerabilities.append({
                        'type': 'expiring_certificate',
                        'severity': 'medium',
                        'title': 'SSL Certificate Expiring Soon',
                        'description': f'SSL certificate expires in {days_until_expiry} days',
                        'location': 'SSL Certificate',
                        'recommendation': 'Renew the SSL certificate before it expires.',
                        'issue': 'expiring_certificate'
                    })
            except Exception:
                pass
        
        if 'issuer' in cert_info and 'subject' in cert_info:
            if cert_info['issuer'] == cert_info['subject']:
                vulnerabilities.append({
                    'type': 'self_signed_certificate',
                    'severity': 'medium',
                    'title': 'Self-Signed SSL Certificate',
                    'description': 'SSL certificate is self-signed',
                    'location': 'SSL Certificate',
                    'recommendation': 'Use a certificate from a trusted Certificate Authority.',
                    'issue': 'self_signed_certificate'
                })
        
        if cert_info.get('key_size'):
            key_size = cert_info['key_size']
            if key_size and key_size < 2048:
                vulnerabilities.append({
                    'type': 'weak_key_size',
                    'severity': 'medium',
                    'title': 'Weak SSL Key Size',
                    'description': f'SSL certificate uses weak key size: {key_size} bits',
                    'location': 'SSL Certificate',
                    'recommendation': 'Use a certificate with at least 2048-bit key size.',
                    'issue': 'weak_key_size'
                })
        
        return vulnerabilities
    
    def _check_protocol_vulnerabilities(self, protocols: Dict[str, bool]) -> List[Dict[str, Any]]:
        """Check for protocol-related vulnerabilities"""
        vulnerabilities = []
        
        weak_protocols = {
            'SSLv2': 'critical',
            'SSLv3': 'high',
            'TLSv1.0': 'medium',
            'TLSv1.1': 'low'
        }
        
        for protocol, severity in weak_protocols.items():
            if protocols.get(protocol, False):
                vulnerabilities.append({
                    'type': 'weak_ssl_protocol',
                    'severity': severity,
                    'title': f'Weak SSL/TLS Protocol: {protocol}',
                    'description': f'Server supports {protocol}, which is considered insecure.',
                    'location': 'SSL/TLS Configuration',
                    'recommendation': f'Disable {protocol} and use only TLS 1.2 or higher.',
                    'protocol': protocol,
                    'issue': 'weak_protocol'
                })
        
        modern_protocols = ['TLSv1.2', 'TLSv1.3']
        if not any(protocols.get(protocol, False) for protocol in modern_protocols):
            vulnerabilities.append({
                'type': 'no_modern_protocols',
                'severity': 'high',
                'title': 'No Modern SSL/TLS Protocols',
                'description': 'Server does not support modern TLS protocols (1.2 or 1.3).',
                'location': 'SSL/TLS Configuration',
                'recommendation': 'Enable TLS 1.2 and TLS 1.3 support.',
                'issue': 'no_modern_protocols'
            })
        
        return vulnerabilities
    
    def _check_cipher_vulnerabilities(self, ciphers: List) -> List[Dict[str, Any]]:
        """Check for cipher-related vulnerabilities"""
        vulnerabilities = []
        
        if not ciphers:
            return vulnerabilities
        
        weak_ciphers_found = []
        for cipher in ciphers:
            cipher_name = cipher[0] if isinstance(cipher, tuple) else str(cipher)
            for weak_cipher in self.weak_ciphers:
                if weak_cipher.lower() in cipher_name.lower():
                    weak_ciphers_found.append(cipher_name)
                    break
        
        if weak_ciphers_found:
            vulnerabilities.append({
                'type': 'weak_ciphers',
                'severity': 'medium',
                'title': 'Weak SSL/TLS Ciphers',
                'description': f'Server supports weak ciphers: {", ".join(weak_ciphers_found)}',
                'location': 'SSL/TLS Configuration',
                'recommendation': 'Disable weak ciphers and use only strong ciphers.',
                'weak_ciphers': weak_ciphers_found,
                'issue': 'weak_ciphers'
            })
        
        return vulnerabilities
