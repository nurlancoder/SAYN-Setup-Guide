"""
Security Headers Scanner Module for SAYN
Analyzes security headers and their configurations
"""

import re
from typing import Dict, List, Any, Optional
import logging

class HeadersScanner:
    """Security headers vulnerability scanner"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger('SAYN.headers_scanner')
        self.security_headers = self._load_security_headers()
        
    def _load_security_headers(self) -> Dict[str, Dict[str, Any]]:
        """Load security headers definitions and checks"""
        return {
            'Content-Security-Policy': {
                'description': 'Content Security Policy header',
                'recommendation': 'Implement a strict CSP to prevent XSS attacks',
                'severity': 'high',
                'checks': [
                    'header_present',
                    'has_default_src',
                    'has_script_src',
                    'has_style_src',
                    'has_frame_ancestors'
                ]
            },
            'X-Frame-Options': {
                'description': 'X-Frame-Options header',
                'recommendation': 'Set to DENY or SAMEORIGIN to prevent clickjacking',
                'severity': 'medium',
                'checks': [
                    'header_present',
                    'valid_value'
                ]
            },
            'X-Content-Type-Options': {
                'description': 'X-Content-Type-Options header',
                'recommendation': 'Set to nosniff to prevent MIME type sniffing',
                'severity': 'medium',
                'checks': [
                    'header_present',
                    'valid_value'
                ]
            },
            'X-XSS-Protection': {
                'description': 'X-XSS-Protection header',
                'recommendation': 'Set to 1; mode=block to enable XSS protection',
                'severity': 'medium',
                'checks': [
                    'header_present',
                    'valid_value'
                ]
            },
            'Strict-Transport-Security': {
                'description': 'HTTP Strict Transport Security header',
                'recommendation': 'Set max-age to at least 31536000 (1 year)',
                'severity': 'high',
                'checks': [
                    'header_present',
                    'has_max_age',
                    'valid_max_age'
                ]
            },
            'Referrer-Policy': {
                'description': 'Referrer Policy header',
                'recommendation': 'Set to strict-origin-when-cross-origin or stricter',
                'severity': 'low',
                'checks': [
                    'header_present',
                    'valid_value'
                ]
            },
            'Permissions-Policy': {
                'description': 'Permissions Policy header (formerly Feature-Policy)',
                'recommendation': 'Restrict access to sensitive browser features',
                'severity': 'medium',
                'checks': [
                    'header_present',
                    'has_restrictions'
                ]
            },
            'Cache-Control': {
                'description': 'Cache Control header',
                'recommendation': 'Set appropriate caching policies for sensitive content',
                'severity': 'low',
                'checks': [
                    'header_present',
                    'no_cache_for_sensitive'
                ]
            },
            'Set-Cookie': {
                'description': 'Cookie security attributes',
                'recommendation': 'Use Secure, HttpOnly, and SameSite attributes',
                'severity': 'medium',
                'checks': [
                    'has_secure_flag',
                    'has_httponly_flag',
                    'has_samesite_flag'
                ]
            }
        }
    
    async def scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Main security headers scanning method"""
        self.logger.info(f"Starting security headers scan for {target}")
        
        vulnerabilities = []
        scan_results = {
            'module': 'headers_scanner',
            'target': target,
            'vulnerabilities': vulnerabilities,
            'scan_completed': False,
            'headers_analyzed': 0,
            'missing_headers': [],
            'weak_headers': []
        }
        
        try:
            scanner_engine = options.get('scanner_engine')
            if not scanner_engine:
                raise ValueError("Scanner engine not provided in options")
            
            response = await scanner_engine.make_request(target)
            if response.get('error'):
                raise Exception(f"Failed to get response: {response['error']}")
            
            headers = response.get('headers', {})
            scan_results['headers_analyzed'] = len(headers)
            
            for header_name, header_config in self.security_headers.items():
                header_vulns = self._analyze_header(header_name, header_config, headers)
                vulnerabilities.extend(header_vulns)
                
                if not header_vulns:
                    scan_results['missing_headers'].append(header_name)
                else:
                    scan_results['weak_headers'].append(header_name)
            
            additional_vulns = self._perform_additional_checks(headers, target)
            vulnerabilities.extend(additional_vulns)
            
            scan_results['vulnerabilities'] = vulnerabilities
            scan_results['scan_completed'] = True
            
            self.logger.info(f"Security headers scan completed. Found {len(vulnerabilities)} issues")
            
        except Exception as e:
            self.logger.error(f"Error during security headers scan: {str(e)}")
            scan_results['error'] = str(e)
            
        return scan_results
    
    def _analyze_header(self, header_name: str, header_config: Dict[str, Any], 
                       headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Analyze a specific security header"""
        vulnerabilities = []
        
        header_value = headers.get(header_name, '')
        
        if not header_value:
            vulnerabilities.append({
                'type': 'missing_security_header',
                'severity': header_config['severity'],
                'title': f'Missing {header_name} Header',
                'description': f'The {header_name} security header is not present. '
                             f'{header_config["description"]}',
                'location': f'HTTP Response Headers',
                'recommendation': header_config['recommendation'],
                'header_name': header_name,
                'header_value': '',
                'issue': 'missing'
            })
            return vulnerabilities
        
        for check in header_config.get('checks', []):
            check_method = getattr(self, f'_check_{check}', None)
            if check_method:
                result = check_method(header_name, header_value, header_config)
                if result:
                    vulnerabilities.append(result)
        
        return vulnerabilities
    
    def _check_header_present(self, header_name: str, header_value: str, 
                             config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if header is present"""
        if not header_value:
            return {
                'type': 'missing_security_header',
                'severity': config['severity'],
                'title': f'Missing {header_name} Header',
                'description': f'The {header_name} security header is not present.',
                'location': 'HTTP Response Headers',
                'recommendation': config['recommendation'],
                'header_name': header_name,
                'header_value': '',
                'issue': 'missing'
            }
        return None
    
    def _check_valid_value(self, header_name: str, header_value: str, 
                          config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if header has a valid value"""
        valid_values = {
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'X-Content-Type-Options': ['nosniff'],
            'X-XSS-Protection': ['0', '1', '1; mode=block'],
            'Referrer-Policy': [
                'no-referrer', 'no-referrer-when-downgrade', 'origin',
                'origin-when-cross-origin', 'same-origin', 'strict-origin',
                'strict-origin-when-cross-origin', 'unsafe-url'
            ]
        }
        
        if header_name in valid_values:
            if header_value not in valid_values[header_name]:
                return {
                    'type': 'invalid_header_value',
                    'severity': config['severity'],
                    'title': f'Invalid {header_name} Value',
                    'description': f'The {header_name} header has an invalid value: "{header_value}"',
                    'location': 'HTTP Response Headers',
                    'recommendation': config['recommendation'],
                    'header_name': header_name,
                    'header_value': header_value,
                    'issue': 'invalid_value'
                }
        
        return None
    
    def _check_has_default_src(self, header_name: str, header_value: str, 
                              config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if CSP has default-src directive"""
        if 'default-src' not in header_value:
            return {
                'type': 'weak_csp',
                'severity': 'medium',
                'title': 'Weak Content Security Policy',
                'description': 'CSP header is missing default-src directive',
                'location': 'HTTP Response Headers',
                'recommendation': 'Add default-src directive to CSP',
                'header_name': header_name,
                'header_value': header_value,
                'issue': 'missing_default_src'
            }
        return None
    
    def _check_has_script_src(self, header_name: str, header_value: str, 
                             config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if CSP has script-src directive"""
        if 'script-src' not in header_value:
            return {
                'type': 'weak_csp',
                'severity': 'medium',
                'title': 'Weak Content Security Policy',
                'description': 'CSP header is missing script-src directive',
                'location': 'HTTP Response Headers',
                'recommendation': 'Add script-src directive to CSP',
                'header_name': header_name,
                'header_value': header_value,
                'issue': 'missing_script_src'
            }
        return None
    
    def _check_has_style_src(self, header_name: str, header_value: str, 
                            config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if CSP has style-src directive"""
        if 'style-src' not in header_value:
            return {
                'type': 'weak_csp',
                'severity': 'low',
                'title': 'Weak Content Security Policy',
                'description': 'CSP header is missing style-src directive',
                'location': 'HTTP Response Headers',
                'recommendation': 'Add style-src directive to CSP',
                'header_name': header_name,
                'header_value': header_value,
                'issue': 'missing_style_src'
            }
        return None
    
    def _check_has_frame_ancestors(self, header_name: str, header_value: str, 
                                  config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if CSP has frame-ancestors directive"""
        if 'frame-ancestors' not in header_value:
            return {
                'type': 'weak_csp',
                'severity': 'medium',
                'title': 'Weak Content Security Policy',
                'description': 'CSP header is missing frame-ancestors directive',
                'location': 'HTTP Response Headers',
                'recommendation': 'Add frame-ancestors directive to CSP',
                'header_name': header_name,
                'header_value': header_value,
                'issue': 'missing_frame_ancestors'
            }
        return None
    
    def _check_has_max_age(self, header_name: str, header_value: str, 
                          config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if HSTS has max-age directive"""
        if 'max-age' not in header_value:
            return {
                'type': 'weak_hsts',
                'severity': 'medium',
                'title': 'Weak HTTP Strict Transport Security',
                'description': 'HSTS header is missing max-age directive',
                'location': 'HTTP Response Headers',
                'recommendation': 'Add max-age directive to HSTS',
                'header_name': header_name,
                'header_value': header_value,
                'issue': 'missing_max_age'
            }
        return None
    
    def _check_valid_max_age(self, header_name: str, header_value: str, 
                            config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if HSTS max-age is sufficient"""
        max_age_match = re.search(r'max-age=(\d+)', header_value)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:  
                return {
                    'type': 'weak_hsts',
                    'severity': 'low',
                    'title': 'Weak HTTP Strict Transport Security',
                    'description': f'HSTS max-age is too short: {max_age} seconds',
                    'location': 'HTTP Response Headers',
                    'recommendation': 'Set max-age to at least 31536000 (1 year)',
                    'header_name': header_name,
                    'header_value': header_value,
                    'issue': 'short_max_age'
                }
        return None
    
    def _check_has_restrictions(self, header_name: str, header_value: str, 
                               config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if Permissions-Policy has restrictions"""
        if header_value == '' or header_value.lower() == 'none':
            return {
                'type': 'weak_permissions_policy',
                'severity': 'low',
                'title': 'Weak Permissions Policy',
                'description': 'Permissions-Policy header has no restrictions',
                'location': 'HTTP Response Headers',
                'recommendation': 'Add restrictions to Permissions-Policy',
                'header_name': header_name,
                'header_value': header_value,
                'issue': 'no_restrictions'
            }
        return None
    
    def _check_no_cache_for_sensitive(self, header_name: str, header_value: str, 
                                     config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if sensitive content is properly cached"""
        return None
    
    def _check_has_secure_flag(self, header_name: str, header_value: str, 
                              config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if cookies have Secure flag"""
        if 'Secure' not in header_value:
            return {
                'type': 'insecure_cookie',
                'severity': 'medium',
                'title': 'Insecure Cookie Configuration',
                'description': 'Cookie is missing Secure flag',
                'location': 'HTTP Response Headers',
                'recommendation': 'Add Secure flag to cookies',
                'header_name': header_name,
                'header_value': header_value,
                'issue': 'missing_secure_flag'
            }
        return None
    
    def _check_has_httponly_flag(self, header_name: str, header_value: str, 
                                config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if cookies have HttpOnly flag"""
        if 'HttpOnly' not in header_value:
            return {
                'type': 'insecure_cookie',
                'severity': 'medium',
                'title': 'Insecure Cookie Configuration',
                'description': 'Cookie is missing HttpOnly flag',
                'location': 'HTTP Response Headers',
                'recommendation': 'Add HttpOnly flag to cookies',
                'header_name': header_name,
                'header_value': header_value,
                'issue': 'missing_httponly_flag'
            }
        return None
    
    def _check_has_samesite_flag(self, header_name: str, header_value: str, 
                                config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if cookies have SameSite flag"""
        if 'SameSite' not in header_value:
            return {
                'type': 'insecure_cookie',
                'severity': 'low',
                'title': 'Insecure Cookie Configuration',
                'description': 'Cookie is missing SameSite flag',
                'location': 'HTTP Response Headers',
                'recommendation': 'Add SameSite flag to cookies',
                'header_name': header_name,
                'header_value': header_value,
                'issue': 'missing_samesite_flag'
            }
        return None
    
    def _perform_additional_checks(self, headers: Dict[str, str], target: str) -> List[Dict[str, Any]]:
        """Perform additional security header checks"""
        vulnerabilities = []
        
        server_header = headers.get('Server', '')
        if server_header:
            vulnerabilities.append({
                'type': 'information_disclosure',
                'severity': 'low',
                'title': 'Server Information Disclosure',
                'description': f'Server header reveals: {server_header}',
                'location': 'HTTP Response Headers',
                'recommendation': 'Remove or obfuscate Server header',
                'header_name': 'Server',
                'header_value': server_header,
                'issue': 'server_disclosure'
            })
        
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            vulnerabilities.append({
                'type': 'information_disclosure',
                'severity': 'low',
                'title': 'Technology Information Disclosure',
                'description': f'X-Powered-By header reveals: {powered_by}',
                'location': 'HTTP Response Headers',
                'recommendation': 'Remove X-Powered-By header',
                'header_name': 'X-Powered-By',
                'header_value': powered_by,
                'issue': 'technology_disclosure'
            })
        
        if target.startswith('https://'):
            if 'Strict-Transport-Security' not in headers:
                vulnerabilities.append({
                    'type': 'missing_security_header',
                    'severity': 'high',
                    'title': 'Missing HSTS on HTTPS',
                    'description': 'HTTPS site is missing Strict-Transport-Security header',
                    'location': 'HTTP Response Headers',
                    'recommendation': 'Add HSTS header for HTTPS sites',
                    'header_name': 'Strict-Transport-Security',
                    'header_value': '',
                    'issue': 'missing_hsts_https'
                })
        
        return vulnerabilities
