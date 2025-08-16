"""
REST API Security Scanner Module for SAYN
Detects vulnerabilities in REST APIs
"""

import re
import asyncio
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse
import logging
import json

class RESTScanner:
    """REST API security vulnerability scanner"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger('SAYN.rest_scanner')
        self.common_endpoints = self._load_common_endpoints()
        
    def _load_common_endpoints(self) -> List[str]:
        """Load common REST API endpoints to test"""
        return [
            '/api',
            '/api/v1',
            '/api/v2',
            '/rest',
            '/rest/v1',
            '/rest/v2',
            '/swagger',
            '/swagger-ui',
            '/swagger.json',
            '/swagger.yaml',
            '/openapi',
            '/openapi.json',
            '/openapi.yaml',
            '/docs',
            '/documentation',
            '/users',
            '/user',
            '/admin',
            '/auth',
            '/login',
            '/logout',
            '/register',
            '/signup',
            '/password',
            '/reset',
            '/profile',
            '/settings',
            '/config',
            '/health',
            '/status',
            '/metrics',
            '/info'
        ]
    
    async def scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Main REST API scanning method"""
        self.logger.info(f"Starting REST API scan for {target}")
        
        scan_results = {
            'module': 'rest_scanner',
            'target': target,
            'vulnerabilities': [],
            'endpoints': [],
            'scan_completed': False
        }
        
        try:
            scanner_engine = options.get('scanner_engine')
            if not scanner_engine:
                raise ValueError("Scanner engine not provided in options")
            
            endpoints = await self._discover_endpoints(scanner_engine, target)
            scan_results['endpoints'] = endpoints
            
            for endpoint in endpoints:
                endpoint_vulns = await self._test_endpoint_vulnerabilities(
                    scanner_engine, target, endpoint, options
                )
                scan_results['vulnerabilities'].extend(endpoint_vulns)
            
            api_vulns = await self._test_api_vulnerabilities(scanner_engine, target, options)
            scan_results['vulnerabilities'].extend(api_vulns)
            
            scan_results['scan_completed'] = True
            
            self.logger.info(f"REST API scan completed. Found {len(scan_results['vulnerabilities'])} vulnerabilities")
            
        except Exception as e:
            self.logger.error(f"Error during REST API scan: {str(e)}")
            scan_results['error'] = str(e)
            
        return scan_results
    
    async def _discover_endpoints(self, scanner_engine, target: str) -> List[str]:
        """Discover REST API endpoints"""
        discovered_endpoints = []
        
        try:
            for endpoint in self.common_endpoints:
                test_url = urljoin(target, endpoint)
                response = await scanner_engine.make_request(test_url)
                
                if not response.get('error'):
                    status_code = response.get('status_code', 0)
                    content = response.get('content', '')
                    
                    if status_code != 404:
                        discovered_endpoints.append(endpoint)
                        
                        if any(doc in endpoint for doc in ['swagger', 'openapi', 'docs']):
                            doc_endpoints = self._extract_endpoints_from_docs(content)
                            discovered_endpoints.extend(doc_endpoints)
            
            robots_endpoints = await self._discover_from_robots(scanner_engine, target)
            discovered_endpoints.extend(robots_endpoints)
            
            sitemap_endpoints = await self._discover_from_sitemap(scanner_engine, target)
            discovered_endpoints.extend(sitemap_endpoints)
            
        except Exception as e:
            self.logger.error(f"Error discovering endpoints: {str(e)}")
            
        return list(set(discovered_endpoints))  
    
    def _extract_endpoints_from_docs(self, content: str) -> List[str]:
        """Extract API endpoints from documentation"""
        endpoints = []
        
        try:
            if content.strip().startswith('{'):
                data = json.loads(content)
                endpoints.extend(self._extract_from_swagger(data))
            
            url_patterns = [
                r'"/api/[^"]*"',
                r'"/rest/[^"]*"',
                r'"/v[0-9]+/[^"]*"',
                r'"/[a-z]+/[a-z]+"'
            ]
            
            for pattern in url_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    endpoint = match.strip('"')
                    if endpoint not in endpoints:
                        endpoints.append(endpoint)
                        
        except Exception as e:
            self.logger.debug(f"Error extracting endpoints from docs: {str(e)}")
            
        return endpoints
    
    def _extract_from_swagger(self, data: Dict) -> List[str]:
        """Extract endpoints from Swagger/OpenAPI specification"""
        endpoints = []
        
        try:
            if 'paths' in data:
                for path in data['paths'].keys():
                    if path not in endpoints:
                        endpoints.append(path)
            
            if 'definitions' in data:
                for definition in data['definitions']:
                    if 'properties' in data['definitions'][definition]:
                        for prop in data['definitions'][definition]['properties']:
                            if 'example' in data['definitions'][definition]['properties'][prop]:
                                example = data['definitions'][definition]['properties'][prop]['example']
                                if isinstance(example, str) and example.startswith('/'):
                                    if example not in endpoints:
                                        endpoints.append(example)
                                        
        except Exception as e:
            self.logger.debug(f"Error extracting from Swagger: {str(e)}")
            
        return endpoints
    
    async def _discover_from_robots(self, scanner_engine, target: str) -> List[str]:
        """Discover endpoints from robots.txt"""
        endpoints = []
        
        try:
            robots_url = urljoin(target, '/robots.txt')
            response = await scanner_engine.make_request(robots_url)
            
            if not response.get('error') and response.get('status_code') == 200:
                content = response.get('content', '')
                lines = content.split('\n')
                
                for line in lines:
                    line = line.strip()
                    if line.startswith('Disallow:') or line.startswith('Allow:'):
                        path = line.split(':', 1)[1].strip()
                        if path.startswith('/') and path not in endpoints:
                            endpoints.append(path)
                            
        except Exception as e:
            self.logger.debug(f"Error discovering from robots.txt: {str(e)}")
            
        return endpoints
    
    async def _discover_from_sitemap(self, scanner_engine, target: str) -> List[str]:
        """Discover endpoints from sitemap"""
        endpoints = []
        
        try:
            sitemap_urls = [
                urljoin(target, '/sitemap.xml'),
                urljoin(target, '/sitemap_index.xml'),
                urljoin(target, '/sitemap.txt')
            ]
            
            for sitemap_url in sitemap_urls:
                response = await scanner_engine.make_request(sitemap_url)
                
                if not response.get('error') and response.get('status_code') == 200:
                    content = response.get('content', '')
                    
                    url_patterns = [
                        r'<loc>([^<]+)</loc>',
                        r'<url><loc>([^<]+)</loc></url>'
                    ]
                    
                    for pattern in url_patterns:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            parsed_url = urlparse(match)
                            if parsed_url.path.startswith('/api') or parsed_url.path.startswith('/rest'):
                                if parsed_url.path not in endpoints:
                                    endpoints.append(parsed_url.path)
                                    
        except Exception as e:
            self.logger.debug(f"Error discovering from sitemap: {str(e)}")
            
        return endpoints
    
    async def _test_endpoint_vulnerabilities(self, scanner_engine, target: str, 
                                           endpoint: str, options: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test a specific endpoint for vulnerabilities"""
        vulnerabilities = []
        
        try:
            endpoint_url = urljoin(target, endpoint)
            
            methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
            
            for method in methods:
                method_vulns = await self._test_method_vulnerabilities(
                    scanner_engine, endpoint_url, method, options
                )
                vulnerabilities.extend(method_vulns)
            
            auth_vulns = await self._test_authentication_bypass(scanner_engine, endpoint_url, options)
            vulnerabilities.extend(auth_vulns)
            
            rate_limit_vulns = await self._test_rate_limiting(scanner_engine, endpoint_url, options)
            vulnerabilities.extend(rate_limit_vulns)
            
        except Exception as e:
            self.logger.error(f"Error testing endpoint {endpoint}: {str(e)}")
            
        return vulnerabilities
    
    async def _test_method_vulnerabilities(self, scanner_engine, url: str, method: str, 
                                         options: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test vulnerabilities for a specific HTTP method"""
        vulnerabilities = []
        
        try:
            response = await scanner_engine.make_request(url, method=method)
            
            if not response.get('error'):
                status_code = response.get('status_code', 0)
                content = response.get('content', '')
                headers = response.get('headers', {})
                
                if status_code == 200 and content:
                    info_disclosure = self._check_information_disclosure(content, url, method)
                    if info_disclosure:
                        vulnerabilities.append(info_disclosure)
                
                security_headers = self._check_security_headers(headers, url, method)
                vulnerabilities.extend(security_headers)
                
                cors_vuln = self._check_cors_misconfiguration(headers, url, method)
                if cors_vuln:
                    vulnerabilities.append(cors_vuln)
                
                payload_vulns = await self._test_malicious_payloads(scanner_engine, url, method, options)
                vulnerabilities.extend(payload_vulns)
                
        except Exception as e:
            self.logger.debug(f"Error testing method {method}: {str(e)}")
            
        return vulnerabilities
    
    def _check_information_disclosure(self, content: str, url: str, method: str) -> Optional[Dict[str, Any]]:
        """Check for information disclosure in response"""
        sensitive_patterns = [
            r'password["\']?\s*[:=]\s*["\'][^"\']*["\']',
            r'api_key["\']?\s*[:=]\s*["\'][^"\']*["\']',
            r'token["\']?\s*[:=]\s*["\'][^"\']*["\']',
            r'secret["\']?\s*[:=]\s*["\'][^"\']*["\']',
            r'private_key["\']?\s*[:=]\s*["\'][^"\']*["\']',
            r'[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{4}',  
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'  
        ]
        
        for pattern in sensitive_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                return {
                    'type': 'information_disclosure',
                    'severity': 'high',
                    'title': 'Sensitive Information Disclosure',
                    'description': f'Sensitive information found in {method} response to {url}',
                    'location': url,
                    'recommendation': 'Remove sensitive information from API responses. Use proper data filtering.',
                    'method': method,
                    'pattern': pattern,
                    'matches': matches[:5]  
                }
        
        return None
    
    def _check_security_headers(self, headers: Dict[str, str], url: str, method: str) -> List[Dict[str, Any]]:
        """Check for missing security headers"""
        vulnerabilities = []
        
        required_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security'
        ]
        
        for header in required_headers:
            if header not in headers:
                vulnerabilities.append({
                    'type': 'missing_security_header',
                    'severity': 'medium',
                    'title': f'Missing Security Header: {header}',
                    'description': f'API endpoint is missing {header} security header',
                    'location': url,
                    'recommendation': f'Add {header} header to API responses.',
                    'method': method,
                    'missing_header': header
                })
        
        return vulnerabilities
    
    def _check_cors_misconfiguration(self, headers: Dict[str, str], url: str, method: str) -> Optional[Dict[str, Any]]:
        """Check for CORS misconfiguration"""
        access_control_origin = headers.get('Access-Control-Allow-Origin', '')
        
        if access_control_origin == '*':
            return {
                'type': 'cors_misconfiguration',
                'severity': 'medium',
                'title': 'CORS Misconfiguration',
                'description': 'API allows requests from any origin (Access-Control-Allow-Origin: *)',
                'location': url,
                'recommendation': 'Restrict CORS to specific trusted domains only.',
                'method': method,
                'cors_header': access_control_origin
            }
        
        return None
    
    async def _test_malicious_payloads(self, scanner_engine, url: str, method: str, 
                                     options: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test with malicious payloads"""
        vulnerabilities = []
        
        if method in ['POST', 'PUT', 'PATCH']:
            malicious_payloads = [
                {'test': 'payload'},
                {'admin': True},
                {'role': 'admin'},
                {'is_admin': 1},
                {'privileged': 'true'}
            ]
            
            for payload in malicious_payloads:
                try:
                    response = await scanner_engine.make_request(
                        url, method=method, json=payload
                    )
                    
                    if not response.get('error'):
                        status_code = response.get('status_code', 0)
                        content = response.get('content', '')
                        
                        if status_code in [200, 201] and content:
                            if any(key in content for key in payload.keys()):
                                vulnerabilities.append({
                                    'type': 'insecure_input_handling',
                                    'severity': 'medium',
                                    'title': 'Insecure Input Handling',
                                    'description': f'API endpoint accepts potentially malicious payload: {payload}',
                                    'location': url,
                                    'recommendation': 'Implement proper input validation and sanitization.',
                                    'method': method,
                                    'payload': payload
                                })
                                
                except Exception as e:
                    self.logger.debug(f"Error testing payload: {str(e)}")
        
        return vulnerabilities
    
    async def _test_authentication_bypass(self, scanner_engine, url: str, 
                                        options: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for authentication bypass vulnerabilities"""
        vulnerabilities = []
        
        bypass_attempts = [
            {'Authorization': 'Bearer null'},
            {'Authorization': 'Bearer undefined'},
            {'Authorization': 'Bearer '},
            {'X-API-Key': 'null'},
            {'X-API-Key': 'undefined'},
            {'X-API-Key': ''},
            {'X-Auth-Token': 'null'},
            {'X-Auth-Token': 'undefined'},
            {'X-Auth-Token': ''}
        ]
        
        for bypass_attempt in bypass_attempts:
            try:
                response = await scanner_engine.make_request(url, headers=bypass_attempt)
                
                if not response.get('error'):
                    status_code = response.get('status_code', 0)
                    
                    if status_code in [200, 201, 202]:
                        vulnerabilities.append({
                            'type': 'authentication_bypass',
                            'severity': 'critical',
                            'title': 'Authentication Bypass',
                            'description': f'API endpoint accessible without valid authentication using: {bypass_attempt}',
                            'location': url,
                            'recommendation': 'Implement proper authentication validation. Reject requests with invalid tokens.',
                            'bypass_attempt': bypass_attempt
                        })
                        
            except Exception as e:
                self.logger.debug(f"Error testing auth bypass: {str(e)}")
        
        return vulnerabilities
    
    async def _test_rate_limiting(self, scanner_engine, url: str, 
                                options: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for rate limiting vulnerabilities"""
        vulnerabilities = []
        
        try:
            requests = []
            for i in range(20):  
                requests.append(scanner_engine.make_request(url))
            
            responses = await asyncio.gather(*requests, return_exceptions=True)
            
            successful_responses = 0
            for response in responses:
                if isinstance(response, dict) and not response.get('error'):
                    status_code = response.get('status_code', 0)
                    if status_code in [200, 201, 202]:
                        successful_responses += 1
            
            if successful_responses > 15:  
                vulnerabilities.append({
                    'type': 'weak_rate_limiting',
                    'severity': 'medium',
                    'title': 'Weak Rate Limiting',
                    'description': f'API endpoint allows {successful_responses}/20 rapid requests without proper rate limiting',
                    'location': url,
                    'recommendation': 'Implement proper rate limiting to prevent abuse and DoS attacks.',
                    'successful_requests': successful_responses,
                    'total_requests': 20
                })
                
        except Exception as e:
            self.logger.debug(f"Error testing rate limiting: {str(e)}")
        
        return vulnerabilities
    
    async def _test_api_vulnerabilities(self, scanner_engine, target: str, 
                                      options: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for API-wide vulnerabilities"""
        vulnerabilities = []
        
        try:
            version_vulns = await self._test_versioning(scanner_engine, target, options)
            vulnerabilities.extend(version_vulns)
            
            error_vulns = await self._test_error_handling(scanner_engine, target, options)
            vulnerabilities.extend(error_vulns)
            
        except Exception as e:
            self.logger.error(f"Error testing API vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    async def _test_versioning(self, scanner_engine, target: str, 
                             options: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for API versioning issues"""
        vulnerabilities = []
        
        version_endpoints = [
            '/api/v1',
            '/api/v2',
            '/api/v3',
            '/rest/v1',
            '/rest/v2'
        ]
        
        for version_endpoint in version_endpoints:
            try:
                url = urljoin(target, version_endpoint)
                response = await scanner_engine.make_request(url)
                
                if not response.get('error'):
                    status_code = response.get('status_code', 0)
                    content = response.get('content', '')
                    
                    if 'v1' in version_endpoint and status_code == 200:
                        vulnerabilities.append({
                            'type': 'deprecated_version_accessible',
                            'severity': 'low',
                            'title': 'Deprecated API Version Accessible',
                            'description': f'Deprecated API version {version_endpoint} is still accessible',
                            'location': url,
                            'recommendation': 'Consider deprecating old API versions and redirecting to newer versions.',
                            'version': version_endpoint
                        })
                        
            except Exception as e:
                self.logger.debug(f"Error testing versioning: {str(e)}")
        
        return vulnerabilities
    
    async def _test_error_handling(self, scanner_engine, target: str, 
                                 options: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for error handling vulnerabilities"""
        vulnerabilities = []
        
        malformed_requests = [
            {'method': 'GET', 'url': urljoin(target, '/api/invalid')},
            {'method': 'POST', 'url': urljoin(target, '/api/test'), 'json': {'invalid': 'data'}},
            {'method': 'GET', 'url': urljoin(target, '/api/../../etc/passwd')},
            {'method': 'GET', 'url': urljoin(target, '/api/%00')}
        ]
        
        for request in malformed_requests:
            try:
                response = await scanner_engine.make_request(
                    request['url'], 
                    method=request['method'],
                    json=request.get('json')
                )
                
                if not response.get('error'):
                    status_code = response.get('status_code', 0)
                    content = response.get('content', '')
                    
                    sensitive_error_patterns = [
                        r'stack trace',
                        r'error in',
                        r'exception',
                        r'debug',
                        r'file.*line',
                        r'class.*exception'
                    ]
                    
                    for pattern in sensitive_error_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            vulnerabilities.append({
                                'type': 'sensitive_error_information',
                                'severity': 'medium',
                                'title': 'Sensitive Error Information Disclosure',
                                'description': f'API reveals sensitive error information in response to malformed request',
                                'location': request['url'],
                                'recommendation': 'Implement proper error handling that does not reveal sensitive information.',
                                'method': request['method'],
                                'pattern': pattern
                            })
                            break
                            
            except Exception as e:
                self.logger.debug(f"Error testing error handling: {str(e)}")
        
        return vulnerabilities
