"""
XSS Scanner Module for SAYN
Detects Cross-Site Scripting vulnerabilities
"""

import re
import asyncio
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import logging

class XSSScanner:
    """Advanced XSS vulnerability scanner"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger('SAYN.xss_scanner')
        self.payloads = self._load_xss_payloads()
        
    def _load_xss_payloads(self) -> List[str]:
        """Load XSS test payloads"""
        return [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '"><script>alert("XSS")</script>',
            'javascript:alert("XSS")',
            
            '&#60;script&#62;alert("XSS")&#60;/script&#62;',
            '%3Cscript%3Ealert("XSS")%3C/script%3E',
            '\\u003Cscript\\u003Ealert("XSS")\\u003C/script\\u003E',
            
            '" onmouseover="alert(\'XSS\')" "',
            '" onfocus="alert(\'XSS\')" "',
            '" onblur="alert(\'XSS\')" "',
            
            '<ScRiPt>alert("XSS")</ScRiPt>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<script>eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41))</script>',
            
            'document.location.hash',
            'window.location.search',
            'document.referrer',
            
            '<iframe src="javascript:alert(\'XSS\')"></iframe>',
            '<object data="javascript:alert(\'XSS\')"></object>',
            '<embed src="javascript:alert(\'XSS\')"></embed>',
            
            'expression(alert("XSS"))',
            'url(javascript:alert("XSS"))',
            
            '<video><source onerror="alert(\'XSS\')">',
            '<audio src=x onerror="alert(\'XSS\')">',
            '<details open ontoggle="alert(\'XSS\')">',
            
            '{{constructor.constructor("alert(\'XSS\')")()}}',
            '${alert("XSS")}',
            '#{alert("XSS")}',
        ]
    
    async def scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Main XSS scanning method"""
        self.logger.info(f"Starting XSS scan for {target}")
        
        vulnerabilities = []
        scan_results = {
            'module': 'xss_scanner',
            'target': target,
            'vulnerabilities': vulnerabilities,
            'scan_completed': False,
            'total_tests': 0,
            'tests_completed': 0
        }
        
        try:
            scanner_engine = options.get('scanner_engine')
            if not scanner_engine:
                self.logger.error(f"Options keys: {list(options.keys())}")
                self.logger.error(f"Options content: {options}")
                raise ValueError("Scanner engine not provided in options")
            
            forms = await self._extract_forms(scanner_engine, target)
            parameters = await self._extract_parameters(scanner_engine, target)
            
            scan_results['total_tests'] = len(forms) * len(self.payloads) + len(parameters) * len(self.payloads)
            
            for form in forms:
                form_vulns = await self._test_form_xss(scanner_engine, target, form)
                vulnerabilities.extend(form_vulns)
                scan_results['tests_completed'] += len(self.payloads)
                
            for param in parameters:
                param_vulns = await self._test_parameter_xss(scanner_engine, target, param)
                vulnerabilities.extend(param_vulns)
                scan_results['tests_completed'] += len(self.payloads)
            
            stored_vulns = await self._test_stored_xss(scanner_engine, target)
            vulnerabilities.extend(stored_vulns)
            
            dom_vulns = await self._test_dom_xss(scanner_engine, target)
            vulnerabilities.extend(dom_vulns)
            
            scan_results['vulnerabilities'] = vulnerabilities
            scan_results['scan_completed'] = True
            
            self.logger.info(f"XSS scan completed. Found {len(vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            self.logger.error(f"Error during XSS scan: {str(e)}")
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
    
    async def _test_form_xss(self, scanner_engine, target: str, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test form inputs for XSS vulnerabilities"""
        vulnerabilities = []
        
        try:
            form_url = urljoin(target, form['action']) if form['action'] else target
            method = form['method']
            
            for input_field in form['inputs']:
                if input_field['type'] in ['text', 'textarea', 'search', 'url', 'tel']:
                    for payload in self.payloads:
                        vuln = await self._test_single_xss(
                            scanner_engine, form_url, method, 
                            input_field['name'], payload, 'form_input'
                        )
                        if vuln:
                            vulnerabilities.append(vuln)
                            
        except Exception as e:
            self.logger.error(f"Error testing form XSS: {str(e)}")
            
        return vulnerabilities
    
    async def _test_parameter_xss(self, scanner_engine, target: str, parameter: str) -> List[Dict[str, Any]]:
        """Test URL parameters for XSS vulnerabilities"""
        vulnerabilities = []
        
        try:
            for payload in self.payloads:
                vuln = await self._test_single_xss(
                    scanner_engine, target, 'GET', 
                    parameter, payload, 'url_parameter'
                )
                if vuln:
                    vulnerabilities.append(vuln)
                    
        except Exception as e:
            self.logger.error(f"Error testing parameter XSS: {str(e)}")
            
        return vulnerabilities
    
    async def _test_single_xss(self, scanner_engine, url: str, method: str, 
                              param_name: str, payload: str, source: str) -> Optional[Dict[str, Any]]:
        """Test a single XSS payload"""
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
            
            if self._is_payload_reflected(payload, content):
                return {
                    'type': 'xss',
                    'severity': self._determine_xss_severity(payload),
                    'title': f'Reflected XSS in {source}',
                    'description': f'Cross-Site Scripting vulnerability found in {source} "{param_name}". '
                                 f'The payload "{payload}" is reflected in the response.',
                    'location': f'{url} (Parameter: {param_name})',
                    'recommendation': 'Implement proper input validation and output encoding. '
                                    'Use Content Security Policy (CSP) headers.',
                    'payload': payload,
                    'source': source,
                    'parameter': param_name,
                    'evidence': self._extract_evidence(payload, content)
                }
                
        except Exception as e:
            self.logger.error(f"Error testing XSS payload: {str(e)}")
            
        return None
    
    def _is_payload_reflected(self, payload: str, content: str) -> bool:
        """Check if XSS payload is reflected in response"""
        if payload in content:
            return True
            
        encoded_payload = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
        if encoded_payload in content:
            return True
            
        import urllib.parse
        url_encoded = urllib.parse.quote(payload)
        if url_encoded in content:
            return True
            
        return False
    
    def _determine_xss_severity(self, payload: str) -> str:
        """Determine severity of XSS vulnerability"""
        dangerous_patterns = [
            r'<script[^>]*>',
            r'javascript:',
            r'on\w+\s*=',
            r'expression\s*\(',
            r'<iframe[^>]*>',
            r'<object[^>]*>',
            r'<embed[^>]*>'
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return 'high'
                
        return 'medium'
    
    def _extract_evidence(self, payload: str, content: str) -> str:
        """Extract evidence of XSS reflection"""
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if payload in line:
                start = max(0, i - 2)
                end = min(len(lines), i + 3)
                return '\n'.join(lines[start:end])
        return content[:500] + '...' if len(content) > 500 else content
    
    async def _test_stored_xss(self, scanner_engine, target: str) -> List[Dict[str, Any]]:
        """Test for stored XSS vulnerabilities"""
        vulnerabilities = []
        
        try:
            common_endpoints = [
                '/comments',
                '/posts',
                '/messages',
                '/feedback',
                '/contact'
            ]
            
            for endpoint in common_endpoints:
                test_url = urljoin(target, endpoint)
                response = await scanner_engine.make_request(test_url)
                
                if not response.get('error'):
                    content = response.get('content', '')
                    for payload in self.payloads:
                        if self._is_payload_reflected(payload, content):
                            vulnerabilities.append({
                                'type': 'stored_xss',
                                'severity': 'high',
                                'title': f'Potential Stored XSS at {endpoint}',
                                'description': f'Potential stored XSS vulnerability detected at {endpoint}. '
                                             f'Content appears to be user-generated and may contain malicious scripts.',
                                'location': test_url,
                                'recommendation': 'Implement proper input validation, output encoding, and Content Security Policy.',
                                'payload': payload,
                                'source': 'stored_content'
                            })
                            break
                            
        except Exception as e:
            self.logger.error(f"Error testing stored XSS: {str(e)}")
            
        return vulnerabilities
    
    async def _test_dom_xss(self, scanner_engine, target: str) -> List[Dict[str, Any]]:
        """Test for DOM-based XSS vulnerabilities"""
        vulnerabilities = []
        
        try:
            response = await scanner_engine.make_request(target)
            if response.get('error'):
                return vulnerabilities
                
            content = response.get('content', '')
            
            dom_patterns = [
                r'document\.location\.hash',
                r'window\.location\.search',
                r'document\.referrer',
                r'innerHTML\s*=',
                r'outerHTML\s*=',
                r'document\.write\s*\(',
                r'eval\s*\(',
                r'setTimeout\s*\([^,]*,\s*[^)]*\)',
                r'setInterval\s*\([^,]*,\s*[^)]*\)'
            ]
            
            for pattern in dom_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    vulnerabilities.append({
                        'type': 'dom_xss',
                        'severity': 'high',
                        'title': 'Potential DOM-based XSS',
                        'description': f'DOM-based XSS pattern detected: {pattern}. '
                                     f'This could lead to client-side code injection.',
                        'location': target,
                        'recommendation': 'Avoid using dangerous JavaScript functions like eval(), innerHTML, etc. '
                                        'Implement proper input validation and sanitization.',
                        'pattern': pattern,
                        'source': 'dom_analysis'
                    })
                    
        except Exception as e:
            self.logger.error(f"Error testing DOM XSS: {str(e)}")
            
        return vulnerabilities
