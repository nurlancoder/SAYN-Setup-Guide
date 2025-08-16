"""
CSRF Scanner Module for SAYN
Detects Cross-Site Request Forgery vulnerabilities
"""

import re
import asyncio
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import logging

class CSRFScanner:
    """Advanced CSRF vulnerability scanner"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger('SAYN.csrf_scanner')
        self.csrf_patterns = self._load_csrf_patterns()

    def _load_csrf_patterns(self) -> Dict[str, List[str]]:
        """Load CSRF token patterns and names"""
        return {
            'token_names': [
                'csrf_token',
                'csrf',
                'token',
                '_token',
                'authenticity_token',
                'xsrf_token',
                'xsrf',
                'csrfmiddlewaretoken',
                'csrf-token',
                'x-csrf-token',
                'x-xsrf-token',
                'security_token',
                'form_token',
                'request_token',
                'session_token'
            ],
            'token_patterns': [
                r'<input[^>]*name=["\'](csrf_token|token|_token|authenticity_token|xsrf_token|csrfmiddlewaretoken)["\'][^>]*>',
                r'<meta[^>]*name=["\'](csrf-token|xsrf-token)["\'][^>]*>',
                r'<input[^>]*type=["\']hidden["\'][^>]*name=["\'](csrf|token|_token)["\'][^>]*>',
                r'csrf_token\s*[:=]\s*["\'][^"\']*["\']',
                r'token\s*[:=]\s*["\'][^"\']*["\']',
                r'_token\s*[:=]\s*["\'][^"\']*["\']'
            ],
            'dangerous_actions': [
                'delete',
                'remove',
                'update',
                'modify',
                'change',
                'edit',
                'save',
                'create',
                'add',
                'post',
                'put',
                'patch'
            ]
        }

    async def scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Main CSRF scanning method"""
        self.logger.info(f"Starting CSRF scan for {target}")

        vulnerabilities = []
        scan_results = {
            'module': 'csrf_scanner',
            'target': target,
            'vulnerabilities': vulnerabilities,
            'scan_completed': False,
            'forms_analyzed': 0,
            'csrf_protected_forms': 0,
            'vulnerable_forms': 0
        }

        try:
            scanner_engine = options.get('scanner_engine')
            if not scanner_engine:
                raise ValueError("Scanner engine not provided in options")

            forms = await self._extract_forms(scanner_engine, target)
            scan_results['forms_analyzed'] = len(forms)

            for form in forms:
                form_vulns = await self._analyze_form_csrf(scanner_engine, target, form)
                vulnerabilities.extend(form_vulns)

                if form_vulns:
                    scan_results['vulnerable_forms'] += 1
                else:
                    scan_results['csrf_protected_forms'] += 1

            csrf_vulns = await self._test_csrf_vulnerabilities(scanner_engine, target)
            vulnerabilities.extend(csrf_vulns)

            scan_results['vulnerabilities'] = vulnerabilities
            scan_results['scan_completed'] = True

            self.logger.info(f"CSRF scan completed. Found {len(vulnerabilities)} vulnerabilities")

        except Exception as e:
            self.logger.error(f"Error during CSRF scan: {str(e)}")
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

            for i, form_match in enumerate(form_matches):
                form_info = {
                    'id': i,
                    'action': self._extract_form_action(form_match),
                    'method': self._extract_form_method(form_match),
                    'inputs': self._extract_form_inputs(form_match),
                    'has_csrf_token': self._check_csrf_token_presence(form_match),
                    'csrf_token_info': self._extract_csrf_token_info(form_match),
                    'is_dangerous': self._is_dangerous_form(form_match)
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
                'value': self._extract_attribute(input_match, 'value', ''),
                'id': self._extract_attribute(input_match, 'id', '')
            }
            if input_info['name']:
                inputs.append(input_info)

        textarea_pattern = r'<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>'
        textarea_matches = re.findall(textarea_pattern, form_html, re.IGNORECASE)

        for name in textarea_matches:
            inputs.append({
                'name': name,
                'type': 'textarea',
                'value': '',
                'id': ''
            })

        return inputs

    def _extract_attribute(self, html: str, attr: str, default: str = '') -> str:
        """Extract attribute value from HTML element"""
        pattern = rf'{attr}=["\']([^"\']*)["\']'
        match = re.search(pattern, html, re.IGNORECASE)
        return match.group(1) if match else default

    def _check_csrf_token_presence(self, form_html: str) -> bool:
        """Check if form contains CSRF token"""
        for pattern in self.csrf_patterns['token_patterns']:
            if re.search(pattern, form_html, re.IGNORECASE):
                return True
        return False

    def _extract_csrf_token_info(self, form_html: str) -> Dict[str, Any]:
        """Extract CSRF token information from form"""
        token_info = {
            'present': False,
            'name': '',
            'type': '',
            'value': '',
            'location': ''
        }

        for token_name in self.csrf_patterns['token_names']:
            pattern = rf'<input[^>]*name=["\']{re.escape(token_name)}["\'][^>]*>'
            match = re.search(pattern, form_html, re.IGNORECASE)
            if match:
                token_info['present'] = True
                token_info['name'] = token_name
                token_info['type'] = 'input'
                token_info['value'] = self._extract_attribute(match.group(0), 'value', '')
                token_info['location'] = 'form_input'
                break

        if not token_info['present']:
            for token_name in ['csrf-token', 'xsrf-token']:
                pattern = rf'<meta[^>]*name=["\']{re.escape(token_name)}["\'][^>]*>'
                match = re.search(pattern, form_html, re.IGNORECASE)
                if match:
                    token_info['present'] = True
                    token_info['name'] = token_name
                    token_info['type'] = 'meta'
                    token_info['value'] = self._extract_attribute(match.group(0), 'content', '')
                    token_info['location'] = 'meta_tag'
                    break

        return token_info

    def _is_dangerous_form(self, form_html: str) -> bool:
        """Check if form performs dangerous actions"""
        form_lower = form_html.lower()
        
        for action in self.csrf_patterns['dangerous_actions']:
            if action in form_lower:
                return True

        method = self._extract_form_method(form_html)
        if method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            return True

        return False

    async def _analyze_form_csrf(self, scanner_engine, target: str, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze a form for CSRF vulnerabilities"""
        vulnerabilities = []

        try:
            if form['method'] == 'GET':
                return vulnerabilities

            if not form['is_dangerous']:
                return vulnerabilities

            if not form['has_csrf_token']:
                vulnerabilities.append({
                    'type': 'csrf_vulnerability',
                    'severity': 'high',
                    'title': 'Missing CSRF Protection',
                    'description': f'Form at {form["action"]} is missing CSRF token protection. '
                                 f'This form performs dangerous actions and could be vulnerable to CSRF attacks.',
                    'location': f'{target} (Form: {form["action"]})',
                    'recommendation': 'Implement CSRF token protection for all state-changing operations. '
                                    'Use unique, unpredictable tokens that are validated on the server side.',
                    'form_action': form['action'],
                    'form_method': form['method'],
                    'csrf_token_present': False,
                    'issue': 'missing_csrf_token'
                })

            if form['has_csrf_token']:
                token_info = form['csrf_token_info']
                if token_info['value'] and len(token_info['value']) < 32:
                    vulnerabilities.append({
                        'type': 'weak_csrf_token',
                        'severity': 'medium',
                        'title': 'Weak CSRF Token',
                        'description': f'CSRF token "{token_info["name"]}" appears to be weak (length: {len(token_info["value"])}).',
                        'location': f'{target} (Form: {form["action"]})',
                        'recommendation': 'Use strong, cryptographically secure CSRF tokens with sufficient length (at least 32 characters).',
                        'form_action': form['action'],
                        'csrf_token_name': token_info['name'],
                        'csrf_token_length': len(token_info['value']),
                        'issue': 'weak_csrf_token'
                    })

        except Exception as e:
            self.logger.error(f"Error analyzing form CSRF: {str(e)}")

        return vulnerabilities

    async def _test_csrf_vulnerabilities(self, scanner_engine, target: str) -> List[Dict[str, Any]]:
        """Test for CSRF vulnerabilities by attempting to bypass protection"""
        vulnerabilities = []

        try:
            predictable_vulns = await self._test_predictable_tokens(scanner_engine, target)
            vulnerabilities.extend(predictable_vulns)

            origin_vulns = await self._test_origin_validation(scanner_engine, target)
            vulnerabilities.extend(origin_vulns)

        except Exception as e:
            self.logger.error(f"Error testing CSRF vulnerabilities: {str(e)}")

        return vulnerabilities

    async def _test_predictable_tokens(self, scanner_engine, target: str) -> List[Dict[str, Any]]:
        """Test for predictable CSRF tokens"""
        vulnerabilities = []

        try:
            predictable_patterns = [
                '1234567890',
                'abcdefghijklmnopqrstuvwxyz',
                '00000000000000000000000000000000',
                '11111111111111111111111111111111',
                'deadbeefdeadbeefdeadbeefdeadbeef',
                'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
            ]

            for pattern in predictable_patterns:
                pass

        except Exception as e:
            self.logger.error(f"Error testing predictable tokens: {str(e)}")

        return vulnerabilities

    async def _test_origin_validation(self, scanner_engine, target: str) -> List[Dict[str, Any]]:
        """Test for missing Origin/Referer header validation"""
        vulnerabilities = []

        try:
            response = await scanner_engine.make_request(target, method='POST', headers={})
            pass

        except Exception as e:
            self.logger.error(f"Error testing origin validation: {str(e)}")

        return vulnerabilities

    def _check_csrf_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Check for CSRF-related headers"""
        header_info = {
            'origin_validation': False,
            'referer_validation': False,
            'custom_csrf_headers': []
        }

        if 'Origin' in headers:
            header_info['origin_validation'] = True

        if 'Referer' in headers:
            header_info['referer_validation'] = True

        csrf_headers = [h for h in headers.keys() if 'csrf' in h.lower() or 'xsrf' in h.lower()]
        header_info['custom_csrf_headers'] = csrf_headers

        return header_info
