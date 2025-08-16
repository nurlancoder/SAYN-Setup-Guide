"""
GraphQL Security Scanner Module for SAYN
Detects GraphQL-specific vulnerabilities and misconfigurations
"""

import re
import asyncio
import json
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse
import logging

class GraphQLScanner:
    """Advanced GraphQL vulnerability scanner"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger('SAYN.graphql_scanner')
        self.introspection_query = self._get_introspection_query()
        self.test_queries = self._load_test_queries()

    def _get_introspection_query(self) -> str:
        """Get GraphQL introspection query"""
        return """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
            directives {
              name
              description
              locations
              args {
                ...InputValue
              }
            }
          }
        }

        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              ...InputValue
            }
            type {
              ...TypeRef
            }
            isDeprecated
            deprecationReason
          }
          inputFields {
            ...InputValue
          }
          interfaces {
            ...TypeRef
          }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
          possibleTypes {
            ...TypeRef
          }
        }

        fragment InputValue on __InputValue {
          name
          description
          type { ...TypeRef }
          defaultValue
        }

        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """

    def _load_test_queries(self) -> Dict[str, str]:
        """Load test queries for GraphQL vulnerabilities"""
        return {
            'introspection': self.introspection_query,
            'user_query': '''
            query {
              user {
                id
                username
                email
                password
                role
                permissions
              }
            }
            ''',
            'admin_query': '''
            query {
              admin {
                id
                username
                email
                role
                permissions
                settings
              }
            }
            ''',
            'system_query': '''
            query {
              system {
                version
                config
                environment
                secrets
              }
            }
            ''',
            'mutation_test': '''
            mutation {
              createUser(input: {
                username: "test"
                email: "test@test.com"
                password: "password123"
              }) {
                id
                username
                email
              }
            }
            ''',
            'subscription_test': '''
            subscription {
              userUpdates {
                id
                username
                email
              }
            }
            '''
        }

    async def scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Main GraphQL scanning method"""
        self.logger.info(f"Starting GraphQL scan for {target}")

        vulnerabilities = []
        scan_results = {
            'module': 'graphql_scanner',
            'target': target,
            'vulnerabilities': vulnerabilities,
            'scan_completed': False,
            'endpoints_found': [],
            'introspection_enabled': False,
            'schema_exposed': False
        }

        try:
            scanner_engine = options.get('scanner_engine')
            if not scanner_engine:
                raise ValueError("Scanner engine not provided in options")

            endpoints = await self._detect_graphql_endpoints(scanner_engine, target)
            scan_results['endpoints_found'] = endpoints

            for endpoint in endpoints:
                endpoint_vulns = await self._scan_graphql_endpoint(scanner_engine, endpoint)
                vulnerabilities.extend(endpoint_vulns)

            introspection_vulns = await self._test_introspection_exposure(scanner_engine, target)
            vulnerabilities.extend(introspection_vulns)

            info_disclosure_vulns = await self._test_information_disclosure(scanner_engine, target)
            vulnerabilities.extend(info_disclosure_vulns)

            auth_bypass_vulns = await self._test_authorization_bypass(scanner_engine, target)
            vulnerabilities.extend(auth_bypass_vulns)

            rate_limit_vulns = await self._test_rate_limiting(scanner_engine, target)
            vulnerabilities.extend(rate_limit_vulns)

            scan_results['vulnerabilities'] = vulnerabilities
            scan_results['scan_completed'] = True

            self.logger.info(f"GraphQL scan completed. Found {len(vulnerabilities)} vulnerabilities")

        except Exception as e:
            self.logger.error(f"Error during GraphQL scan: {str(e)}")
            scan_results['error'] = str(e)

        return scan_results

    async def _detect_graphql_endpoints(self, scanner_engine, target: str) -> List[str]:
        """Detect GraphQL endpoints on the target"""
        endpoints = []
        common_paths = [
            '/graphql',
            '/graphiql',
            '/api/graphql',
            '/api/graphiql',
            '/gql',
            '/query',
            '/api/query',
            '/graphql/console',
            '/playground',
            '/api/playground'
        ]

        try:
            for path in common_paths:
                endpoint_url = urljoin(target, path)
                response = await scanner_engine.make_request(endpoint_url)
                
                if not response.get('error'):
                    content = response.get('content', '')
                    headers = response.get('headers', {})
                    
                    if self._is_graphql_endpoint(content, headers):
                        endpoints.append(endpoint_url)

        except Exception as e:
            self.logger.error(f"Error detecting GraphQL endpoints: {str(e)}")

        return endpoints

    def _is_graphql_endpoint(self, content: str, headers: Dict[str, str]) -> bool:
        """Check if response indicates a GraphQL endpoint"""
        graphql_indicators = [
            'graphql',
            'graphiql',
            '__schema',
            '__type',
            '__typename',
            'query {',
            'mutation {',
            'subscription {',
            'IntrospectionQuery',
            'GraphQL'
        ]

        content_lower = content.lower()
        for indicator in graphql_indicators:
            if indicator.lower() in content_lower:
                return True

        graphql_headers = [
            'graphql',
            'application/graphql',
            'application/json'
        ]

        for header_name, header_value in headers.items():
            header_lower = f"{header_name}: {header_value}".lower()
            for graphql_header in graphql_headers:
                if graphql_header in header_lower:
                    return True

        return False

    async def _scan_graphql_endpoint(self, scanner_engine, endpoint: str) -> List[Dict[str, Any]]:
        """Scan a specific GraphQL endpoint for vulnerabilities"""
        vulnerabilities = []

        try:
            introspection_vuln = await self._test_endpoint_introspection(scanner_engine, endpoint)
            if introspection_vuln:
                vulnerabilities.append(introspection_vuln)

            error_vuln = await self._test_error_messages(scanner_engine, endpoint)
            if error_vuln:
                vulnerabilities.append(error_vuln)

            batch_vuln = await self._test_batch_queries(scanner_engine, endpoint)
            if batch_vuln:
                vulnerabilities.append(batch_vuln)

        except Exception as e:
            self.logger.error(f"Error scanning GraphQL endpoint {endpoint}: {str(e)}")

        return vulnerabilities

    async def _test_introspection_exposure(self, scanner_engine, target: str) -> List[Dict[str, Any]]:
        """Test for GraphQL introspection exposure"""
        vulnerabilities = []

        try:
            introspection_response = await self._send_graphql_query(
                scanner_engine, target, self.introspection_query
            )

            if introspection_response and not introspection_response.get('errors'):
                schema_data = introspection_response.get('data', {})
                if schema_data and '__schema' in schema_data:
                    vulnerabilities.append({
                        'type': 'graphql_introspection_exposure',
                        'severity': 'high',
                        'title': 'GraphQL Introspection Enabled',
                        'description': 'GraphQL introspection is enabled, exposing the complete schema. '
                                     'This can reveal sensitive information about the API structure.',
                        'location': target,
                        'recommendation': 'Disable GraphQL introspection in production environments. '
                                        'Use proper access controls and consider using persisted queries.',
                        'evidence': json.dumps(schema_data, indent=2)[:1000],
                        'issue': 'introspection_enabled'
                    })

        except Exception as e:
            self.logger.error(f"Error testing introspection exposure: {str(e)}")

        return vulnerabilities

    async def _test_information_disclosure(self, scanner_engine, target: str) -> List[Dict[str, Any]]:
        """Test for information disclosure in GraphQL responses"""
        vulnerabilities = []

        try:
            for query_name, query in self.test_queries.items():
                if query_name == 'introspection':
                    continue  

                response = await self._send_graphql_query(scanner_engine, target, query)
                
                if response:
                    sensitive_data = self._check_sensitive_data(response)
                    if sensitive_data:
                        vulnerabilities.append({
                            'type': 'graphql_information_disclosure',
                            'severity': 'medium',
                            'title': f'GraphQL Information Disclosure - {query_name}',
                            'description': f'Sensitive information is exposed through GraphQL query "{query_name}".',
                            'location': target,
                            'recommendation': 'Implement proper authorization and data filtering. '
                                            'Ensure sensitive fields are not exposed to unauthorized users.',
                            'evidence': json.dumps(sensitive_data, indent=2)[:1000],
                            'query_name': query_name,
                            'issue': 'information_disclosure'
                        })

        except Exception as e:
            self.logger.error(f"Error testing information disclosure: {str(e)}")

        return vulnerabilities

    async def _test_authorization_bypass(self, scanner_engine, target: str) -> List[Dict[str, Any]]:
        """Test for authorization bypass vulnerabilities"""
        vulnerabilities = []

        try:
            admin_response = await self._send_graphql_query(
                scanner_engine, target, self.test_queries['admin_query']
            )

            if admin_response and not admin_response.get('errors'):
                vulnerabilities.append({
                    'type': 'graphql_authorization_bypass',
                    'severity': 'critical',
                    'title': 'GraphQL Authorization Bypass',
                    'description': 'Admin-level GraphQL queries can be executed without proper authentication.',
                    'location': target,
                    'recommendation': 'Implement proper authentication and authorization for all GraphQL operations. '
                                    'Use field-level permissions and role-based access control.',
                    'evidence': json.dumps(admin_response, indent=2)[:1000],
                    'issue': 'authorization_bypass'
                })

        except Exception as e:
            self.logger.error(f"Error testing authorization bypass: {str(e)}")

        return vulnerabilities

    async def _test_rate_limiting(self, scanner_engine, target: str) -> List[Dict[str, Any]]:
        """Test for rate limiting vulnerabilities"""
        vulnerabilities = []

        try:
            rapid_requests = []
            for i in range(10):
                request = self._send_graphql_query(scanner_engine, target, self.test_queries['user_query'])
                rapid_requests.append(request)

            responses = await asyncio.gather(*rapid_requests, return_exceptions=True)
            
            successful_responses = [r for r in responses if r and not isinstance(r, Exception)]
            
            if len(successful_responses) >= 8: 
                vulnerabilities.append({
                    'type': 'graphql_rate_limiting_bypass',
                    'severity': 'medium',
                    'title': 'GraphQL Rate Limiting Bypass',
                    'description': 'GraphQL endpoint does not implement proper rate limiting, '
                                 'making it vulnerable to abuse and DoS attacks.',
                    'location': target,
                    'recommendation': 'Implement rate limiting for GraphQL endpoints. '
                                    'Consider using depth limiting and query complexity analysis.',
                    'evidence': f'Successfully sent {len(successful_responses)} rapid requests',
                    'issue': 'no_rate_limiting'
                })

        except Exception as e:
            self.logger.error(f"Error testing rate limiting: {str(e)}")

        return vulnerabilities

    async def _send_graphql_query(self, scanner_engine, target: str, query: str) -> Optional[Dict[str, Any]]:
        """Send a GraphQL query to the target"""
        try:
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }

            payload = {
                'query': query
            }

            response = await scanner_engine.make_request(
                target, 
                method='POST', 
                headers=headers, 
                data=json.dumps(payload)
            )

            if response.get('error'):
                return None

            content = response.get('content', '')
            if content:
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    return None

        except Exception as e:
            self.logger.error(f"Error sending GraphQL query: {str(e)}")

        return None

    def _check_sensitive_data(self, response: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for sensitive data in GraphQL response"""
        sensitive_patterns = [
            'password',
            'secret',
            'token',
            'key',
            'credential',
            'private',
            'admin',
            'root',
            'system',
            'config',
            'environment'
        ]

        response_str = json.dumps(response, default=str).lower()
        sensitive_data = {}

        for pattern in sensitive_patterns:
            if pattern in response_str:
                sensitive_data[pattern] = True

        return sensitive_data if sensitive_data else None

    async def _test_endpoint_introspection(self, scanner_engine, endpoint: str) -> Optional[Dict[str, Any]]:
        """Test if introspection is enabled on a specific endpoint"""
        try:
            response = await self._send_graphql_query(scanner_engine, endpoint, self.introspection_query)
            
            if response and not response.get('errors'):
                return {
                    'type': 'graphql_introspection_endpoint',
                    'severity': 'high',
                    'title': f'GraphQL Introspection Enabled on {endpoint}',
                    'description': f'GraphQL introspection is enabled on endpoint {endpoint}.',
                    'location': endpoint,
                    'recommendation': 'Disable introspection on this endpoint.',
                    'evidence': 'Introspection query returned schema data',
                    'issue': 'introspection_enabled'
                }

        except Exception as e:
            self.logger.error(f"Error testing endpoint introspection: {str(e)}")

        return None

    async def _test_error_messages(self, scanner_engine, endpoint: str) -> Optional[Dict[str, Any]]:
        """Test for verbose error messages"""
        try:
            malformed_query = '''
            query {
              nonExistentField {
                id
              }
            }
            '''

            response = await self._send_graphql_query(scanner_engine, endpoint, malformed_query)
            
            if response and response.get('errors'):
                error_messages = response.get('errors', [])
                for error in error_messages:
                    if 'message' in error and len(error['message']) > 100:
                        return {
                            'type': 'graphql_verbose_errors',
                            'severity': 'medium',
                            'title': 'GraphQL Verbose Error Messages',
                            'description': 'GraphQL endpoint returns verbose error messages that may reveal sensitive information.',
                            'location': endpoint,
                            'recommendation': 'Implement proper error handling and avoid exposing internal details.',
                            'evidence': json.dumps(error_messages, indent=2),
                            'issue': 'verbose_errors'
                        }

        except Exception as e:
            self.logger.error(f"Error testing error messages: {str(e)}")

        return None

    async def _test_batch_queries(self, scanner_engine, endpoint: str) -> Optional[Dict[str, Any]]:
        """Test for batch query vulnerabilities"""
        try:
            batch_payload = [
                {'query': self.test_queries['user_query']},
                {'query': self.test_queries['admin_query']},
                {'query': self.test_queries['system_query']}
            ]

            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }

            response = await scanner_engine.make_request(
                endpoint, 
                method='POST', 
                headers=headers, 
                data=json.dumps(batch_payload)
            )

            if response and not response.get('error'):
                content = response.get('content', '')
                if content:
                    try:
                        batch_response = json.loads(content)
                        if isinstance(batch_response, list) and len(batch_response) > 1:
                            return {
                                'type': 'graphql_batch_queries',
                                'severity': 'medium',
                                'title': 'GraphQL Batch Queries Enabled',
                                'description': 'GraphQL endpoint supports batch queries, which may be used for abuse.',
                                'location': endpoint,
                                'recommendation': 'Consider disabling batch queries or implementing proper rate limiting.',
                                'evidence': json.dumps(batch_response, indent=2)[:1000],
                                'issue': 'batch_queries_enabled'
                            }
                    except json.JSONDecodeError:
                        pass

        except Exception as e:
            self.logger.error(f"Error testing batch queries: {str(e)}")

        return None
