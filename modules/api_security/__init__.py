"""
API Security Module for SAYN
Coordinates API security scanning operations
"""

import asyncio
from typing import Dict, List, Any
from .rest_scanner import RESTScanner
from .graphql_scanner import GraphQLScanner

class APISecurityScanner:
    """Main API security scanner that coordinates all API security checks"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.rest_scanner = RESTScanner(config)
        self.graphql_scanner = GraphQLScanner(config)
    
    async def scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run all API security scans"""
        scan_results = {
            'module': 'api_security',
            'target': target,
            'vulnerabilities': [],
            'endpoints': [],
            'api_type': 'unknown',
            'scan_completed': False
        }
        
        try:
            api_type = await self._detect_api_type(target, options)
            scan_results['api_type'] = api_type
            
            if api_type == 'rest':
                rest_results = await self.rest_scanner.scan(target, options)
                scan_results['vulnerabilities'].extend(rest_results.get('vulnerabilities', []))
                scan_results['endpoints'] = rest_results.get('endpoints', [])
            elif api_type == 'graphql':
                graphql_results = await self.graphql_scanner.scan(target, options)
                scan_results['vulnerabilities'].extend(graphql_results.get('vulnerabilities', []))
                scan_results['endpoints'] = graphql_results.get('endpoints', [])
            else:
                rest_results = await self.rest_scanner.scan(target, options)
                graphql_results = await self.graphql_scanner.scan(target, options)
                
                scan_results['vulnerabilities'].extend(rest_results.get('vulnerabilities', []))
                scan_results['vulnerabilities'].extend(graphql_results.get('vulnerabilities', []))
                scan_results['endpoints'].extend(rest_results.get('endpoints', []))
                scan_results['endpoints'].extend(graphql_results.get('endpoints', []))
            
            scan_results['scan_completed'] = True
            
        except Exception as e:
            scan_results['error'] = str(e)
            
        return scan_results
    
    async def _detect_api_type(self, target: str, options: Dict[str, Any]) -> str:
        """Detect if the target is a REST API, GraphQL API, or unknown"""
        try:
            scanner_engine = options.get('scanner_engine')
            if not scanner_engine:
                return 'unknown'
            
            response = await scanner_engine.make_request(target)
            if response.get('error'):
                return 'unknown'
            
            content = response.get('content', '').lower()
            headers = response.get('headers', {})
            
            graphql_indicators = [
                'graphql',
                'query',
                'mutation',
                'subscription',
                '__schema',
                'introspection'
            ]
            
            for indicator in graphql_indicators:
                if indicator in content:
                    return 'graphql'
            
            rest_indicators = [
                'api',
                'swagger',
                'openapi',
                'endpoints',
                'resources'
            ]
            
            for indicator in rest_indicators:
                if indicator in content:
                    return 'rest'
            
            content_type = headers.get('content-type', '').lower()
            if 'application/json' in content_type:
                return 'rest'
            
            return 'unknown'
            
        except Exception:
            return 'unknown'
